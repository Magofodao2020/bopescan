// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of
// scope — see AGENTS.md.

//! Permanent WMI event subscriptions: what Windows will run by itself when an event happens
//! (B.O.P.E, ADR 0127).
//!
//! A subscription is three objects in a WMI namespace: an `__EventFilter` (the event query), a
//! consumer (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`, …: what is done) and a
//! `__FilterToConsumerBinding` joining them. `ROOT\subscription` and `ROOT\default` are read through
//! WMI's documented query interface with the account's own rights. Nothing is created, changed,
//! deleted or run.
//!
//! Kept (`scope` is the discriminator): every filter (`filter`) with its name, query language and
//! query; every consumer (`consumer`) with its class, name, the **program** a command line starts (never
//! its arguments, only whether there are any), its working folder, a script consumer's engine and
//! script file, and for an inline script only its length, SHA-256 and the program or script file names
//! it mentions — never its text; every binding (`binding`) with the filter and consumer it joins. A
//! program or script file that exists is hashed and its signature checked. The subscriptions Windows
//! ships (`SCM Event Log Filter`/`Consumer`, `BVTFilter`/`BVTConsumer`) are marked `known_default`.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, Observation, UnmeasuredReason};
use bope_host::{Host, Platform, SourceError, WmiObject, WmiSubscriptionClass};

use crate::catalog;
use crate::common::{Fields, hash_and_signature, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "wmi_subscription";
const DISCRIMINATOR: &str = "scope";
/// The namespaces read.
pub const NAMESPACES: [&str; 2] = [r"ROOT\subscription", r"ROOT\default"];
const FILTER_PROPERTIES: [&str; 4] = ["Name", "Query", "QueryLanguage", "EventNamespace"];
const CONSUMER_PROPERTIES: [&str; 8] = [
    "Name",
    "CommandLineTemplate",
    "ExecutablePath",
    "WorkingDirectory",
    "ScriptingEngine",
    "ScriptFileName",
    "ScriptText",
    "FileName",
];
const BINDING_PROPERTIES: [&str; 2] = ["Filter", "Consumer"];
/// Names of the subscriptions Windows itself creates.
pub const KNOWN_DEFAULTS: [&str; 4] = [
    "SCM Event Log Filter",
    "SCM Event Log Consumer",
    "BVTFilter",
    "BVTConsumer",
];
/// Extensions of the file names picked out of an inline script.
const MENTIONED: [&str; 9] = [
    ".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".lua", ".hta",
];

static FIELDS: [Field; 30] = [
    Field::text("binding_consumer"),
    Field::text("binding_filter"),
    Field::text("class"),
    Field::boolean("common_legitimate"),
    Field::text("consumer_kind"),
    Field::text("event_namespace"),
    Field::boolean("has_arguments"),
    Field::boolean("known_default"),
    Field::text("location_kind"),
    Field::text("match_kind"),
    Field::text("mentioned"),
    Field::text("name"),
    Field::text("namespace"),
    Field::text("path"),
    Field::text("program"),
    Field::text("query"),
    Field::text("query_language"),
    Field::boolean("roblox_context"),
    Field::text("scope"),
    Field::text("script_engine"),
    Field::text("script_file"),
    Field::number("script_length"),
    Field::text("script_sha256"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
    Field::text("working_directory"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// The `wmi_subscription` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct WmiSubscription;

fn prop<'a>(o: &'a WmiObject, name: &str) -> Option<&'a str> {
    o.properties
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.trim().is_empty())
}

fn consumer_kind(class: &str) -> &'static str {
    match class {
        "CommandLineEventConsumer" => "command_line",
        "ActiveScriptEventConsumer" => "active_script",
        "LogFileEventConsumer" => "log_file",
        "NTEventLogEventConsumer" => "event_log",
        "SMTPEventConsumer" => "smtp",
        _ => "other",
    }
}

/// File names with a program or script extension in `text`, at most ten, without duplicates.
pub fn mentioned_files(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in text.split(|c: char| c.is_whitespace() || "\"'()[]{};,=&|<>`".contains(c)) {
        let lower = token.to_ascii_lowercase();
        if MENTIONED.iter().any(|e| lower.ends_with(e)) {
            let name = location::last_segment(token).to_owned();
            if !name.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(&name)) {
                out.push(name);
            }
        }
        if out.len() >= 10 {
            break;
        }
    }
    out
}

/// `Name="x"` out of a WMI object path such as `__EventFilter.Name="x"`.
pub fn path_name(object_path: &str) -> String {
    object_path
        .split_once("Name=")
        .map_or(object_path, |(_, rest)| rest)
        .trim_matches(['"', '\\'])
        .to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    bope_host::sha256_reader(bytes).unwrap_or_default()
}

impl WmiSubscription {
    fn tool(fields: Fields, names: &[&str], path: Option<&str>) -> Fields {
        let found = names
            .iter()
            .find_map(|n| catalog::match_name(n).into_iter().next());
        let roblox = names.iter().any(|n| catalog::path_mentions_roblox(n))
            || path.is_some_and(catalog::path_mentions_roblox);
        let fields = fields.with("roblox_context", roblox);
        match found {
            Some(m) => fields
                .with("tool_id", m.tool.id)
                .with("tool_kind", m.tool.kind.as_str())
                .with("match_kind", m.kind.as_str())
                .with("common_legitimate", m.tool.common_legitimate),
            None => fields,
        }
    }

    fn consumer(host: &dyn Host, namespace: &str, o: &WmiObject) -> Observation {
        let name = prop(o, "Name").unwrap_or_default().to_owned();
        let kind = consumer_kind(&o.class);
        let command = prop(o, "CommandLineTemplate");
        let program = prop(o, "ExecutablePath")
            .map(str::to_owned)
            .or_else(|| command.map(location::program_of_command))
            .filter(|p| !p.is_empty());
        let has_arguments = command.map(|c| {
            let program_len = program.as_deref().map_or(0, str::len);
            c.trim().trim_matches('"').len() > program_len + 1
        });
        let script_file = prop(o, "ScriptFileName").or_else(|| prop(o, "FileName"));
        let script = prop(o, "ScriptText");
        let mentioned = script.map(mentioned_files).unwrap_or_default();
        let checked = program.as_deref().or(script_file);
        let mut fields = Fields::new()
            .with(DISCRIMINATOR, "consumer")
            .with("namespace", namespace)
            .with("class", o.class.clone())
            .with("consumer_kind", kind)
            .with("name", name.clone())
            .with("known_default", KNOWN_DEFAULTS.contains(&name.as_str()))
            .maybe("program", program.clone())
            .maybe("has_arguments", has_arguments)
            .maybe("working_directory", prop(o, "WorkingDirectory"))
            .maybe("script_engine", prop(o, "ScriptingEngine"))
            .maybe("script_file", script_file)
            .maybe("script_length", script.map(str::len))
            .maybe("script_sha256", script.map(|s| sha256_hex(s.as_bytes())))
            .maybe(
                "mentioned",
                (!mentioned.is_empty()).then(|| mentioned.join(", ")),
            );
        if let Some(path) = checked {
            fields = fields
                .with("path", path.to_owned())
                .with(location::FIELD, location::classify(path).as_str());
            if crate::paths::is_drive_rooted(path) && matches!(host.times(path), Ok(Some(_))) {
                let (with, _) = hash_and_signature(host, path, fields);
                fields = with;
            }
        }
        let mut names: Vec<&str> = vec![name.as_str()];
        if let Some(p) = checked {
            names.push(location::last_segment(p));
        }
        names.extend(mentioned.iter().map(String::as_str));
        Self::tool(fields, &names, checked).observe(ID)
    }
}

impl Collector for WmiSubscription {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn discriminator(&self) -> Option<&'static str> {
        Some(DISCRIMINATOR)
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let mut observations = Vec::new();
        let mut read_any = false;
        let mut first_error: Option<SourceError> = None;
        for namespace in NAMESPACES {
            let mut read =
                |class, properties: &[&str]| match host.wmi_objects(namespace, class, properties) {
                    Ok(Some(objects)) => {
                        read_any = true;
                        objects
                    }
                    Ok(None) => Vec::new(),
                    Err(e) => {
                        first_error.get_or_insert(e);
                        Vec::new()
                    }
                };
            let filters = read(WmiSubscriptionClass::Filter, &FILTER_PROPERTIES);
            let consumers = read(WmiSubscriptionClass::Consumer, &CONSUMER_PROPERTIES);
            let bindings = read(WmiSubscriptionClass::Binding, &BINDING_PROPERTIES);
            for o in &filters {
                let name = prop(o, "Name").unwrap_or_default().to_owned();
                let fields = Fields::new()
                    .with(DISCRIMINATOR, "filter")
                    .with("namespace", namespace)
                    .with("class", o.class.clone())
                    .with("name", name.clone())
                    .with("known_default", KNOWN_DEFAULTS.contains(&name.as_str()))
                    .maybe("query", prop(o, "Query"))
                    .maybe("query_language", prop(o, "QueryLanguage"))
                    .maybe("event_namespace", prop(o, "EventNamespace"));
                observations.push(Self::tool(fields, &[name.as_str()], None).observe(ID));
            }
            for o in &consumers {
                observations.push(Self::consumer(host, namespace, o));
            }
            for o in &bindings {
                let filter = prop(o, "Filter").map(path_name).unwrap_or_default();
                let consumer = prop(o, "Consumer").unwrap_or_default();
                let consumer_class = consumer.split('.').next().unwrap_or_default().to_owned();
                let consumer_name = path_name(consumer);
                let fields = Fields::new()
                    .with(DISCRIMINATOR, "binding")
                    .with("namespace", namespace)
                    .with("class", o.class.clone())
                    .with("name", format!("{filter} → {consumer_name}"))
                    .with("binding_filter", filter.clone())
                    .with("binding_consumer", consumer_name.clone())
                    .with("consumer_kind", consumer_kind(&consumer_class))
                    .with(
                        "known_default",
                        KNOWN_DEFAULTS.contains(&filter.as_str())
                            && KNOWN_DEFAULTS.contains(&consumer_name.as_str()),
                    );
                observations.push(
                    Self::tool(fields, &[filter.as_str(), consumer_name.as_str()], None)
                        .observe(ID),
                );
            }
        }
        match (read_any, first_error) {
            (false, Some(SourceError::Unsupported(_))) => {
                unmeasured(ID, UnmeasuredReason::SourceAbsent)
            }
            (false, Some(error)) => unmeasured(ID, crate::common::reason(host, &error)),
            (false, None) => unmeasured(ID, UnmeasuredReason::SourceAbsent),
            (true, error) => {
                let mut gaps = BTreeMap::new();
                if error.is_some() {
                    gaps.insert("namespace".to_owned(), UnmeasuredReason::Partial);
                }
                CollectorRun::Measured {
                    collector: ID.to_owned(),
                    observations,
                    gaps,
                    discriminator_gaps: Vec::new(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    fn host(extra: &str) -> FixtureHost {
        let yaml = format!(
            r#"platform: windows
filesystem:
  'C:\Users\a\AppData\Local\Solara':
    - {{ name: Solara.exe, sha256: '{}' }}
wmi:
  namespaces:
    'ROOT\subscription':
      - class: __EventFilter
        properties: {{ Name: 'SCM Event Log Filter', Query: 'select * from MSFT_SCMEventLogEvent', QueryLanguage: WQL }}
      - class: NTEventLogEventConsumer
        properties: {{ Name: 'SCM Event Log Consumer' }}
      - class: __EventFilter
        properties: {{ Name: 'Upd', Query: 'SELECT * FROM __InstanceModificationEvent WITHIN 60', QueryLanguage: WQL }}
      - class: CommandLineEventConsumer
        properties: {{ Name: 'Upd', CommandLineTemplate: '"C:\Users\a\AppData\Local\Solara\Solara.exe" --silent' }}
      - class: ActiveScriptEventConsumer
        properties: {{ Name: 'Js', ScriptingEngine: 'JScript', ScriptText: 'var s = new ActiveXObject("WScript.Shell"); s.Run("C:\\x\\krnl.exe");' }}
      - class: __FilterToConsumerBinding
        properties: {{ Filter: '__EventFilter.Name="Upd"', Consumer: 'CommandLineEventConsumer.Name="Upd"' }}
{extra}"#,
            "a".repeat(64)
        );
        FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    #[test]
    fn subscriptions_are_read_and_described_without_script_text() {
        let CollectorRun::Measured { observations, .. } = WmiSubscription.collect(&host("")) else {
            panic!()
        };
        assert_eq!(observations.len(), 6);
        let scm = &observations[0];
        assert_eq!(scm.fields["known_default"], true);
        let cmd = observations
            .iter()
            .find(|o| o.fields["class"] == "CommandLineEventConsumer")
            .unwrap();
        assert_eq!(
            cmd.fields["program"],
            r"C:\Users\a\AppData\Local\Solara\Solara.exe"
        );
        assert_eq!(cmd.fields["has_arguments"], true);
        assert_eq!(cmd.fields["tool_id"], "solara");
        assert_eq!(cmd.fields["sha256"], "a".repeat(64));
        assert_eq!(cmd.fields["location_kind"], "appdata_local");
        let js = observations
            .iter()
            .find(|o| o.fields["class"] == "ActiveScriptEventConsumer")
            .unwrap();
        assert_eq!(js.fields["mentioned"], "krnl.exe");
        assert_eq!(js.fields["tool_id"], "krnl");
        assert!(js.fields.contains_key("script_length"));
        assert!(
            !serde_json::to_string(js).unwrap().contains("WScript"),
            "the script's text is never kept"
        );
        let binding = observations
            .iter()
            .find(|o| o.fields["scope"] == "binding")
            .unwrap();
        assert_eq!(binding.fields["binding_filter"], "Upd");
        assert_eq!(binding.fields["consumer_kind"], "command_line");
    }

    #[test]
    fn no_wmi_or_a_denied_namespace_is_unmeasured() {
        let none = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            WmiSubscription.collect(&none),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
        let denied = FixtureHost::from_yaml_str(
            "platform: windows\nwmi:\n  access_denied: ['ROOT\\subscription', 'ROOT\\default']\n",
            "inline",
        )
        .unwrap();
        assert!(matches!(
            WmiSubscription.collect(&denied),
            CollectorRun::Unmeasured { .. }
        ));
    }

    #[test]
    fn file_names_are_picked_out_of_text() {
        assert_eq!(
            mentioned_files(r#"cmd /c "C:\a\b.exe" & powershell -f x.ps1 notes.txt"#),
            vec!["b.exe".to_owned(), "x.ps1".to_owned()]
        );
        assert_eq!(path_name(r#"__EventFilter.Name="Upd""#), "Upd");
    }
}
