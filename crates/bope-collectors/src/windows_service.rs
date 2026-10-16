// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of
// scope — see AGENTS.md.

//! Five Windows services whose own records other sources read, as the Service Control Manager reports
//! them now, and what the `System` log remembers of them (B.O.P.E, ADR 0130).
//!
//! `PcaSvc` (Program Compatibility Assistant), `DiagTrack` (Connected User Experiences and Telemetry),
//! `DPS` (Diagnostic Policy Service), `SysMain` and `EventLog`. Each has an ordinary reason to be
//! stopped or disabled (a tuning guide, an edition, a policy, a failed update), so **nothing here is
//! read as suspicious by this module**; a stopped service only says why another source may hold less.
//!
//! Two kinds of observation, told apart by `scope`:
//!
//! - `current`: one per service, always, with `query` saying what the manager answered — `ok`,
//!   `not_installed`, `access_denied` or `failed` — and, when it answered, `state`, `pid`, and from the
//!   configuration query (`config_query`) `start_type`, `disabled`, `display_name`, `account` and
//!   `binary_path`. `collected_at` is when the host asked: the state is the state at that moment only.
//! - `history`: Service Control Manager events 7034, 7036, 7040 and 7045 of these services from
//!   `System.evtx`, read-only: `event`, `event_at`, `record_id`, the texts as the record holds them, and
//!   `state` / `start_type` only when the record's word is one this module recognises. One `history`
//!   observation with `event: log_span` carries the span the log covers, so that "no event" is read
//!   only inside it.
//!
//! The manager is asked with query rights only; the log is read as a file, never through a writer.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{Host, Platform, ServiceRunState, ServiceStartType, SourceError};
use bope_parsers::evtx::{ServiceEvent, ServiceEvents, service_events};
use jiff::Timestamp;

use crate::common::Fields;
use crate::failure::reason_for;
use crate::{Collector, Field, evtx};

const ID: &str = "windows_service";
const DISCRIMINATOR: &str = "scope";

/// The services read, by internal name, with the English display names their history may carry.
pub const SERVICES: [(&str, &[&str]); 5] = [
    ("PcaSvc", &["Program Compatibility Assistant Service"]),
    ("DiagTrack", &["Connected User Experiences and Telemetry"]),
    ("DPS", &["Diagnostic Policy Service"]),
    ("SysMain", &["SysMain", "Superfetch"]),
    ("EventLog", &["Windows Event Log"]),
];

/// Most history events kept, newest first, across the five services.
pub const MAX_HISTORY: usize = 400;

static FIELDS: [Field; 26] = [
    Field::text("account"),
    Field::text("binary_path"),
    Field::timestamp("collected_at").off_timeline(),
    Field::text("config_query"),
    Field::boolean("disabled"),
    Field::text("display_name"),
    Field::text("event"),
    Field::timestamp("event_at"),
    Field::number("event_id"),
    Field::boolean("exists"),
    Field::text("installed_account"),
    Field::text("installed_image_path"),
    Field::text("installed_start_type"),
    Field::timestamp("log_first").off_timeline(),
    Field::timestamp("log_last").off_timeline(),
    Field::text("matched_by"),
    Field::number("pid"),
    Field::text("query"),
    Field::number("record_id"),
    Field::text("scope"),
    Field::text("service"),
    Field::text("shown_name"),
    Field::text("start_type"),
    Field::text("start_type_text"),
    Field::text("state"),
    Field::text("state_text"),
];

static REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::Partial,
];

/// The `windows_service` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsService;

/// The state a 7036 record's word names, when it is one this module recognises (English or
/// Portuguese); `None` otherwise, never a guess.
pub fn state_of(text: &str) -> Option<&'static str> {
    match text.trim().to_lowercase().as_str() {
        "running" | "em execução" | "executando" => Some("running"),
        "stopped" | "parado" | "interrompido" => Some("stopped"),
        "paused" | "em pausa" | "pausado" => Some("paused"),
        _ => None,
    }
}

/// The start type a 7040 or 7045 record's words name, when recognised.
pub fn start_type_of(text: &str) -> Option<&'static str> {
    match text.trim().to_lowercase().as_str() {
        "disabled" | "desabilitado" | "desativado" => Some("disabled"),
        "auto start" | "automatic" | "automático" | "inicialização automática" => {
            Some("automatic")
        }
        "demand start" | "manual" | "inicialização sob demanda" | "inicialização manual" => {
            Some("manual")
        }
        "boot start" => Some("boot"),
        "system start" => Some("system"),
        _ => None,
    }
}

fn event_kind(id: u32) -> &'static str {
    match id {
        7034 => "unexpected_end",
        7036 => "state_change",
        7040 => "start_type_change",
        _ => "installed",
    }
}

/// Which of [`SERVICES`] an event is about, and how that was known.
fn matched(
    event: &ServiceEvent,
    display_names: &BTreeMap<&str, String>,
) -> Option<(&'static str, &'static str)> {
    for (name, english) in SERVICES {
        if event
            .service
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case(name))
        {
            return Some((name, "service_name"));
        }
        let shown = event.shown_name.as_deref().unwrap_or_default();
        if !shown.is_empty()
            && (english.iter().any(|e| e.eq_ignore_ascii_case(shown))
                || display_names
                    .get(name)
                    .is_some_and(|d| d.eq_ignore_ascii_case(shown)))
        {
            return Some((name, "display_name"));
        }
    }
    None
}

fn query_word(error: &SourceError) -> &'static str {
    match error {
        SourceError::AccessDenied => "access_denied",
        _ => "failed",
    }
}

fn current(host: &dyn Host, name: &str) -> (Observation, Option<SourceError>, Option<String>) {
    let fields = Fields::new()
        .with(DISCRIMINATOR, "current")
        .with("service", name);
    match host.service_status(name) {
        Ok(None) => (
            fields
                .with("query", "not_installed")
                .with("exists", false)
                .observe(ID),
            None,
            None,
        ),
        Err(error) => (
            fields.with("query", query_word(&error)).observe(ID),
            Some(error),
            None,
        ),
        Ok(Some(status)) => {
            let mut fields = fields
                .with("query", "ok")
                .with("exists", true)
                .with("state", status.state.as_str())
                .time("collected_at", Some(status.queried_at))
                .maybe(
                    "pid",
                    status
                        .pid
                        .filter(|_| status.state != ServiceRunState::Stopped),
                );
            let mut display = None;
            match status.config {
                Ok(config) => {
                    display.clone_from(&config.display_name);
                    fields = fields
                        .with("config_query", "ok")
                        .with("start_type", config.start_type.as_str())
                        .with("disabled", config.start_type == ServiceStartType::Disabled)
                        .maybe("display_name", config.display_name)
                        .maybe("account", config.account)
                        .maybe("binary_path", config.binary_path);
                }
                Err(error) => fields = fields.with("config_query", query_word(&error)),
            }
            (fields.observe(ID), None, display)
        }
    }
}

fn history_observation(event: &ServiceEvent, name: &str, by: &str) -> Observation {
    Fields::new()
        .with(DISCRIMINATOR, "history")
        .with("service", name)
        .with("matched_by", by)
        .with("event", event_kind(event.event_id))
        .with("event_id", event.event_id)
        .with("record_id", event.record_id)
        .time("event_at", Some(event.written))
        .maybe("shown_name", event.shown_name.clone())
        .maybe("state_text", event.state_text.clone())
        .maybe("state", event.state_text.as_deref().and_then(state_of))
        .maybe(
            "start_type_text",
            event
                .start_before
                .as_ref()
                .zip(event.start_after.as_ref())
                .map(|(a, b)| format!("{a} → {b}")),
        )
        .maybe(
            "start_type",
            event
                .start_after
                .as_deref()
                .or(event.start_type.as_deref())
                .and_then(start_type_of),
        )
        .maybe("installed_image_path", event.image_path.clone())
        .maybe("installed_start_type", event.start_type.clone())
        .maybe("installed_account", event.account.clone())
        .observe(ID)
}

/// Parses on a thread of its own within `evtx`'s budget, as `windows_start` does (ADR 0024).
fn parse_within(bytes: Vec<u8>) -> Option<Result<ServiceEvents, bope_parsers::error::ParseError>> {
    let (answer, result) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("windows-service-parse".to_owned())
        .spawn(move || {
            let keep = |e: &ServiceEvent| {
                // Kept wide here; `matched` decides with the display names the manager reported.
                e.service.is_some() || e.shown_name.is_some()
            };
            let _ = answer.send(service_events(&bytes, &keep));
        })
        .ok()?;
    result.recv_timeout(evtx::PARSE_BUDGET).ok()
}

/// The history, or why it could not be read.
fn history(
    host: &dyn Host,
    display_names: &BTreeMap<&str, String>,
) -> Result<Vec<Observation>, UnmeasuredReason> {
    let root = host
        .env_var(evtx::SYSTEM_ROOT)
        .map(|r| r.trim_end_matches(['\\', '/']).to_owned())
        .filter(|r| !r.is_empty())
        .ok_or(UnmeasuredReason::ReadFailed)?;
    let path = format!(
        r"{root}\{}\{}",
        evtx::LOGS_RELATIVE_PATH,
        crate::windows_start::SYSTEM_LOG
    );
    let bytes = match host.read_file(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(UnmeasuredReason::SourceAbsent),
        Err(error) => return Err(reason_for(host, &error)),
    };
    let Some(Ok(parsed)) = parse_within(bytes) else {
        return Err(UnmeasuredReason::ReadFailed);
    };
    let mut kept: Vec<(Timestamp, Observation)> = parsed
        .events
        .iter()
        .filter_map(|e| {
            matched(e, display_names)
                .map(|(name, by)| (e.written, history_observation(e, name, by)))
        })
        .collect();
    // Newest first for the bound, then back to the order they happened.
    kept.sort_by_key(|k| std::cmp::Reverse(k.0));
    kept.truncate(MAX_HISTORY);
    kept.reverse();
    let mut out: Vec<Observation> = kept.into_iter().map(|(_, o)| o).collect();
    let span = Fields::new()
        .with(DISCRIMINATOR, "history")
        .with("event", "log_span")
        .with("service", "*")
        .time("log_first", parsed.span.map(|s| s.0))
        .time("log_last", parsed.span.map(|s| s.1))
        .observe(ID);
    out.insert(0, span);
    Ok(out)
}

impl Collector for WindowsService {
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
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }
        let mut observations = Vec::new();
        let mut display_names = BTreeMap::new();
        let mut errors: Vec<SourceError> = Vec::new();
        for (name, _) in SERVICES {
            let (observation, error, display) = current(host, name);
            observations.push(observation);
            errors.extend(error);
            if let Some(display) = display {
                display_names.insert(name, display);
            }
        }
        let history = history(host, &display_names);
        let mut discriminator_gaps = Vec::new();
        let current_unread = errors.len() == SERVICES.len();
        if !errors.is_empty() {
            let reason = if current_unread {
                match &errors[0] {
                    SourceError::Unsupported(_) => UnmeasuredReason::SourceAbsent,
                    e => reason_for(host, e),
                }
            } else {
                UnmeasuredReason::Partial
            };
            discriminator_gaps.push(DiscriminatorGaps {
                discriminator: DISCRIMINATOR.to_owned(),
                value: "current".into(),
                gaps: BTreeMap::from([("state".to_owned(), reason)]),
            });
        }
        match history {
            Ok(events) => observations.extend(events),
            Err(reason) => {
                if current_unread {
                    // Neither part could be read: the run did not look at all.
                    return CollectorRun::Unmeasured {
                        collector: ID.to_owned(),
                        reason: discriminator_gaps[0].gaps["state"],
                    };
                }
                discriminator_gaps.push(DiscriminatorGaps {
                    discriminator: DISCRIMINATOR.to_owned(),
                    value: "history".into(),
                    gaps: BTreeMap::from([("event_at".to_owned(), reason)]),
                });
            }
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    fn host(services: &str) -> FixtureHost {
        let yaml = format!(
            "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\n{services}"
        );
        FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    const ALL: &str = r"services:
  queried_at: '2026-10-16T10:00:00Z'
  installed:
    PcaSvc: { state: running, pid: 1200, config: { start_type: manual, display_name: 'Program Compatibility Assistant Service', account: LocalSystem, binary_path: 'C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p' } }
    DiagTrack: { state: stopped, config: { start_type: disabled, account: LocalSystem } }
    DPS: { state: start_pending, pid: 800, config: { start_type: automatic } }
    SysMain: { state: running, pid: 900, config_access_denied: true }
    EventLog: { access_denied: true }
";

    fn current_of<'a>(observations: &'a [Observation], name: &str) -> &'a Observation {
        observations
            .iter()
            .find(|o| o.fields["scope"] == "current" && o.fields["service"] == name)
            .unwrap()
    }

    #[test]
    fn each_service_says_what_the_manager_answered() {
        let CollectorRun::Measured {
            observations,
            discriminator_gaps,
            ..
        } = WindowsService.collect(&host(ALL))
        else {
            panic!()
        };
        let pca = current_of(&observations, "PcaSvc");
        assert_eq!(pca.fields["state"], "running");
        assert_eq!(pca.fields["pid"], 1200);
        assert_eq!(pca.fields["start_type"], "manual");
        assert_eq!(pca.fields["disabled"], false);
        assert_eq!(pca.fields["account"], "LocalSystem");
        assert_eq!(pca.fields["collected_at"], "2026-10-16T10:00:00Z");
        let diag = current_of(&observations, "DiagTrack");
        assert_eq!(diag.fields["state"], "stopped");
        assert_eq!(diag.fields["disabled"], true);
        assert!(
            !diag.fields.contains_key("pid"),
            "a stopped service has no process"
        );
        let dps = current_of(&observations, "DPS");
        assert_eq!(dps.fields["state"], "start_pending");
        let sysmain = current_of(&observations, "SysMain");
        assert_eq!(sysmain.fields["config_query"], "access_denied");
        assert!(!sysmain.fields.contains_key("start_type"));
        let log = current_of(&observations, "EventLog");
        assert_eq!(log.fields["query"], "access_denied");
        assert!(
            !log.fields.contains_key("state"),
            "a refused query states nothing"
        );
        assert!(
            discriminator_gaps
                .iter()
                .any(|g| g.value == "current" && g.gaps["state"] == UnmeasuredReason::Partial)
        );
        // No System.evtx in this fixture: history is a gap of its own, never "no events".
        assert!(
            discriminator_gaps
                .iter()
                .any(|g| g.value == "history"
                    && g.gaps["event_at"] == UnmeasuredReason::SourceAbsent)
        );
        assert!(!observations.iter().any(|o| o.fields["scope"] == "history"));
    }

    #[test]
    fn a_missing_service_is_not_installed_not_an_error() {
        let yaml = "services:\n  queried_at: '2026-10-16T10:00:00Z'\n  installed:\n    PcaSvc: { state: running, config: { start_type: manual } }\n";
        let CollectorRun::Measured { observations, .. } = WindowsService.collect(&host(yaml))
        else {
            panic!()
        };
        let missing = current_of(&observations, "DiagTrack");
        assert_eq!(missing.fields["query"], "not_installed");
        assert_eq!(missing.fields["exists"], false);
    }

    #[test]
    fn nothing_readable_is_unmeasured() {
        let denied =
            host("services:\n  queried_at: '2026-10-16T10:00:00Z'\n  access_denied: true\n");
        assert!(matches!(
            WindowsService.collect(&denied),
            CollectorRun::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                ..
            }
        ));
        let none = host("");
        assert!(matches!(
            WindowsService.collect(&none),
            CollectorRun::Unmeasured {
                reason: UnmeasuredReason::SourceAbsent,
                ..
            }
        ));
        let other = FixtureHost::from_yaml_str("platform: other\n", "inline").unwrap();
        assert!(matches!(
            WindowsService.collect(&other),
            CollectorRun::Unmeasured {
                reason: UnmeasuredReason::NotWindows,
                ..
            }
        ));
    }

    #[test]
    fn history_is_matched_by_key_or_by_display_name_only() {
        let at: Timestamp = "2026-10-01T08:00:00Z".parse().unwrap();
        let event = |service: Option<&str>, shown: Option<&str>| ServiceEvent {
            written: at,
            record_id: 1,
            event_id: 7036,
            service: service.map(str::to_owned),
            shown_name: shown.map(str::to_owned),
            state_text: Some("stopped".to_owned()),
            start_before: None,
            start_after: None,
            image_path: None,
            start_type: None,
            account: None,
        };
        let names = BTreeMap::from([("DPS", "Serviço de Política de Diagnóstico".to_owned())]);
        assert_eq!(
            matched(&event(Some("sysmain"), None), &names),
            Some(("SysMain", "service_name"))
        );
        assert_eq!(
            matched(
                &event(None, Some("Serviço de Política de Diagnóstico")),
                &names
            ),
            Some(("DPS", "display_name"))
        );
        assert_eq!(
            matched(&event(None, Some("Windows Event Log")), &names),
            Some(("EventLog", "display_name"))
        );
        assert_eq!(
            matched(&event(Some("Spooler"), Some("Print Spooler")), &names),
            None
        );
        let o = history_observation(&event(Some("SysMain"), None), "SysMain", "service_name");
        assert_eq!(o.fields["event"], "state_change");
        assert_eq!(o.fields["state"], "stopped");
        assert_eq!(o.fields["event_at"], "2026-10-01T08:00:00Z");
    }

    #[test]
    fn words_are_recognised_or_left_alone() {
        assert_eq!(state_of("Running"), Some("running"));
        assert_eq!(state_of("em execução"), Some("running"));
        assert_eq!(state_of("wird ausgeführt"), None);
        assert_eq!(start_type_of("disabled"), Some("disabled"));
        assert_eq!(start_type_of("auto start"), Some("automatic"));
        assert_eq!(start_type_of("x"), None);
    }
}
