// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Roblox `FastFlag` **values**, compared with the reference, and what the PC still holds about
//! earlier values (B.O.P.E, ADR 0136).
//!
//! `fastflags` says which settings files exist and what kinds of flags they set; this collector reads
//! the values in them and compares each with the copy of the `MaximumADHD/Roblox-FFlag-Tracker`
//! reference the scan was given.
//!
//! # Scopes
//!
//! - `reference` (always one row): whether a reference was available, its revision, when it was
//!   fetched, how many entries it holds, the client version its commit names, the version of the
//!   player in the active version folder, and how far the two correspond (`exact`, `different_version`,
//!   `reference_version_unknown`, `client_version_unknown`, `unavailable`). Only `exact` makes a
//!   comparison more than indicative, and even then the reference is what the live channel delivers,
//!   not what this client had to use.
//! - `value`: one row per flag set in a settings file the player reads or a bootstrapper keeps for it
//!   (at most [`MAX_VALUES_PER_FILE`] per file), with the comparison.
//! - `change`: a flag whose value differs between two copies on the PC — a backup, an older version
//!   folder, the bootstrapper's copy — with both values, both files and both modification times, and
//!   whether the active file now holds the reference value. That is what "set, then put back" leaves on
//!   disk; it is never inferred from one file alone, and no time is invented: the times are the files'
//!   own.
//! - `dump` and `dump_value`: Roblox crash dumps (`RobloxPlayerBeta.exe.*.dmp` under
//!   `%LOCALAPPDATA%\CrashDumps`, and `*.dmp` under `%LOCALAPPDATA%\Roblox\logs`), and the `FastFlag`
//!   assignments written as JSON text in their captured memory, with the time the dump was written.
//!   A dump is the client's memory at that moment: a value in it is what that process held then.
//!
//! # What a row does not prove
//!
//! A value that differs from the reference is not an exploit: most edited flags change graphics or
//! frame rate, the reference changes every few days, and Roblox ignores flags outside an allow-list. A
//! flag missing from the reference is never a difference. A value in a dump is not proof it was in
//! effect.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{Host, MAX_READ_AT_BYTES, Platform};
use bope_parsers::{memory, minidump, pe};
use serde_json::Value;

use crate::common::{Fields, env_folder, join, unmeasured};
use crate::fastflags::{SettingsFile, flag_kind, is_flag_name, settings_files};
use crate::flag_reference::{ReferenceSnapshot, comparison_fields};
use crate::{CollectContext, Collector, Field};

/// Collector id.
pub const ID: &str = "roblox_flags";
const DISCRIMINATOR: &str = "scope";
/// Largest settings file read.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Most value rows per file.
pub const MAX_VALUES_PER_FILE: usize = 300;
/// Most change rows.
pub const MAX_CHANGES: usize = 300;
/// Most crash dumps read.
pub const MAX_DUMPS: usize = 12;
/// Most bytes of one dump's captured memory searched.
pub const MAX_DUMP_SCAN: u64 = 512 * 1024 * 1024;
/// Most value rows per dump.
pub const MAX_VALUES_PER_DUMP: usize = 200;
/// How long the dumps may take.
pub const BUDGET: Duration = Duration::from_secs(60);
/// Largest `.rsrc` section read for the player's version.
const MAX_RESOURCE: usize = 32 * 1024 * 1024;

static FIELDS: [Field; 37] = [
    Field::boolean("active_version"),
    Field::boolean("applies_to_player"),
    Field::boolean("available"),
    Field::boolean("backup"),
    Field::text("client_version"),
    Field::text("commit_date"),
    Field::text("comparison"),
    Field::boolean("complete"),
    Field::text("current_path"),
    Field::text("current_value"),
    Field::text("earlier_comparison"),
    Field::timestamp("earlier_modified"),
    Field::text("earlier_path"),
    Field::text("earlier_value"),
    Field::text("encoding"),
    Field::number("entries"),
    Field::text("fetched_at"),
    Field::text("finding"),
    Field::text("flag"),
    Field::text("flag_kind"),
    Field::number("flag_values"),
    Field::text("location"),
    Field::timestamp("modified"),
    Field::text("owner"),
    Field::text("path"),
    Field::number("process_id"),
    Field::text("reference_client_version"),
    Field::text("reference_key"),
    Field::text("reference_revision"),
    Field::text("reference_value"),
    Field::text("revision_kind"),
    Field::text("scope"),
    Field::text("source_url"),
    Field::text("unavailable_reason"),
    Field::text("value"),
    Field::text("version_correspondence"),
    Field::timestamp("written_at"),
];

static REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `roblox_flags` collector, with the reference its values are compared with.
#[derive(Debug, Clone, Default)]
pub struct RobloxFlags {
    reference: Option<std::sync::Arc<ReferenceSnapshot>>,
}

impl RobloxFlags {
    /// The collector, comparing with `reference` when there is one.
    pub fn new(reference: Option<std::sync::Arc<ReferenceSnapshot>>) -> Self {
        Self { reference }
    }
}

/// A JSON value as the text the reference comparison uses.
pub fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.chars().take(memory::MAX_TEXT).collect()),
        _ => None,
    }
}

/// The flags a settings file sets, in key order.
fn values_of(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    Some(
        value
            .as_object()?
            .iter()
            .filter(|(key, _)| is_flag_name(key))
            .filter_map(|(key, value)| Some((key.clone(), value_text(value)?)))
            .collect(),
    )
}

/// The version of the player in the active version folder.
fn client_version(host: &dyn Host, files: &[SettingsFile]) -> Option<String> {
    let active = files.iter().find(|f| f.active_version)?;
    let settings = active.path.rsplit_once('\\')?.0;
    let folder = settings.rsplit_once('\\')?.0;
    let exe = join(folder, "RobloxPlayerBeta.exe");
    let headers = host.read_file_at(&exe, 0, 64 * 1024).ok()??;
    let mut read = |offset: u64, len: usize| host.read_file_at(&exe, offset, len).ok().flatten();
    let version = pe::version_of_large(&headers, MAX_RESOURCE, &mut read)?;
    version.file_version.or(version.fixed_file_version)
}

fn correspondence(snapshot: Option<&ReferenceSnapshot>, client: Option<&str>) -> &'static str {
    let Some(snapshot) = snapshot else {
        return "unavailable";
    };
    match (snapshot.reference_client_version.as_deref(), client) {
        (None, _) => "reference_version_unknown",
        (Some(_), None) => "client_version_unknown",
        (Some(reference), Some(client)) if reference == client.replace(", ", ".") => "exact",
        _ => "different_version",
    }
}

/// One settings file read.
struct Read<'a> {
    file: &'a SettingsFile,
    values: BTreeMap<String, String>,
}

/// The crash dumps of the player.
fn dump_paths(host: &dyn Host) -> Vec<(String, Option<jiff::Timestamp>)> {
    let mut found = Vec::new();
    let Some(local) = env_folder(host, "LOCALAPPDATA") else {
        return found;
    };
    let crash = join(&local, "CrashDumps");
    for entry in host.list_dir(&crash).ok().flatten().unwrap_or_default() {
        let lower = entry.name.to_ascii_lowercase();
        if entry.is_file
            && lower.starts_with("robloxplayerbeta")
            && std::path::Path::new(&lower)
                .extension()
                .is_some_and(|e| e == "dmp")
        {
            found.push((join(&crash, &entry.name), entry.modified));
        }
    }
    let logs = join(&local, r"Roblox\logs");
    let mut folders = vec![logs.clone()];
    for entry in host.list_dir(&logs).ok().flatten().unwrap_or_default() {
        if !entry.is_file {
            folders.push(join(&logs, &entry.name));
        }
    }
    for folder in folders {
        for entry in host.list_dir(&folder).ok().flatten().unwrap_or_default() {
            if entry.is_file && entry.name.to_ascii_lowercase().ends_with(".dmp") {
                found.push((join(&folder, &entry.name), entry.modified));
            }
        }
    }
    // Newest first, so the limit keeps the most recent.
    found.sort_by_key(|f| std::cmp::Reverse(f.1));
    found
}

impl RobloxFlags {
    fn reference_row(&self, client: Option<&str>) -> Observation {
        let snapshot = self.reference.as_deref();
        let mut row = Fields::new()
            .with(DISCRIMINATOR, "reference")
            .with("available", snapshot.is_some())
            .maybe("client_version", client.map(str::to_owned))
            .with("version_correspondence", correspondence(snapshot, client));
        match snapshot {
            Some(s) => {
                row = row
                    .with("reference_revision", s.revision.clone())
                    .with("revision_kind", s.revision_kind.clone())
                    .maybe("commit_date", s.commit_date.clone())
                    .with("fetched_at", s.fetched_at.clone())
                    .with("source_url", s.source_url.clone())
                    .with("entries", s.reference.len())
                    .maybe(
                        "reference_client_version",
                        s.reference_client_version.clone(),
                    );
            }
            None => row = row.with("unavailable_reason", "no_reference_copy"),
        }
        row.observe(ID)
    }

    fn compare(&self, fields: Fields, flag: &str, value: &str) -> Fields {
        comparison_fields(fields, self.reference.as_deref(), flag, value)
    }

    /// Whether the reference holds `value` for `flag`.
    fn is_reference_value(&self, flag: &str, value: &str) -> Option<bool> {
        let snapshot = self.reference.as_deref()?;
        match snapshot.reference.compare(flag, value) {
            bope_parsers::fflag_reference::Comparison::Equal(_) => Some(true),
            bope_parsers::fflag_reference::Comparison::Differs(_) => Some(false),
            bope_parsers::fflag_reference::Comparison::NotInReference => None,
        }
    }

    /// Change rows: each copy against the active file.
    fn changes(&self, reads: &[Read<'_>]) -> Vec<Observation> {
        let mut rows = Vec::new();
        let Some(active) = reads.iter().find(|r| r.file.active_version) else {
            return rows;
        };
        for other in reads.iter().filter(|r| !std::ptr::eq(*r, active)) {
            for (flag, earlier) in &other.values {
                if rows.len() >= MAX_CHANGES {
                    return rows;
                }
                let current = active.values.get(flag);
                if current == Some(earlier) {
                    continue;
                }
                let earlier_matches = self.is_reference_value(flag, earlier);
                let current_matches = match current {
                    Some(value) => self.is_reference_value(flag, value),
                    None => None,
                };
                let finding = match (current, earlier_matches, current_matches) {
                    (_, Some(false), Some(true)) => "other_copy_differs_active_matches_reference",
                    (None, Some(false), _) => "other_copy_differs_active_unset",
                    (None, _, _) => "set_in_other_copy_only",
                    (Some(_), _, _) => "differs_between_copies",
                };
                let mut row = Fields::new()
                    .with(DISCRIMINATOR, "change")
                    .with("flag", flag.clone())
                    .with("flag_kind", flag_kind(flag))
                    .with("finding", finding)
                    .with("earlier_value", earlier.clone())
                    .with("earlier_path", other.file.path.clone())
                    .time("earlier_modified", other.file.entry.modified)
                    .with("location", other.file.location)
                    .with("backup", other.file.backup)
                    .with("current_path", active.file.path.clone())
                    .time("modified", active.file.entry.modified)
                    .maybe("current_value", current.cloned());
                if let Some(matches) = earlier_matches {
                    row = row.with(
                        "earlier_comparison",
                        if matches { "equal" } else { "differs" },
                    );
                }
                if let Some(value) = current {
                    row = self.compare(row, flag, value);
                }
                rows.push(row.observe(ID));
            }
        }
        rows
    }

    /// Dump rows, within the budget. Returns whether every dump was read.
    fn dumps(
        &self,
        host: &dyn Host,
        context: &CollectContext<'_>,
        rows: &mut Vec<Observation>,
    ) -> bool {
        let deadline = Instant::now() + BUDGET;
        let paths = dump_paths(host);
        let complete = paths.len() <= MAX_DUMPS;
        for (path, _) in paths.into_iter().take(MAX_DUMPS) {
            if context.cancelled() || Instant::now() >= deadline {
                return false;
            }
            context.note(&format!("reading crash dump {path}"));
            let Ok(Some(head)) = host.read_file_at(&path, 0, 64 * 1024) else {
                continue;
            };
            let Ok(extent) = minidump::metadata_extent(&head) else {
                continue;
            };
            let header = if usize::try_from(extent).unwrap_or(usize::MAX) > head.len() {
                match host.read_file_at(
                    &path,
                    0,
                    usize::try_from(extent)
                        .unwrap_or(MAX_READ_AT_BYTES)
                        .min(MAX_READ_AT_BYTES),
                ) {
                    Ok(Some(bytes)) => bytes,
                    _ => continue,
                }
            } else {
                head
            };
            let Ok(dump) = minidump::parse(&header) else {
                continue;
            };
            let is_player = dump.modules.iter().any(|m| {
                m.name
                    .to_ascii_lowercase()
                    .ends_with("robloxplayerbeta.exe")
            }) || path.to_ascii_lowercase().contains("robloxplayerbeta");
            if !is_player {
                continue;
            }
            let written_at = jiff::Timestamp::from_second(i64::from(dump.written_at)).ok();
            let mut seen = std::collections::BTreeSet::new();
            let mut values = Vec::new();
            let mut scanned = 0_u64;
            'ranges: for range in &dump.memory {
                let mut offset = 0_u64;
                while offset < range.size {
                    if scanned >= MAX_DUMP_SCAN || Instant::now() >= deadline {
                        break 'ranges;
                    }
                    let len = usize::try_from(range.size - offset)
                        .unwrap_or(MAX_READ_AT_BYTES)
                        .min(MAX_READ_AT_BYTES);
                    let Ok(Some(bytes)) = host.read_file_at(&path, range.file_offset + offset, len)
                    else {
                        break;
                    };
                    for assignment in memory::flag_assignments(
                        &bytes,
                        range.address + offset,
                        MAX_VALUES_PER_DUMP,
                    ) {
                        if values.len() < MAX_VALUES_PER_DUMP
                            && seen.insert((assignment.name.clone(), assignment.value.clone()))
                        {
                            values.push(assignment);
                        }
                    }
                    scanned += len as u64;
                    offset += len as u64;
                }
            }
            rows.push(
                Fields::new()
                    .with(DISCRIMINATOR, "dump")
                    .with("path", path.clone())
                    .time("written_at", written_at)
                    .maybe("process_id", dump.process_id)
                    .with("flag_values", values.len())
                    .observe(ID),
            );
            for assignment in values {
                let row = Fields::new()
                    .with(DISCRIMINATOR, "dump_value")
                    .with("path", path.clone())
                    .time("written_at", written_at)
                    .with("flag", assignment.name.clone())
                    .with("flag_kind", flag_kind(&assignment.name))
                    .with("value", assignment.value.clone())
                    .with("encoding", assignment.encoding.as_str());
                rows.push(
                    self.compare(row, &assignment.name, &assignment.value)
                        .observe(ID),
                );
            }
        }
        complete
    }
}

impl Collector for RobloxFlags {
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
        self.collect_with(host, &CollectContext::none())
    }

    fn collect_with(&self, host: &dyn Host, context: &CollectContext<'_>) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let found = settings_files(host);
        let mut reads = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for file in &found.files {
            if !seen.insert(file.path.to_ascii_lowercase())
                || file.entry.size.is_some_and(|s| s > MAX_FILE_BYTES)
            {
                continue;
            }
            if let Ok(Some(bytes)) = host.read_file(&file.path)
                && let Some(values) = values_of(&bytes)
            {
                reads.push(Read { file, values });
            }
        }
        let client = client_version(host, &found.files);
        let mut observations = vec![self.reference_row(client.as_deref())];
        for read in reads
            .iter()
            .filter(|r| r.file.applies_to_player || r.file.location == "bootstrapper")
        {
            for (flag, value) in read.values.iter().take(MAX_VALUES_PER_FILE) {
                let row = Fields::new()
                    .with(DISCRIMINATOR, "value")
                    .with("flag", flag.clone())
                    .with("flag_kind", flag_kind(flag))
                    .with("value", value.clone())
                    .with("path", read.file.path.clone())
                    .with("location", read.file.location)
                    .with("owner", read.file.owner.clone())
                    .with("applies_to_player", read.file.applies_to_player)
                    .with("active_version", read.file.active_version)
                    .with("backup", read.file.backup)
                    .time("modified", read.file.entry.modified);
                observations.push(self.compare(row, flag, value).observe(ID));
            }
        }
        observations.extend(self.changes(&reads));
        let dumps_complete = self.dumps(host, context, &mut observations);
        let mut discriminator_gaps = Vec::new();
        let mut gaps_for = |place: &str, fields: &[&str]| {
            discriminator_gaps.push(DiscriminatorGaps {
                discriminator: DISCRIMINATOR.to_owned(),
                value: Value::from(place),
                gaps: fields
                    .iter()
                    .map(|f| ((*f).to_owned(), UnmeasuredReason::BudgetSpent))
                    .collect(),
            });
        };
        if found.stopped {
            gaps_for("value", &["flag", "comparison"]);
            gaps_for("change", &["flag", "finding"]);
        }
        if !dumps_complete {
            gaps_for("dump_value", &["flag", "comparison"]);
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
    use std::sync::Arc;

    use bope_host::FixtureHost;

    use super::*;

    const HOST: &str = r#"platform: windows
env:
  USERPROFILE: 'C:\Users\a'
  LOCALAPPDATA: 'C:\Users\a\AppData\Local'
filesystem:
  'C:\Users\a\AppData\Local\Roblox\Versions':
    - { name: version-old, directory: true, modified: '2026-09-01T00:00:00Z' }
    - { name: version-new, directory: true, modified: '2026-10-10T00:00:00Z' }
  'C:\Users\a\AppData\Local\Roblox\Versions\version-old':
    - { name: RobloxPlayerBeta.exe }
    - { name: ClientSettings, directory: true }
  'C:\Users\a\AppData\Local\Roblox\Versions\version-old\ClientSettings':
    - name: ClientAppSettings.json
      modified: '2026-10-01T12:00:00Z'
      content: '{"DFIntS2PhysicsSenderRate": 1, "FFlagDebugGraphicsPreferD3D11": true}'
  'C:\Users\a\AppData\Local\Roblox\Versions\version-new':
    - { name: RobloxPlayerBeta.exe }
    - { name: ClientSettings, directory: true }
  'C:\Users\a\AppData\Local\Roblox\Versions\version-new\ClientSettings':
    - name: ClientAppSettings.json
      modified: '2026-10-14T19:00:00Z'
      content: '{"DFIntS2PhysicsSenderRate": 15, "DFIntTaskSchedulerTargetFps": 240}'
"#;

    fn snapshot() -> Arc<ReferenceSnapshot> {
        let mut text = String::from("{");
        for index in 0..bope_parsers::fflag_reference::MIN_ENTRIES {
            text.push_str("\"FFlagFiller");
            text.push_str(&index.to_string());
            text.push_str("\": true,");
        }
        text.push_str("\"DFIntS2PhysicsSenderRate\": 15, \"DFIntTaskSchedulerTargetFps\": 60}");
        Arc::new(ReferenceSnapshot {
            reference: bope_parsers::fflag_reference::parse(text.as_bytes()).unwrap(),
            revision: "abc".to_owned(),
            commit_date: None,
            fetched_at: "2026-10-16T00:00:00Z".to_owned(),
            source_url: "https://example.invalid".to_owned(),
            revision_kind: "commit".to_owned(),
            reference_client_version: Some("0.695.0.6950777".to_owned()),
        })
    }

    fn rows(run: &CollectorRun, scope: &str) -> Vec<Observation> {
        match run {
            CollectorRun::Measured { observations, .. } => observations
                .iter()
                .filter(|o| o.fields[DISCRIMINATOR] == scope)
                .cloned()
                .collect(),
            CollectorRun::Unmeasured { .. } => panic!("{run:?}"),
        }
    }

    #[test]
    fn values_are_compared_and_a_value_put_back_is_shown_with_both_files() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let run = RobloxFlags::new(Some(snapshot())).collect(&host);
        let reference = &rows(&run, "reference")[0];
        assert_eq!(reference.fields["available"], true);
        assert_eq!(reference.fields["entries"], 1002);
        assert_eq!(
            reference.fields["version_correspondence"],
            "client_version_unknown"
        );
        let values = rows(&run, "value");
        let fps = values
            .iter()
            .find(|o| {
                o.fields["flag"] == "DFIntTaskSchedulerTargetFps"
                    && o.fields["active_version"] == true
            })
            .unwrap();
        assert_eq!(fps.fields["comparison"], "differs");
        assert_eq!(fps.fields["reference_value"], "60");
        let changes = rows(&run, "change");
        let physics = changes
            .iter()
            .find(|o| o.fields["flag"] == "DFIntS2PhysicsSenderRate")
            .unwrap();
        assert_eq!(
            physics.fields["finding"],
            "other_copy_differs_active_matches_reference"
        );
        assert_eq!(physics.fields["earlier_value"], "1");
        assert_eq!(physics.fields["current_value"], "15");
        assert_eq!(physics.fields["earlier_modified"], "2026-10-01T12:00:00Z");
    }

    #[test]
    fn without_a_reference_the_reference_row_says_so_and_nothing_is_compared() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let run = RobloxFlags::default().collect(&host);
        let reference = &rows(&run, "reference")[0];
        assert_eq!(reference.fields["available"], false);
        assert_eq!(reference.fields["unavailable_reason"], "no_reference_copy");
        assert_eq!(reference.fields["version_correspondence"], "unavailable");
        assert!(
            rows(&run, "value")
                .iter()
                .all(|o| o.fields["comparison"] == "no_reference")
        );
    }

    #[test]
    fn a_crash_dump_gives_the_values_the_player_held_when_it_was_written() {
        let host = format!(
            "{HOST}  'C:\\Users\\a\\AppData\\Local\\CrashDumps':\n    - {{ name: RobloxPlayerBeta.exe.1200.dmp, hex: '{DUMP}' }}\n"
        );
        let host = FixtureHost::from_yaml_str(&host, "inline").unwrap();
        let run = RobloxFlags::new(Some(snapshot())).collect(&host);
        let dump = &rows(&run, "dump")[0];
        assert_eq!(dump.fields["written_at"], "2026-10-14T20:00:00Z");
        assert_eq!(dump.fields["process_id"], 1200);
        let physics = rows(&run, "dump_value")
            .into_iter()
            .find(|o| o.fields["flag"] == "DFIntS2PhysicsSenderRate")
            .unwrap();
        assert_eq!(physics.fields["value"], "1");
        assert_eq!(physics.fields["comparison"], "differs");
    }

    const DUMP: &str = "4d444d5093a7000003000000200000000000000040dfcf6a00000000000000000400000070000000440000000500000014000000ea0000000f00000018000000fe0000000100000000000000f77f0000001000000000000000000000b40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003200000043003a005c0052005c0052006f0062006c006f00780050006c00610079006500720042006500740061002e0065007800650001000000000000200000000043000000160100001800000001000000b004000000000000000000000000000078787b224446496e7453325068797369637353656e64657252617465223a20312c202246466c61674465627567446973706c6179465053223a202254727565227d7979";
}
