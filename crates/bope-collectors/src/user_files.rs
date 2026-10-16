// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Programs, archives and scripts in the account's Downloads, Desktop and Documents folders
//! (B.O.P.E, ADR 0110). **Full scan only.**
//!
//! The folders and their direct subfolders are listed (two levels, nothing deeper), and only files of
//! these kinds are reported, by `kind`:
//!
//! - **`program`** — `.exe`, `.dll`, `.msi`, `.scr`, `.sys`: hash, embedded signature, and the
//!   **Mark of the Web** Windows attached when it was downloaded (`Zone.Identifier`: the zone, and the
//!   host it came from).
//! - **`archive`** — `.zip`, `.rar`, `.7z`: name, times and Mark of the Web.
//! - **`lua_script`** — `.lua`, `.luau`: which executor-only functions it calls
//!   (`bope_parsers::lua_markers`), never its text.
//! - **`automation_script`** — `.ahk`, `.ah2`, `.au3`, `.py`, `.js`, `.mjs`, `.cjs`, `.ps1`, `.bat`,
//!   `.cmd`, `.vbs`, `.rec`, `.mcr`: name and times only. `AutoHotkey`, `AutoIt`, `TinyTask` and similar
//!   macro tools save their macros in these formats; so do programmers and system administrators.
//!
//! Nothing else in those folders is reported, opened or hashed.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, Observation, ScanTier, UnmeasuredReason};
use bope_host::{DirEntryInfo, Host, Platform};
use bope_parsers::lua_markers;

use crate::common::{Fields, hash_and_signature, join, unmeasured, user_profile};
use crate::{Collector, Field, location};

const ID: &str = "user_files";

/// How long the collector hashes and scans before it stops and says so.
pub const BUDGET: Duration = Duration::from_secs(25);
/// Largest script scanned for markers.
pub const MAX_SCRIPT_BYTES: u64 = 2 * 1024 * 1024;

const PROGRAM: [&str; 5] = ["exe", "dll", "msi", "scr", "sys"];
const ARCHIVE: [&str; 3] = ["zip", "rar", "7z"];
const LUA: [&str; 2] = ["lua", "luau"];
const AUTOMATION: [&str; 13] = [
    "ahk", "ah2", "au3", "py", "js", "mjs", "cjs", "ps1", "bat", "cmd", "vbs", "rec", "mcr",
];

static FIELDS: [Field; 18] = [
    Field::timestamp("created"),
    Field::number("distinct_markers"),
    Field::text("download_host"),
    Field::text("extension"),
    Field::text("folder"),
    Field::boolean("has_referrer"),
    Field::text("kind"),
    Field::text("location_kind"),
    Field::text("markers"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::text("path"),
    Field::boolean("remote_loadstring"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::number("zone_id"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `user_files` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserFiles;

/// What a `Zone.Identifier` stream says: the zone, the host of `HostUrl`, and whether a referrer was
/// recorded. Never the URL's path or query.
pub fn zone_identifier(text: &str) -> (Option<u32>, Option<String>, bool) {
    let mut zone = None;
    let mut host = None;
    let mut referrer = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("ZoneId=") {
            zone = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("HostUrl=") {
            host = value
                .split_once("://")
                .map(|(_, rest)| rest)
                .and_then(|rest| rest.split(['/', '?', '#']).next())
                .map(|h| h.rsplit('@').next().unwrap_or(h).to_ascii_lowercase())
                .filter(|h| !h.is_empty());
        } else if line.starts_with("ReferrerUrl=") {
            referrer = true;
        }
    }
    (zone, host, referrer)
}

struct Walk<'a> {
    host: &'a dyn Host,
    deadline: Instant,
    observations: Vec<Observation>,
    budget_spent: bool,
}

impl Walk<'_> {
    fn file(&mut self, folder_label: &str, dir: &str, entry: &DirEntryInfo) {
        let Some(ext) = location::extension(&entry.name) else {
            return;
        };
        let kind = if PROGRAM.contains(&ext.as_str()) {
            "program"
        } else if ARCHIVE.contains(&ext.as_str()) {
            "archive"
        } else if LUA.contains(&ext.as_str()) {
            "lua_script"
        } else if AUTOMATION.contains(&ext.as_str()) {
            "automation_script"
        } else {
            return;
        };
        let path = join(dir, &entry.name);
        let mut fields = Fields::new()
            .with("kind", kind)
            .with("folder", folder_label)
            .with(location::FIELD, location::classify(&path).as_str())
            .with("extension", ext)
            .with("name", entry.name.clone())
            .with("path", path.clone())
            .time("created", entry.created)
            .time("modified", entry.modified);
        let in_time = Instant::now() < self.deadline;
        if !in_time && matches!(kind, "program" | "lua_script") {
            self.budget_spent = true;
        }
        if kind == "program" && in_time {
            fields = hash_and_signature(self.host, &path, fields).0;
        }
        if matches!(kind, "program" | "archive")
            && let Ok(Some(bytes)) = self.host.read_file(&format!("{path}:Zone.Identifier"))
        {
            let (zone, host, referrer) = zone_identifier(&String::from_utf8_lossy(&bytes));
            fields = fields
                .maybe("zone_id", zone)
                .maybe("download_host", host)
                .with("has_referrer", referrer);
        }
        if kind == "lua_script"
            && in_time
            && entry.size.is_none_or(|s| s <= MAX_SCRIPT_BYTES)
            && let Ok(Some(bytes)) = self.host.read_file(&path)
        {
            let markers = lua_markers::scan(&bytes);
            fields = fields
                .with("distinct_markers", markers.distinct)
                .with("markers", markers.found.join(", "))
                .with("remote_loadstring", markers.remote_loadstring);
        }
        self.observations.push(fields.observe(ID));
    }

    fn folder(&mut self, label: &str, dir: &str, depth: u8) {
        let Ok(Some(entries)) = self.host.list_dir(dir) else {
            return;
        };
        for entry in &entries {
            if entry.is_file {
                self.file(label, dir, entry);
            } else if depth > 0 && !crate::paths::is_unusable_segment(&entry.name) {
                self.folder(label, &join(dir, &entry.name), depth - 1);
            }
        }
    }
}

impl Collector for UserFiles {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn tier(&self) -> ScanTier {
        ScanTier::Full
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let Some(profile) = user_profile(host) else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };
        let mut walk = Walk {
            host,
            deadline: Instant::now() + BUDGET,
            observations: Vec::new(),
            budget_spent: false,
        };
        for (label, sub) in [
            ("downloads", "Downloads"),
            ("desktop", "Desktop"),
            ("documents", "Documents"),
            ("desktop", r"OneDrive\Desktop"),
        ] {
            walk.folder(label, &join(&profile, sub), 1);
        }
        let mut gaps = BTreeMap::new();
        if walk.budget_spent {
            for field in ["sha256", "signature", "distinct_markers", "markers"] {
                gaps.insert(field.to_owned(), UnmeasuredReason::BudgetSpent);
            }
        }
        crate::common::measured(ID, walk.observations, gaps)
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn a_zone_identifier_gives_the_zone_and_the_host_only() {
        let (zone, host, referrer) = zone_identifier(
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://ref.example/x\r\nHostUrl=https://user:pw@CDN.Example.com:443/path/file.exe?token=secret\r\n",
        );
        assert_eq!(zone, Some(3));
        assert_eq!(host.as_deref(), Some("cdn.example.com:443"));
        assert!(referrer);
    }

    #[test]
    fn programs_archives_and_scripts_are_reported_and_nothing_else() {
        let host = FixtureHost::from_yaml_str(
            r#"platform: windows
env:
  USERPROFILE: 'C:\Users\a'
filesystem:
  'C:\Users\a\Downloads':
    - name: Loader.exe
      sha256: '6666666666666666666666666666666666666666666666666666666666666666'
      signature: { state: no_embedded_signature }
      modified: '2026-10-14T20:00:00Z'
    - { name: 'Loader.exe:Zone.Identifier', content: "[ZoneTransfer]\nZoneId=3\nHostUrl=https://files.example.invalid/l.exe\n" }
    - { name: holiday.jpg }
    - { name: scripts, directory: true }
  'C:\Users\a\Downloads\scripts':
    - { name: aimbot.lua, content: "local g = getgenv()\nhookmetamethod(game, '__index', x)\n" }
  'C:\Users\a\Documents':
    - { name: clicker.ahk, modified: '2026-10-13T10:00:00Z' }
    - { name: report.docx }
"#,
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured { observations, .. } = UserFiles.collect(&host) else {
            panic!("measured");
        };
        assert_eq!(observations.len(), 3, "{observations:?}");
        let exe = observations
            .iter()
            .find(|o| o.fields["name"] == "Loader.exe")
            .unwrap();
        assert_eq!(exe.fields["kind"], "program");
        assert_eq!(exe.fields["zone_id"], 3);
        assert_eq!(exe.fields["download_host"], "files.example.invalid");
        assert_eq!(exe.fields["signature"], "no_embedded_signature");
        let lua = observations
            .iter()
            .find(|o| o.fields["name"] == "aimbot.lua")
            .unwrap();
        assert_eq!(lua.fields["distinct_markers"], 2);
        assert_eq!(lua.fields["folder"], "downloads");
        let ahk = observations
            .iter()
            .find(|o| o.fields["name"] == "clicker.ahk")
            .unwrap();
        assert_eq!(ahk.fields["kind"], "automation_script");
    }
}
