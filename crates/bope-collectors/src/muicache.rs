// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `MuiCache`: the display names Explorer cached for programs this account opened through the shell
//! (B.O.P.E, ADR 0104).
//!
//! Each value under `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`
//! is named `<path>.FriendlyAppName` or `<path>.ApplicationCompany` and holds the string Windows read
//! from the program's version resource. One observation per program path, with the two strings when
//! present.
//!
//! **What it does not carry: a time.** This source says that Explorer looked up the program's name —
//! typically because it was started, or offered in an "Open with" list — and nothing about when.
//! The strings are whatever the file's version resource said, so a renamed file keeps its original
//! product name here, which is sometimes what tells two files apart.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, RegistryData};

use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "muicache";

/// The key read.
pub const KEY: &str =
    r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

const SUFFIXES: [(&str, &str); 2] = [
    (".FriendlyAppName", "friendly_name"),
    (".ApplicationCompany", "company"),
];

static FIELDS: [Field; 5] = [
    Field::text("company"),
    Field::text("friendly_name"),
    Field::text("location_kind"),
    Field::text("name"),
    Field::text("path"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// The `muicache` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct MuiCache;

impl Collector for MuiCache {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let names = match host.value_names(KEY) {
            Ok(Some(names)) => names,
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(ID, reason(host, &error)),
        };
        // path (as written) → (field → text), keyed case-insensitively.
        let mut programs: BTreeMap<String, (String, BTreeMap<&'static str, String>)> =
            BTreeMap::new();
        for value in names {
            let Some((path, field)) = SUFFIXES.iter().find_map(|(suffix, field)| {
                let cut = value.len().checked_sub(suffix.len())?;
                (value.is_char_boundary(cut) && value[cut..].eq_ignore_ascii_case(suffix))
                    .then(|| (value[..cut].to_owned(), *field))
            }) else {
                continue;
            };
            let text = match host.read_value(KEY, &value) {
                Ok(Some(RegistryData::Text(text))) => Some(text),
                _ => None,
            };
            let entry = programs
                .entry(path.to_ascii_lowercase())
                .or_insert_with(|| (path.clone(), BTreeMap::new()));
            if let Some(text) = text.filter(|t| !t.trim().is_empty()) {
                entry.1.insert(field, text);
            }
        }
        let observations = programs
            .into_values()
            .map(|(path, strings)| {
                let mut fields = Fields::new()
                    .with(location::FIELD, location::classify(&path).as_str())
                    .with("name", location::last_segment(&path))
                    .with("path", path.clone());
                for (field, text) in strings {
                    fields = fields.with(field, text);
                }
                fields.observe(ID)
            })
            .collect();
        measured(ID, observations, BTreeMap::new())
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn both_strings_of_one_program_make_one_observation() {
        let key = KEY.replace('\\', "\\\\");
        let yaml = format!(
            "platform: windows\nregistry:\n  \"{key}\":\n    'C:\\Users\\a\\Downloads\\x.exe.FriendlyAppName': 'Some Injector'\n    'C:\\Users\\a\\Downloads\\x.exe.ApplicationCompany': 'Unknown Ltd'\n    'C:\\Windows\\notepad.exe.FriendlyAppName': 'Notepad'\n    'LangID': {{ hex: '0904' }}\n"
        );
        let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
        let CollectorRun::Measured { observations, .. } = MuiCache.collect(&host) else {
            panic!("expected measured");
        };
        assert_eq!(observations.len(), 2);
        let x = observations
            .iter()
            .find(|o| o.fields["name"] == "x.exe")
            .unwrap();
        assert_eq!(x.fields["friendly_name"], "Some Injector");
        assert_eq!(x.fields["company"], "Unknown Ltd");
        assert_eq!(x.fields["location_kind"], "user_downloads");
    }

    #[test]
    fn an_absent_key_is_absent() {
        let host = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            MuiCache.collect(&host),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
    }
}
