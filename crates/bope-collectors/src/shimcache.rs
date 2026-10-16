// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `AppCompatCache` ("`ShimCache`"): files the compatibility engine looked at (B.O.P.E, ADR 0105).
//!
//! Reads `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, value
//! `AppCompatCache`, and decodes it with `bope_parsers::shimcache`. One observation per entry, with its
//! position (0 is the newest), its path, and the **file's last-modification time** it recorded —
//! `file_modified`, deliberately not called a run time.
//!
//! **What it does not prove.** On Windows 10 and 11 an entry does not prove the file was run; the
//! compatibility engine also records files Explorer merely displayed or that were extracted. The value
//! is written at shutdown, so files seen since the last restart are usually missing. Up to 1 024
//! entries are kept, oldest dropped first. Reading the key needs no administrator rights on most
//! installations, but the value may be refused.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform};
use bope_parsers::shimcache::{self as parser, Format};

use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "shimcache";

/// The key read.
pub const KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
/// The value read.
pub const VALUE: &str = "AppCompatCache";

static FIELDS: [Field; 7] = [
    Field::text("extension"),
    Field::timestamp("file_modified"),
    Field::text("format"),
    Field::text("location_kind"),
    Field::text("name"),
    Field::text("path"),
    Field::number("position"),
];

static REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::Partial,
    UnmeasuredReason::ReadFailed,
];

/// The `shimcache` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShimCache;

impl Collector for ShimCache {
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
        let bytes = match host.read_bytes(KEY, VALUE) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(ID, reason(host, &error)),
        };
        let Ok(cache) = parser::parse(&bytes) else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };
        let format = match cache.format {
            Format::Win10 { .. } => "win10",
            Format::Win8 => "win8",
            // A layout this build does not decode is a read that could not be understood.
            Format::Unsupported { .. } => return unmeasured(ID, UnmeasuredReason::ReadFailed),
        };
        let observations = cache
            .entries
            .iter()
            .map(|entry| {
                let path = location::strip_nt_prefix(&entry.path).to_owned();
                let name = location::last_segment(&path).to_owned();
                Fields::new()
                    .maybe("extension", location::extension(&name))
                    .time("file_modified", entry.modified)
                    .with("format", format)
                    .with(location::FIELD, location::classify(&path).as_str())
                    .with("name", name)
                    .with("path", path)
                    .with("position", entry.position)
                    .observe(ID)
            })
            .collect();
        let mut gaps = BTreeMap::new();
        if cache.stopped.is_some() {
            // The entries before the damage are real; what came after is unknown, so a rule asking
            // "is X absent" must not answer from a partial read.
            for field in ["name", "path"] {
                gaps.insert(field.to_owned(), UnmeasuredReason::Partial);
            }
        }
        measured(ID, observations, gaps)
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    use crate::common::hex;

    fn host(value: &[u8]) -> FixtureHost {
        let key = KEY.replace('\\', "\\\\");
        FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nregistry:\n  \"{key}\":\n    AppCompatCache: {{ hex: '{}' }}\n",
                hex(value)
            ),
            "inline",
        )
        .unwrap()
    }

    #[test]
    fn entries_carry_position_path_and_file_time() {
        let value = parser::build_win10(&[
            (
                r"\??\C:\Users\a\Downloads\Xeno\Xeno.exe",
                134_353_296_000_000_000,
                &[],
            ),
            (r"C:\Windows\System32\cmd.exe", 1, &[9]),
        ]);
        let CollectorRun::Measured {
            observations, gaps, ..
        } = ShimCache.collect(&host(&value))
        else {
            panic!("measured");
        };
        assert!(gaps.is_empty());
        assert_eq!(observations.len(), 2);
        let first = &observations[0];
        assert_eq!(first.fields["path"], r"C:\Users\a\Downloads\Xeno\Xeno.exe");
        assert_eq!(first.fields["position"], 0);
        assert_eq!(first.fields["file_modified"], "2026-10-01T12:00:00Z");
        assert_eq!(first.fields["location_kind"], "user_downloads");
        assert_eq!(first.fields["extension"], "exe");
    }

    #[test]
    fn a_damaged_value_is_partial_and_an_unknown_layout_is_unreadable() {
        let mut value = parser::build_win10(&[(r"C:\a.exe", 1, &[]), (r"C:\b.exe", 1, &[])]);
        value.truncate(value.len() - 2);
        let CollectorRun::Measured {
            gaps, observations, ..
        } = ShimCache.collect(&host(&value))
        else {
            panic!("measured");
        };
        assert_eq!(observations.len(), 1);
        assert_eq!(gaps.get("path"), Some(&UnmeasuredReason::Partial));
        let mut win7 = vec![0_u8; 64];
        win7[0..4].copy_from_slice(&0xBADC_0FEE_u32.to_le_bytes());
        assert_eq!(
            ShimCache.collect(&host(&win7)),
            unmeasured(ID, UnmeasuredReason::ReadFailed)
        );
    }
}
