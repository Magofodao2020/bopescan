// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Explorer's most-recently-used lists, narrowed to what a PC check needs (B.O.P.E, ADR 0113).
//! **Full scan only.** `list` is the discriminator:
//!
//! - **`run_mru`** — the Run box (`Win`+`R`) history: the **program** each line started, never its
//!   arguments, with its position (0 is the most recent).
//! - **`typed_paths`** — folders typed into Explorer's address bar.
//! - **`recent_docs`** — files recently opened through the shell, **only** from the per-extension
//!   lists for program, script, macro and archive extensions ([`RECENT_EXTENSIONS`]); documents,
//!   pictures and every other extension are not read.
//! - **`last_visited`** — the programs that last used a common Open or Save dialog
//!   (`ComDlg32\LastVisitedPidlMRU`): the program's file name only; the folder it visited is not
//!   decoded.
//!
//! None of these lists carries a time per entry. They are per account, and clearing them is an
//! ordinary Windows privacy option.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, ScanTier, UnmeasuredReason};
use bope_host::{Host, Platform, RegistryData};

use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "shell_mru";

const EXPLORER: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer";

/// The extensions whose `RecentDocs` lists are read.
pub const RECENT_EXTENSIONS: [&str; 13] = [
    ".exe", ".dll", ".lua", ".luau", ".ahk", ".au3", ".js", ".py", ".zip", ".rar", ".7z", ".rec",
    ".bat",
];

static FIELDS: [Field; 6] = [
    Field::text("extension"),
    Field::text("list"),
    Field::text("location_kind"),
    Field::text("name"),
    Field::text("path"),
    Field::number("position"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// The `shell_mru` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShellMru;

/// The UTF-16LE string at the start of a binary MRU value, up to its terminating NUL.
pub fn leading_utf16(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .take_while(|u| *u != 0)
        .collect();
    (!units.is_empty()).then(|| String::from_utf16_lossy(&units))
}

/// Value names in most-recent-first order from an `MRUListEx` value (a list of `u32` ending in
/// `0xFFFFFFFF`), or `None` when there is none.
pub fn mru_list_ex(bytes: &[u8]) -> Vec<u32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .take_while(|n| *n != u32::MAX)
        .collect()
}

fn text(host: &dyn Host, key: &str, value: &str) -> Option<String> {
    match host.read_value(key, value) {
        Ok(Some(RegistryData::Text(t))) => Some(t),
        _ => None,
    }
}

type Rows = Vec<bope_core::model::Observation>;

fn run_mru(host: &dyn Host, out: &mut Rows) {
    let key = format!(r"{EXPLORER}\RunMRU");
    let Some(order) = text(host, &key, "MRUList") else {
        return;
    };
    for (position, letter) in order.chars().enumerate() {
        let Some(command) = text(host, &key, &letter.to_string()) else {
            continue;
        };
        let command = command.strip_suffix(r"\1").unwrap_or(&command);
        let program = location::program_of_command(command);
        if program.is_empty() {
            continue;
        }
        out.push(
            Fields::new()
                .with("list", "run_mru")
                .with("position", position)
                .with(location::FIELD, location::classify(&program).as_str())
                .with("name", location::last_segment(&program))
                .with("path", program.clone())
                .observe(ID),
        );
    }
}

fn typed_paths(host: &dyn Host, out: &mut Rows) {
    let key = format!(r"{EXPLORER}\TypedPaths");
    for index in 1..=50 {
        let Some(path) = text(host, &key, &format!("url{index}")) else {
            continue;
        };
        out.push(
            Fields::new()
                .with("list", "typed_paths")
                .with("position", index - 1)
                .with(location::FIELD, location::classify(&path).as_str())
                .with("path", path)
                .observe(ID),
        );
    }
}

fn binary_list(
    host: &dyn Host,
    key: &str,
    list: &str,
    extension: Option<&str>,
    out: &mut Rows,
) -> Result<(), bope_host::SourceError> {
    let order = host
        .read_bytes(key, "MRUListEx")?
        .map(|b| mru_list_ex(&b))
        .unwrap_or_default();
    for (position, index) in order.iter().enumerate() {
        let Some(bytes) = host.read_bytes(key, &index.to_string())? else {
            continue;
        };
        let Some(name) = leading_utf16(&bytes) else {
            continue;
        };
        out.push(
            Fields::new()
                .with("list", list)
                .with("position", position)
                .maybe(
                    "extension",
                    extension.map(|e| e.trim_start_matches('.').to_owned()),
                )
                .with("name", name)
                .observe(ID),
        );
    }
    Ok(())
}

impl Collector for ShellMru {
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

    fn discriminator(&self) -> Option<&'static str> {
        Some("list")
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let mut out = Vec::new();
        let result = (|| {
            run_mru(host, &mut out);
            typed_paths(host, &mut out);
            for extension in RECENT_EXTENSIONS {
                binary_list(
                    host,
                    &format!(r"{EXPLORER}\RecentDocs\{extension}"),
                    "recent_docs",
                    Some(extension),
                    &mut out,
                )?;
            }
            binary_list(
                host,
                &format!(r"{EXPLORER}\ComDlg32\LastVisitedPidlMRU"),
                "last_visited",
                None,
                &mut out,
            )
        })();
        match result {
            Ok(()) => measured(ID, out, BTreeMap::new()),
            Err(error) => unmeasured(ID, reason(host, &error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    fn utf16_hex(text: &str, tail: &[u8]) -> String {
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(tail);
        crate::common::hex(&bytes)
    }

    #[test]
    fn lists_are_read_in_order_with_programs_only() {
        let e = EXPLORER.replace('\\', "\\\\");
        let yaml = format!(
            "platform: windows\nregistry:\n  \"{e}\\\\RunMRU\":\n    MRUList: 'ba'\n    a: 'notepad C:\\private\\diary.txt\\1'\n    b: '\"C:\\Users\\a\\Downloads\\inj.exe\" -pid 4\\1'\n  \"{e}\\\\TypedPaths\":\n    url1: 'C:\\Users\\a\\AppData\\Local\\Temp\\x'\n  \"{e}\\\\RecentDocs\\\\.lua\":\n    MRUListEx: {{ hex: '01000000ffffffff' }}\n    '1': {{ hex: '{}' }}\n  \"{e}\\\\RecentDocs\\\\.docx\":\n    MRUListEx: {{ hex: '00000000ffffffff' }}\n    '0': {{ hex: '{}' }}\n  \"{e}\\\\ComDlg32\\\\LastVisitedPidlMRU\":\n    MRUListEx: {{ hex: '00000000ffffffff' }}\n    '0': {{ hex: '{}' }}\n",
            utf16_hex("esp.lua", &[1, 2, 3]),
            utf16_hex("secret.docx", &[]),
            utf16_hex("Solara.exe", &[0x14, 0]),
        );
        let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
        let CollectorRun::Measured { observations, .. } = ShellMru.collect(&host) else {
            panic!("measured");
        };
        let all = format!("{observations:?}");
        assert!(
            !all.contains("diary") && !all.contains("-pid") && !all.contains("secret.docx"),
            "{all}"
        );
        let run: Vec<_> = observations
            .iter()
            .filter(|o| o.fields["list"] == "run_mru")
            .collect();
        assert_eq!(run[0].fields["name"], "inj.exe");
        assert_eq!(run[0].fields["position"], 0);
        assert_eq!(run[1].fields["name"], "notepad");
        assert!(
            observations
                .iter()
                .any(|o| o.fields["list"] == "recent_docs" && o.fields["name"] == "esp.lua")
        );
        assert!(
            observations
                .iter()
                .any(|o| o.fields["list"] == "last_visited" && o.fields["name"] == "Solara.exe")
        );
        assert!(
            observations
                .iter()
                .any(|o| o.fields["list"] == "typed_paths" && o.fields["location_kind"] == "temp")
        );
    }
}
