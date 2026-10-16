// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `UserAssist`: programs and shortcuts this account started from Explorer, with how often and when
//! last (B.O.P.E, ADR 0104).
//!
//! Reads every value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\
//! {GUID}\Count`, decodes the ROT13 name and the data with `bope_parsers::userassist`, and emits one
//! observation per program. Explorer's own bookkeeping values are skipped. A known-folder GUID at the
//! start of a name is replaced by that folder as this account's environment places it, or kept as
//! `%FolderName%` when the environment does not say.
//!
//! **Depth.** `UserAssist` keeps entries until the account is deleted or a cleaner removes them, so it
//! can reach back months. It is per account: an elevated scan run under another administrator account
//! reads that account's entries, not the player's. "Track app launches" switched off in Settings stops
//! Windows from writing here at all, which is an ordinary privacy setting and not a sign of anything.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform};
use bope_parsers::userassist::{
    self as parser, EXECUTABLES_GUID, SHORTCUTS_GUID, decode_name, is_bookkeeping,
};

use crate::common::{Fields, env_folder, measured, reason, unmeasured, user_profile};
use crate::{Collector, Field, location};

const ID: &str = "userassist";

/// The key whose subkeys are the `UserAssist` GUIDs.
pub const ROOT: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

static FIELDS: [Field; 8] = [
    Field::number("focus_count"),
    Field::number("focus_ms"),
    Field::text("guid_kind"),
    Field::timestamp("last_run"),
    Field::text("location_kind"),
    Field::text("name"),
    Field::text("path"),
    Field::number("run_count"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// The `userassist` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserAssist;

impl Collector for UserAssist {
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
        let guids = match host.subkeys(ROOT) {
            Ok(Some(guids)) => guids,
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(ID, reason(host, &error)),
        };
        let mut observations = Vec::new();
        let mut gaps = BTreeMap::new();
        for guid in guids {
            let key = format!(r"{ROOT}\{guid}\Count");
            let names = match host.value_names(&key) {
                Ok(Some(names)) => names,
                Ok(None) => continue,
                Err(error) => return unmeasured(ID, reason(host, &error)),
            };
            let guid_kind = if guid.eq_ignore_ascii_case(EXECUTABLES_GUID) {
                "executable"
            } else if guid.eq_ignore_ascii_case(SHORTCUTS_GUID) {
                "shortcut"
            } else {
                "other"
            };
            for encoded in names {
                let name = decode_name(&encoded);
                if is_bookkeeping(&name.decoded) {
                    continue;
                }
                let path = expand(host, &name);
                let mut fields = Fields::new()
                    .with("guid_kind", guid_kind)
                    .with(location::FIELD, location::classify(&path).as_str())
                    .with("name", location::last_segment(&path))
                    .with("path", path.clone());
                match host
                    .read_bytes(&key, &encoded)
                    .map(|b| b.map(|b| parser::parse_data(&b)))
                {
                    Ok(Some(Ok(data))) => {
                        fields = fields
                            .with("run_count", data.run_count)
                            .maybe("focus_count", data.focus_count)
                            .maybe("focus_ms", data.focus_ms)
                            .time("last_run", data.last_run);
                    }
                    Ok(None) => {}
                    Ok(Some(Err(_))) | Err(_) => {
                        for field in ["last_run", "run_count"] {
                            gaps.insert(field.to_owned(), UnmeasuredReason::ReadFailed);
                        }
                    }
                }
                observations.push(fields.observe(ID));
            }
        }
        measured(ID, observations, gaps)
    }
}

/// The path a decoded name stands for on this account.
fn expand(host: &dyn Host, name: &parser::UserAssistName) -> String {
    let Some(folder) = name.known_folder else {
        return name.rest.clone();
    };
    let system_root = || env_folder(host, "SystemRoot").or_else(|| env_folder(host, "WinDir"));
    let profile = |sub: &str| user_profile(host).map(|p| format!(r"{p}\{sub}"));
    let base = match folder {
        "ProgramFilesX64" => {
            env_folder(host, "ProgramW6432").or_else(|| env_folder(host, "ProgramFiles"))
        }
        "ProgramFiles" => env_folder(host, "ProgramFiles"),
        "ProgramFilesX86" => env_folder(host, "ProgramFiles(x86)"),
        "ProgramFilesCommon" => env_folder(host, "CommonProgramFiles"),
        "System" => system_root().map(|r| format!(r"{r}\System32")),
        "SystemX86" => system_root().map(|r| format!(r"{r}\SysWOW64")),
        "Windows" => system_root(),
        "Downloads" => profile("Downloads"),
        "Desktop" => profile("Desktop"),
        "Documents" => profile("Documents"),
        "LocalAppData" => env_folder(host, "LOCALAPPDATA"),
        "RoamingAppData" => env_folder(host, "APPDATA"),
        _ => None,
    };
    format!(
        "{}{}",
        base.unwrap_or_else(|| format!("%{folder}%")),
        name.rest
    )
}

#[cfg(test)]
mod tests {
    use bope_core::model::Observation;
    use bope_host::{FixtureHost, NonWindowsHost};
    use bope_parsers::userassist::rot13;

    use super::*;

    fn data_hex(run: u32, filetime: u64) -> String {
        let mut data = [0_u8; 72];
        data[4..8].copy_from_slice(&run.to_le_bytes());
        data[60..68].copy_from_slice(&filetime.to_le_bytes());
        crate::common::hex(&data)
    }

    fn host(extra: &str) -> FixtureHost {
        let key = format!(r"{ROOT}\{EXECUTABLES_GUID}\Count").replace('\\', "\\\\");
        let downloads = rot13(r"{374DE290-123F-4565-9164-39C4925E467B}\Solara\Bootstrapper.exe");
        let plain = rot13(r"C:\Program Files\Roblox\RobloxPlayerLauncher.exe");
        let yaml = format!(
            "platform: windows\nenv:\n  USERPROFILE: 'C:\\Users\\a'\nregistry:\n  \"{key}\":\n    '{downloads}': {{ hex: '{}' }}\n    '{plain}': {{ hex: '{}' }}\n    'HRZR_PGYFRFFVBA': {{ hex: '{}' }}\n{extra}",
            data_hex(4, 134_353_296_000_000_000),
            data_hex(1, 0),
            data_hex(0, 0),
        );
        FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    fn observations(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => panic!("{run:?}"),
        }
    }

    #[test]
    fn entries_are_decoded_expanded_and_classified() {
        let run = UserAssist.collect(&host(""));
        let all = observations(&run);
        assert_eq!(all.len(), 2, "{all:?}");
        let tool = all
            .iter()
            .find(|o| o.fields["name"] == "Bootstrapper.exe")
            .unwrap();
        assert_eq!(
            tool.fields["path"],
            r"C:\Users\a\Downloads\Solara\Bootstrapper.exe"
        );
        assert_eq!(tool.fields["location_kind"], "user_downloads");
        assert_eq!(tool.fields["run_count"], 4);
        assert_eq!(tool.fields["last_run"], "2026-10-01T12:00:00Z");
        assert_eq!(tool.fields["guid_kind"], "executable");
        let launcher = all
            .iter()
            .find(|o| o.fields["name"] == "RobloxPlayerLauncher.exe")
            .unwrap();
        assert!(!launcher.fields.contains_key("last_run"));
    }

    #[test]
    fn no_key_is_absent_and_another_os_is_not_windows() {
        let empty = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert_eq!(
            UserAssist.collect(&empty),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
        assert_eq!(
            UserAssist.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
    }

    #[test]
    fn a_value_that_does_not_decode_is_a_gap_not_a_guess() {
        let key = format!(r"{ROOT}\{EXECUTABLES_GUID}\Count").replace('\\', "\\\\");
        let yaml = format!(
            "platform: windows\nregistry:\n  \"{key}\":\n    'P:\\\\k.rkr': {{ hex: '0102' }}\n"
        );
        let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
        match UserAssist.collect(&host) {
            CollectorRun::Measured {
                gaps, observations, ..
            } => {
                assert_eq!(observations.len(), 1);
                assert_eq!(gaps.get("run_count"), Some(&UnmeasuredReason::ReadFailed));
            }
            other @ CollectorRun::Unmeasured { .. } => panic!("{other:?}"),
        }
    }
}
