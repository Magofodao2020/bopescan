// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Registry settings that make Windows load or start something **inside or instead of** another
//! program (B.O.P.E, ADR 0106).
//!
//! Five mechanisms, told apart by `mechanism`, each read from `HKLM` (and `WOW6432Node` where Windows
//! keeps a 32-bit copy):
//!
//! - **`ifeo_debugger`** — `Image File Execution Options\<exe>\Debugger`: Windows starts the named
//!   program instead of `<exe>`. Debuggers and Process Explorer's "Replace Task Manager" set it.
//! - **`ifeo_verifier`** — `Image File Execution Options\<exe>\VerifierDlls`: DLLs Application Verifier
//!   loads into `<exe>`.
//! - **`silent_process_exit`** — `SilentProcessExit\<exe>\MonitorProcess`: a program started when
//!   `<exe>` exits.
//! - **`appinit_dlls`** — `Windows NT\CurrentVersion\Windows\AppInit_DLLs`, reported only when not
//!   empty, with whether `LoadAppInit_DLLs` turns it on.
//! - **`appcert_dlls`** — `Session Manager\AppCertDlls`: DLLs loaded into every process that creates
//!   another one.
//! - **`winlogon`** — `Winlogon\Shell` and `Winlogon\Userinit` (in `HKLM` and `HKCU`), with whether
//!   the value is Windows' own default.
//!
//! Only the **program** a value names is reported, never its arguments (ADR 0060 section 4).
//! Nothing is changed, removed or disabled.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, RegistryData};

use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "hijack";

const IFEO_ROOTS: [&str; 2] = [
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
];
const SILENT_EXIT_ROOT: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
const APPINIT_KEYS: [&str; 2] = [
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
];
const APPCERT_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";
const WINLOGON_KEYS: [(&str, &str); 2] = [
    (
        "hklm",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ),
    (
        "hkcu",
        r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ),
];

static FIELDS: [Field; 8] = [
    Field::boolean("enabled"),
    Field::text("location_kind"),
    Field::text("mechanism"),
    Field::text("program"),
    Field::text("program_name"),
    Field::text("scope"),
    Field::text("target"),
    Field::boolean("windows_default"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// The `hijack` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hijack;

fn text(host: &dyn Host, key: &str, value: &str) -> Result<Option<String>, bope_host::SourceError> {
    Ok(match host.read_value(key, value)? {
        Some(RegistryData::Text(text)) => Some(text),
        _ => None,
    })
}

fn program_fields(fields: Fields, program: &str) -> Fields {
    let program = location::program_of_command(program);
    fields
        .with(location::FIELD, location::classify(&program).as_str())
        .with("program_name", location::last_segment(&program))
        .with("program", program.clone())
}

impl Collector for Hijack {
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
        match collect_all(host) {
            Ok(observations) => measured(ID, observations, BTreeMap::new()),
            Err(error) => unmeasured(ID, reason(host, &error)),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn collect_all(
    host: &dyn Host,
) -> Result<Vec<bope_core::model::Observation>, bope_host::SourceError> {
    let mut out = Vec::new();
    for root in IFEO_ROOTS {
        for target in host.subkeys(root)?.unwrap_or_default() {
            let key = format!(r"{root}\{target}");
            if let Some(debugger) = text(host, &key, "Debugger")?.filter(|t| !t.trim().is_empty()) {
                out.push(
                    program_fields(
                        Fields::new()
                            .with("mechanism", "ifeo_debugger")
                            .with("target", target.clone()),
                        &debugger,
                    )
                    .observe(ID),
                );
            }
            if let Some(dlls) = text(host, &key, "VerifierDlls")?.filter(|t| !t.trim().is_empty()) {
                for dll in dlls.split([' ', ',', ';']).filter(|d| !d.is_empty()) {
                    out.push(
                        program_fields(
                            Fields::new()
                                .with("mechanism", "ifeo_verifier")
                                .with("target", target.clone()),
                            dll,
                        )
                        .observe(ID),
                    );
                }
            }
        }
    }
    for target in host.subkeys(SILENT_EXIT_ROOT)?.unwrap_or_default() {
        let key = format!(r"{SILENT_EXIT_ROOT}\{target}");
        if let Some(monitor) = text(host, &key, "MonitorProcess")?.filter(|t| !t.trim().is_empty())
        {
            out.push(
                program_fields(
                    Fields::new()
                        .with("mechanism", "silent_process_exit")
                        .with("target", target.clone()),
                    &monitor,
                )
                .observe(ID),
            );
        }
    }
    for key in APPINIT_KEYS {
        let Some(dlls) = text(host, key, "AppInit_DLLs")?.filter(|t| !t.trim().is_empty()) else {
            continue;
        };
        let enabled = host.read_u32(key, "LoadAppInit_DLLs")?.map(|v| v != 0);
        let scope = if key.contains("WOW6432Node") {
            "wow64"
        } else {
            "native"
        };
        for dll in dlls.split([' ', ',']).filter(|d| !d.is_empty()) {
            out.push(
                program_fields(
                    Fields::new()
                        .with("mechanism", "appinit_dlls")
                        .with("scope", scope)
                        .maybe("enabled", enabled),
                    dll,
                )
                .observe(ID),
            );
        }
    }
    for name in host.value_names(APPCERT_KEY)?.unwrap_or_default() {
        if let Some(dll) = text(host, APPCERT_KEY, &name)?.filter(|t| !t.trim().is_empty()) {
            out.push(
                program_fields(Fields::new().with("mechanism", "appcert_dlls"), &dll).observe(ID),
            );
        }
    }
    for (scope, key) in WINLOGON_KEYS {
        for (value, default) in [("Shell", "explorer.exe"), ("Userinit", "userinit.exe")] {
            let Some(configured) = text(host, key, value)?.filter(|t| !t.trim().is_empty()) else {
                continue;
            };
            for part in configured
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
            {
                let program = location::program_of_command(part);
                let is_default = location::last_segment(&program).eq_ignore_ascii_case(default)
                    && matches!(
                        location::classify(&program),
                        location::LocationKind::Windows | location::LocationKind::Unknown
                    );
                out.push(
                    program_fields(
                        Fields::new()
                            .with("mechanism", "winlogon")
                            .with("scope", scope)
                            .with("target", value)
                            .with("windows_default", is_default),
                        part,
                    )
                    .observe(ID),
                );
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    fn esc(key: &str) -> String {
        key.replace('\\', "\\\\")
    }

    #[test]
    fn each_mechanism_is_reported_with_its_program_and_never_its_arguments() {
        let yaml = format!(
            "platform: windows\nregistry:\n  \"{}\\\\RobloxPlayerBeta.exe\":\n    Debugger: '\"C:\\Users\\a\\AppData\\Local\\Temp\\x.exe\" --secret'\n  \"{}\\\\taskmgr.exe\":\n    Debugger: 'C:\\Tools\\procexp64.exe'\n  \"{}\\\\notepad.exe\":\n    GlobalFlag: 512\n  \"{}\":\n    AppInit_DLLs: 'C:\\Users\\a\\x.dll'\n    LoadAppInit_DLLs: 1\n  \"{}\":\n    Shell: 'explorer.exe'\n    Userinit: 'C:\\Windows\\system32\\userinit.exe,C:\\Users\\a\\evil.exe,'\n",
            esc(IFEO_ROOTS[0]),
            esc(IFEO_ROOTS[0]),
            esc(IFEO_ROOTS[0]),
            esc(APPINIT_KEYS[0]),
            esc(WINLOGON_KEYS[0].1),
        );
        let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
        let CollectorRun::Measured { observations, .. } = Hijack.collect(&host) else {
            panic!("measured");
        };
        let all = format!("{observations:?}");
        assert!(!all.contains("--secret"), "{all}");
        let by = |mechanism: &str| -> Vec<_> {
            observations
                .iter()
                .filter(|o| o.fields["mechanism"] == mechanism)
                .collect()
        };
        let debuggers = by("ifeo_debugger");
        assert_eq!(debuggers.len(), 2);
        let roblox = debuggers
            .iter()
            .find(|o| o.fields["target"] == "RobloxPlayerBeta.exe")
            .unwrap();
        assert_eq!(roblox.fields["location_kind"], "temp");
        let appinit = by("appinit_dlls");
        assert_eq!(appinit[0].fields["enabled"], true);
        let winlogon = by("winlogon");
        assert_eq!(winlogon.len(), 3);
        assert!(winlogon.iter().any(
            |o| o.fields["program_name"] == "evil.exe" && o.fields["windows_default"] == false
        ));
        assert_eq!(
            winlogon
                .iter()
                .filter(|o| o.fields["windows_default"] == true)
                .count(),
            2
        );
    }

    #[test]
    fn an_ordinary_machine_reports_only_the_defaults() {
        let yaml = format!(
            "platform: windows\nregistry:\n  \"{}\":\n    Shell: 'explorer.exe'\n    Userinit: 'C:\\Windows\\system32\\userinit.exe,'\n  \"{}\":\n    AppInit_DLLs: ''\n    LoadAppInit_DLLs: 0\n",
            esc(WINLOGON_KEYS[0].1),
            esc(APPINIT_KEYS[0])
        );
        let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
        let CollectorRun::Measured { observations, .. } = Hijack.collect(&host) else {
            panic!("measured");
        };
        assert_eq!(observations.len(), 2);
        assert!(
            observations
                .iter()
                .all(|o| o.fields["windows_default"] == true)
        );
    }
}
