// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Installed programs, as Windows' "Apps" list knows them (B.O.P.E, ADR 0111).
//!
//! Reads every subkey of `...\CurrentVersion\Uninstall` under `HKLM`, `HKLM\SOFTWARE\WOW6432Node` and
//! `HKCU`: the display name, publisher, version, install date and install folder. Entries without a
//! display name and Windows' own system components are skipped.
//!
//! `category` sorts a program into the groups a PC check asks about, by words in its display name
//! (see [`CATEGORIES`]): macro and automation tools, peripheral suites that can store macros, memory
//! and process tools, script runtimes, VPN and proxy software, trace cleaners and virtual machines.
//! **Every one of these groups is ordinary software that many players have for ordinary reasons**;
//! the category says what the program can do, never what it was used for.
//!
//! **Depth.** A program removed with its uninstaller leaves no entry, and a portable program never had
//! one. `InstallDate` is a local date (`YYYYMMDD`) the installer chose to write, or nothing.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, RegistryData};

use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "installed_programs";

/// The three uninstall roots and their `hive` value.
pub const ROOTS: [(&str, &str); 3] = [
    (
        "hklm",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        "hklm_wow64",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        "hkcu",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
];

/// Category, and words that put a display name in it (compared without ASCII case, as whole words or
/// phrases). The first category that matches is used.
pub const CATEGORIES: [(&str, &[&str]); 8] = [
    (
        "memory_tool",
        &[
            "Cheat Engine",
            "Process Hacker",
            "System Informer",
            "x64dbg",
            "ReClass",
            "Extreme Injector",
        ],
    ),
    (
        "macro_tool",
        &[
            "AutoHotkey",
            "AutoIt",
            "TinyTask",
            "Pulover's Macro Creator",
            "Macro Recorder",
            "Jitbit",
            "Murgee",
            "OP Auto Clicker",
            "GS Auto Clicker",
        ],
    ),
    (
        "peripheral_suite",
        &[
            "Logitech G HUB",
            "Logitech Gaming Software",
            "Razer Synapse",
            "Bloody",
            "SteelSeries GG",
            "SteelSeries Engine",
            "iCUE",
            "ROCCAT Swarm",
            "NGENUITY",
            "Glorious Core",
            "Wooting",
        ],
    ),
    (
        "trace_cleaner",
        &[
            "CCleaner",
            "BleachBit",
            "PrivaZer",
            "Wise Disk Cleaner",
            "Glary Utilities",
            "Revo Uninstaller",
        ],
    ),
    (
        "vpn_proxy",
        &[
            "NordVPN",
            "ExpressVPN",
            "ProtonVPN",
            "Proton VPN",
            "Surfshark",
            "Mullvad",
            "WireGuard",
            "OpenVPN",
            "Windscribe",
            "Cloudflare WARP",
            "Hotspot Shield",
            "Radmin VPN",
            "ZeroTier",
            "Hamachi",
            "Proxifier",
            "TunnelBear",
            "CyberGhost",
        ],
    ),
    (
        "virtual_machine",
        &[
            "VMware Workstation",
            "VMware Player",
            "VirtualBox",
            "Parallels",
            "QEMU",
            "BlueStacks",
            "LDPlayer",
            "MuMu",
        ],
    ),
    (
        "script_runtime",
        &["Node.js", "Python", "Deno", "AutoIt", "Lua"],
    ),
    (
        "roblox_bootstrapper",
        &["Bloxstrap", "Fishstrap", "Voidstrap"],
    ),
];

static FIELDS: [Field; 9] = [
    Field::text("category"),
    Field::text("hive"),
    Field::text("install_date"),
    Field::text("install_location"),
    Field::text("location_kind"),
    Field::text("name"),
    Field::text("publisher"),
    Field::text("uninstall_key"),
    Field::text("version"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// The `installed_programs` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstalledPrograms;

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Whether `phrase` appears in `name` as a whole word or phrase, without ASCII case.
pub fn has_phrase(name: &str, phrase: &str) -> bool {
    let hay = name.to_ascii_lowercase();
    let needle = phrase.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = hay[from..].find(&needle) {
        let at = from + found;
        let end = at + needle.len();
        let before = at == 0 || !is_word_byte(hay.as_bytes()[at - 1]);
        let after = end == hay.len() || !is_word_byte(hay.as_bytes()[end]);
        if before && after {
            return true;
        }
        from = at + 1;
    }
    false
}

/// The category of a display name.
pub fn category(name: &str) -> Option<&'static str> {
    CATEGORIES
        .iter()
        .find(|(_, words)| words.iter().any(|w| has_phrase(name, w)))
        .map(|(category, _)| *category)
}

fn text(host: &dyn Host, key: &str, value: &str) -> Option<String> {
    match host.read_value(key, value) {
        Ok(Some(RegistryData::Text(text))) if !text.trim().is_empty() => {
            Some(text.trim().to_owned())
        }
        _ => None,
    }
}

impl Collector for InstalledPrograms {
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
        let mut observations = Vec::new();
        for (hive, root) in ROOTS {
            let keys = match host.subkeys(root) {
                Ok(Some(keys)) => keys,
                Ok(None) => continue,
                Err(error) => return unmeasured(ID, reason(host, &error)),
            };
            for subkey in keys {
                let key = format!(r"{root}\{subkey}");
                let Some(name) = text(host, &key, "DisplayName") else {
                    continue;
                };
                if host.read_u32(&key, "SystemComponent").ok().flatten() == Some(1) {
                    continue;
                }
                let install_location = text(host, &key, "InstallLocation");
                observations.push(
                    Fields::new()
                        .with("hive", hive)
                        .with("uninstall_key", subkey)
                        .maybe("category", category(&name))
                        .with("name", name)
                        .maybe("publisher", text(host, &key, "Publisher"))
                        .maybe("version", text(host, &key, "DisplayVersion"))
                        .maybe("install_date", text(host, &key, "InstallDate"))
                        .maybe(
                            location::FIELD,
                            install_location
                                .as_deref()
                                .map(|l| location::classify(l).as_str()),
                        )
                        .maybe("install_location", install_location)
                        .observe(ID),
                );
            }
        }
        measured(ID, observations, BTreeMap::new())
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn categories_match_whole_words_only() {
        assert_eq!(category("Cheat Engine 7.5"), Some("memory_tool"));
        assert_eq!(category("AutoHotkey 2.0.18"), Some("macro_tool"));
        assert_eq!(category("Logitech G HUB"), Some("peripheral_suite"));
        assert_eq!(category("Python 3.12.6 (64-bit)"), Some("script_runtime"));
        assert_eq!(category("Pythonista Game"), None);
        assert_eq!(category("Mozilla Firefox"), None);
        assert_eq!(category("Bloxstrap"), Some("roblox_bootstrapper"));
    }

    #[test]
    fn entries_are_listed_and_system_components_skipped() {
        let root = ROOTS[0].1.replace('\\', "\\\\");
        let cu = ROOTS[2].1.replace('\\', "\\\\");
        let host = FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nregistry:\n  \"{root}\\\\Cheat Engine_is1\":\n    DisplayName: 'Cheat Engine 7.5'\n    Publisher: 'Cheat Engine'\n    InstallDate: '20261012'\n    InstallLocation: 'C:\\Program Files\\Cheat Engine 7.5\\'\n  \"{root}\\\\{{X}}\":\n    DisplayName: 'Some Runtime'\n    SystemComponent: 1\n  \"{root}\\\\NoName\":\n    Publisher: x\n  \"{cu}\\\\Roblox Player\":\n    DisplayName: 'Roblox Player'\n    Publisher: 'Roblox Corporation'\n"
            ),
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured { observations, .. } = InstalledPrograms.collect(&host) else {
            panic!("measured");
        };
        assert_eq!(observations.len(), 2, "{observations:?}");
        let ce = &observations[0];
        assert_eq!(ce.fields["category"], "memory_tool");
        assert_eq!(ce.fields["install_date"], "20261012");
        assert_eq!(ce.fields["location_kind"], "program_files");
        assert_eq!(observations[1].fields["hive"], "hkcu");
        assert!(!observations[1].fields.contains_key("category"));
    }
}
