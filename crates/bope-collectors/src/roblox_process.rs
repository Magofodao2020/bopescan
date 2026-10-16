// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The running Roblox player from the inside — which modules it has loaded and what executable
//! memory it holds — and the programs running from folders every user may write to
//! (B.O.P.E, ADR 0102).
//!
//! Places, told apart by `scope`:
//!
//! - **`roblox_process`** — each running `RobloxPlayerBeta.exe` (or the Microsoft Store edition's
//!   `Windows10Universal.exe` under a `ROBLOXCORPORATION.` folder): path, start, and the name of the
//!   process that created it when that process is still running and started first.
//! - **`roblox_module`** — each module loaded in it **outside `%SystemRoot%`**, with where it is, its
//!   hash and its embedded signature. Modules under `%SystemRoot%` are counted on the process row.
//! - **`roblox_memory`** — counts of committed executable regions by kind (private, mapped, image).
//!   Region descriptors only; no memory content is read.
//! - **`user_location_process`** — every other running process whose image is in a folder a user may
//!   write to (Temp, Downloads, Desktop, Documents, `AppData`, Public, the Recycle Bin), with hash and
//!   signature.
//!
//! **Expected refusals.** Roblox's anti-cheat (Hyperion) protects the player process, so on an ordinary
//! PC the module and memory reads are refused. That is reported as `access_denied` for those two places
//! and is the anti-cheat working, not anything about the player. Nothing here attaches to, suspends,
//! injects into or writes to any process, and no kernel driver is used to get around the refusal.
//!
//! Hashing and signature checks stop after [`BUDGET`]; what was not reached is `budget_spent`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{Host, Platform, ProcessRecord};

use crate::common::{Fields, hash_and_signature, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "roblox_process";
const DISCRIMINATOR: &str = "scope";

/// How long this collector hashes and checks signatures before it stops and says so.
pub const BUDGET: Duration = Duration::from_secs(25);

static FIELDS: [Field; 22] = [
    Field::text("edition"),
    Field::number("image_regions"),
    Field::text("location_kind"),
    Field::number("mapped_bytes"),
    Field::number("mapped_regions"),
    Field::boolean("memory_walk_complete"),
    Field::text("name"),
    Field::text("parent_name"),
    Field::text("path"),
    Field::text("player_name"),
    Field::number("private_bytes"),
    Field::number("private_regions"),
    Field::number("regions_walked"),
    Field::text("scope"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::timestamp("started_at").off_timeline(),
    Field::number("system_modules"),
    Field::boolean("under_player_folder"),
    Field::number("user_modules"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `roblox_process` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct RobloxProcess;

/// Whether a running process is the Roblox player, and which edition.
pub fn roblox_edition(process: &ProcessRecord) -> Option<&'static str> {
    if process.name.eq_ignore_ascii_case("RobloxPlayerBeta.exe") {
        return Some("desktop");
    }
    let store = process.name.eq_ignore_ascii_case("Windows10Universal.exe")
        && process
            .path
            .as_deref()
            .is_some_and(|p| p.to_ascii_uppercase().contains(r"\ROBLOXCORPORATION."));
    store.then_some("store")
}

fn folder_of(path: &str) -> &str {
    path.rfind(['\\', '/']).map_or("", |i| &path[..i])
}

fn is_under(path: &str, folder: &str) -> bool {
    !folder.is_empty()
        && path.len() > folder.len()
        && path.is_char_boundary(folder.len())
        && path[..folder.len()].eq_ignore_ascii_case(folder)
        && path[folder.len()..].starts_with('\\')
}

impl Collector for RobloxProcess {
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

    #[allow(clippy::too_many_lines)]
    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let processes = match host.running_processes() {
            Ok(list) => list,
            Err(error) => return unmeasured(ID, crate::common::reason(host, &error)),
        };
        let by_pid: BTreeMap<u32, &ProcessRecord> = processes.iter().map(|p| (p.pid, p)).collect();
        let parent_name = |process: &ProcessRecord| -> Option<String> {
            let parent = by_pid.get(&process.parent_pid?)?;
            // A parent id is reused after the parent exits: only a parent that started first is it.
            match (parent.started_at, process.started_at) {
                (Some(parent_start), Some(start)) if parent_start > start => None,
                _ => Some(parent.name.clone()),
            }
        };
        let deadline = Instant::now() + BUDGET;
        let mut observations = Vec::new();
        let mut place_gaps: BTreeMap<&'static str, UnmeasuredReason> = BTreeMap::new();
        let system_root = crate::common::env_folder(host, "SystemRoot")
            .or_else(|| crate::common::env_folder(host, "WinDir"))
            .unwrap_or_else(|| r"C:\Windows".to_owned());

        for process in &processes {
            let Some(edition) = roblox_edition(process) else {
                continue;
            };
            let player_folder = process
                .path
                .as_deref()
                .map(folder_of)
                .unwrap_or_default()
                .to_owned();
            let mut row = Fields::new()
                .with(DISCRIMINATOR, "roblox_process")
                .with("edition", edition)
                .with("name", process.name.clone())
                .maybe("path", process.path.clone())
                .maybe("parent_name", parent_name(process))
                .time("started_at", process.started_at);
            match host.process_modules(process.pid) {
                Ok(modules) => {
                    let (system, user): (Vec<&String>, Vec<&String>) =
                        modules.iter().partition(|m| is_under(m, &system_root));
                    row = row
                        .with("system_modules", system.len())
                        .with("user_modules", user.len());
                    for module in user {
                        let mut fields = Fields::new()
                            .with(DISCRIMINATOR, "roblox_module")
                            .with("player_name", process.name.clone())
                            .with(location::FIELD, location::classify(module).as_str())
                            .with("name", location::last_segment(module))
                            .with("path", module.clone())
                            .with("under_player_folder", is_under(module, &player_folder));
                        if Instant::now() < deadline {
                            fields = hash_and_signature(host, module, fields).0;
                        } else {
                            place_gaps
                                .entry("roblox_module")
                                .or_insert(UnmeasuredReason::BudgetSpent);
                        }
                        observations.push(fields.observe(ID));
                    }
                }
                Err(error) => {
                    place_gaps
                        .entry("roblox_module")
                        .or_insert_with(|| crate::common::reason(host, &error));
                }
            }
            match host.executable_memory(process.pid) {
                Ok(memory) => observations.push(
                    Fields::new()
                        .with(DISCRIMINATOR, "roblox_memory")
                        .with("player_name", process.name.clone())
                        .with("private_regions", memory.private_regions)
                        .with("private_bytes", memory.private_bytes)
                        .with("mapped_regions", memory.mapped_regions)
                        .with("mapped_bytes", memory.mapped_bytes)
                        .with("image_regions", memory.image_regions)
                        .with("regions_walked", memory.regions_walked)
                        .with("memory_walk_complete", memory.complete)
                        .observe(ID),
                ),
                Err(error) => {
                    place_gaps
                        .entry("roblox_memory")
                        .or_insert_with(|| crate::common::reason(host, &error));
                }
            }
            observations.push(row.observe(ID));
        }

        for process in &processes {
            if roblox_edition(process).is_some() {
                continue;
            }
            let Some(path) = process.path.as_deref().filter(|p| !p.is_empty()) else {
                continue;
            };
            let kind = location::classify(path);
            if !kind.is_user_writable() {
                continue;
            }
            let mut fields = Fields::new()
                .with(DISCRIMINATOR, "user_location_process")
                .with(location::FIELD, kind.as_str())
                .with("name", process.name.clone())
                .with("path", path.to_owned())
                .maybe("parent_name", parent_name(process))
                .time("started_at", process.started_at);
            if Instant::now() < deadline {
                fields = hash_and_signature(host, path, fields).0;
            } else {
                place_gaps
                    .entry("user_location_process")
                    .or_insert(UnmeasuredReason::BudgetSpent);
            }
            observations.push(fields.observe(ID));
        }

        let discriminator_gaps = place_gaps
            .into_iter()
            .map(|(place, reason)| {
                let fields: &[&str] = match place {
                    "roblox_memory" => &[
                        "image_regions",
                        "mapped_bytes",
                        "mapped_regions",
                        "memory_walk_complete",
                        "private_bytes",
                        "private_regions",
                        "regions_walked",
                    ],
                    "roblox_module" if reason == UnmeasuredReason::BudgetSpent => {
                        &["sha256", "signature", "signer", "signer_cert_sha256"]
                    }
                    "user_location_process" => {
                        &["sha256", "signature", "signer", "signer_cert_sha256"]
                    }
                    _ => &[
                        "location_kind",
                        "name",
                        "path",
                        "sha256",
                        "signature",
                        "signer",
                        "signer_cert_sha256",
                        "under_player_folder",
                    ],
                };
                DiscriminatorGaps {
                    discriminator: DISCRIMINATOR.to_owned(),
                    value: serde_json::Value::from(place),
                    gaps: fields.iter().map(|f| ((*f).to_owned(), reason)).collect(),
                }
            })
            .collect();
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

/// Observations of one scope, for tests and the assessment.
pub fn of_scope<'a>(observations: &'a [Observation], scope: &str) -> Vec<&'a Observation> {
    observations
        .iter()
        .filter(|o| o.fields.get(DISCRIMINATOR).and_then(|v| v.as_str()) == Some(scope))
        .collect()
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    const HOST: &str = r"platform: windows
elevated: true
env:
  SystemRoot: 'C:\Windows'
processes:
  - { pid: 900, name: explorer.exe, path: 'C:\Windows\explorer.exe', started_at: '2026-10-15T08:00:00Z' }
  - pid: 1200
    name: RobloxPlayerBeta.exe
    path: 'C:\Users\a\AppData\Local\Roblox\Versions\version-1\RobloxPlayerBeta.exe'
    started_at: '2026-10-15T09:00:00Z'
    parent_pid: 900
    modules:
      - 'C:\Users\a\AppData\Local\Roblox\Versions\version-1\RobloxPlayerBeta.exe'
      - 'C:\Windows\System32\ntdll.dll'
      - 'C:\Windows\System32\kernel32.dll'
      - 'C:\Users\a\AppData\Local\Temp\inject.dll'
    memory: { private_regions: 3, private_bytes: 12288, image_regions: 40, regions_walked: 900 }
  - { pid: 1300, name: helper.exe, path: 'C:\Users\a\Downloads\helper.exe', parent_pid: 900, started_at: '2026-10-15T09:01:00Z' }
  - { pid: 1400, name: game.exe, path: 'D:\Games\game.exe' }
filesystem:
  'C:\Users\a\AppData\Local\Temp':
    - { name: inject.dll, sha256: '3333333333333333333333333333333333333333333333333333333333333333', signature: { state: no_embedded_signature } }
  'C:\Users\a\Downloads':
    - { name: helper.exe, sha256: '4444444444444444444444444444444444444444444444444444444444444444', signature: { state: invalid } }
";

    #[test]
    fn modules_outside_windows_memory_and_user_location_processes_are_reported() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let CollectorRun::Measured {
            observations,
            discriminator_gaps,
            ..
        } = RobloxProcess.collect(&host)
        else {
            panic!("measured");
        };
        assert!(
            discriminator_gaps
                .iter()
                .all(|g| g.value != "roblox_module")
        );
        let player = of_scope(&observations, "roblox_process");
        assert_eq!(player[0].fields["parent_name"], "explorer.exe");
        assert_eq!(player[0].fields["system_modules"], 2);
        assert_eq!(player[0].fields["user_modules"], 2);
        let modules = of_scope(&observations, "roblox_module");
        let inject = modules
            .iter()
            .find(|m| m.fields["name"] == "inject.dll")
            .unwrap();
        assert_eq!(inject.fields["location_kind"], "temp");
        assert_eq!(inject.fields["under_player_folder"], false);
        assert_eq!(inject.fields["signature"], "no_embedded_signature");
        let own = modules
            .iter()
            .find(|m| m.fields["name"] == "RobloxPlayerBeta.exe")
            .unwrap();
        assert_eq!(own.fields["under_player_folder"], true);
        let memory = of_scope(&observations, "roblox_memory");
        assert_eq!(memory[0].fields["private_regions"], 3);
        let user = of_scope(&observations, "user_location_process");
        assert_eq!(user.len(), 1);
        assert_eq!(user[0].fields["name"], "helper.exe");
        assert_eq!(user[0].fields["signature"], "invalid");
    }

    #[test]
    fn a_protected_player_is_access_denied_for_modules_and_memory_only() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nelevated: true\nprocesses:\n  - { pid: 7, name: RobloxPlayerBeta.exe, path: 'C:\\Users\\a\\AppData\\Local\\Roblox\\Versions\\v\\RobloxPlayerBeta.exe', denied: true }\n",
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured {
            observations,
            discriminator_gaps,
            ..
        } = RobloxProcess.collect(&host)
        else {
            panic!("measured");
        };
        assert_eq!(of_scope(&observations, "roblox_process").len(), 1);
        let places: Vec<_> = discriminator_gaps
            .iter()
            .map(|g| {
                (
                    g.value.as_str().unwrap().to_owned(),
                    g.gaps.values().next().copied(),
                )
            })
            .collect();
        assert_eq!(
            places,
            vec![
                (
                    "roblox_memory".to_owned(),
                    Some(UnmeasuredReason::AccessDenied)
                ),
                (
                    "roblox_module".to_owned(),
                    Some(UnmeasuredReason::AccessDenied)
                ),
            ]
        );
    }
}
