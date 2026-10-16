// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Roblox's own folders: the installed player, the files beside it, the client settings file, the
//! log folder and third-party bootstrappers (B.O.P.E, ADR 0107).
//!
//! Places, told apart by `location` (the discriminator):
//!
//! - **`version_folder`** — each `version-*` folder under `%LOCALAPPDATA%\Roblox\Versions` and
//!   `%ProgramFiles(x86)%\Roblox\Versions`, with its times and whether it holds the player.
//! - **`player_exe`** — `RobloxPlayerBeta.exe` in a version folder: hash and embedded signature.
//! - **`version_binary`** — every other `.dll`, `.exe` or `.asi` directly in a version folder, with
//!   hash and signature. Only the folder's own level is read.
//! - **`client_settings`** — `ClientSettings\ClientAppSettings.json` in a version folder: how many
//!   settings it sets, never their values. Bootstrappers such as Bloxstrap write this file to change
//!   graphics and frame-rate settings; Roblox itself honours only an allow-list of them.
//! - **`logs`** — `%LOCALAPPDATA%\Roblox\logs`: how many log files and the oldest and newest
//!   last-write times, which bound when the player last ran. No log is opened.
//! - **`bootstrapper`** — `%LOCALAPPDATA%\Bloxstrap`, `Fishstrap` and `Voidstrap`: present or not, with
//!   times. These are open-source launchers, not cheats.
//!
//! The Microsoft Store edition lives under `C:\Program Files\WindowsApps`, which Windows does not let
//! an ordinary program list; its process is still seen by the `process` and `roblox_process`
//! collectors.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{DirEntryInfo, Host, Platform};

use crate::common::{Fields, env_folder, hash_and_signature, join, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "roblox";
const DISCRIMINATOR: &str = "location";

/// File name of the Roblox player.
pub const PLAYER_EXE: &str = "RobloxPlayerBeta.exe";
/// Third-party bootstrappers looked for under `%LOCALAPPDATA%`.
pub const BOOTSTRAPPERS: [&str; 3] = ["Bloxstrap", "Fishstrap", "Voidstrap"];

static FIELDS: [Field; 15] = [
    Field::timestamp("created"),
    Field::text("extension"),
    Field::number("files"),
    Field::number("flag_count"),
    Field::boolean("has_player"),
    Field::text("location"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::timestamp("newest_write"),
    Field::timestamp("oldest_write"),
    Field::text("path"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::SourceAbsent,
];

/// The `roblox` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct Roblox;

struct Run {
    observations: Vec<Observation>,
    place_gaps: BTreeMap<&'static str, UnmeasuredReason>,
}

impl Run {
    fn gap(&mut self, place: &'static str, reason: UnmeasuredReason) {
        self.place_gaps.entry(place).or_insert(reason);
    }
}

fn entry_fields(location: &str, path: &str, entry: &DirEntryInfo) -> Fields {
    Fields::new()
        .with(DISCRIMINATOR, location)
        .with("name", entry.name.clone())
        .with("path", path.to_owned())
        .time("created", entry.created)
        .time("modified", entry.modified)
}

impl Collector for Roblox {
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
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let local = env_folder(host, "LOCALAPPDATA");
        let mut run = Run {
            observations: Vec::new(),
            place_gaps: BTreeMap::new(),
        };
        let roots: Vec<String> = [
            local.as_ref().map(|l| format!(r"{l}\Roblox\Versions")),
            env_folder(host, "ProgramFiles(x86)").map(|p| format!(r"{p}\Roblox\Versions")),
        ]
        .into_iter()
        .flatten()
        .collect();
        if roots.is_empty() {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        }
        for root in &roots {
            versions(host, root, &mut run);
        }
        if let Some(local) = &local {
            logs(host, &join(local, r"Roblox\logs"), &mut run);
            for name in BOOTSTRAPPERS {
                let path = join(local, name);
                match host.times(&path) {
                    Ok(Some(times)) => run.observations.push(
                        Fields::new()
                            .with(DISCRIMINATOR, "bootstrapper")
                            .with("name", name)
                            .with("path", path)
                            .time("created", times.created)
                            .time("modified", times.modified)
                            .observe(ID),
                    ),
                    Ok(None) => {}
                    Err(error) => run.gap("bootstrapper", crate::common::reason(host, &error)),
                }
            }
        } else {
            for place in ["logs", "bootstrapper"] {
                run.gap(place, UnmeasuredReason::ReadFailed);
            }
        }
        let discriminator_gaps = run
            .place_gaps
            .into_iter()
            .map(|(place, reason)| DiscriminatorGaps {
                discriminator: DISCRIMINATOR.to_owned(),
                value: serde_json::Value::from(place),
                gaps: FIELDS
                    .iter()
                    .filter(|f| f.name != DISCRIMINATOR)
                    .map(|f| (f.name.to_owned(), reason))
                    .collect(),
            })
            .collect();
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: run.observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

const VERSION_PLACES: [&str; 4] = [
    "version_folder",
    "player_exe",
    "version_binary",
    "client_settings",
];

fn versions(host: &dyn Host, root: &str, run: &mut Run) {
    let folders = match host.list_dir(root) {
        Ok(Some(entries)) => entries,
        Ok(None) => return,
        Err(error) => {
            let reason = crate::common::reason(host, &error);
            for place in VERSION_PLACES {
                run.gap(place, reason);
            }
            return;
        }
    };
    for folder in folders
        .iter()
        .filter(|e| !e.is_file && e.name.to_ascii_lowercase().starts_with("version-"))
    {
        let dir = join(root, &folder.name);
        let entries = match host.list_dir(&dir) {
            Ok(Some(entries)) => entries,
            Ok(None) => continue,
            Err(error) => {
                let reason = crate::common::reason(host, &error);
                for place in ["player_exe", "version_binary", "client_settings"] {
                    run.gap(place, reason);
                }
                continue;
            }
        };
        let has_player = entries
            .iter()
            .any(|e| e.is_file && e.name.eq_ignore_ascii_case(PLAYER_EXE));
        run.observations.push(
            entry_fields("version_folder", &dir, folder)
                .with("has_player", has_player)
                .with("files", entries.iter().filter(|e| e.is_file).count())
                .observe(ID),
        );
        for file in entries.iter().filter(|e| e.is_file) {
            let Some(ext) = location::extension(&file.name) else {
                continue;
            };
            if !matches!(ext.as_str(), "exe" | "dll" | "asi") {
                continue;
            }
            let path = join(&dir, &file.name);
            let place = if file.name.eq_ignore_ascii_case(PLAYER_EXE) {
                "player_exe"
            } else {
                "version_binary"
            };
            let (fields, _) = hash_and_signature(
                host,
                &path,
                entry_fields(place, &path, file).with("extension", ext),
            );
            run.observations.push(fields.observe(ID));
        }
        client_settings(host, &dir, run);
    }
}

fn client_settings(host: &dyn Host, version_dir: &str, run: &mut Run) {
    let dir = join(version_dir, "ClientSettings");
    let entries = match host.list_dir(&dir) {
        Ok(Some(entries)) => entries,
        Ok(None) => return,
        Err(error) => {
            run.gap("client_settings", crate::common::reason(host, &error));
            return;
        }
    };
    for file in entries
        .iter()
        .filter(|e| e.is_file && e.name.eq_ignore_ascii_case("ClientAppSettings.json"))
    {
        let path = join(&dir, &file.name);
        let count = match host.read_file(&path) {
            Ok(Some(bytes)) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.as_object().map(serde_json::Map::len)),
            _ => None,
        };
        run.observations.push(
            entry_fields("client_settings", &path, file)
                .maybe("flag_count", count)
                .observe(ID),
        );
    }
}

fn logs(host: &dyn Host, dir: &str, run: &mut Run) {
    let entries = match host.list_dir(dir) {
        Ok(Some(entries)) => entries,
        Ok(None) => return,
        Err(error) => {
            run.gap("logs", crate::common::reason(host, &error));
            return;
        }
    };
    let logs: Vec<&DirEntryInfo> = entries
        .iter()
        .filter(|e| e.is_file && location::extension(&e.name).as_deref() == Some("log"))
        .collect();
    let writes: Vec<jiff::Timestamp> = logs.iter().filter_map(|e| e.modified).collect();
    run.observations.push(
        Fields::new()
            .with(DISCRIMINATOR, "logs")
            .with("path", dir.to_owned())
            .with("files", logs.len())
            .time("oldest_write", writes.iter().min().copied())
            .time("newest_write", writes.iter().max().copied())
            .observe(ID),
    );
}

#[cfg(test)]
mod tests {
    use bope_host::{FixtureHost, NonWindowsHost};

    use super::*;

    const HOST: &str = r#"platform: windows
env:
  LOCALAPPDATA: 'C:\Users\a\AppData\Local'
filesystem:
  'C:\Users\a\AppData\Local\Roblox\Versions':
    - { name: version-abc123, directory: true, created: '2026-10-01T10:00:00Z', modified: '2026-10-01T10:00:00Z' }
  'C:\Users\a\AppData\Local\Roblox\Versions\version-abc123':
    - name: RobloxPlayerBeta.exe
      sha256: '1111111111111111111111111111111111111111111111111111111111111111'
      signature: { state: valid, signer: 'Roblox Corporation', signer_cert_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }
    - name: version.dll
      sha256: '2222222222222222222222222222222222222222222222222222222222222222'
      signature: { state: no_embedded_signature }
      modified: '2026-10-14T21:00:00Z'
    - { name: content, directory: true }
    - { name: ClientSettings, directory: true }
  'C:\Users\a\AppData\Local\Roblox\Versions\version-abc123\ClientSettings':
    - name: ClientAppSettings.json
      content: '{"DFIntTaskSchedulerTargetFps": 240, "FFlagDebugGraphicsPreferD3D11": true}'
  'C:\Users\a\AppData\Local\Roblox\logs':
    - { name: 0.1_Player_a.log, modified: '2026-10-14T20:00:00Z' }
    - { name: 0.1_Player_b.log, modified: '2026-10-15T09:00:00Z' }
    - { name: notes.txt, modified: '2026-01-01T00:00:00Z' }
  'C:\Users\a\AppData\Local':
    - { name: Bloxstrap, directory: true, created: '2026-09-01T00:00:00Z' }
"#;

    fn run() -> Vec<Observation> {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        match Roblox.collect(&host) {
            CollectorRun::Measured {
                observations,
                discriminator_gaps,
                ..
            } => {
                assert!(discriminator_gaps.is_empty(), "{discriminator_gaps:?}");
                observations
            }
            other @ CollectorRun::Unmeasured { .. } => panic!("{other:?}"),
        }
    }

    fn at<'a>(all: &'a [Observation], place: &str) -> Vec<&'a Observation> {
        all.iter()
            .filter(|o| o.fields["location"] == place)
            .collect()
    }

    #[test]
    fn the_player_its_neighbours_settings_logs_and_bootstrappers_are_read() {
        let all = run();
        let folder = at(&all, "version_folder");
        assert_eq!(folder[0].fields["has_player"], true);
        let player = at(&all, "player_exe");
        assert_eq!(player[0].fields["signature"], "valid");
        assert_eq!(player[0].fields["signer"], "Roblox Corporation");
        let dll = at(&all, "version_binary");
        assert_eq!(dll.len(), 1);
        assert_eq!(dll[0].fields["name"], "version.dll");
        assert_eq!(dll[0].fields["signature"], "no_embedded_signature");
        let settings = at(&all, "client_settings");
        assert_eq!(settings[0].fields["flag_count"], 2);
        let logs = at(&all, "logs");
        assert_eq!(logs[0].fields["files"], 2);
        assert_eq!(logs[0].fields["newest_write"], "2026-10-15T09:00:00Z");
        let boot = at(&all, "bootstrapper");
        assert_eq!(boot.len(), 1);
        assert_eq!(boot[0].fields["name"], "Bloxstrap");
    }

    #[test]
    fn a_pc_without_roblox_is_measured_with_nothing_and_another_os_is_not() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\n",
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured { observations, .. } = Roblox.collect(&host) else {
            panic!("measured");
        };
        assert!(observations.is_empty());
        assert_eq!(
            Roblox.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
    }

    #[test]
    fn a_versions_folder_refused_is_a_gap_for_the_version_places_only() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nelevated: true\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\naccess_denied: ['C:\\Users\\a\\AppData\\Local\\Roblox\\Versions']\n",
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured {
            discriminator_gaps, ..
        } = Roblox.collect(&host)
        else {
            panic!("measured");
        };
        let places: Vec<_> = discriminator_gaps.iter().map(|g| g.value.clone()).collect();
        assert_eq!(places.len(), 4, "{places:?}");
        assert!(!places.contains(&serde_json::Value::from("logs")));
    }
}
