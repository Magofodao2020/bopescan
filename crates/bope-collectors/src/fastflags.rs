// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Roblox `FastFlag` files: which exist, where, which one the player reads, and what kinds of flags
//! they set (B.O.P.E, ADR 0122).
//!
//! Looks at:
//!
//! - `ClientSettings\ClientAppSettings.json` in every Roblox version folder — under
//!   `%LOCALAPPDATA%\Roblox\Versions`, both `Program Files` and the bootstrappers' own `Versions`
//!   folders. A version folder holding `RobloxPlayerBeta.exe` is one the player starts from, so its
//!   file is `applies_to_player: true`; the newest such folder is `active_version: true`.
//! - Each bootstrapper's folder (`Bloxstrap`, `Fishstrap`, `Voidstrap`, `Froststrap` under
//!   `%LOCALAPPDATA%`), three levels deep, for JSON files named like `FastFlag` settings — the copy a
//!   bootstrapper keeps and writes into the version folder when it launches Roblox
//!   (`applies_to_player: false`: configured, applied only through that launcher).
//! - Folders named like a `FastFlag` tool in `%LOCALAPPDATA%`, `%APPDATA%`, Downloads, Desktop and
//!   Documents, two levels deep, for JSON files, including backups (`.json.bak`, `*backup*.json`).
//!
//! Of each file: size, times, SHA-256, whether it parses, how many keys look like `FastFlags`, how many
//! fall in each kind by name (network/physics, frame rate, rendering, debug, other), and the **names**
//! of the network/physics flags (at most 25). Values are never kept.
//!
//! **What this does not say.** That a flag works: recent Roblox clients ignore flags outside an
//! allow-list, and which flags are honoured changes with Roblox versions. That a flag is forbidden:
//! most edited flags change graphics or frame rate. There is no trusted reference copy of a "stock"
//! file, so nothing is compared against one. A network/physics flag name is a reason to ask, not a
//! finding by itself.

use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, Observation, UnmeasuredReason};
use bope_host::{DirEntryInfo, Host, Platform};

use crate::catalog::{self, ToolKind};
use crate::common::{Fields, env_folder, join, unmeasured, user_profile};
use crate::{Collector, Field, location};

const ID: &str = "fastflags";
const DISCRIMINATOR: &str = "location";
/// Largest settings file read.
pub const MAX_BYTES: u64 = 1024 * 1024;
/// Most files read.
pub const MAX_FILES: usize = 60;
/// How long the collector looks before it stops and says so.
pub const BUDGET: Duration = Duration::from_secs(8);
/// Bootstrapper folders under `%LOCALAPPDATA%`.
pub const BOOTSTRAPPERS: [&str; 4] = ["Bloxstrap", "Fishstrap", "Voidstrap", "Froststrap"];
/// Most network/physics flag names kept per file.
const MAX_NAMES: usize = 25;

static FIELDS: [Field; 21] = [
    Field::boolean("active_version"),
    Field::boolean("applies_to_player"),
    Field::boolean("backup"),
    Field::timestamp("created"),
    Field::number("flag_count"),
    Field::number("flags_debug"),
    Field::number("flags_fps"),
    Field::number("flags_network"),
    Field::number("flags_other"),
    Field::number("flags_rendering"),
    Field::number("keys"),
    Field::text("location"),
    Field::text("location_kind"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::text("network_flags"),
    Field::text("owner"),
    Field::boolean("parses"),
    Field::text("path"),
    Field::text("sha256"),
    Field::number("size"),
];

static REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `fastflags` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct FastFlags;

/// Whether a JSON key is written the way Roblox `FastFlags` are: an optional `D`/`S` prefix, then
/// `FFlag`, `FInt`, `FString` or `FLog`, then a name.
pub fn is_flag_name(key: &str) -> bool {
    let rest = key
        .strip_prefix("DF")
        .or_else(|| key.strip_prefix("SF"))
        .or_else(|| key.strip_prefix('F'));
    rest.is_some_and(|r| {
        ["Flag", "Int", "String", "Log"]
            .iter()
            .any(|p| r.strip_prefix(p).is_some_and(|n| !n.is_empty()))
    })
}

/// The kind of a flag, from its name only.
pub fn flag_kind(key: &str) -> &'static str {
    let lower = key.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| lower.contains(w));
    if has(&[
        "physics",
        "replicat",
        "sender",
        "network",
        "raknet",
        "packet",
        "bandwidth",
        "ping",
        "s2p",
        "humanoid",
        "assembly",
    ]) {
        "network"
    } else if has(&["fps", "framerate", "taskscheduler"]) {
        "fps"
    } else if has(&[
        "render",
        "graphics",
        "texture",
        "shadow",
        "light",
        "d3d",
        "vulkan",
        "opengl",
        "metal",
        "mesh",
        "grass",
        "fog",
        "post",
        "bloom",
        "msaa",
        "antialias",
        "quality",
        "terrain",
    ]) {
        "rendering"
    } else if has(&["debug"]) {
        "debug"
    } else {
        "other"
    }
}

/// Whether an already lower-cased name ends with `suffix`.
fn has_suffix(lower: &str, suffix: &str) -> bool {
    lower.len() > suffix.len() && lower.get(lower.len() - suffix.len()..) == Some(suffix)
}

struct Candidate {
    location: &'static str,
    owner: String,
    path: String,
    entry: DirEntryInfo,
    applies: bool,
    version_folder: Option<(String, Option<jiff::Timestamp>)>,
}

struct Look<'a> {
    host: &'a dyn Host,
    deadline: Instant,
    found: Vec<Candidate>,
    stopped: bool,
}

impl Look<'_> {
    fn list(&mut self, dir: &str) -> Vec<DirEntryInfo> {
        if Instant::now() >= self.deadline {
            self.stopped = true;
            return Vec::new();
        }
        self.host.list_dir(dir).ok().flatten().unwrap_or_default()
    }

    /// Every `version-*` folder of a `Versions` folder.
    fn versions(&mut self, versions: &str, owner: &str) {
        for v in self.list(versions) {
            if v.is_file || !v.name.to_ascii_lowercase().starts_with("version-") {
                continue;
            }
            let folder = join(versions, &v.name);
            let files = self.list(&folder);
            let has_player = files
                .iter()
                .any(|f| f.is_file && f.name.eq_ignore_ascii_case("RobloxPlayerBeta.exe"));
            let settings = join(&folder, "ClientSettings");
            for f in self.list(&settings) {
                if f.is_file && f.name.eq_ignore_ascii_case("ClientAppSettings.json") {
                    self.found.push(Candidate {
                        location: "version_folder",
                        owner: owner.to_owned(),
                        path: join(&settings, &f.name),
                        entry: f,
                        applies: has_player,
                        version_folder: Some((folder.clone(), v.modified.or(v.created))),
                    });
                }
            }
        }
    }

    /// JSON files named like `FastFlag` settings under `dir`, `depth` levels down.
    fn settings_files(
        &mut self,
        location: &'static str,
        owner: &str,
        dir: &str,
        depth: u8,
        any_json: bool,
    ) {
        for entry in self.list(dir) {
            let path = join(dir, &entry.name);
            if !entry.is_file {
                if depth > 0 && !entry.name.eq_ignore_ascii_case("Versions") {
                    self.settings_files(location, owner, &path, depth - 1, any_json);
                }
                continue;
            }
            let lower = entry.name.to_ascii_lowercase();
            let json = has_suffix(&lower, ".json") || has_suffix(&lower, ".json.bak");
            let named = lower.contains("clientappsettings")
                || lower.contains("fflag")
                || lower.contains("fastflag")
                || lower.contains("clientsettings");
            if json && (named || any_json) {
                self.found.push(Candidate {
                    location,
                    owner: owner.to_owned(),
                    path,
                    entry,
                    applies: false,
                    version_folder: None,
                });
            }
        }
    }
}

/// One `FastFlag` settings file found.
#[derive(Debug, Clone)]
pub struct SettingsFile {
    /// Where it was found: `version_folder`, `bootstrapper` or `tool_folder`.
    pub location: &'static str,
    /// Whose folder: `roblox`, a bootstrapper, or the tool folder's name, lower-cased.
    pub owner: String,
    /// Full path.
    pub path: String,
    /// What the listing said of it.
    pub entry: DirEntryInfo,
    /// In a version folder holding the player: the player reads it when started from there.
    pub applies_to_player: bool,
    /// In the newest version folder holding the player.
    pub active_version: bool,
    /// Named like a backup copy.
    pub backup: bool,
}

/// Every settings file found, and whether the look stopped before it was done.
#[derive(Debug, Clone, Default)]
pub struct Found {
    /// The files, in the order found.
    pub files: Vec<SettingsFile>,
    /// The budget ran out before every folder was listed.
    pub stopped: bool,
}

/// Finds the `FastFlag` settings files of the player, the bootstrappers and folders named like a
/// `FastFlag` tool, within [`BUDGET`].
pub fn settings_files(host: &dyn Host) -> Found {
    let mut look = Look {
        host,
        deadline: Instant::now() + BUDGET,
        found: Vec::new(),
        stopped: false,
    };
    let local = env_folder(host, "LOCALAPPDATA");
    if let Some(local) = &local {
        look.versions(&join(local, r"Roblox\Versions"), "roblox");
        for name in BOOTSTRAPPERS {
            let folder = join(local, name);
            look.versions(&join(&folder, "Versions"), &name.to_ascii_lowercase());
            look.settings_files(
                "bootstrapper",
                &name.to_ascii_lowercase(),
                &folder,
                3,
                false,
            );
        }
    }
    for var in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(pf) = env_folder(host, var) {
            look.versions(&join(&pf, r"Roblox\Versions"), "roblox");
        }
    }
    // Folders named like a FastFlag tool.
    let mut tool_roots = Vec::new();
    tool_roots.extend(local.clone());
    tool_roots.extend(env_folder(host, "APPDATA"));
    if let Some(profile) = user_profile(host) {
        for sub in ["Downloads", "Desktop", "Documents"] {
            tool_roots.push(join(&profile, sub));
        }
    }
    for root in tool_roots {
        for entry in look.list(&root) {
            if entry.is_file {
                continue;
            }
            let is_tool = catalog::match_name(&entry.name).iter().any(|m| {
                m.tool.kind == ToolKind::FflagManager || m.tool.id == "client_settings_term"
            });
            if is_tool {
                let owner = entry.name.to_ascii_lowercase();
                look.settings_files("tool_folder", &owner, &join(&root, &entry.name), 2, true);
            }
        }
    }

    // The newest version folder holding the player is the active one.
    let active = look
        .found
        .iter()
        .filter(|c| c.applies)
        .filter_map(|c| c.version_folder.as_ref())
        .max_by_key(|(_, t)| *t)
        .map(|(f, _)| f.clone());
    let files = look
        .found
        .into_iter()
        .map(|c| {
            let lower = c.entry.name.to_ascii_lowercase();
            SettingsFile {
                active_version: c.applies
                    && c.version_folder.as_ref().map(|(f, _)| f) == active.as_ref(),
                backup: has_suffix(&lower, ".bak") || lower.contains("backup"),
                location: c.location,
                owner: c.owner,
                path: c.path,
                entry: c.entry,
                applies_to_player: c.applies,
            }
        })
        .collect();
    Found {
        files,
        stopped: look.stopped,
    }
}

fn analyse(bytes: &[u8]) -> Option<(usize, usize, [usize; 5], Vec<String>)> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;
    let mut kinds = [0_usize; 5];
    let mut network = Vec::new();
    let mut flags = 0;
    for key in object.keys() {
        if !is_flag_name(key) {
            continue;
        }
        flags += 1;
        let kind = flag_kind(key);
        let at = match kind {
            "network" => 0,
            "fps" => 1,
            "rendering" => 2,
            "debug" => 3,
            _ => 4,
        };
        kinds[at] += 1;
        if kind == "network" && network.len() < MAX_NAMES {
            network.push(key.clone());
        }
    }
    Some((object.len(), flags, kinds, network))
}

impl Collector for FastFlags {
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
        let found = settings_files(host);
        let mut observations: Vec<Observation> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for c in found.files.iter().take(MAX_FILES) {
            if !seen.insert(c.path.to_ascii_lowercase()) {
                continue;
            }
            let mut fields = Fields::new()
                .with(DISCRIMINATOR, c.location)
                .with("owner", c.owner.clone())
                .with("name", c.entry.name.clone())
                .with("path", c.path.clone())
                .with(location::FIELD, location::classify(&c.path).as_str())
                .with("applies_to_player", c.applies_to_player)
                .with("active_version", c.active_version)
                .with("backup", c.backup)
                .maybe("size", c.entry.size)
                .time("created", c.entry.created)
                .time("modified", c.entry.modified);
            if c.entry.size.is_some_and(|s| s > MAX_BYTES) {
                observations.push(fields.observe(ID));
                continue;
            }
            if let Ok(hash) = host.file_sha256(&c.path) {
                fields = fields.with("sha256", hash);
            }
            if let Ok(Some(bytes)) = host.read_file(&c.path) {
                match analyse(&bytes) {
                    Some((keys, flags, kinds, network)) => {
                        fields = fields
                            .with("parses", true)
                            .with("keys", keys)
                            .with("flag_count", flags)
                            .with("flags_network", kinds[0])
                            .with("flags_fps", kinds[1])
                            .with("flags_rendering", kinds[2])
                            .with("flags_debug", kinds[3])
                            .with("flags_other", kinds[4]);
                        if !network.is_empty() {
                            fields = fields.with("network_flags", network.join(", "));
                        }
                    }
                    None => fields = fields.with("parses", false),
                }
            }
            observations.push(fields.observe(ID));
        }
        let mut gaps = std::collections::BTreeMap::new();
        if found.stopped || found.files.len() > MAX_FILES {
            gaps.insert("path".to_owned(), UnmeasuredReason::BudgetSpent);
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::{FixtureHost, NonWindowsHost};

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
    - { name: ClientAppSettings.json, content: '{"FFlagDebugGraphicsPreferD3D11": true}' }
  'C:\Users\a\AppData\Local\Roblox\Versions\version-new':
    - { name: RobloxPlayerBeta.exe }
    - { name: ClientSettings, directory: true }
  'C:\Users\a\AppData\Local\Roblox\Versions\version-new\ClientSettings':
    - name: ClientAppSettings.json
      modified: '2026-10-14T19:00:00Z'
      content: '{"DFIntTaskSchedulerTargetFps": 240, "DFIntS2PhysicsSenderRate": 1, "FFlagDebugDisplayFPS": true, "note": "x"}'
  'C:\Users\a\AppData\Local\Bloxstrap':
    - { name: Modifications, directory: true }
  'C:\Users\a\AppData\Local\Bloxstrap\Modifications':
    - { name: ClientSettings, directory: true }
  'C:\Users\a\AppData\Local\Bloxstrap\Modifications\ClientSettings':
    - { name: ClientAppSettings.json, content: '{"FIntRenderShadowIntensity": 0}' }
  'C:\Users\a\Downloads':
    - { name: FFlag Manager, directory: true }
  'C:\Users\a\Downloads\FFlag Manager':
    - { name: flags_backup.json, content: 'not json' }
    - { name: readme.txt, content: 'x' }
"#;

    fn observations() -> Vec<Observation> {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        match FastFlags.collect(&host) {
            CollectorRun::Measured { observations, .. } => observations,
            other @ CollectorRun::Unmeasured { .. } => panic!("{other:?}"),
        }
    }

    #[test]
    fn flag_names_are_recognised_and_sorted_by_kind() {
        assert!(is_flag_name("DFIntS2PhysicsSenderRate"));
        assert!(is_flag_name("FFlagDebugDisplayFPS"));
        assert!(is_flag_name("FStringX"));
        assert!(is_flag_name("SFFlagY"));
        assert!(!is_flag_name("note"));
        assert!(!is_flag_name("FFlag"));
        assert_eq!(flag_kind("DFIntS2PhysicsSenderRate"), "network");
        assert_eq!(flag_kind("DFIntTaskSchedulerTargetFps"), "fps");
        assert_eq!(flag_kind("FIntRenderShadowIntensity"), "rendering");
    }

    #[test]
    fn the_active_version_file_the_bootstrapper_copy_and_a_tool_backup_are_told_apart() {
        let all = observations();
        let active: Vec<_> = all
            .iter()
            .filter(|o| o.fields["active_version"] == true)
            .collect();
        assert_eq!(active.len(), 1);
        let a = active[0];
        assert!(a.fields["path"].as_str().unwrap().contains("version-new"));
        assert_eq!(a.fields["flag_count"], 3);
        assert_eq!(a.fields["keys"], 4);
        assert_eq!(a.fields["flags_network"], 1);
        assert_eq!(a.fields["network_flags"], "DFIntS2PhysicsSenderRate");
        assert!(
            !format!("{:?}", a.fields).contains("240"),
            "values are never kept"
        );
        let old = all
            .iter()
            .find(|o| o.fields["path"].as_str().unwrap().contains("version-old"))
            .unwrap();
        assert_eq!(old.fields["applies_to_player"], true);
        assert_eq!(old.fields["active_version"], false);
        let boot = all
            .iter()
            .find(|o| o.fields["location"] == "bootstrapper")
            .unwrap();
        assert_eq!(boot.fields["owner"], "bloxstrap");
        assert_eq!(boot.fields["applies_to_player"], false);
        assert_eq!(boot.fields["flags_rendering"], 1);
        let backup = all
            .iter()
            .find(|o| o.fields["location"] == "tool_folder")
            .unwrap();
        assert_eq!(backup.fields["parses"], false);
        assert_eq!(backup.fields["backup"], true);
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn another_os_is_not_windows() {
        assert_eq!(
            FastFlags.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
    }
}
