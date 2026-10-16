// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Folders laid out the way Roblox script executors lay out their own folder (B.O.P.E, ADR 0108).
//!
//! Executors keep the scripts they run automatically in an `autoexec` folder and the files scripts
//! write in a `workspace` folder, side by side, next to the executor itself. This collector looks for
//! that **pair** in a bounded set of places — the top two levels of Desktop, Downloads, Documents,
//! `%LOCALAPPDATA%`, `%APPDATA%`, the user's Temp folder and the profile folder itself — and reports
//! each folder that has it (`scope: layout`), together with:
//!
//! - every `.exe` and `.dll` directly in that folder, with hash and embedded signature
//!   (`scope: binary`);
//! - each script in its `autoexec` folder, with which executor-only functions it calls
//!   (`bope_parsers::lua_markers`) and never its text (`scope: autoexec_script`).
//!
//! A folder whose name is exactly one of [`PUBLIC_NAMES`] is reported too (`scope: named_folder`),
//! as **context**: those are names of executors discussed publicly, many are ordinary words, and a
//! name is whatever someone typed.
//!
//! **What it does not show.** That anything ran. A folder can be left behind after a download that was
//! never opened, and nothing here looks at any folder outside the places above.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{DirEntryInfo, Host, Platform};
use bope_parsers::lua_markers;

use crate::common::{Fields, env_folder, hash_and_signature, join, unmeasured, user_profile};
use crate::{Collector, Field, location};

const ID: &str = "executor_footprint";
const DISCRIMINATOR: &str = "scope";

/// How long the collector lists, hashes and scans before it stops and says so.
pub const BUDGET: Duration = Duration::from_secs(20);
/// Most folders it lists in one scan.
pub const MAX_LISTINGS: usize = 6_000;
/// Largest script it scans for markers.
pub const MAX_SCRIPT_BYTES: u64 = 2 * 1024 * 1024;

/// Folder names of Roblox executors discussed in public communities, compared exactly without ASCII
/// case. Context only (see the module documentation).
pub const PUBLIC_NAMES: [&str; 16] = [
    "Celery",
    "Fluxus",
    "JJSploit",
    "KRNL",
    "Nihon",
    "Oxygen U",
    "Script-Ware",
    "ScriptWare",
    "Seliware",
    "Solara",
    "Synapse",
    "Synapse X",
    "Xeno",
    "Wave",
    "Zenith",
    "Potassium",
];

/// Extensions treated as scripts in an `autoexec` folder.
const SCRIPT_EXTENSIONS: [&str; 3] = ["lua", "luau", "txt"];

static FIELDS: [Field; 18] = [
    Field::number("autoexec_files"),
    Field::timestamp("created"),
    Field::number("distinct_markers"),
    Field::text("extension"),
    Field::boolean("has_autoexec"),
    Field::boolean("has_bin"),
    Field::boolean("has_scripts"),
    Field::boolean("has_workspace"),
    Field::text("location_kind"),
    Field::text("markers"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::text("path"),
    Field::boolean("remote_loadstring"),
    Field::text("scope"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `executor_footprint` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutorFootprint;

struct Walk<'a> {
    host: &'a dyn Host,
    deadline: Instant,
    listings: usize,
    observations: Vec<Observation>,
    stopped: bool,
    refused: bool,
}

impl Walk<'_> {
    fn list(&mut self, dir: &str) -> Option<Vec<DirEntryInfo>> {
        if self.listings >= MAX_LISTINGS || Instant::now() >= self.deadline {
            self.stopped = true;
            return None;
        }
        self.listings += 1;
        match self.host.list_dir(dir) {
            Ok(entries) => entries,
            Err(bope_host::SourceError::AccessDenied) => {
                // One protected folder in a profile is ordinary (junctions such as `My Music`).
                None
            }
            Err(_) => {
                self.refused = true;
                None
            }
        }
    }

    /// Looks at `dir` (whose own listing entry is `entry`), then at its subfolders down to `depth`.
    fn visit(&mut self, dir: &str, entry: Option<&DirEntryInfo>, depth: u8) {
        let folder_name = location::last_segment(dir).to_owned();
        let children = self.list(dir);
        let has = |name: &str| {
            children.as_ref().is_some_and(|children| {
                children
                    .iter()
                    .any(|c| !c.is_file && c.name.eq_ignore_ascii_case(name))
            })
        };
        if has("autoexec") && has("workspace") {
            if let Some(children) = &children {
                self.layout(dir, entry, children, &folder_name);
            }
        } else if entry.is_some()
            && PUBLIC_NAMES
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&folder_name))
        {
            self.observations.push(
                Fields::new()
                    .with(DISCRIMINATOR, "named_folder")
                    .with(location::FIELD, location::classify(dir).as_str())
                    .with("name", folder_name)
                    .with("path", dir.to_owned())
                    .time("created", entry.and_then(|e| e.created))
                    .time("modified", entry.and_then(|e| e.modified))
                    .observe(ID),
            );
        }
        let Some(children) = children else {
            return;
        };
        if depth == 0 {
            return;
        }
        for child in children.iter().filter(|c| !c.is_file) {
            if crate::paths::is_unusable_segment(&child.name) {
                continue;
            }
            self.visit(&join(dir, &child.name), Some(child), depth - 1);
        }
    }

    fn layout(
        &mut self,
        dir: &str,
        entry: Option<&DirEntryInfo>,
        children: &[DirEntryInfo],
        name: &str,
    ) {
        let has = |n: &str| {
            children
                .iter()
                .any(|c| !c.is_file && c.name.eq_ignore_ascii_case(n))
        };
        let autoexec_dir = join(dir, "autoexec");
        let scripts: Vec<DirEntryInfo> = self
            .list(&autoexec_dir)
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.is_file)
            .filter(|s| {
                location::extension(&s.name)
                    .is_some_and(|e| SCRIPT_EXTENSIONS.contains(&e.as_str()))
            })
            .collect();
        self.observations.push(
            Fields::new()
                .with(DISCRIMINATOR, "layout")
                .with(location::FIELD, location::classify(dir).as_str())
                .with("name", name.to_owned())
                .with("path", dir.to_owned())
                .with("has_autoexec", true)
                .with("has_workspace", true)
                .with("has_scripts", has("scripts"))
                .with("has_bin", has("bin"))
                .with("autoexec_files", scripts.len())
                .time("created", entry.and_then(|e| e.created))
                .time("modified", entry.and_then(|e| e.modified))
                .observe(ID),
        );
        for file in children.iter().filter(|c| c.is_file) {
            let Some(ext) = location::extension(&file.name) else {
                continue;
            };
            if !matches!(ext.as_str(), "exe" | "dll") {
                continue;
            }
            let path = join(dir, &file.name);
            let mut fields = Fields::new()
                .with(DISCRIMINATOR, "binary")
                .with(location::FIELD, location::classify(&path).as_str())
                .with("extension", ext)
                .with("name", file.name.clone())
                .with("path", path.clone())
                .time("created", file.created)
                .time("modified", file.modified);
            if Instant::now() < self.deadline {
                let (with, _) = hash_and_signature(self.host, &path, fields);
                fields = with;
                // `signer_cert_sha256` is left out here: a reviewer reads the signer's name beside the
                // layout, and no rule allows by it in this collector.
                fields.0.remove("signer_cert_sha256");
            } else {
                self.stopped = true;
            }
            self.observations.push(fields.observe(ID));
        }
        for script in scripts {
            let path = join(&autoexec_dir, &script.name);
            let mut fields = Fields::new()
                .with(DISCRIMINATOR, "autoexec_script")
                .with(location::FIELD, location::classify(&path).as_str())
                .maybe("extension", location::extension(&script.name))
                .with("name", script.name.clone())
                .with("path", path.clone())
                .time("modified", script.modified);
            if script.size.is_none_or(|s| s <= MAX_SCRIPT_BYTES)
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
    }
}

/// The roots walked, each with how many levels below it are looked at.
fn roots(host: &dyn Host) -> Vec<(String, u8)> {
    let mut roots = Vec::new();
    if let Some(profile) = user_profile(host) {
        for sub in ["Desktop", "Downloads", "Documents", r"OneDrive\Desktop"] {
            roots.push((join(&profile, sub), 2));
        }
        roots.push((profile, 1));
    }
    if let Some(local) = env_folder(host, "LOCALAPPDATA") {
        roots.push((join(&local, "Temp"), 1));
        roots.push((local, 1));
    }
    if let Some(roaming) = env_folder(host, "APPDATA") {
        roots.push((roaming, 1));
    }
    roots
}

impl Collector for ExecutorFootprint {
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
        let roots = roots(host);
        if roots.is_empty() {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        }
        let mut walk = Walk {
            host,
            deadline: Instant::now() + BUDGET,
            listings: 0,
            observations: Vec::new(),
            stopped: false,
            refused: false,
        };
        for (root, depth) in roots {
            walk.visit(&root, None, depth);
        }
        // Several roots overlap (the profile contains Desktop): keep one row per scope and path.
        let mut seen = std::collections::BTreeSet::new();
        walk.observations.retain(|o| {
            seen.insert((
                o.fields.get(DISCRIMINATOR).cloned().map(|v| v.to_string()),
                o.fields
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(str::to_ascii_lowercase),
            ))
        });
        let reason = if walk.stopped {
            Some(UnmeasuredReason::BudgetSpent)
        } else if walk.refused {
            Some(UnmeasuredReason::ReadFailed)
        } else {
            None
        };
        let discriminator_gaps = reason
            .map(|reason| {
                ["layout", "named_folder"]
                    .into_iter()
                    .map(|place| DiscriminatorGaps {
                        discriminator: DISCRIMINATOR.to_owned(),
                        value: serde_json::Value::from(place),
                        gaps: BTreeMap::from([
                            ("name".to_owned(), reason),
                            ("path".to_owned(), reason),
                        ]),
                    })
                    .collect()
            })
            .unwrap_or_default();
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: walk.observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    const HOST: &str = r#"platform: windows
env:
  USERPROFILE: 'C:\Users\a'
  LOCALAPPDATA: 'C:\Users\a\AppData\Local'
  APPDATA: 'C:\Users\a\AppData\Roaming'
filesystem:
  'C:\Users\a':
    - { name: Downloads, directory: true }
    - { name: Desktop, directory: true }
  'C:\Users\a\Downloads':
    - { name: tools, directory: true }
    - { name: Solara, directory: true, created: '2026-10-10T10:00:00Z' }
  'C:\Users\a\Downloads\tools':
    - { name: SomeExec, directory: true, created: '2026-10-12T10:00:00Z' }
  'C:\Users\a\Downloads\tools\SomeExec':
    - { name: autoexec, directory: true }
    - { name: workspace, directory: true }
    - { name: bin, directory: true }
    - name: SomeExec.exe
      sha256: '5555555555555555555555555555555555555555555555555555555555555555'
      signature: { state: no_embedded_signature }
  'C:\Users\a\Downloads\tools\SomeExec\autoexec':
    - name: esp.lua
      content: "local mt = getrawmetatable(game)\nsetreadonly(mt,false)\nloadstring(game:HttpGet('x'))()\n"
    - { name: readme.md, content: 'hello' }
  'C:\Users\a\Desktop':
    - { name: MyGame, directory: true }
  'C:\Users\a\Desktop\MyGame':
    - { name: workspace, directory: true }
    - { name: src, directory: true }
"#;

    #[test]
    fn the_layout_its_binary_and_its_autoexec_scripts_are_reported() {
        let host = FixtureHost::from_yaml_str(HOST, "inline").unwrap();
        let CollectorRun::Measured {
            observations,
            discriminator_gaps,
            ..
        } = ExecutorFootprint.collect(&host)
        else {
            panic!("measured");
        };
        assert!(discriminator_gaps.is_empty());
        let scope = |s: &str| -> Vec<&Observation> {
            observations
                .iter()
                .filter(|o| o.fields["scope"] == s)
                .collect()
        };
        let layout = scope("layout");
        assert_eq!(layout.len(), 1, "{observations:?}");
        assert_eq!(
            layout[0].fields["path"],
            r"C:\Users\a\Downloads\tools\SomeExec"
        );
        assert_eq!(layout[0].fields["has_bin"], true);
        assert_eq!(layout[0].fields["autoexec_files"], 1);
        let binary = scope("binary");
        assert_eq!(binary[0].fields["signature"], "no_embedded_signature");
        let script = scope("autoexec_script");
        assert_eq!(script[0].fields["distinct_markers"], 3);
        assert_eq!(script[0].fields["remote_loadstring"], true);
        assert!(!format!("{observations:?}").contains("setreadonly(mt"));
        let named = scope("named_folder");
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].fields["name"], "Solara");
    }
}
