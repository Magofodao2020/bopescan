// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Shortcuts (`.lnk`) that point at Roblox tools or at programs in the person's own folders, and
//! whether their targets are still there (B.O.P.E, ADR 0119).
//!
//! Places: the Desktop (the account's, `OneDrive\Desktop` and the public one), the Start menu
//! (the account's and all users', three levels), the taskbar's pinned items, and `Recent`. Each
//! shortcut is parsed with [`bope_parsers::lnk`]: target path, the target's times as they were when
//! the shortcut was saved, whether it passes arguments (never the arguments themselves).
//!
//! Kept: a shortcut whose own name or target name matches [`crate::catalog`]; and, outside `Recent`,
//! a shortcut to a program (`.exe`) in a folder the account can write to (Downloads, Desktop, Temp,
//! `AppData`). From `Recent`, which lists documents a person opened, **only** catalog matches are kept.
//!
//! `target_exists` is whether something is at the target path now. `false` means nothing is there
//! today — moved, renamed, deleted, or on a drive that is not connected — never "deleted" by itself.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, Observation, UnmeasuredReason};
use bope_host::{DirEntryInfo, Host, Platform};
use bope_parsers::lnk;

use crate::catalog;
use crate::common::{Fields, env_folder, join, unmeasured, user_profile};
use crate::{Collector, Field, location};

const ID: &str = "shortcuts";
const DISCRIMINATOR: &str = "place";

/// How long the collector reads shortcuts before it stops and says so.
pub const BUDGET: Duration = Duration::from_secs(10);
/// Most shortcut files read.
pub const MAX_SHORTCUTS: usize = 3_000;

static FIELDS: [Field; 21] = [
    Field::boolean("common_legitimate"),
    Field::timestamp("created"),
    Field::boolean("has_arguments"),
    Field::text("match_kind"),
    Field::text("matched_on"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::boolean("network"),
    Field::text("path"),
    Field::text("place"),
    Field::boolean("roblox_context"),
    Field::timestamp("target_accessed").off_timeline(),
    Field::timestamp("target_created"),
    Field::boolean("target_exists"),
    Field::text("target_location_kind"),
    Field::timestamp("target_modified"),
    Field::text("target_name"),
    Field::text("target_path"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
    Field::text("why"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `shortcuts` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct Shortcuts;

fn places(host: &dyn Host) -> Vec<(&'static str, String, u8)> {
    let mut out = Vec::new();
    if let Some(profile) = user_profile(host) {
        out.push(("desktop", join(&profile, "Desktop"), 1));
        out.push(("desktop", join(&profile, r"OneDrive\Desktop"), 1));
    }
    if let Some(public) = env_folder(host, "PUBLIC") {
        out.push(("desktop", join(&public, "Desktop"), 1));
    }
    if let Some(roaming) = env_folder(host, "APPDATA") {
        out.push((
            "start_menu",
            join(&roaming, r"Microsoft\Windows\Start Menu\Programs"),
            3,
        ));
        out.push((
            "taskbar",
            join(
                &roaming,
                r"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar",
            ),
            0,
        ));
        out.push(("recent", join(&roaming, r"Microsoft\Windows\Recent"), 0));
    }
    if let Some(data) = env_folder(host, "ProgramData") {
        out.push((
            "start_menu",
            join(&data, r"Microsoft\Windows\Start Menu\Programs"),
            3,
        ));
    }
    out
}

struct Walk<'a> {
    host: &'a dyn Host,
    deadline: Instant,
    read: usize,
    observations: Vec<Observation>,
    stopped: bool,
    refused: bool,
}

impl Walk<'_> {
    fn visit(&mut self, place: &'static str, dir: &str, depth: u8) {
        if Instant::now() >= self.deadline || self.read >= MAX_SHORTCUTS {
            self.stopped = true;
            return;
        }
        let children = match self.host.list_dir(dir) {
            Ok(Some(c)) => c,
            Ok(None) | Err(bope_host::SourceError::AccessDenied) => return,
            Err(_) => {
                self.refused = true;
                return;
            }
        };
        for child in &children {
            if crate::paths::is_unusable_segment(&child.name) {
                continue;
            }
            let path = join(dir, &child.name);
            if !child.is_file {
                if depth > 0 {
                    self.visit(place, &path, depth - 1);
                }
                continue;
            }
            if location::extension(&child.name).as_deref() == Some("lnk") {
                self.shortcut(place, &path, child);
            }
        }
    }

    fn shortcut(&mut self, place: &'static str, path: &str, entry: &DirEntryInfo) {
        if Instant::now() >= self.deadline || self.read >= MAX_SHORTCUTS {
            self.stopped = true;
            return;
        }
        self.read += 1;
        let Ok(Some(bytes)) = self.host.read_file(path) else {
            return;
        };
        let Ok(link) = lnk::parse(&bytes) else {
            return;
        };
        let target = link.best_path().map(str::to_owned);
        let target_name = target
            .as_deref()
            .map(|t| location::last_segment(t).to_owned());
        let by_target = target_name
            .as_deref()
            .and_then(|n| catalog::match_name(n).into_iter().next());
        let by_name = catalog::match_name(&entry.name).into_iter().next();
        let (found, matched_on) = match (by_target, by_name) {
            (Some(t), Some(n)) if n.kind > t.kind => (Some(n), "shortcut_name"),
            (Some(t), _) => (Some(t), "target"),
            (None, Some(n)) => (Some(n), "shortcut_name"),
            (None, None) => (None, ""),
        };
        let target_kind = target.as_deref().map(location::classify);
        let user_program = target_kind.is_some_and(location::LocationKind::is_user_writable)
            && target_name
                .as_deref()
                .and_then(location::extension)
                .as_deref()
                == Some("exe");
        let why = if found.is_some() {
            "catalog_match"
        } else if place != "recent" && user_program {
            "program_in_user_folder"
        } else {
            return;
        };
        let target_exists = target
            .as_deref()
            .filter(|_| !link.network)
            .and_then(|t| self.host.times(t).ok())
            .map(|t| t.is_some());
        let roblox_context = catalog::path_mentions_roblox(path)
            || target.as_deref().is_some_and(catalog::path_mentions_roblox);
        let mut fields = Fields::new()
            .with(DISCRIMINATOR, place)
            .with("name", entry.name.clone())
            .with("path", path.to_owned())
            .with("why", why)
            .with("has_arguments", link.has_arguments)
            .with("network", link.network)
            .with("roblox_context", roblox_context)
            .maybe("target_path", target.clone())
            .maybe("target_name", target_name)
            .maybe(
                "target_location_kind",
                target_kind.map(location::LocationKind::as_str),
            )
            .maybe("target_exists", target_exists)
            .time("target_created", link.target_created)
            .time("target_modified", link.target_modified)
            .time("target_accessed", link.target_accessed)
            .time("created", entry.created)
            .time("modified", entry.modified);
        if let Some(m) = found {
            fields = fields
                .with("tool_id", m.tool.id)
                .with("tool_kind", m.tool.kind.as_str())
                .with("match_kind", m.kind.as_str())
                .with("matched_on", matched_on)
                .with("common_legitimate", m.tool.common_legitimate);
        }
        self.observations.push(fields.observe(ID));
    }
}

impl Collector for Shortcuts {
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
        let places = places(host);
        if places.is_empty() {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        }
        let mut walk = Walk {
            host,
            deadline: Instant::now() + BUDGET,
            read: 0,
            observations: Vec::new(),
            stopped: false,
            refused: false,
        };
        for (place, dir, depth) in &places {
            walk.visit(place, dir, *depth);
        }
        let mut gaps = BTreeMap::new();
        if walk.stopped {
            gaps.insert("target_path".to_owned(), UnmeasuredReason::BudgetSpent);
        } else if walk.refused {
            gaps.insert("target_path".to_owned(), UnmeasuredReason::ReadFailed);
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: walk.observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn host() -> FixtureHost {
        let gone = crate::common::hex(&lnk::build_local(
            r"C:\Users\a\Downloads\FFlag Manager\FFlagManager.exe",
            134_353_296_000_000_000,
            true,
        ));
        let here = crate::common::hex(&lnk::build_local(
            r"C:\Users\a\AppData\Local\Bloxstrap\Bloxstrap.exe",
            0,
            false,
        ));
        let doc = crate::common::hex(&lnk::build_local(
            r"C:\Users\a\Documents\notes.docx",
            0,
            false,
        ));
        let tool = crate::common::hex(&lnk::build_local(
            r"C:\Users\a\Downloads\thing.exe",
            0,
            false,
        ));
        let office = crate::common::hex(&lnk::build_local(
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            0,
            false,
        ));
        let yaml = format!(
            r"platform: windows
env:
  USERPROFILE: 'C:\Users\a'
  APPDATA: 'C:\Users\a\AppData\Roaming'
filesystem:
  'C:\Users\a\Desktop':
    - {{ name: FFlag Manager.lnk, hex: '{gone}', modified: '2026-10-01T12:05:00Z' }}
    - {{ name: Bloxstrap.lnk, hex: '{here}' }}
    - {{ name: Thing.lnk, hex: '{tool}' }}
    - {{ name: Word.lnk, hex: '{office}' }}
  'C:\Users\a\AppData\Local\Bloxstrap':
    - {{ name: Bloxstrap.exe, size: 1 }}
  'C:\Users\a\AppData\Roaming\Microsoft\Windows\Recent':
    - {{ name: notes.docx.lnk, hex: '{doc}' }}
    - {{ name: thing.exe.lnk, hex: '{tool}' }}
"
        );
        FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    fn observations() -> Vec<Observation> {
        match Shortcuts.collect(&host()) {
            CollectorRun::Measured { observations, .. } => observations,
            other @ CollectorRun::Unmeasured { .. } => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_shortcut_to_a_tool_that_is_gone_is_kept_with_its_times() {
        let all = observations();
        let gone = all
            .iter()
            .find(|o| o.fields["name"] == "FFlag Manager.lnk")
            .unwrap();
        assert_eq!(gone.fields["tool_id"], "fflag_manager");
        assert_eq!(gone.fields["target_exists"], false);
        assert_eq!(gone.fields["target_modified"], "2026-10-01T12:00:00Z");
        assert_eq!(gone.fields["has_arguments"], true);
        let here = all
            .iter()
            .find(|o| o.fields["name"] == "Bloxstrap.lnk")
            .unwrap();
        assert_eq!(here.fields["target_exists"], true);
        assert_eq!(here.fields["roblox_context"], true);
    }

    #[test]
    fn recent_keeps_only_catalog_matches_and_other_places_keep_user_programs() {
        let all = observations();
        assert!(all.iter().all(|o| o.fields["name"] != "notes.docx.lnk"));
        assert!(all.iter().all(|o| o.fields["name"] != "thing.exe.lnk"));
        assert!(all.iter().all(|o| o.fields["name"] != "Word.lnk"));
        let thing = all
            .iter()
            .find(|o| o.fields["name"] == "Thing.lnk")
            .unwrap();
        assert_eq!(thing.fields["why"], "program_in_user_folder");
        assert!(!thing.fields.contains_key("tool_id"));
    }

    #[test]
    fn another_os_is_not_windows() {
        assert_eq!(
            Shortcuts.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
    }
}
