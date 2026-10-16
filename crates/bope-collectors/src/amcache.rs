// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `Amcache.hve`: program files Windows inventoried, read from a copy Windows already made
//! (B.O.P.E, ADR 0120).
//!
//! Windows keeps `%SystemRoot%\AppCompat\Programs\Amcache.hve` open without sharing, so the live file
//! normally cannot be read. This collector tries it once, then looks for the hive in **existing**
//! volume shadow copies (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...`, highest `N` first,
//! up to [`MAX_SHADOW_INDEX`]). It never creates a shadow copy, never loads the hive into the registry
//! and never writes anything. Reading shadow copies needs administrator rights.
//!
//! Kept: a summary (`scope: hive`: where it was read from, the hive's last-written time, entry counts,
//! whether transaction logs were pending) and one row per inventoried file whose name matches the
//! Roblox tool catalog, whose path names Roblox, or that sits in a folder the account can write to
//! (`scope: file`), and shortcut entries matching the catalog (`scope: shortcut`). Programs under
//! Windows and Program Files that match nothing are counted, not listed.
//!
//! **What an entry means.** Windows' inventory saw the file — it ran, was installed, or was scanned. It
//! is not proof of execution, and `key_written` is when the entry was written. A shadow copy is older
//! than the scan: anything after it is missing, which `hive_written` bounds.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, SourceError};
use bope_parsers::amcache;

use crate::catalog;
use crate::common::{Fields, env_folder, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "amcache";
const DISCRIMINATOR: &str = "scope";
/// Highest shadow copy number probed.
pub const MAX_SHADOW_INDEX: u32 = 256;
const RELATIVE: &str = r"AppCompat\Programs\Amcache.hve";

static FIELDS: [Field; 24] = [
    Field::boolean("common_legitimate"),
    Field::boolean("dirty"),
    Field::number("files_listed"),
    Field::number("files_total"),
    Field::timestamp("hive_written"),
    Field::timestamp("key_written"),
    Field::text("link_date"),
    Field::text("location_kind"),
    Field::text("match_kind"),
    Field::text("name"),
    Field::boolean("os_component"),
    Field::text("path"),
    Field::text("product"),
    Field::text("publisher"),
    Field::boolean("roblox_context"),
    Field::text("scope"),
    Field::text("sha1"),
    Field::number("shadow_index"),
    Field::number("shortcuts_total"),
    Field::number("size"),
    Field::text("source"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
    Field::text("version"),
];

static REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `amcache` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct Amcache;

/// The newest shadow copy holding the hive, and its number.
pub(crate) fn newest_shadow(host: &dyn Host, relative: &str) -> Option<(u32, String)> {
    (1..=MAX_SHADOW_INDEX).rev().find_map(|n| {
        let path = format!(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{n}\{relative}");
        matches!(host.times(&path), Ok(Some(_))).then_some((n, path))
    })
}

impl Collector for Amcache {
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
        let Some(root) = env_folder(host, "SystemRoot").or_else(|| env_folder(host, "WinDir"))
        else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };
        let live = format!(r"{root}\{RELATIVE}");
        let (bytes, source, shadow_index) = match host.read_file(&live) {
            Ok(Some(bytes)) => (bytes, "live", None),
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(SourceError::TooLarge { .. }) => {
                return unmeasured(ID, UnmeasuredReason::BudgetSpent);
            }
            Err(_) => {
                // `C:\Windows` → `Windows\AppCompat\...` inside a snapshot of the system volume.
                let inside = root.get(3..).map(|r| format!(r"{r}\{RELATIVE}"));
                let shadow = inside.as_deref().and_then(|i| newest_shadow(host, i));
                let Some((n, path)) = shadow else {
                    return unmeasured(
                        ID,
                        if host.is_elevated() == Some(true) {
                            UnmeasuredReason::SourceAbsent
                        } else {
                            UnmeasuredReason::NotAdmin
                        },
                    );
                };
                match host.read_file(&path) {
                    Ok(Some(bytes)) => (bytes, "shadow_copy", Some(n)),
                    Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
                    Err(SourceError::TooLarge { .. }) => {
                        return unmeasured(ID, UnmeasuredReason::BudgetSpent);
                    }
                    Err(error) => return unmeasured(ID, crate::common::reason(host, &error)),
                }
            }
        };
        let Ok(parsed) = amcache::parse(&bytes) else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };
        let mut observations = Vec::new();
        let mut listed = 0_usize;
        for file in &parsed.files {
            let path = file.path.clone().unwrap_or_default();
            let name = file.name.clone().unwrap_or_default();
            let found = catalog::match_name(&name).into_iter().next();
            let kind = location::classify(&path);
            let roblox_context = catalog::path_mentions_roblox(&path);
            let keep = found.is_some() || roblox_context || kind.is_user_writable();
            if !keep || file.os_component {
                continue;
            }
            listed += 1;
            let mut fields = Fields::new()
                .with(DISCRIMINATOR, "file")
                .with("path", path.clone())
                .with("name", name)
                .with(location::FIELD, kind.as_str())
                .with("roblox_context", roblox_context)
                .with("os_component", file.os_component)
                .maybe("sha1", file.sha1.clone())
                .maybe("publisher", file.publisher.clone())
                .maybe("product", file.product.clone())
                .maybe("version", file.version.clone())
                .maybe("link_date", file.link_date.clone())
                .maybe("size", file.size)
                .time("key_written", file.key_written);
            if let Some(m) = found {
                fields = fields
                    .with("tool_id", m.tool.id)
                    .with("tool_kind", m.tool.kind.as_str())
                    .with("match_kind", m.kind.as_str())
                    .with("common_legitimate", m.tool.common_legitimate);
            }
            observations.push(fields.observe(ID));
        }
        for shortcut in &parsed.shortcuts {
            let Some(path) = &shortcut.path else {
                continue;
            };
            let Some(m) = catalog::match_name(path).into_iter().next() else {
                continue;
            };
            observations.push(
                Fields::new()
                    .with(DISCRIMINATOR, "shortcut")
                    .with("path", path.clone())
                    .with("name", location::last_segment(path).to_owned())
                    .with(location::FIELD, location::classify(path).as_str())
                    .with("roblox_context", catalog::path_mentions_roblox(path))
                    .with("tool_id", m.tool.id)
                    .with("tool_kind", m.tool.kind.as_str())
                    .with("match_kind", m.kind.as_str())
                    .with("common_legitimate", m.tool.common_legitimate)
                    .time("key_written", shortcut.key_written)
                    .observe(ID),
            );
        }
        let mut gaps = BTreeMap::new();
        if parsed.layout_unsupported {
            gaps.insert("path".to_owned(), UnmeasuredReason::ReadFailed);
        }
        observations.insert(
            0,
            Fields::new()
                .with(DISCRIMINATOR, "hive")
                .with("source", source)
                .maybe("shadow_index", shadow_index)
                .with("dirty", parsed.dirty)
                .with("files_total", parsed.files.len())
                .with("files_listed", listed)
                .with("shortcuts_total", parsed.shortcuts.len())
                .time("hive_written", parsed.hive_written)
                .observe(ID),
        );
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
    use bope_core::model::Observation;
    use bope_host::{FixtureHost, NonWindowsHost};
    use bope_parsers::regf;

    use super::*;

    fn hive() -> String {
        crate::common::hex(&regf::build(&[
            (
                r"Root\InventoryApplicationFile\solara.exe|1",
                134_353_296_000_000_000,
                &[
                    (
                        "LowerCaseLongPath",
                        r"c:\users\a\downloads\solara\solara.exe",
                    ),
                    ("FileId", "0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ],
            ),
            (
                r"Root\InventoryApplicationFile\notepad.exe|2",
                1,
                &[
                    ("LowerCaseLongPath", r"c:\windows\system32\notepad.exe"),
                    ("IsOsComponent", "1"),
                ],
            ),
            (
                r"Root\InventoryApplicationFile\winword.exe|3",
                1,
                &[(
                    "LowerCaseLongPath",
                    r"c:\program files\microsoft office\winword.exe",
                )],
            ),
            (
                r"Root\InventoryApplicationShortcut\x",
                1,
                &[("ShortcutPath", r"c:\users\a\desktop\krnl.lnk")],
            ),
        ]))
    }

    fn run(yaml_tail: &str) -> CollectorRun {
        let yaml = format!(
            "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\naccess_denied: ['C:\\Windows\\AppCompat\\Programs\\Amcache.hve']\n{yaml_tail}"
        );
        Amcache.collect(&FixtureHost::from_yaml_str(&yaml, "inline").unwrap())
    }

    fn observations(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => panic!("{run:?}"),
        }
    }

    #[test]
    fn the_newest_shadow_copy_is_read_and_only_relevant_files_are_listed() {
        let tail = format!(
            "filesystem:\n  '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\\Windows\\AppCompat\\Programs':\n    - {{ name: Amcache.hve, hex: '{}' }}\n  '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\AppCompat\\Programs':\n    - {{ name: Amcache.hve, content: 'not a hive' }}\n",
            hive()
        );
        let run = run(&tail);
        let all = observations(&run);
        assert_eq!(all[0].fields["source"], "shadow_copy");
        assert_eq!(all[0].fields["shadow_index"], 2);
        assert_eq!(all[0].fields["files_total"], 3);
        assert_eq!(all[0].fields["files_listed"], 1);
        let solara = all
            .iter()
            .find(|o| o.fields.get("name").is_some_and(|n| n == "solara.exe"))
            .unwrap();
        assert_eq!(solara.fields["tool_id"], "solara");
        assert_eq!(solara.fields["location_kind"], "user_downloads");
        assert_eq!(solara.fields["key_written"], "2026-10-01T12:00:00Z");
        assert!(all.iter().any(|o| o.fields["scope"] == "shortcut"));
        assert!(
            all.iter()
                .all(|o| o.fields.get("name").is_none_or(|n| n != "winword.exe"))
        );
    }

    #[test]
    fn no_shadow_copy_is_absent_and_not_elevated_is_not_admin() {
        assert_eq!(run(""), unmeasured(ID, UnmeasuredReason::SourceAbsent));
        let yaml = "platform: windows\nelevated: false\nenv:\n  SystemRoot: 'C:\\Windows'\naccess_denied: ['C:\\Windows\\AppCompat\\Programs\\Amcache.hve']\n";
        assert_eq!(
            Amcache.collect(&FixtureHost::from_yaml_str(yaml, "inline").unwrap()),
            unmeasured(ID, UnmeasuredReason::NotAdmin)
        );
        assert_eq!(
            Amcache.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
    }
}
