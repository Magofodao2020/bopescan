// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of
// scope — see AGENTS.md.

//! Folders Explorer remembers (`ShellBags`) and the files and folders the common Open/Save dialog
//! remembers (`OpenSavePidlMRU`), narrowed to the Roblox tool catalog (B.O.P.E, ADR 0126).
//! **Full scan only.** `list` is the discriminator:
//!
//! - **`shellbag`** — a folder whose view Explorer saved: `BagMRU` under the account's `UsrClass.dat`
//!   (`HKCU\Software\Classes\Local Settings\...\Shell\BagMRU`) and under `NTUSER.DAT`
//!   (`HKCU\Software\Microsoft\Windows\Shell\BagMRU`). Each node's shell item is decoded and joined
//!   with its parents' into a path. The folder may since have been deleted, renamed or been on a drive
//!   that is no longer attached: the path is what Explorer saw.
//! - **`open_save`** — an entry of `ComDlg32\OpenSavePidlMRU`, by extension, with its position in the
//!   list (0 is the most recent).
//!
//! Every path passes through memory once; only those with a segment that matches the catalog as a
//! distinctive or ambiguous alias, or that name Roblox, are kept. Opening a folder or picking a file
//! in a dialog is **not** running a program. The times are the folder's own FAT times when the shell
//! item was made (two-second precision), not when it was opened; registry key times are not read.

use std::collections::BTreeSet;

use bope_core::model::{CollectorRun, Observation, ScanTier, UnmeasuredReason};
use bope_host::{Host, Platform, SourceError};
use bope_parsers::shell_items::{self, ShellItem};

use crate::catalog::{self, MatchKind};
use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "shellbags";
/// The two `BagMRU` roots, with the hive each is in.
pub const BAG_ROOTS: [(&str, &str); 2] = [
    (
        "usrclass",
        r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    ),
    ("ntuser", r"HKCU\Software\Microsoft\Windows\Shell\BagMRU"),
];
/// The common dialog's list of opened and saved items.
pub const OPEN_SAVE: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU";
/// Most `BagMRU` nodes visited.
pub const MAX_NODES: usize = 20_000;
/// Most rows kept.
pub const MAX_ROWS: usize = 500;
const MAX_DEPTH: usize = 40;

static FIELDS: [Field; 20] = [
    Field::timestamp("accessed"),
    Field::boolean("common_legitimate"),
    Field::timestamp("created"),
    Field::text("drive"),
    Field::text("extension"),
    Field::text("list"),
    Field::text("location_kind"),
    Field::text("match_kind"),
    Field::text("matched_segment"),
    Field::number("mft_record"),
    Field::number("mft_sequence"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::text("path"),
    Field::number("position"),
    Field::boolean("roblox_context"),
    Field::text("source"),
    Field::boolean("system_drive"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `shellbags` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShellBags;

struct Walk<'a> {
    host: &'a dyn Host,
    system_drive: Option<String>,
    rows: Vec<Observation>,
    seen: BTreeSet<String>,
    nodes: usize,
    stopped: bool,
}

/// A path for the folder classifier: `%USERPROFILE%` read as a profile folder.
fn classifiable(path: &str) -> String {
    path.strip_prefix("%USERPROFILE%")
        .map_or_else(|| path.to_owned(), |rest| format!(r"C:\Users\_{rest}"))
}

impl Walk<'_> {
    /// Keeps `items` as a row when a segment matches the catalog or the path names Roblox.
    fn consider(&mut self, list: &str, source: &str, items: &[ShellItem], extra: Fields) {
        if self.rows.len() >= MAX_ROWS {
            self.stopped = true;
            return;
        }
        let path = shell_items::path(items);
        if path.is_empty() {
            return;
        }
        let segments: Vec<String> = items.iter().filter_map(shell_items::segment).collect();
        let found = segments.iter().rev().find_map(|s| {
            catalog::match_name(s)
                .into_iter()
                .next()
                .filter(|m| m.kind >= MatchKind::AmbiguousAlias)
                .map(|m| (s.clone(), m))
        });
        let roblox = catalog::path_mentions_roblox(&path);
        if found.is_none() && !roblox {
            return;
        }
        if !self.seen.insert(format!("{list}|{}", path.to_lowercase())) {
            return;
        }
        let file = items.iter().rev().find_map(|i| match i {
            ShellItem::File(f) => Some(f),
            _ => None,
        });
        let drive = items.iter().find_map(|i| match i {
            ShellItem::Volume { name } => Some(name.trim_end_matches('\\').to_ascii_uppercase()),
            _ => None,
        });
        let system_drive = drive
            .as_deref()
            .zip(self.system_drive.as_deref())
            .map(|(d, s)| d.eq_ignore_ascii_case(s));
        let mut fields = extra
            .with("list", list)
            .with("source", source)
            .with("path", path.clone())
            .with("name", location::last_segment(&path).to_owned())
            .with(
                location::FIELD,
                location::classify(&classifiable(&path)).as_str(),
            )
            .with("roblox_context", roblox)
            .maybe("drive", drive)
            .maybe("system_drive", system_drive)
            .time("modified", file.and_then(|f| f.modified))
            .time("created", file.and_then(|f| f.created))
            .time("accessed", file.and_then(|f| f.accessed))
            .maybe("mft_record", file.and_then(|f| f.mft_record))
            .maybe("mft_sequence", file.and_then(|f| f.mft_sequence));
        if let Some((segment, m)) = found {
            fields = fields
                .with("matched_segment", segment)
                .with("tool_id", m.tool.id)
                .with("tool_kind", m.tool.kind.as_str())
                .with("match_kind", m.kind.as_str())
                .with("common_legitimate", m.tool.common_legitimate);
        }
        self.rows.push(fields.observe(ID));
    }

    fn bags(
        &mut self,
        source: &str,
        key: &str,
        prefix: &[ShellItem],
        depth: usize,
    ) -> Result<(), SourceError> {
        if depth > MAX_DEPTH {
            return Ok(());
        }
        let Some(values) = self.host.value_names(key)? else {
            return Ok(());
        };
        let subkeys = self.host.subkeys(key)?.unwrap_or_default();
        let mut numbered: Vec<u32> = values.iter().filter_map(|v| v.parse().ok()).collect();
        numbered.sort_unstable();
        for n in numbered {
            if self.nodes >= MAX_NODES {
                self.stopped = true;
                return Ok(());
            }
            self.nodes += 1;
            let Some(bytes) = self.host.read_bytes(key, &n.to_string())? else {
                continue;
            };
            let Ok(items) = shell_items::list(&bytes) else {
                continue;
            };
            let mut path = prefix.to_vec();
            path.extend(items);
            self.consider("shellbag", source, &path, Fields::new());
            let child = n.to_string();
            if subkeys.iter().any(|s| s == &child) {
                self.bags(source, &format!(r"{key}\{child}"), &path, depth + 1)?;
            }
        }
        Ok(())
    }

    fn open_save(&mut self) -> Result<(), SourceError> {
        let Some(extensions) = self.host.subkeys(OPEN_SAVE)? else {
            return Ok(());
        };
        for extension in extensions {
            let key = format!(r"{OPEN_SAVE}\{extension}");
            let order = self
                .host
                .read_bytes(&key, "MRUListEx")?
                .map(|b| crate::shell_mru::mru_list_ex(&b))
                .unwrap_or_default();
            for (position, index) in order.iter().enumerate() {
                let Some(bytes) = self.host.read_bytes(&key, &index.to_string())? else {
                    continue;
                };
                let Ok(items) = shell_items::list(&bytes) else {
                    continue;
                };
                self.consider(
                    "open_save",
                    "ntuser",
                    &items,
                    Fields::new()
                        .with("extension", extension.trim_start_matches('.').to_owned())
                        .with("position", position),
                );
            }
        }
        Ok(())
    }
}

impl Collector for ShellBags {
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
        let mut walk = Walk {
            host,
            system_drive: host
                .env_var("SystemDrive")
                .map(|d| d.trim_end_matches('\\').to_ascii_uppercase()),
            rows: Vec::new(),
            seen: BTreeSet::new(),
            nodes: 0,
            stopped: false,
        };
        let result = (|| {
            for (source, root) in BAG_ROOTS {
                walk.bags(source, root, &[], 0)?;
            }
            walk.open_save()
        })();
        match result {
            Ok(()) => {
                let mut gaps = std::collections::BTreeMap::new();
                if walk.stopped {
                    gaps.insert("path".to_owned(), UnmeasuredReason::BudgetSpent);
                    gaps.insert("tool_id".to_owned(), UnmeasuredReason::BudgetSpent);
                }
                measured(ID, walk.rows, gaps)
            }
            Err(error) => unmeasured(ID, reason(host, &error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    const FAT: u32 = ((46 << 9) | (10 << 5) | 1) | (((12 << 11) | (30 << 5) | 5) << 16);

    fn hex(parts: &[Vec<u8>]) -> String {
        let mut b: Vec<u8> = parts.concat();
        b.extend([0, 0]);
        crate::common::hex(&b)
    }

    fn host() -> FixtureHost {
        let bag = BAG_ROOTS[0].1.replace('\\', "\\\\");
        let open = OPEN_SAVE.replace('\\', "\\\\");
        let yaml = format!(
            "platform: windows\nenv:\n  SystemDrive: 'C:'\nregistry:\n  \"{bag}\":\n    '0': {{ hex: '{}' }}\n    NodeSlot: 1\n  \"{bag}\\\\0\":\n    '0': {{ hex: '{}' }}\n  \"{bag}\\\\0\\\\0\":\n    '0': {{ hex: '{}' }}\n    '1': {{ hex: '{}' }}\n  \"{bag}\\\\0\\\\0\\\\0\":\n    '0': {{ hex: '{}' }}\n  \"{open}\\\\exe\":\n    MRUListEx: {{ hex: '00000000ffffffff' }}\n    '0': {{ hex: '{}' }}\n",
            hex(&[shell_items::build_my_computer()]),
            hex(&[shell_items::build_volume('E')]),
            hex(&[shell_items::build_folder("Ferramentas", FAT, 900)]),
            hex(&[shell_items::build_folder("Fotos", FAT, 901)]),
            hex(&[shell_items::build_folder("Solara", FAT, 902)]),
            hex(&[
                shell_items::build_my_computer(),
                shell_items::build_volume('C'),
                shell_items::build_folder("Users", FAT, 1),
                shell_items::build_folder("a", FAT, 2),
                shell_items::build_folder("Downloads", FAT, 3),
                shell_items::build_folder("KRNL.exe", FAT, 4),
            ]),
        );
        FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    #[test]
    fn catalog_folders_on_another_drive_and_dialog_picks_are_kept_and_nothing_else() {
        let CollectorRun::Measured { observations, .. } = ShellBags.collect(&host()) else {
            panic!()
        };
        assert_eq!(observations.len(), 2, "{observations:#?}");
        let bag = &observations[0];
        assert_eq!(bag.fields["list"], "shellbag");
        assert_eq!(bag.fields["path"], r"E:\Ferramentas\Solara");
        assert_eq!(bag.fields["drive"], "E:");
        assert_eq!(bag.fields["system_drive"], false);
        assert_eq!(bag.fields["tool_id"], "solara");
        assert_eq!(bag.fields["mft_record"], 902);
        assert_eq!(bag.fields["modified"], "2026-10-01T12:30:10Z");
        let pick = &observations[1];
        assert_eq!(pick.fields["list"], "open_save");
        assert_eq!(pick.fields["extension"], "exe");
        assert_eq!(pick.fields["path"], r"C:\Users\a\Downloads\KRNL.exe");
        assert_eq!(pick.fields["location_kind"], "user_downloads");
        assert_eq!(pick.fields["position"], 0);
    }

    #[test]
    fn nothing_there_is_measured_empty_and_a_denied_key_is_unmeasured() {
        let empty = FixtureHost::from_yaml_str("platform: windows\n", "inline").unwrap();
        assert!(matches!(
            ShellBags.collect(&empty),
            CollectorRun::Measured { ref observations, .. } if observations.is_empty()
        ));
        let bag = BAG_ROOTS[0].1.replace('\\', "\\\\");
        let denied = FixtureHost::from_yaml_str(
            &format!("platform: windows\nregistry:\n  \"{bag}\":\n    '0': {{ hex: '00' }}\naccess_denied: [\"{bag}\"]\n"),
            "inline",
        )
        .unwrap();
        assert!(matches!(
            ShellBags.collect(&denied),
            CollectorRun::Unmeasured { .. }
        ));
    }
}
