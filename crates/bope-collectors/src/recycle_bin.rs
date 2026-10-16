// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of
// scope — see AGENTS.md.

//! The times of the account's own Recycle Bin on the system drive (B.O.P.E, ADR 0131).
//!
//! `C:\$Recycle.Bin\<SID>` of the account the scan runs as is listed once; each `$I` file is read
//! (it is a few hundred bytes of metadata: the original path, the size and the deletion time) and
//! parsed by [`bope_parsers::recycle`]. **No `$R` file is opened**: its presence, size and times come
//! from the same listing. Nothing is restored, moved, deleted or changed.
//!
//! Two kinds of observation, told apart by `scope`:
//!
//! - `bin`: one, about the folder as a whole, with no name in it: the folder's own creation and
//!   last-write times (`folder_created`, `folder_modified`), how many `$I` and `$R` entries it holds,
//!   how many of each have no partner, how many `$I` could not be read, and the newest and oldest
//!   deletion times recorded and the newest artifact write time. "When was the Recycle Bin modified"
//!   is answered with the **last modification observed in an artifact**, which is the newest of the
//!   folder's own write time and its entries'; emptying the bin removes entries and rewrites the
//!   folder, so a recent folder write with no entry that new is consistent with an emptying — and with
//!   anything else that wrote the folder. No global "modified at" exists, and none is invented.
//! - `item`: one per `$I`, with `deleted_at` from inside it, the `$I` entry's own times, and whether
//!   its `$R` partner is there with that entry's times. `content_modified` is the `$R`'s last-write
//!   time: Windows moves a file into the bin on the same volume, which keeps that time, but any program
//!   can set it, so it is reported as the artifact's, not as the file's history.
//!
//! The account's SID is used to find the folder and is not kept. SS mode never lists `item`
//! observations that match no rule (ADR 0014); see `bope-core::view` for what it shows.

use std::collections::{BTreeMap, BTreeSet};

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{DirEntryInfo, Host, Platform};
use bope_parsers::recycle;
use jiff::Timestamp;

use crate::catalog;
use crate::common::{Fields, join, unmeasured};
use crate::failure::reason_for;
use crate::{Collector, Field, location};

const ID: &str = "recycle_bin";
const DISCRIMINATOR: &str = "scope";
/// Most `$I` files read in one scan.
pub const MAX_ITEMS: usize = 2_000;

static FIELDS: [Field; 30] = [
    Field::timestamp("content_created").off_timeline(),
    Field::number("content_entries"),
    Field::boolean("content_is_folder"),
    Field::timestamp("content_modified"),
    Field::boolean("content_present"),
    Field::number("content_size"),
    Field::timestamp("deleted_at"),
    Field::text("drive"),
    Field::timestamp("folder_created").off_timeline(),
    Field::timestamp("folder_modified"),
    Field::timestamp("index_created").off_timeline(),
    Field::number("index_entries"),
    Field::text("index_file"),
    Field::timestamp("index_modified").off_timeline(),
    Field::timestamp("last_artifact_change").off_timeline(),
    Field::text("last_artifact_change_source"),
    Field::text("location_kind"),
    Field::text("match_kind"),
    Field::text("name"),
    Field::timestamp("newest_deleted_at").off_timeline(),
    Field::timestamp("oldest_deleted_at").off_timeline(),
    Field::number("orphan_content"),
    Field::number("orphan_index"),
    Field::text("path"),
    Field::boolean("read_capped"),
    Field::text("scope"),
    Field::number("size"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
    Field::number("unreadable_index"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// The `recycle_bin` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecycleBin;

fn system_drive(host: &dyn Host) -> Option<String> {
    let drive_of = |v: String| -> Option<String> {
        let d: String = v.chars().take(2).collect();
        (d.len() == 2 && d.ends_with(':')).then_some(d.to_uppercase())
    };
    host.env_var("SystemDrive")
        .and_then(drive_of)
        .or_else(|| host.env_var("SystemRoot").and_then(drive_of))
}

/// The newest of the folder's own write time and its entries' times, with which it was.
pub fn last_artifact_change(
    folder_modified: Option<Timestamp>,
    entries: &[DirEntryInfo],
) -> Option<(Timestamp, &'static str)> {
    let entry = entries
        .iter()
        .flat_map(|e| [e.modified, e.created])
        .flatten()
        .max();
    match (folder_modified, entry) {
        (Some(f), Some(e)) if e > f => Some((e, "entry")),
        (Some(f), _) => Some((f, "folder")),
        (None, Some(e)) => Some((e, "entry")),
        (None, None) => None,
    }
}

impl Collector for RecycleBin {
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
        let Some(drive) = system_drive(host) else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };
        let sid = match host.account_sid() {
            Ok(sid) => sid,
            Err(error) => return unmeasured(ID, reason_for(host, &error)),
        };
        let bin = format!(r"{drive}\$Recycle.Bin\{sid}");
        let children = match host.list_dir(&bin) {
            Ok(Some(children)) => children,
            // Windows creates the folder the first time the account deletes something on the drive.
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(ID, reason_for(host, &error)),
        };
        let folder = host.times(&bin).ok().flatten();
        let by_name: BTreeMap<String, &DirEntryInfo> = children
            .iter()
            .map(|c| (c.name.to_lowercase(), c))
            .collect();
        let index: Vec<&DirEntryInfo> = children
            .iter()
            .filter(|c| c.is_file && c.name.starts_with("$I"))
            .collect();
        let content: Vec<&DirEntryInfo> = children
            .iter()
            .filter(|c| c.name.starts_with("$R"))
            .collect();
        let index_ids: BTreeSet<String> =
            index.iter().map(|c| c.name[2..].to_lowercase()).collect();
        let content_ids: BTreeSet<String> =
            content.iter().map(|c| c.name[2..].to_lowercase()).collect();

        let mut observations = Vec::new();
        let mut unreadable = 0usize;
        let mut deleted: Vec<Timestamp> = Vec::new();
        for item in index.iter().take(MAX_ITEMS) {
            let id = item.name[2..].to_lowercase();
            let partner = by_name.get(&format!("$r{id}")).copied();
            let parsed = host
                .read_file(&join(&bin, &item.name))
                .ok()
                .flatten()
                .and_then(|bytes| recycle::parse(&bytes).ok());
            let Some(r) = parsed else {
                unreadable += 1;
                continue;
            };
            deleted.extend(r.deleted_at);
            let found = catalog::match_name(&r.original_path).into_iter().next();
            let mut fields = Fields::new()
                .with(DISCRIMINATOR, "item")
                .with("drive", drive.clone())
                .with("index_file", item.name.clone())
                .with("path", r.original_path.clone())
                .with("name", location::last_segment(&r.original_path).to_owned())
                .with(
                    location::FIELD,
                    location::classify(&r.original_path).as_str(),
                )
                .with("size", r.size)
                .time("deleted_at", r.deleted_at)
                .time("index_created", item.created)
                .time("index_modified", item.modified)
                .with("content_present", partner.is_some());
            if let Some(p) = partner {
                fields = fields
                    .with("content_is_folder", !p.is_file)
                    .maybe("content_size", p.size)
                    .time("content_created", p.created)
                    .time("content_modified", p.modified);
            }
            if let Some(m) = found {
                fields = fields
                    .with("tool_id", m.tool.id)
                    .with("tool_kind", m.tool.kind.as_str())
                    .with("match_kind", m.kind.as_str());
            }
            observations.push(fields.observe(ID));
        }
        let last = last_artifact_change(folder.and_then(|f| f.modified), &children);
        let bin_fields = Fields::new()
            .with(DISCRIMINATOR, "bin")
            .with("drive", drive)
            .time("folder_created", folder.and_then(|f| f.created))
            .time("folder_modified", folder.and_then(|f| f.modified))
            .with("index_entries", index.len())
            .with("content_entries", content.len())
            .with("orphan_index", index_ids.difference(&content_ids).count())
            .with("orphan_content", content_ids.difference(&index_ids).count())
            .with("unreadable_index", unreadable)
            .with("read_capped", index.len() > MAX_ITEMS)
            .time("newest_deleted_at", deleted.iter().max().copied())
            .time("oldest_deleted_at", deleted.iter().min().copied())
            .time("last_artifact_change", last.map(|l| l.0))
            .maybe("last_artifact_change_source", last.map(|l| l.1));
        observations.insert(0, bin_fields.observe(ID));
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_core::model::Observation;
    use bope_host::FixtureHost;

    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn host(entries: &str, folder: &str) -> FixtureHost {
        let solara = crate::common::hex(&recycle::build(
            r"C:\Users\a\Downloads\Solara.exe",
            4096,
            133_700_000_000_000_000,
        ));
        let doc = crate::common::hex(&recycle::build(
            r"C:\Users\a\Documents\notes.txt",
            12,
            133_600_000_000_000_000,
        ));
        let yaml = format!(
            "platform: windows\nelevated: false\naccount_sid: '{SID}'\nenv:\n  SystemDrive: 'C:'\nfilesystem:\n  'C:\\$Recycle.Bin':\n    - {{ name: '{SID}', directory: true{folder} }}\n  'C:\\$Recycle.Bin\\{SID}':\n    - {{ name: '$IAB12CD.exe', hex: '{solara}', created: '2024-09-01T10:00:00Z', modified: '2024-09-01T10:00:00Z' }}\n    - {{ name: '$RAB12CD.exe', size: 4096, created: '2024-08-30T09:00:00Z', modified: '2024-08-31T09:00:00Z' }}\n    - {{ name: '$IZZ99.txt', hex: '{doc}', created: '2024-06-01T00:00:00Z', modified: '2024-06-01T00:00:00Z' }}\n    - {{ name: '$IBAD.txt', hex: '00' }}\n    - {{ name: '$RLONE.dat', size: 1 }}\n    - {{ name: desktop.ini, size: 129 }}\n{entries}"
        );
        FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    fn run(host: &FixtureHost) -> Vec<Observation> {
        match RecycleBin.collect(host) {
            CollectorRun::Measured { observations, .. } => observations,
            other @ CollectorRun::Unmeasured { .. } => panic!("{other:?}"),
        }
    }

    #[test]
    fn each_item_keeps_its_own_times_and_the_bin_its_summary() {
        let observations = run(&host(
            "",
            ", created: '2023-01-01T00:00:00Z', modified: '2024-10-10T12:00:00Z'",
        ));
        let bin = &observations[0];
        assert_eq!(bin.fields["scope"], "bin");
        assert_eq!(bin.fields["index_entries"], 3);
        assert_eq!(bin.fields["content_entries"], 2);
        assert_eq!(bin.fields["orphan_index"], 2, "$IZZ99 and $IBAD have no $R");
        assert_eq!(bin.fields["orphan_content"], 1, "$RLONE has no $I");
        assert_eq!(bin.fields["unreadable_index"], 1);
        assert_eq!(bin.fields["folder_modified"], "2024-10-10T12:00:00Z");
        assert_eq!(bin.fields["last_artifact_change"], "2024-10-10T12:00:00Z");
        assert_eq!(bin.fields["last_artifact_change_source"], "folder");
        assert!(
            !serde_json::to_string(bin).unwrap().contains(SID),
            "the SID is never kept"
        );
        let solara = observations
            .iter()
            .find(|o| o.fields.get("tool_id").is_some_and(|t| t == "solara"))
            .unwrap();
        assert_eq!(solara.fields["content_present"], true);
        assert_eq!(solara.fields["content_modified"], "2024-08-31T09:00:00Z");
        assert_eq!(solara.fields["index_created"], "2024-09-01T10:00:00Z");
        assert!(solara.fields.contains_key("deleted_at"));
        let notes = observations
            .iter()
            .find(|o| o.fields.get("name").is_some_and(|n| n == "notes.txt"))
            .unwrap();
        assert_eq!(notes.fields["content_present"], false);
        assert!(!notes.fields.contains_key("content_modified"));
        assert!(!notes.fields.contains_key("tool_id"));
    }

    #[test]
    fn without_a_folder_time_the_newest_entry_is_the_last_change_observed() {
        let observations = run(&host("", ""));
        let bin = &observations[0];
        assert!(!bin.fields.contains_key("folder_modified"));
        assert_eq!(bin.fields["last_artifact_change"], "2024-09-01T10:00:00Z");
        assert_eq!(bin.fields["last_artifact_change_source"], "entry");
    }

    #[test]
    fn an_empty_bin_has_no_deletion_time() {
        let yaml = format!(
            "platform: windows\naccount_sid: '{SID}'\nenv:\n  SystemDrive: 'C:'\nfilesystem:\n  'C:\\$Recycle.Bin':\n    - {{ name: '{SID}', directory: true, modified: '2024-10-10T12:00:00Z' }}\n  'C:\\$Recycle.Bin\\{SID}': []\n"
        );
        let observations = run(&FixtureHost::from_yaml_str(&yaml, "inline").unwrap());
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].fields["index_entries"], 0);
        assert!(!observations[0].fields.contains_key("newest_deleted_at"));
        assert_eq!(
            observations[0].fields["last_artifact_change"],
            "2024-10-10T12:00:00Z"
        );
    }

    #[test]
    fn a_missing_or_refused_bin_is_unmeasured() {
        let missing = FixtureHost::from_yaml_str(
            &format!("platform: windows\naccount_sid: '{SID}'\nenv:\n  SystemDrive: 'C:'\n"),
            "inline",
        )
        .unwrap();
        assert_eq!(
            RecycleBin.collect(&missing),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
        let refused = FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nelevated: false\naccount_sid: '{SID}'\nenv:\n  SystemDrive: 'C:'\naccess_denied: ['C:\\$Recycle.Bin\\{SID}']\n"
            ),
            "inline",
        )
        .unwrap();
        assert_eq!(
            RecycleBin.collect(&refused),
            unmeasured(ID, UnmeasuredReason::NotAdmin)
        );
        let no_sid =
            FixtureHost::from_yaml_str("platform: windows\nenv:\n  SystemDrive: 'C:'\n", "inline")
                .unwrap();
        assert!(matches!(
            RecycleBin.collect(&no_sid),
            CollectorRun::Unmeasured { .. }
        ));
    }

    #[test]
    fn last_change_prefers_the_newer_of_folder_and_entries() {
        let at = |s: &str| s.parse::<Timestamp>().unwrap();
        let mut entry = DirEntryInfo::named("$Ix", true);
        entry.modified = Some(at("2024-01-02T00:00:00Z"));
        assert_eq!(
            last_artifact_change(Some(at("2024-01-01T00:00:00Z")), &[entry.clone()]),
            Some((at("2024-01-02T00:00:00Z"), "entry"))
        );
        assert_eq!(
            last_artifact_change(Some(at("2024-01-03T00:00:00Z")), &[entry]),
            Some((at("2024-01-03T00:00:00Z"), "folder"))
        );
        assert_eq!(last_artifact_change(None, &[]), None);
    }
}
