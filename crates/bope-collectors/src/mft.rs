// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of
// scope — see AGENTS.md.

//! The system volume's Master File Table, read for **metadata** of entries whose names match the
//! Roblox tool catalog (B.O.P.E, ADR 0125). **Full scan only.**
//!
//! The volume is opened read-only through its device path (`\\.\C:`), which needs administrator
//! rights; nothing is locked, dismounted or written. The boot sector says where `$MFT` starts, record
//! 0 says where the rest of it lies, and every file record is then read in 1 MiB pieces up to
//! [`MAX_RECORDS`] records or [`BUDGET`]. Each record's names pass through memory once; only those that
//! match the catalog as a distinctive or ambiguous alias are kept, with the folder path rebuilt from
//! the parent records.
//!
//! Kept per entry (`scope: entry`): the record number and sequence, whether the record is **in use**,
//! whether it is a folder, the name, the path, the `$STANDARD_INFORMATION` and `$FILE_NAME` times and
//! the data size. `in_use: false` is a record NTFS marked free: the metadata of a deleted entry that
//! NTFS can reuse at any time. **Its content is not recovered and not read**. `si_created_before_fn`
//! says that the creation time programs can set is earlier than the one only NTFS sets — ordinary for
//! files copied or extracted with their original times, and also what a changed timestamp leaves.
//!
//! A summary (`scope: volume`) counts the records read, in use and not, and records whose update
//! sequence did not match (torn or damaged).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, ScanTier, UnmeasuredReason};
use bope_host::{Host, Platform, SourceError};
use bope_parsers::ntfs::{self, FileRecord};

use crate::catalog::{self, MatchKind};
use crate::common::{Fields, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "mft";
const DISCRIMINATOR: &str = "scope";
/// Most file records read.
pub const MAX_RECORDS: u64 = 6_000_000;
/// Most entries kept.
pub const MAX_ENTRIES: usize = 2_000;
/// Time the read may take.
pub const BUDGET: Duration = Duration::from_secs(90);
/// Bytes read at a time.
const CHUNK: u64 = 1024 * 1024;

static FIELDS: [Field; 30] = [
    Field::boolean("common_legitimate"),
    Field::boolean("directory"),
    Field::timestamp("fn_created").off_timeline(),
    Field::timestamp("fn_modified").off_timeline(),
    Field::boolean("in_use"),
    Field::text("location_kind"),
    Field::text("match_kind"),
    Field::number("matches"),
    Field::text("name"),
    Field::boolean("partial"),
    Field::text("path"),
    Field::boolean("path_complete"),
    Field::number("record"),
    Field::number("record_size"),
    Field::number("records_in_use"),
    Field::number("records_not_in_use"),
    Field::number("records_read"),
    Field::boolean("roblox_context"),
    Field::text("scope"),
    Field::number("sequence"),
    Field::timestamp("si_changed").off_timeline(),
    Field::timestamp("si_created"),
    Field::boolean("si_created_before_fn"),
    Field::timestamp("si_modified"),
    Field::number("size"),
    Field::text("stopped_by"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
    Field::number("torn_records"),
    Field::text("volume"),
];

static REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `mft` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mft;

/// A folder's record, for rebuilding paths.
struct Folder {
    name: String,
    parent: u64,
    parent_sequence: u16,
    sequence: u16,
}

/// The path of `record` from the folders read, and whether every parent was found with the sequence
/// number the child recorded.
fn path_of(volume: char, record: &FileRecord, folders: &BTreeMap<u64, Folder>) -> (String, bool) {
    let Some(name) = record.best_name() else {
        return (String::new(), false);
    };
    let mut segments = vec![name.name.clone()];
    let mut parent = name.parent;
    let mut expected = name.parent_sequence;
    let mut complete = true;
    for _ in 0..64 {
        if parent == ntfs::ROOT_RECORD {
            break;
        }
        match folders.get(&parent) {
            Some(f) if f.sequence == expected || expected == 0 => {
                segments.push(f.name.clone());
                parent = f.parent;
                expected = f.parent_sequence;
            }
            _ => {
                complete = false;
                segments.push("?".to_owned());
                break;
            }
        }
    }
    segments.reverse();
    let mut path = if complete {
        format!("{volume}:")
    } else {
        String::new()
    };
    for s in segments {
        if !path.is_empty() || complete {
            path.push('\\');
        }
        path.push_str(&s);
    }
    (path, complete)
}

impl Collector for Mft {
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

    fn tier(&self) -> ScanTier {
        ScanTier::Full
    }

    #[allow(clippy::too_many_lines)]
    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let Some(volume) = host
            .env_var("SystemDrive")
            .and_then(|d| d.chars().next())
            .filter(char::is_ascii_alphabetic)
            .map(|c| c.to_ascii_uppercase())
        else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };
        let fail = |error: &SourceError| -> CollectorRun {
            unmeasured(
                ID,
                match error {
                    SourceError::Unsupported(_) => UnmeasuredReason::SourceAbsent,
                    SourceError::AccessDenied if host.is_elevated() != Some(true) => {
                        UnmeasuredReason::NotAdmin
                    }
                    SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
                    _ => UnmeasuredReason::ReadFailed,
                },
            )
        };
        let boot = match host.read_volume_at(volume, 0, 512) {
            Ok(bytes) => match ntfs::boot(&bytes) {
                Ok(boot) => boot,
                // Not NTFS: there is no file table to read.
                Err(_) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            },
            Err(e) => return fail(&e),
        };
        let record_size = u64::from(boot.record_size);
        let Some(mft_start) = boot.mft_cluster.checked_mul(boot.cluster_size) else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };
        let first = match host.read_volume_at(
            volume,
            mft_start,
            usize::try_from(record_size).unwrap_or(1024),
        ) {
            Ok(b) => b,
            Err(e) => return fail(&e),
        };
        let mut first = first;
        if !ntfs::apply_fixups(&mut first, boot.sector_size) {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        }
        let Some(mft) = ntfs::record(&first, 0).filter(|r| !r.runs.is_empty()) else {
            return unmeasured(ID, UnmeasuredReason::ReadFailed);
        };

        let deadline = Instant::now() + BUDGET;
        let mut folders: BTreeMap<u64, Folder> = BTreeMap::new();
        let mut matches: Vec<(FileRecord, catalog::Match)> = Vec::new();
        let (mut read, mut in_use, mut free, mut torn) = (0_u64, 0_u64, 0_u64, 0_u64);
        let mut stopped_by: Option<&str> = None;
        let mut number = 0_u64;
        let mut more_matches = 0_u64;
        'runs: for (cluster, clusters) in &mft.runs {
            let start = cluster.saturating_mul(boot.cluster_size);
            let length = clusters.saturating_mul(boot.cluster_size);
            let mut at = 0;
            while at < length {
                if read >= MAX_RECORDS {
                    stopped_by = Some("records");
                    break 'runs;
                }
                if Instant::now() >= deadline {
                    stopped_by = Some("time");
                    break 'runs;
                }
                let want = CHUNK.min(length - at);
                let Ok(bytes) =
                    host.read_volume_at(volume, start + at, usize::try_from(want).unwrap_or(0))
                else {
                    stopped_by = Some("read_error");
                    break 'runs;
                };
                for slot in bytes.chunks(usize::try_from(record_size).unwrap_or(1024)) {
                    let this = number;
                    number += 1;
                    if u64::try_from(slot.len()).unwrap_or(0) < record_size {
                        continue;
                    }
                    read += 1;
                    if slot.get(0..4) != Some(b"FILE".as_slice()) {
                        continue;
                    }
                    let mut owned = slot.to_vec();
                    if !ntfs::apply_fixups(&mut owned, boot.sector_size) {
                        torn += 1;
                        continue;
                    }
                    let Some(rec) = ntfs::record(&owned, this) else {
                        continue;
                    };
                    if rec.in_use {
                        in_use += 1;
                    } else {
                        free += 1;
                    }
                    if rec.base_record != 0 {
                        continue;
                    }
                    let Some(name) = rec.best_name().cloned() else {
                        continue;
                    };
                    if rec.directory {
                        // A live folder wins over a freed one with the same number.
                        let keep = folders.get(&this).is_none_or(|_| rec.in_use);
                        if keep {
                            folders.insert(
                                this,
                                Folder {
                                    name: name.name.clone(),
                                    parent: name.parent,
                                    parent_sequence: name.parent_sequence,
                                    sequence: rec.sequence,
                                },
                            );
                        }
                    }
                    let found = catalog::match_name(&name.name)
                        .into_iter()
                        .next()
                        .filter(|m| m.kind >= MatchKind::AmbiguousAlias);
                    if let Some(m) = found {
                        if matches.len() < MAX_ENTRIES {
                            matches.push((rec, m));
                        } else {
                            more_matches += 1;
                        }
                    }
                }
                at += want;
            }
        }

        let mut observations = Vec::new();
        for (rec, m) in &matches {
            let Some(name) = rec.best_name() else {
                continue;
            };
            let (path, complete) = path_of(volume, rec, &folders);
            let before = match (rec.si_created, name.created) {
                (Some(si), Some(fname)) => Some(si.as_second() + 1 < fname.as_second()),
                _ => None,
            };
            observations.push(
                Fields::new()
                    .with(DISCRIMINATOR, "entry")
                    .with("record", rec.number)
                    .with("sequence", rec.sequence)
                    .with("in_use", rec.in_use)
                    .with("directory", rec.directory)
                    .with("name", name.name.clone())
                    .with("path", path.clone())
                    .with("path_complete", complete)
                    .with(location::FIELD, location::classify(&path).as_str())
                    .with("roblox_context", catalog::path_mentions_roblox(&path))
                    .maybe("size", rec.size)
                    .time("si_created", rec.si_created)
                    .time("si_modified", rec.si_modified)
                    .time("si_changed", rec.si_changed)
                    .time("fn_created", name.created)
                    .time("fn_modified", name.modified)
                    .maybe("si_created_before_fn", before)
                    .with("tool_id", m.tool.id)
                    .with("tool_kind", m.tool.kind.as_str())
                    .with("match_kind", m.kind.as_str())
                    .with("common_legitimate", m.tool.common_legitimate)
                    .observe(ID),
            );
        }
        let partial = stopped_by.is_some() || more_matches > 0;
        let mut gaps = BTreeMap::new();
        if stopped_by.is_some() {
            let reason = if stopped_by == Some("read_error") {
                UnmeasuredReason::Partial
            } else {
                UnmeasuredReason::BudgetSpent
            };
            gaps.insert("name".to_owned(), reason);
            gaps.insert("tool_id".to_owned(), reason);
        }
        observations.insert(
            0,
            Fields::new()
                .with(DISCRIMINATOR, "volume")
                .with("volume", format!("{volume}:"))
                .with("record_size", record_size)
                .with("records_read", read)
                .with("records_in_use", in_use)
                .with("records_not_in_use", free)
                .with("torn_records", torn)
                .with(
                    "matches",
                    u64::try_from(matches.len()).unwrap_or(0) + more_matches,
                )
                .with("partial", partial)
                .maybe("stopped_by", stopped_by)
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
    use bope_parsers::ntfs::BuildRecord;

    use super::*;

    const T2025: u64 = 133_800_000_000_000_000;
    const T2026: u64 = 134_100_000_000_000_000;

    fn volume() -> String {
        let r = |number, name: &str, parent, in_use, directory, si, fname| BuildRecord {
            number,
            name: name.to_owned(),
            parent,
            in_use,
            directory,
            si_created: si,
            fn_created: fname,
        };
        crate::common::hex(&ntfs::build_volume(&[
            r(16, "Users", 5, true, true, T2025, T2025),
            r(17, "a", 16, true, true, T2025, T2025),
            r(18, "Downloads", 17, true, true, T2025, T2025),
            r(19, "Solara.exe", 18, false, false, T2025, T2026),
            r(20, "Bloxstrap", 17, true, true, T2026, T2026),
            r(21, "notes.txt", 18, true, false, T2026, T2026),
        ]))
    }

    fn run(elevated: bool, volume_block: &str) -> CollectorRun {
        let yaml = format!(
            "platform: windows\nelevated: {elevated}\nenv:\n  SystemDrive: 'C:'\n{volume_block}"
        );
        Mft.collect(&FixtureHost::from_yaml_str(&yaml, "inline").unwrap())
    }

    fn observations(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => panic!("{run:?}"),
        }
    }

    #[test]
    fn a_freed_record_of_a_catalog_name_is_listed_with_its_path_and_times() {
        let run = run(true, &format!("volumes:\n  C: {{ hex: '{}' }}\n", volume()));
        let all = observations(&run);
        assert_eq!(all[0].fields["scope"], "volume");
        assert_eq!(all[0].fields["records_not_in_use"], 1);
        assert_eq!(all[0].fields["matches"], 2);
        let solara = all
            .iter()
            .find(|o| o.fields.get("name").is_some_and(|n| n == "Solara.exe"))
            .unwrap();
        assert_eq!(solara.fields["in_use"], false);
        assert_eq!(solara.fields["path"], r"C:\Users\a\Downloads\Solara.exe");
        assert_eq!(solara.fields["path_complete"], true);
        assert_eq!(solara.fields["location_kind"], "user_downloads");
        assert_eq!(solara.fields["si_created_before_fn"], true);
        assert_eq!(solara.fields["tool_id"], "solara");
        let blox = all
            .iter()
            .find(|o| o.fields.get("name").is_some_and(|n| n == "Bloxstrap"))
            .unwrap();
        assert_eq!(blox.fields["directory"], true);
        assert_eq!(blox.fields["in_use"], true);
        assert!(
            all.iter()
                .all(|o| o.fields.get("name").is_none_or(|n| n != "notes.txt"))
        );
    }

    #[test]
    fn without_rights_or_a_volume_it_does_not_measure() {
        assert_eq!(
            run(false, "volumes:\n  C: { access_denied: true }\n"),
            unmeasured(ID, UnmeasuredReason::NotAdmin)
        );
        assert_eq!(
            run(true, "volumes:\n  C: { access_denied: true }\n"),
            unmeasured(ID, UnmeasuredReason::AccessDenied)
        );
        assert_eq!(
            run(true, ""),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
        assert_eq!(
            run(true, "volumes:\n  C: { hex: '00112233' }\n"),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
        assert_eq!(
            Mft.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
    }
}
