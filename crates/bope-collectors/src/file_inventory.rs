// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The executable images on every local drive, found by walking the folders and assessed for
//! integrity — **full scan only** (B.O.P.E, ADR 0133).
//!
//! # The walk
//!
//! Every fixed, removable and RAM drive `GetLogicalDrives` names is walked from its root, folder by
//! folder; network shares and optical drives are listed and not walked, each with that reason. Places
//! that matter most are walked first — the Roblox and launcher folders, each profile's `AppData`,
//! `Downloads`, `Desktop`, `Documents` and `Temp`, `ProgramData`, both `Program Files`, `System32`,
//! `SysWOW64` and the drivers folder — so a walk the budget stops has covered them. `WinSxS`, which
//! holds tens of thousands of component copies, is walked last.
//!
//! A junction, symbolic link or mount point is never followed (`DirEntryInfo::is_link`): it can lead
//! back up the tree or onto another drive. A folder is walked once whatever path reached it. A folder
//! that cannot be listed is counted, and the first [`MAX_INACCESSIBLE_ROWS`] are reported by path.
//!
//! # What is assessed
//!
//! Every file whose extension is one executable images carry (`.exe`, `.dll`, `.sys`, `.ocx`, `.scr`,
//! `.cpl`, `.drv`, `.efi`) — and, outside the Windows and `Program Files` folders, every file of another
//! extension whose first bytes are a PE image: a program disguised by its name. Each goes through
//! [`crate::integrity::Assessor`]: hash, PE structure, embedded signature, catalog, timestamp, and the
//! class those give. Nothing is executed or loaded.
//!
//! # What is reported
//!
//! One `summary` with every count — listed, assessed, skipped, inaccessible, not reached — and the
//! number of files in each integrity class; one row per drive; one row per file whose class is
//! `malicious_corroborated`, `integrity_compromised`, `suspicious` or `inconclusive`, and per `unknown`
//! or `not_verified` file in a folder the user can write to or outside the system folders of a drive,
//! at most [`MAX_FILE_ROWS`]; the rest of each
//! class is counted. Files Windows or a valid signature vouches for are counted, not listed.
//!
//! **A walk is not the whole disk unless the summary says so.** `complete: false` — the budget, the
//! cancellation or a limit stopped it — makes every rule about the file rows `budget_spent` rather than
//! `not_found`, so nothing reads as "looked everywhere and found nothing" about files never looked at.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, ScanTier, UnmeasuredReason};
use bope_host::{DriveKind, Host, Platform, SourceError};

use crate::common::{Fields, env_folder, join, unmeasured};
use crate::integrity::{Assessor, IntegrityClass, extension};
use crate::location::{self, LocationKind};
use crate::{CollectContext, Collector, Field};

/// Collector id.
pub const ID: &str = "file_inventory";
const DISCRIMINATOR: &str = "scope";

/// How long the walk and the assessments may run before they stop and say so.
pub const BUDGET: Duration = Duration::from_secs(25 * 60);
/// Most files listed.
pub const MAX_FILES_LISTED: u64 = 10_000_000;
/// Most images assessed.
pub const MAX_ASSESSED: u64 = 250_000;
/// Most files of another extension whose first bytes are read to find a disguised image.
pub const MAX_SNIFFED: u64 = 200_000;
/// Most file rows reported; the rest are counted by class.
pub const MAX_FILE_ROWS: usize = 5_000;
/// Most inaccessible folders reported by path.
pub const MAX_INACCESSIBLE_ROWS: usize = 200;
/// Deepest folder walked below a root.
pub const MAX_DEPTH: usize = 64;
/// Largest file whose first bytes are read for a disguised image.
const MAX_SNIFF_SIZE: u64 = 512 * 1024 * 1024;

/// Extensions whose files are assessed as images.
const ASSESSED: [&str; 8] = ["exe", "dll", "sys", "ocx", "scr", "cpl", "drv", "efi"];
/// Extensions of image files that are counted and not assessed: resource-only satellites.
const COUNTED_IMAGES: [&str; 4] = ["mui", "ax", "tlb", "acm"];
/// Script extensions, counted.
const SCRIPTS: [&str; 9] = [
    "ps1", "psm1", "bat", "cmd", "vbs", "js", "jse", "lua", "ahk",
];
/// Archive extensions, counted.
const ARCHIVES: [&str; 5] = ["zip", "rar", "7z", "cab", "iso"];

static FIELDS: [Field; 69] = [
    Field::number("archives"),
    Field::text("catalog"),
    Field::text("catalog_file"),
    Field::text("catalog_signer"),
    Field::text("catalog_signer_cert_sha256"),
    Field::boolean("checksum_matches"),
    Field::number("class_inconclusive"),
    Field::number("class_integrity_compromised"),
    Field::number("class_malicious_corroborated"),
    Field::number("class_not_verified"),
    Field::number("class_suspicious"),
    Field::number("class_unknown"),
    Field::number("class_valid_signature"),
    Field::number("class_verified_reference"),
    Field::boolean("clr"),
    Field::text("company"),
    Field::boolean("complete"),
    Field::timestamp("created"),
    Field::number("depth_limited"),
    Field::number("directories_inaccessible"),
    Field::number("directories_listed"),
    Field::number("disguised_images"),
    Field::text("drive_kind"),
    Field::number("elapsed_seconds"),
    Field::number("exports"),
    Field::text("extension"),
    Field::text("file_description"),
    Field::text("file_version"),
    Field::number("files_listed"),
    Field::text("filesystem"),
    Field::number("images_assessed"),
    Field::number("images_counted_only"),
    Field::number("images_found"),
    Field::number("images_not_assessed"),
    Field::number("imported_dlls"),
    Field::text("injection_imports"),
    Field::text("integrity_class"),
    Field::text("integrity_reasons"),
    Field::boolean("is_dll"),
    Field::text("limitations"),
    Field::number("links_skipped"),
    Field::text("location_kind"),
    Field::text("machine"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::text("original_filename"),
    Field::number("overlay_bytes"),
    Field::boolean("partial_structure"),
    Field::text("path"),
    Field::text("pe_anomalies"),
    Field::number("pe_timestamp"),
    Field::text("product"),
    Field::text("reason"),
    Field::number("rows_withheld"),
    Field::text("scope"),
    Field::number("scripts"),
    Field::text("section_permissions"),
    Field::number("sections"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::timestamp("signed_at"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::number("size"),
    Field::text("stopped_by"),
    Field::number("subsystem"),
    Field::number("tls_callbacks"),
    Field::text("volume"),
    Field::boolean("walked"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotConsented,
    UnmeasuredReason::BudgetSpent,
    UnmeasuredReason::ReadFailed,
];

/// The `file_inventory` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileInventory;

/// Why a walk stopped before its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Budget,
    Cancelled,
    FileLimit,
}

impl Stop {
    fn as_str(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::Cancelled => "cancelled",
            Self::FileLimit => "file_limit",
        }
    }
}

#[derive(Default)]
struct Counts {
    files_listed: u64,
    directories_listed: u64,
    directories_inaccessible: u64,
    links_skipped: u64,
    depth_limited: u64,
    images_found: u64,
    images_counted_only: u64,
    images_assessed: u64,
    images_not_assessed: u64,
    sniffed: u64,
    disguised_images: u64,
    scripts: u64,
    archives: u64,
    classes: BTreeMap<IntegrityClass, u64>,
    withheld: u64,
}

struct Walk<'h, 'c> {
    host: &'h dyn Host,
    context: &'c CollectContext<'c>,
    assessor: Assessor<'h>,
    deadline: Instant,
    started: Instant,
    counts: Counts,
    visited: BTreeSet<String>,
    rows: Vec<Observation>,
    inaccessible: Vec<Observation>,
    stop: Option<Stop>,
    per_volume: BTreeMap<char, u64>,
}

/// Whether a path is under one of the folders whose files are not sniffed for disguised images.
fn trusted_tree(kind: LocationKind) -> bool {
    matches!(kind, LocationKind::Windows | LocationKind::ProgramFiles)
}

impl Walk<'_, '_> {
    fn check_stop(&mut self) -> bool {
        if self.stop.is_some() {
            return true;
        }
        if self.context.cancelled() {
            self.stop = Some(Stop::Cancelled);
        } else if Instant::now() >= self.deadline {
            self.stop = Some(Stop::Budget);
        } else if self.counts.files_listed >= MAX_FILES_LISTED {
            self.stop = Some(Stop::FileLimit);
        }
        self.stop.is_some()
    }

    fn walk(&mut self, root: &str, deferred: &mut Vec<String>) {
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        queue.push_back((root.trim_end_matches('\\').to_owned(), 0));
        while let Some((dir, depth)) = queue.pop_front() {
            if self.check_stop() {
                return;
            }
            let key = dir.to_ascii_lowercase();
            if !self.visited.insert(key.clone()) {
                continue;
            }
            if depth > 0 && key.ends_with(r"\windows\winsxs") && !deferred.contains(&dir) {
                self.visited.remove(&key);
                deferred.push(dir);
                continue;
            }
            let listed = match self.host.list_dir(&format!("{dir}\\")) {
                Ok(Some(entries)) => entries,
                Ok(None) => continue,
                Err(error) => {
                    self.counts.directories_inaccessible += 1;
                    if self.inaccessible.len() < MAX_INACCESSIBLE_ROWS {
                        self.inaccessible.push(
                            Fields::new()
                                .with(DISCRIMINATOR, "inaccessible")
                                .with("path", dir.clone())
                                .with(
                                    "reason",
                                    match error {
                                        SourceError::AccessDenied => "access_denied",
                                        _ => "read_failed",
                                    },
                                )
                                .observe(ID),
                        );
                    }
                    continue;
                }
            };
            self.counts.directories_listed += 1;
            if self.counts.directories_listed.is_multiple_of(500) {
                self.context.note(&format!(
                    "{dir} — {} files, {} images assessed",
                    self.counts.files_listed, self.counts.images_assessed
                ));
            }
            for entry in listed {
                if entry.is_link {
                    self.counts.links_skipped += 1;
                    continue;
                }
                let path = join(&dir, &entry.name);
                if !entry.is_file {
                    if depth + 1 > MAX_DEPTH {
                        self.counts.depth_limited += 1;
                    } else {
                        queue.push_back((path, depth + 1));
                    }
                    continue;
                }
                self.counts.files_listed += 1;
                if let Some(letter) = path.chars().next() {
                    *self
                        .per_volume
                        .entry(letter.to_ascii_uppercase())
                        .or_default() += 1;
                }
                self.file(
                    &path,
                    &entry.name,
                    entry.size,
                    entry.created,
                    entry.modified,
                );
                if self.check_stop() {
                    return;
                }
            }
        }
    }

    fn file(
        &mut self,
        path: &str,
        name: &str,
        size: Option<u64>,
        created: Option<jiff::Timestamp>,
        modified: Option<jiff::Timestamp>,
    ) {
        let ext = extension(name);
        if SCRIPTS.contains(&ext.as_str()) {
            self.counts.scripts += 1;
        }
        if ARCHIVES.contains(&ext.as_str()) {
            self.counts.archives += 1;
        }
        if COUNTED_IMAGES.contains(&ext.as_str()) {
            self.counts.images_counted_only += 1;
            return;
        }
        let assessed_by_name = ASSESSED.contains(&ext.as_str());
        let place = location::classify(path);
        let disguised = !assessed_by_name
            && !trusted_tree(place)
            && size.is_some_and(|s| (64..=MAX_SNIFF_SIZE).contains(&s))
            && self.counts.sniffed < MAX_SNIFFED
            && {
                self.counts.sniffed += 1;
                crate::integrity::sniff(self.host, path).unwrap_or(false)
            };
        if !assessed_by_name && !disguised {
            return;
        }
        if disguised {
            self.counts.disguised_images += 1;
        }
        self.counts.images_found += 1;
        if self.counts.images_assessed >= MAX_ASSESSED {
            self.counts.images_not_assessed += 1;
            return;
        }
        self.counts.images_assessed += 1;
        let assessment = self.assessor.assess(path);
        *self.counts.classes.entry(assessment.class).or_default() += 1;
        let reported = match assessment.class {
            IntegrityClass::MaliciousCorroborated
            | IntegrityClass::IntegrityCompromised
            | IntegrityClass::Suspicious
            | IntegrityClass::Inconclusive => true,
            // A folder on a drive other than Windows' is writable by every account under the ACL
            // Windows gives a new drive's root, so its unsigned images are listed too.
            IntegrityClass::Unknown | IntegrityClass::NotVerified => {
                place.is_user_writable() || place == LocationKind::OtherDrivePath
            }
            IntegrityClass::ValidSignature | IntegrityClass::VerifiedReference => false,
        };
        if !reported {
            return;
        }
        if self.rows.len() >= MAX_FILE_ROWS {
            self.counts.withheld += 1;
            return;
        }
        self.rows.push(
            assessment
                .fields
                .with(DISCRIMINATOR, "file")
                .with("path", path.to_owned())
                .maybe("size", size)
                .time("created", created)
                .time("modified", modified)
                .observe(ID),
        );
    }
}

/// The folders walked first, as they exist on this host.
fn priority_roots(host: &dyn Host) -> Vec<String> {
    let mut roots = Vec::new();
    let windows = env_folder(host, "SystemRoot").unwrap_or_else(|| r"C:\Windows".to_owned());
    let system_drive = env_folder(host, "SystemDrive")
        .or_else(|| windows.get(..2).map(str::to_owned))
        .unwrap_or_else(|| "C:".to_owned());
    if let Some(local) = env_folder(host, "LOCALAPPDATA") {
        for name in [
            "Roblox",
            "Bloxstrap",
            "Fishstrap",
            "Voidstrap",
            "Froststrap",
            "Temp",
        ] {
            roots.push(join(&local, name));
        }
    }
    let users = join(&system_drive, "Users");
    for profile in host.list_dir(&users).ok().flatten().unwrap_or_default() {
        if profile.is_file || profile.is_link {
            continue;
        }
        let base = join(&users, &profile.name);
        for sub in ["Downloads", "Desktop", "Documents", "AppData"] {
            roots.push(join(&base, sub));
        }
        roots.push(base);
    }
    for variable in ["ProgramData", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(folder) = env_folder(host, variable) {
            roots.push(folder);
        }
    }
    for sub in [r"System32\drivers", "System32", "SysWOW64", "Temp"] {
        roots.push(join(&windows, sub));
    }
    roots.push(windows);
    roots
}

impl Collector for FileInventory {
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

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        self.collect_with(host, &CollectContext::none())
    }

    #[allow(clippy::too_many_lines)]
    fn collect_with(&self, host: &dyn Host, context: &CollectContext<'_>) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let started = Instant::now();
        let mut volume_rows = Vec::new();
        let mut walk_roots: Vec<String> = Vec::new();
        let mut later_roots: Vec<String> = Vec::new();
        match host.volumes() {
            Ok(volumes) => {
                for volume in volumes {
                    let walked = matches!(
                        volume.kind,
                        DriveKind::Fixed | DriveKind::Removable | DriveKind::RamDisk
                    );
                    let mut row = Fields::new()
                        .with(DISCRIMINATOR, "volume")
                        .with("volume", volume.root.clone())
                        .with("drive_kind", volume.kind.as_str())
                        .maybe("filesystem", volume.filesystem.clone())
                        .with("walked", walked);
                    if !walked {
                        row = row.with(
                            "reason",
                            match volume.kind {
                                DriveKind::Network => "network_share_not_walked",
                                DriveKind::CdRom => "optical_drive_not_walked",
                                _ => "unknown_drive_not_walked",
                            },
                        );
                    }
                    volume_rows.push((volume.root.clone(), row));
                    if walked {
                        if volume.kind == DriveKind::Fixed {
                            walk_roots.push(volume.root);
                        } else {
                            later_roots.push(volume.root);
                        }
                    }
                }
            }
            Err(_) => {
                // Without the drive list the system drive is still walked, and the summary says the
                // other drives were not enumerated.
                let drive = env_folder(host, "SystemDrive").unwrap_or_else(|| "C:".to_owned());
                walk_roots.push(format!("{drive}\\"));
                volume_rows.push((
                    format!("{drive}\\"),
                    Fields::new()
                        .with(DISCRIMINATOR, "volume")
                        .with("volume", format!("{drive}\\"))
                        .with("walked", true)
                        .with("reason", "drive_list_unreadable_system_drive_only"),
                ));
            }
        }
        let mut walk = Walk {
            host,
            context,
            assessor: Assessor::new(host),
            deadline: started + BUDGET,
            started,
            counts: Counts::default(),
            visited: BTreeSet::new(),
            rows: Vec::new(),
            inaccessible: Vec::new(),
            stop: None,
            per_volume: BTreeMap::new(),
        };
        context.note("walking the priority folders");
        let mut deferred = Vec::new();
        for root in priority_roots(host) {
            walk.walk(&root, &mut deferred);
        }
        for root in walk_roots.iter().chain(&later_roots) {
            context.note(&format!("walking {root}"));
            walk.walk(root, &mut deferred);
        }
        while let Some(dir) = deferred.pop() {
            context.note(&format!("walking {dir}"));
            walk.walk(&dir, &mut Vec::new());
        }

        // A walk that could list no folder at all looked at nothing, whatever stopped it.
        let nothing_listed = walk.counts.directories_listed == 0;
        let complete = walk.stop.is_none() && !nothing_listed;
        let stopped_by = walk
            .stop
            .map(Stop::as_str)
            .or(nothing_listed.then_some("nothing_listed"));
        let counts = &walk.counts;
        let mut summary = Fields::new()
            .with(DISCRIMINATOR, "summary")
            .with("complete", complete)
            .maybe("stopped_by", stopped_by)
            .with("files_listed", counts.files_listed)
            .with("directories_listed", counts.directories_listed)
            .with("directories_inaccessible", counts.directories_inaccessible)
            .with("links_skipped", counts.links_skipped)
            .with("depth_limited", counts.depth_limited)
            .with("images_found", counts.images_found)
            .with("images_counted_only", counts.images_counted_only)
            .with("images_assessed", counts.images_assessed)
            .with("images_not_assessed", counts.images_not_assessed)
            .with("disguised_images", counts.disguised_images)
            .with("scripts", counts.scripts)
            .with("archives", counts.archives)
            .with("rows_withheld", counts.withheld)
            .with("elapsed_seconds", walk.started.elapsed().as_secs());
        for class in IntegrityClass::ALL {
            summary = summary.with(
                &format!("class_{}", class.as_str()),
                counts.classes.get(&class).copied().unwrap_or(0),
            );
        }
        let mut observations = vec![summary.observe(ID)];
        for (root, row) in volume_rows {
            let letter = root.chars().next().map(|c| c.to_ascii_uppercase());
            let files = letter.and_then(|l| walk.per_volume.get(&l)).copied();
            observations.push(row.maybe("files_listed", files).observe(ID));
        }
        observations.append(&mut walk.inaccessible);
        observations.append(&mut walk.rows);

        let mut discriminator_gaps = Vec::new();
        if !complete {
            let reason = if walk.stop.is_none() {
                UnmeasuredReason::ReadFailed
            } else {
                UnmeasuredReason::BudgetSpent
            };
            discriminator_gaps.push(DiscriminatorGaps {
                discriminator: DISCRIMINATOR.to_owned(),
                value: serde_json::Value::from("file"),
                gaps: ["integrity_class", "integrity_reasons", "path", "sha256"]
                    .iter()
                    .map(|f| ((*f).to_owned(), reason))
                    .collect(),
            });
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;
    use crate::roblox_process::of_scope;

    fn measured(run: &CollectorRun) -> (&[Observation], &[DiscriminatorGaps]) {
        match run {
            CollectorRun::Measured {
                observations,
                discriminator_gaps,
                ..
            } => (observations, discriminator_gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn fixture() -> FixtureHost {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts/file-inventory");
        FixtureHost::load(&dir).unwrap()
    }

    #[test]
    fn the_walk_covers_every_drive_follows_no_link_and_reports_what_needs_reading() {
        let run = FileInventory.collect(&fixture());
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let summary = of_scope(observations, "summary")[0];
        assert_eq!(summary.fields["complete"], true);
        assert_eq!(summary.fields["links_skipped"], 1);
        assert_eq!(summary.fields["directories_inaccessible"], 1);
        assert_eq!(summary.fields["disguised_images"], 1);
        let files = of_scope(observations, "file");
        let class_of = |name: &str| {
            files.iter().find(|o| o.fields["name"] == name).map(|o| {
                o.fields["integrity_class"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
        };
        assert_eq!(class_of("version.dll").as_deref(), Some("suspicious"));
        assert_eq!(class_of("cover.jpg").as_deref(), Some("suspicious"));
        assert_eq!(
            class_of("patched.dll").as_deref(),
            Some("integrity_compromised")
        );
        assert_eq!(class_of("mod.dll").as_deref(), Some("unknown"));
        // Windows' own catalog-listed file and a validly signed game file are counted, not listed.
        assert_eq!(class_of("kernel32.dll"), None);
        assert_eq!(class_of("game.dll"), None);
        assert_eq!(summary.fields["class_verified_reference"], 2);
        assert_eq!(summary.fields["class_valid_signature"], 1);
        // The link target was never walked, and the network drive was listed, not walked.
        assert!(files.iter().all(|o| {
            !o.fields["path"]
                .as_str()
                .unwrap_or_default()
                .contains("Looped")
        }));
        let volumes = of_scope(observations, "volume");
        assert!(volumes.iter().any(
            |o| o.fields["walked"] == false && o.fields["reason"] == "network_share_not_walked"
        ));
        assert!(
            volumes
                .iter()
                .any(|o| o.fields["volume"] == "D:\\" && o.fields["walked"] == true)
        );
        assert!(
            files
                .iter()
                .any(|o| o.fields["path"] == r"D:\Games\Mods\mod.dll")
        );
    }

    #[test]
    fn a_stopped_walk_is_incomplete_and_makes_the_file_rows_unmeasured() {
        let cancel = std::sync::atomic::AtomicBool::new(true);
        let note = |_: &str| {};
        let run = FileInventory.collect_with(&fixture(), &CollectContext::new(&cancel, &note));
        let (observations, gaps) = measured(&run);
        let summary = of_scope(observations, "summary")[0];
        assert_eq!(summary.fields["complete"], false);
        assert_eq!(summary.fields["stopped_by"], "cancelled");
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            gaps[0].gaps["integrity_class"],
            UnmeasuredReason::BudgetSpent
        );
    }

    #[test]
    fn it_is_full_only_and_not_windows_is_unmeasured() {
        assert_eq!(FileInventory.tier(), ScanTier::Full);
        let host = FixtureHost::from_yaml_str("platform: other\n", "inline").unwrap();
        assert!(matches!(
            FileInventory.collect(&host),
            CollectorRun::Unmeasured {
                reason: UnmeasuredReason::NotWindows,
                ..
            }
        ));
    }
}
