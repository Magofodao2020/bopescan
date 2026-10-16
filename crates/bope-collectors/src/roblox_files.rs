// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Files, folders, archive entries and Recycle Bin items whose **names** match the Roblox tool catalog
//! (B.O.P.E, ADR 0118).
//!
//! Walks a bounded set of places — `%LOCALAPPDATA%` and `%APPDATA%` (two levels), the profile's
//! `Downloads`, `Desktop` and `Documents` (two levels), `%TEMP%` (two levels), `%ProgramData%` and the
//! two `Program Files` folders (one level) — and keeps **only** the entries whose name matches
//! [`crate::catalog`]. Nothing else from those listings leaves this module, so a standard scan does not
//! list a person's documents: it answers "is there anything named like a Roblox tool here".
//!
//! For a matched program (`.exe`/`.dll`) it adds the SHA-256 and the embedded signature. A `.zip` in
//! one of those places whose name matches, or that sits in Downloads, Desktop or Temp, is opened as
//! far as its central directory (names only, nothing extracted; [`bope_parsers::zip_names`]) and its
//! matching entries are kept, with whether it holds an executor's `autoexec` + `workspace` layout.
//! `.rar` (RAR 4 and 5) and `.7z` archives are listed the same way from their headers
//! ([`bope_parsers::archive_names`], ADR 0128): RAR file headers are read one at a time with the packed
//! data between them skipped unread, and a 7z end header is decompressed only up to its declared size.
//! An archive whose headers are encrypted is reported as such (`encrypted_headers`), with no names.
//!
//! The account's own Recycle Bin (`C:\$Recycle.Bin\<SID>`) is read too: each `$I` file says where a
//! deleted item was and when it was deleted (`scope: recycled`). That is the one place here that shows
//! a deletion as such; a name missing from a folder is never reported as deleted.
//!
//! **Limits.** Budgets of time ([`BUDGET`]), listings, hashes and archive bytes. Folders that hold
//! other software's data (`Microsoft`, `Packages`, browsers' profiles, `node_modules`) are not entered.
//! A match is a name: a program can be renamed to anything, and an ordinary file can carry a name that
//! matches. Self-extracting archives and split archives past their first part are not listed.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{DirEntryInfo, Host, Platform};
use bope_parsers::{archive_names, recycle, zip_names};

use crate::catalog::{self, Match, MatchKind};
use crate::common::{Fields, env_folder, hash_and_signature, join, unmeasured, user_profile};
use crate::{Collector, Field, location};

const ID: &str = "roblox_files";
const DISCRIMINATOR: &str = "scope";

/// How long the walk runs before it stops and says so.
pub const BUDGET: Duration = Duration::from_secs(25);
/// Most folders listed.
pub const MAX_LISTINGS: usize = 8_000;
/// Most files hashed.
pub const MAX_HASHES: usize = 80;
/// Largest archive opened, and most archives opened.
pub const MAX_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024;
/// Most archives opened in one scan.
pub const MAX_ARCHIVES: usize = 25;
/// Largest `.rar` or `.7z` listed: only its headers are read, so this is far above the zip limit.
pub const MAX_INDEXED_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Most reads made to list one `.rar` or `.7z`.
pub const MAX_ARCHIVE_READS: usize = 25_000;

/// Folders never entered: other software's data, large and irrelevant.
const SKIP: [&str; 12] = [
    "microsoft",
    "packages",
    "google",
    "mozilla",
    "node_modules",
    ".git",
    "nvidia corporation",
    "nvidia",
    "amd",
    "windowsapps",
    "steamapps",
    "crashdumps",
];

static FIELDS: [Field; 26] = [
    Field::text("alias"),
    Field::text("archive"),
    Field::text("archive_format"),
    Field::boolean("common_legitimate"),
    Field::timestamp("created"),
    Field::timestamp("deleted_at"),
    Field::boolean("encrypted"),
    Field::boolean("encrypted_headers"),
    Field::boolean("executor_layout"),
    Field::text("extension"),
    Field::boolean("in_bin"),
    Field::text("location_kind"),
    Field::text("match_kind"),
    Field::timestamp("modified"),
    Field::text("name"),
    Field::text("path"),
    Field::text("place"),
    Field::boolean("roblox_context"),
    Field::boolean("roblox_specific"),
    Field::text("scope"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::number("size"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `roblox_files` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct RobloxFiles;

struct Walk<'a> {
    host: &'a dyn Host,
    deadline: Instant,
    listings: usize,
    hashes: usize,
    archives: usize,
    observations: Vec<Observation>,
    seen: BTreeSet<String>,
    stopped: bool,
    refused: bool,
}

/// The fields every match carries.
fn matched(fields: Fields, m: &Match, path: &str) -> Fields {
    fields
        .with("tool_id", m.tool.id)
        .with("tool_kind", m.tool.kind.as_str())
        .with("match_kind", m.kind.as_str())
        .with("alias", m.alias)
        .with("common_legitimate", m.tool.common_legitimate)
        .with("roblox_specific", m.tool.roblox_specific)
        .with("roblox_context", catalog::path_mentions_roblox(path))
}

impl Walk<'_> {
    fn out_of_budget(&mut self) -> bool {
        if self.listings >= MAX_LISTINGS || Instant::now() >= self.deadline {
            self.stopped = true;
        }
        self.stopped
    }

    fn list(&mut self, dir: &str) -> Option<Vec<DirEntryInfo>> {
        if self.out_of_budget() {
            return None;
        }
        self.listings += 1;
        match self.host.list_dir(dir) {
            Ok(entries) => entries,
            Err(bope_host::SourceError::AccessDenied) => None,
            Err(_) => {
                self.refused = true;
                None
            }
        }
    }

    /// `owned`: `dir` is inside Roblox's own folder or a legitimate launcher's, where generic terms and
    /// partial names (`ClientSettings`, `…strap…`) are that program's own files and are not rows.
    fn visit(&mut self, place: &'static str, dir: &str, depth: u8, owned: bool) {
        let Some(children) = self.list(dir) else {
            return;
        };
        for child in &children {
            if crate::paths::is_unusable_segment(&child.name) {
                continue;
            }
            let path = join(dir, &child.name);
            let found = catalog::match_name(&child.name);
            let best = found
                .first()
                .copied()
                .filter(|m| !owned || m.kind >= MatchKind::AmbiguousAlias);
            if let Some(m) = best
                && self.seen.insert(path.to_lowercase())
            {
                self.entry(place, &path, child, &m);
            }
            if child.is_file {
                let is_archive = matches!(
                    location::extension(&child.name).as_deref(),
                    Some("zip" | "rar" | "7z")
                );
                let loose = matches!(place, "downloads" | "desktop" | "temp");
                if is_archive && (best.is_some() || loose) {
                    self.archive(place, &path, child);
                }
                continue;
            }
            if SKIP.contains(&child.name.to_lowercase().as_str()) {
                continue;
            }
            // A folder named like a tool is looked into one level further than its place allows.
            let strong = best.is_some_and(|m| m.kind >= MatchKind::AmbiguousAlias);
            let next = if strong { depth.max(1) } else { depth };
            let owns = owned
                || child.name.eq_ignore_ascii_case("Roblox")
                || best.is_some_and(|m| m.tool.common_legitimate);
            if next > 0 {
                self.visit(place, &path, next - 1, owns);
            }
        }
    }

    fn entry(&mut self, place: &'static str, path: &str, entry: &DirEntryInfo, m: &Match) {
        let extension = if entry.is_file {
            location::extension(&entry.name)
        } else {
            None
        };
        let mut fields = matched(
            Fields::new()
                .with(
                    DISCRIMINATOR,
                    if entry.is_file { "file" } else { "directory" },
                )
                .with("place", place)
                .with(location::FIELD, location::classify(path).as_str())
                .with("name", entry.name.clone())
                .with("path", path.to_owned())
                .maybe("extension", extension.clone())
                .maybe("size", entry.size)
                .time("created", entry.created)
                .time("modified", entry.modified),
            m,
            path,
        );
        let program = matches!(extension.as_deref(), Some("exe" | "dll"));
        if program && m.kind != MatchKind::WeakPartial {
            if self.hashes < MAX_HASHES && Instant::now() < self.deadline {
                self.hashes += 1;
                let (with, _) = hash_and_signature(self.host, path, fields);
                fields = with;
                fields.0.remove("signer_cert_sha256");
            } else {
                self.stopped = true;
            }
        }
        self.observations.push(fields.observe(ID));
    }

    /// The names in a `.rar` or `.7z`, read from its headers through the host at offsets.
    fn indexed_archive(&mut self, path: &str) -> Option<archive_names::Listing> {
        let size = self.host.file_size(path).ok().flatten()?;
        let deadline = self.deadline;
        let mut reads = 0;
        let host = self.host;
        archive_names::list(
            |offset, len| {
                reads += 1;
                if reads > MAX_ARCHIVE_READS || Instant::now() >= deadline {
                    return None;
                }
                host.read_file_at(path, offset, len.min(bope_host::MAX_READ_AT_BYTES))
                    .ok()
                    .flatten()
            },
            size,
        )
        .ok()
    }

    #[allow(clippy::too_many_lines)]
    fn archive(&mut self, place: &'static str, path: &str, entry: &DirEntryInfo) {
        let extension = location::extension(path);
        let indexed = matches!(extension.as_deref(), Some("rar" | "7z"));
        let limit = if indexed {
            MAX_INDEXED_ARCHIVE_BYTES
        } else {
            MAX_ARCHIVE_BYTES
        };
        if self.archives >= MAX_ARCHIVES || entry.size.is_some_and(|s| s > limit) {
            return;
        }
        if self.out_of_budget() {
            return;
        }
        self.archives += 1;
        // (name, size, encrypted)
        let (format, entries, encrypted_headers): (&str, Vec<(String, u64, bool)>, bool) =
            if indexed {
                let Some(listing) = self.indexed_archive(path) else {
                    return;
                };
                (
                    listing.format.as_str(),
                    listing
                        .entries
                        .iter()
                        .map(|e| {
                            let name = if e.directory {
                                format!("{}/", e.name.trim_end_matches('/'))
                            } else {
                                e.name.clone()
                            };
                            (name, e.size, e.encrypted)
                        })
                        .collect(),
                    listing.encrypted_headers,
                )
            } else {
                let Ok(Some(bytes)) = self.host.read_file(path) else {
                    return;
                };
                let Ok(listing) = zip_names::list(&bytes) else {
                    return;
                };
                (
                    "zip",
                    listing
                        .entries
                        .iter()
                        .map(|e| (e.name.clone(), u64::from(e.size), false))
                        .collect(),
                    false,
                )
            };
        let lower: Vec<String> = entries
            .iter()
            .map(|e| e.0.to_lowercase().replace('\\', "/"))
            .collect();
        let has_dir = |d: &str| {
            lower
                .iter()
                .any(|n| n.starts_with(&format!("{d}/")) || n.contains(&format!("/{d}/")))
        };
        let layout = has_dir("autoexec") && has_dir("workspace");
        if layout || encrypted_headers {
            self.observations.push(
                Fields::new()
                    .with(DISCRIMINATOR, "archive")
                    .with("place", place)
                    .with(location::FIELD, location::classify(path).as_str())
                    .with("name", location::last_segment(path).to_owned())
                    .with("path", path.to_owned())
                    .with("archive_format", format)
                    .with("executor_layout", layout)
                    .with("encrypted_headers", encrypted_headers)
                    .maybe("size", entry.size)
                    .time("modified", entry.modified)
                    .observe(ID),
            );
        }
        let mut kept = 0;
        for (inner, size, encrypted) in &entries {
            let name = inner.trim_end_matches('/');
            let Some(m) = catalog::match_name(name).into_iter().next() else {
                continue;
            };
            if m.kind == MatchKind::WeakPartial || kept >= 50 {
                continue;
            }
            kept += 1;
            let shown = name.rsplit('/').next().unwrap_or(name).to_owned();
            self.observations.push(
                matched(
                    Fields::new()
                        .with(DISCRIMINATOR, "archive_entry")
                        .with("place", place)
                        .with(location::FIELD, location::classify(path).as_str())
                        .with("archive", path.to_owned())
                        .with("archive_format", format)
                        .with("name", shown)
                        .with("path", format!(r"{path}\{}", name.replace('/', "\\")))
                        .with("size", *size)
                        .with("encrypted", *encrypted)
                        .with("executor_layout", layout),
                    &m,
                    path,
                )
                .observe(ID),
            );
        }
    }

    /// The account's own Recycle Bin.
    fn recycle_bin(&mut self) {
        let drive_of = |v: String| -> Option<String> {
            let d: String = v.chars().take(2).collect();
            (d.len() == 2 && d.ends_with(':')).then_some(d)
        };
        let Some(drive) = self
            .host
            .env_var("SystemDrive")
            .and_then(drive_of)
            .or_else(|| self.host.env_var("SystemRoot").and_then(drive_of))
        else {
            return;
        };
        let Ok(sid) = self.host.account_sid() else {
            return;
        };
        let bin = format!(r"{drive}\$Recycle.Bin\{sid}");
        let Some(children) = self.list(&bin) else {
            return;
        };
        let names: BTreeSet<String> = children.iter().map(|c| c.name.to_lowercase()).collect();
        for item in children.iter().filter(|c| c.is_file) {
            let Some(id) = item.name.strip_prefix("$I") else {
                continue;
            };
            if self.out_of_budget() {
                return;
            }
            let path = join(&bin, &item.name);
            let Ok(Some(bytes)) = self.host.read_file(&path) else {
                continue;
            };
            let Ok(r) = recycle::parse(&bytes) else {
                continue;
            };
            let Some(m) = catalog::match_name(&r.original_path).into_iter().next() else {
                continue;
            };
            let in_bin = names.contains(&format!("$r{}", id.to_lowercase()));
            self.observations.push(
                matched(
                    Fields::new()
                        .with(DISCRIMINATOR, "recycled")
                        .with("place", "recycle_bin")
                        .with(
                            location::FIELD,
                            location::classify(&r.original_path).as_str(),
                        )
                        .with("name", location::last_segment(&r.original_path).to_owned())
                        .with("path", r.original_path.clone())
                        .with("size", r.size)
                        .with("in_bin", in_bin)
                        .time("deleted_at", r.deleted_at),
                    &m,
                    &r.original_path,
                )
                .observe(ID),
            );
        }
    }
}

/// The places walked, each with how many levels below it are looked at.
fn roots(host: &dyn Host) -> Vec<(&'static str, String, u8)> {
    let mut roots = Vec::new();
    if let Some(profile) = user_profile(host) {
        roots.push(("downloads", join(&profile, "Downloads"), 2));
        roots.push(("desktop", join(&profile, "Desktop"), 2));
        roots.push(("desktop", join(&profile, r"OneDrive\Desktop"), 2));
        roots.push(("documents", join(&profile, "Documents"), 2));
    }
    if let Some(temp) = env_folder(host, "TEMP")
        .or_else(|| env_folder(host, "LOCALAPPDATA").map(|l| join(&l, "Temp")))
    {
        roots.push(("temp", temp, 2));
    }
    if let Some(local) = env_folder(host, "LOCALAPPDATA") {
        roots.push(("local_appdata", local, 2));
    }
    if let Some(roaming) = env_folder(host, "APPDATA") {
        roots.push(("roaming_appdata", roaming, 2));
    }
    if let Some(data) = env_folder(host, "ProgramData") {
        roots.push(("program_data", data, 1));
    }
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(pf) = env_folder(host, var) {
            roots.push(("program_files", pf, 1));
        }
    }
    roots
}

impl Collector for RobloxFiles {
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
            hashes: 0,
            archives: 0,
            observations: Vec::new(),
            seen: BTreeSet::new(),
            stopped: false,
            refused: false,
        };
        // Temp lives under LOCALAPPDATA: walked as `temp` first, and not again inside it.
        for (place, root, depth) in &roots {
            walk.visit(place, root, *depth, false);
        }
        walk.recycle_bin();
        let reason = if walk.stopped {
            Some(UnmeasuredReason::BudgetSpent)
        } else if walk.refused {
            Some(UnmeasuredReason::ReadFailed)
        } else {
            None
        };
        let discriminator_gaps = reason
            .map(|reason| {
                ["file", "directory", "archive_entry"]
                    .into_iter()
                    .map(|scope| DiscriminatorGaps {
                        discriminator: DISCRIMINATOR.to_owned(),
                        value: serde_json::Value::from(scope),
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
    use bope_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn host() -> FixtureHost {
        let zip = crate::common::hex(&zip_names::build(&[
            "Solara/autoexec/",
            "Solara/workspace/",
            "Solara/Solara.exe",
            "readme.txt",
        ]));
        let recycled = crate::common::hex(&recycle::build(
            r"C:\Users\a\Downloads\FFlagManager.exe",
            2048,
            134_353_296_000_000_000,
        ));
        let other = crate::common::hex(&recycle::build(r"C:\Users\a\Documents\taxes.pdf", 1, 1));
        let rar = crate::common::hex(&bope_parsers::archive_names::build_rar5(
            &[
                "Wave/",
                "Wave/Wave.exe",
                "Wave/autoexec/",
                "Wave/workspace/",
            ],
            false,
        ));
        let seven = crate::common::hex(&bope_parsers::archive_names::build_7z(
            &["tools/", "tools/KRNL.exe", "tools/notes.txt"],
            true,
        ));
        let locked = crate::common::hex(&bope_parsers::archive_names::build_rar5(&[], true));
        let yaml = format!(
            r"platform: windows
account_sid: 'S-1-5-21-1-2-3-1001'
env:
  USERPROFILE: 'C:\Users\a'
  LOCALAPPDATA: 'C:\Users\a\AppData\Local'
  APPDATA: 'C:\Users\a\AppData\Roaming'
  SystemDrive: 'C:'
filesystem:
  'C:\Users\a\Downloads':
    - name: Bloxstrap-v2.8.0.exe
      size: 1000
      sha256: '1111111111111111111111111111111111111111111111111111111111111111'
      signature: {{ state: no_embedded_signature }}
      modified: '2026-10-14T20:00:00Z'
    - {{ name: holiday.jpg, size: 5 }}
    - {{ name: bootstrap.min.css, size: 5 }}
    - {{ name: MyStrapThing.exe, size: 5 }}
    - name: pack.zip
      size: 100
      hex: '{zip}'
    - {{ name: wave.rar, size: 100, hex: '{rar}' }}
    - {{ name: misc.7z, size: 100, hex: '{seven}' }}
    - {{ name: locked.rar, size: 100, hex: '{locked}' }}
  'C:\Users\a\AppData\Local':
    - {{ name: Bloxstrap, directory: true }}
    - {{ name: Microsoft, directory: true }}
  'C:\Users\a\AppData\Local\Bloxstrap':
    - {{ name: Bloxstrap.exe, size: 10 }}
    - {{ name: Modifications, directory: true }}
  'C:\Users\a\AppData\Local\Microsoft':
    - {{ name: Synapse X.exe, size: 1 }}
  'C:\$Recycle.Bin\S-1-5-21-1-2-3-1001':
    - {{ name: '$IABC123.exe', hex: '{recycled}' }}
    - {{ name: '$RABC123.exe', size: 2048 }}
    - {{ name: '$IDEF456.pdf', hex: '{other}' }}
"
        );
        FixtureHost::from_yaml_str(&yaml, "inline").unwrap()
    }

    fn observations() -> Vec<Observation> {
        match RobloxFiles.collect(&host()) {
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

    fn named<'a>(all: &'a [Observation], name: &str) -> Option<&'a Observation> {
        all.iter().find(|o| o.fields["name"] == name)
    }

    #[test]
    fn only_matching_names_leave_the_walk() {
        let all = observations();
        let blox = named(&all, "Bloxstrap-v2.8.0.exe").unwrap();
        assert_eq!(blox.fields["tool_id"], "bloxstrap");
        assert_eq!(blox.fields["match_kind"], "known_tool");
        assert_eq!(blox.fields["common_legitimate"], true);
        assert_eq!(blox.fields["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(blox.fields["place"], "downloads");
        assert!(named(&all, "holiday.jpg").is_none());
        assert!(named(&all, "bootstrap.min.css").is_none());
        let weak = named(&all, "MyStrapThing.exe").unwrap();
        assert_eq!(weak.fields["match_kind"], "weak_partial");
        assert!(!weak.fields.contains_key("sha256"));
        // The tool's own folder is entered further than its place's depth.
        assert!(named(&all, "Bloxstrap.exe").is_some());
        // Microsoft's folder is never entered.
        assert!(named(&all, "Synapse X.exe").is_none());
    }

    #[test]
    fn archives_list_names_and_the_executor_layout() {
        let all = observations();
        let layout = all.iter().find(|o| o.fields["scope"] == "archive").unwrap();
        assert_eq!(layout.fields["executor_layout"], true);
        let inner = all
            .iter()
            .find(|o| o.fields["scope"] == "archive_entry" && o.fields["name"] == "Solara.exe")
            .unwrap();
        assert_eq!(inner.fields["tool_id"], "solara");
        assert_eq!(inner.fields["executor_layout"], true);
    }

    #[test]
    fn rar_and_7z_indexes_are_listed_and_encrypted_headers_reported() {
        let all = observations();
        let wave = all
            .iter()
            .find(|o| o.fields["scope"] == "archive_entry" && o.fields["name"] == "Wave.exe")
            .unwrap();
        assert_eq!(wave.fields["archive_format"], "rar5");
        assert_eq!(wave.fields["executor_layout"], true);
        assert_eq!(
            wave.fields["path"],
            r"C:\Users\a\Downloads\wave.rar\Wave\Wave.exe"
        );
        let krnl = all
            .iter()
            .find(|o| o.fields["scope"] == "archive_entry" && o.fields["name"] == "KRNL.exe")
            .unwrap();
        assert_eq!(krnl.fields["archive_format"], "7z");
        assert_eq!(krnl.fields["tool_id"], "krnl");
        assert!(
            all.iter()
                .all(|o| o.fields.get("name").is_none_or(|n| n != "notes.txt"))
        );
        let locked = all
            .iter()
            .find(|o| o.fields["scope"] == "archive" && o.fields["name"] == "locked.rar")
            .unwrap();
        assert_eq!(locked.fields["encrypted_headers"], true);
    }

    #[test]
    fn the_recycle_bin_says_what_was_deleted_and_when() {
        let all = observations();
        let item = all
            .iter()
            .find(|o| o.fields["scope"] == "recycled")
            .unwrap();
        assert_eq!(item.fields["name"], "FFlagManager.exe");
        assert_eq!(item.fields["deleted_at"], "2026-10-01T12:00:00Z");
        assert_eq!(item.fields["in_bin"], true);
        assert_eq!(
            all.iter()
                .filter(|o| o.fields["scope"] == "recycled")
                .count(),
            1,
            "an unrelated deleted file is not listed"
        );
    }

    #[test]
    fn another_os_is_not_windows() {
        assert_eq!(
            RobloxFiles.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
    }
}
