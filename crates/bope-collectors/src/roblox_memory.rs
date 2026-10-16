// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The Roblox player's process from the inside: who it is, what it has loaded, which executable
//! memory nothing accounts for, which code differs from its file, and which strings and `FastFlag`
//! values its memory holds (B.O.P.E, ADR 0134).
//!
//! # Which process
//!
//! A process is a Roblox player when its image is `RobloxPlayerBeta.exe` (or the Microsoft Store
//! edition's `Windows10Universal.exe` under a `ROBLOXCORPORATION.` folder). The name alone is not
//! trusted: each player row says which identity checks held — the name, a path under a `Versions`
//! folder, an embedded signature that verifies, a signer named `Roblox Corporation` — and an
//! `identity_confidence` from them. Every other row names the player's `pid`, so two instances never
//! mix.
//!
//! # What is read, for each player the account may open
//!
//! - its modules, each assessed with [`crate::integrity::Assessor`] (`scope: module`);
//! - its committed regions: private executable memory, whether it begins with a PE header, and image
//!   mappings the loader does not list (`scope: region`);
//! - every module's executable sections compared with its file, laid out and relocated as the loader
//!   does, the address tables it fills skipped (`scope: code_change`), and the first bytes of every
//!   exported function checked for a jump the file does not have (`scope: hook`) — with where that jump
//!   goes and whose code is there;
//! - its readable private and mapped memory, up to [`MAX_SCAN_BYTES`], for strings in the categories of
//!   [`bope_parsers::memory::StringCategory`] (`scope: string`) — at most [`MAX_STRINGS_PER_CATEGORY`]
//!   per category, never an uncategorised one — `FastFlag` assignments written as JSON
//!   (`scope: flag_value`), compared with the reference when the scan has one, and the network and
//!   physics flag identifiers with how many pointers in the same memory point at them
//!   (`scope: identifier`).
//!
//! # What it does not do
//!
//! Nothing is written to the process, nothing is suspended, no thread is created, and no flag is
//! changed. The player's own anti-cheat (Hyperion) usually refuses the access: then the player row says
//! `access: refused` and every place of this collector is `access_denied` — the anti-cheat working, not
//! a fact about the person.
//!
//! # What a row does not prove
//!
//! A string in memory is not evidence anything used it. A flag identifier is not an active flag, and a
//! number near one is not its value: only an assignment written as JSON text is read as a value, and
//! even that may be a copy the client read and did not apply. A changed byte in code is what overlays,
//! anti-cheat and security software also leave; Roblox's own image is protected and changed at run
//! time by its anti-cheat, so differences there are expected and reported as context.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{Host, MemoryRegion, PointerWidth, ProcessMemory, ProcessRecord, RegionKind};
use bope_parsers::memory::{self, StringCategory};

use crate::common::{Fields, hash_and_signature, unmeasured};
use crate::flag_reference::{ReferenceSnapshot, comparison_fields};
use crate::integrity::{Assessor, IntegrityClass};
use crate::procmem::{
    ModuleMap, NotCompared, compare_module, executable_allocations, hex_address, read_chunks,
    unlisted_images,
};
use crate::roblox_process::roblox_edition;
use crate::{CollectContext, Collector, Field};

/// Collector id.
pub const ID: &str = "roblox_memory";
const DISCRIMINATOR: &str = "scope";

/// How long one scan of all players may take.
pub const BUDGET: Duration = Duration::from_secs(120);
/// Most bytes of one player's memory scanned for strings.
pub const MAX_SCAN_BYTES: u64 = 768 * 1024 * 1024;
/// Most strings kept per category per player.
pub const MAX_STRINGS_PER_CATEGORY: usize = 40;
/// Most flag assignments kept per player.
pub const MAX_FLAG_VALUES: usize = 400;
/// Most identifier rows per player.
pub const MAX_IDENTIFIERS: usize = 200;
/// Most regions walked.
const MAX_REGIONS: usize = 400_000;
/// Most bytes searched for pointers to identifiers.
const MAX_POINTER_BYTES: u64 = 128 * 1024 * 1024;
/// Most ranges named on a code row.
const MAX_RANGES_SHOWN: usize = 8;

/// Every place a player's internals are reported in; refused together when the process is.
const INTERNAL_PLACES: [&str; 7] = [
    "module",
    "region",
    "code_change",
    "hook",
    "string",
    "flag_value",
    "identifier",
];

static FIELDS: [Field; 92] = [
    Field::text("access"),
    Field::text("address"),
    Field::text("base"),
    Field::number("bytes_compared"),
    Field::number("bytes_differing"),
    Field::number("bytes_scanned"),
    Field::number("bytes_unreadable"),
    Field::text("catalog"),
    Field::text("catalog_file"),
    Field::text("catalog_signer"),
    Field::text("catalog_signer_cert_sha256"),
    Field::text("category"),
    Field::boolean("checksum_matches"),
    Field::boolean("clr"),
    Field::text("company"),
    Field::text("comparison"),
    Field::boolean("complete"),
    Field::text("edition"),
    Field::text("encoding"),
    Field::boolean("expected_runtime_change"),
    Field::number("exports"),
    Field::text("extension"),
    Field::text("file_description"),
    Field::text("file_version"),
    Field::text("finding"),
    Field::text("flag"),
    Field::text("flag_kind"),
    Field::number("flag_values"),
    Field::text("function"),
    Field::text("hook_kind"),
    Field::number("hooks"),
    Field::number("identifiers"),
    Field::text("identity_checks"),
    Field::text("identity_confidence"),
    Field::number("imported_dlls"),
    Field::text("injection_imports"),
    Field::text("integrity_class"),
    Field::text("integrity_reasons"),
    Field::boolean("is_dll"),
    Field::number("length"),
    Field::text("limitations"),
    Field::text("location_kind"),
    Field::text("machine"),
    Field::text("mapped_file"),
    Field::text("method"),
    Field::text("module"),
    Field::number("modules"),
    Field::number("modules_changed"),
    Field::number("modules_compared"),
    Field::text("name"),
    Field::text("not_compared"),
    Field::text("original_filename"),
    Field::number("overlay_bytes"),
    Field::text("owner_module"),
    Field::text("parent_name"),
    Field::boolean("partial_structure"),
    Field::text("path"),
    Field::text("pe_anomalies"),
    Field::number("pe_timestamp"),
    Field::text("permissions"),
    Field::number("pid"),
    Field::number("players_running"),
    Field::text("pointer_width"),
    Field::number("pointers"),
    Field::text("product"),
    Field::text("ranges"),
    Field::text("reference_key"),
    Field::text("reference_revision"),
    Field::text("reference_value"),
    Field::text("region_kind"),
    Field::text("scope"),
    Field::text("section_permissions"),
    Field::number("sections"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::timestamp("signed_at").off_timeline(),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::number("size"),
    Field::timestamp("started_at").off_timeline(),
    Field::text("stopped_by"),
    Field::number("strings"),
    Field::number("subsystem"),
    Field::text("target"),
    Field::text("target_class"),
    Field::text("target_module"),
    Field::text("text"),
    Field::number("tls_callbacks"),
    Field::boolean("under_player_folder"),
    Field::text("value"),
    Field::text("value_interpretation"),
    Field::text("value_source"),
];

static REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `roblox_memory` collector, with the reference its flag rows are compared with.
#[derive(Debug, Clone, Default)]
pub struct RobloxMemory {
    reference: Option<Arc<ReferenceSnapshot>>,
}

impl RobloxMemory {
    /// The collector, comparing with `reference` when there is one.
    pub fn new(reference: Option<Arc<ReferenceSnapshot>>) -> Self {
        Self { reference }
    }
}

/// What the identity checks of one player found, and the confidence they give.
pub fn identity(host: &dyn Host, process: &ProcessRecord) -> (Vec<&'static str>, &'static str) {
    let mut checks = vec!["name"];
    let path = process.path.as_deref().unwrap_or_default();
    let lower = path.to_ascii_lowercase();
    if lower.contains(r"\versions\version-") || lower.contains(r"\robloxcorporation.") {
        checks.push("path");
    }
    let mut signed_by_roblox = false;
    if !path.is_empty()
        && let Ok(bope_host::SignatureCheck::Valid { signer, .. }) = host.file_signature(path)
    {
        checks.push("signature_valid");
        if signer.to_ascii_lowercase().contains("roblox corporation") {
            checks.push("signer_roblox");
            signed_by_roblox = true;
        }
    }
    let confidence = if signed_by_roblox && checks.contains(&"path") {
        "high"
    } else if signed_by_roblox || checks.contains(&"path") {
        "medium"
    } else {
        "low"
    };
    (checks, confidence)
}

fn width_word(width: Option<PointerWidth>) -> Option<&'static str> {
    width.map(|w| match w {
        PointerWidth::Bits32 => "32",
        PointerWidth::Bits64 => "64",
    })
}

/// The flag identifiers whose name puts them among the network and physics flags.
fn is_network_flag(name: &str) -> bool {
    crate::fastflags::flag_kind(name) == "network"
}

struct Player<'a> {
    host: &'a dyn Host,
    process: &'a ProcessRecord,
    reader: &'a dyn ProcessMemory,
    assessor: &'a Assessor<'a>,
    reference: Option<&'a ReferenceSnapshot>,
    deadline: Instant,
    context: &'a CollectContext<'a>,
    rows: Vec<Observation>,
    stopped: Option<&'static str>,
}

impl Player<'_> {
    fn base(&self, scope: &str) -> Fields {
        Fields::new()
            .with(DISCRIMINATOR, scope)
            .with("pid", self.process.pid)
    }

    fn out_of_time(&mut self) -> bool {
        if self.stopped.is_none() {
            if self.context.cancelled() {
                self.stopped = Some("cancelled");
            } else if Instant::now() >= self.deadline {
                self.stopped = Some("budget");
            }
        }
        self.stopped.is_some()
    }

    #[allow(clippy::too_many_lines)]
    fn read(&mut self) -> Fields {
        let modules = self.reader.modules().unwrap_or_default();
        let map = ModuleMap::new(modules);
        let player_folder = self
            .process
            .path
            .as_deref()
            .and_then(|p| p.rfind('\\').map(|i| p[..i].to_owned()))
            .unwrap_or_default();
        let owner_name = |address: u64| {
            map.owner(address)
                .map(|m| crate::location::last_segment(&m.path).to_owned())
        };

        // Modules.
        let mut classes: BTreeMap<String, IntegrityClass> = BTreeMap::new();
        for module in map.modules() {
            if self.out_of_time() {
                break;
            }
            let assessment = self.assessor.assess(&module.path);
            classes.insert(module.path.to_ascii_lowercase(), assessment.class);
            let routine = matches!(
                assessment.class,
                IntegrityClass::VerifiedReference | IntegrityClass::ValidSignature
            ) && self.assessor.under_windows(&module.path);
            if routine {
                continue;
            }
            let under_player = !player_folder.is_empty()
                && module
                    .path
                    .to_ascii_lowercase()
                    .starts_with(&format!("{}\\", player_folder.to_ascii_lowercase()));
            self.rows.push(
                assessment
                    .fields
                    .with(DISCRIMINATOR, "module")
                    .with("pid", self.process.pid)
                    .with("path", module.path.clone())
                    .with("base", hex_address(module.base))
                    .with("size", module.size)
                    .with("under_player_folder", under_player)
                    .observe(ID),
            );
        }

        // Regions.
        let (regions, regions_complete) = self.reader.regions(MAX_REGIONS).unwrap_or_default();
        if !regions_complete {
            self.stopped.get_or_insert("region_limit");
        }
        for allocation in executable_allocations(self.reader, &regions, 4096) {
            let finding = if allocation.holds_image {
                "hand_mapped_image"
            } else {
                "private_executable"
            };
            self.rows.push(
                self.base("region")
                    .with("finding", finding)
                    .with("address", hex_address(allocation.region.base))
                    .with("size", allocation.region.size)
                    .with("permissions", allocation.region.permissions())
                    .with("region_kind", "private")
                    .observe(ID),
            );
        }
        for image in unlisted_images(&regions, &map) {
            self.rows.push(
                self.base("region")
                    .with("finding", "unlisted_image")
                    .with("address", hex_address(image.allocation_base))
                    .with("size", image.size)
                    .with("permissions", image.permissions())
                    .with("region_kind", "image")
                    .maybe("mapped_file", image.mapped_file.clone())
                    .observe(ID),
            );
        }
        for region in regions
            .iter()
            .filter(|r| r.kind == RegionKind::Image && r.is_executable() && r.is_writable())
        {
            self.rows.push(
                self.base("region")
                    .with("finding", "writable_executable_image")
                    .with("address", hex_address(region.base))
                    .with("size", region.size)
                    .with("permissions", region.permissions())
                    .with("region_kind", "image")
                    .maybe("owner_module", owner_name(region.base))
                    .observe(ID),
            );
        }

        // Code compared with the files.
        let player_image = self.process.path.as_deref().map(str::to_ascii_lowercase);
        let mut compared = 0_u64;
        let mut changed = 0_u64;
        let mut hooks = 0_u64;
        for module in map.modules() {
            if self.out_of_time() {
                break;
            }
            let is_player_image =
                player_image.as_deref() == Some(&*module.path.to_ascii_lowercase());
            match compare_module(self.host, self.reader, module) {
                Ok(comparison) => {
                    compared += 1;
                    if comparison.bytes_differing > 0 || comparison.bytes_unreadable > 0 {
                        changed += u64::from(comparison.bytes_differing > 0);
                        self.rows.push(
                            self.base("code_change")
                                .with("module", module.path.clone())
                                .with("base", hex_address(module.base))
                                .with("sections", comparison.sections)
                                .with("bytes_compared", comparison.bytes_compared)
                                .with("bytes_differing", comparison.bytes_differing)
                                .with("bytes_unreadable", comparison.bytes_unreadable)
                                .with("expected_runtime_change", is_player_image)
                                .with(
                                    "ranges",
                                    comparison
                                        .ranges
                                        .iter()
                                        .take(MAX_RANGES_SHOWN)
                                        .map(|(at, len)| format!("{}+{len}", hex_address(*at)))
                                        .collect::<Vec<_>>()
                                        .join(","),
                                )
                                .observe(ID),
                        );
                    }
                    for hook in comparison.hooks {
                        hooks += 1;
                        let target_owner = hook.target.and_then(|t| map.owner(t));
                        let target_region = hook.target.and_then(|t| {
                            regions
                                .iter()
                                .find(|r| t >= r.base && t < r.base.saturating_add(r.size))
                        });
                        let target_class = target_owner
                            .and_then(|m| classes.get(&m.path.to_ascii_lowercase()))
                            .map(|c| c.as_str());
                        let target_module = match (target_owner, target_region) {
                            (Some(owner), _) => {
                                crate::location::last_segment(&owner.path).to_owned()
                            }
                            (None, Some(region)) => format!("unbacked_{}", region.kind.as_str()),
                            (None, None) => "unknown".to_owned(),
                        };
                        self.rows.push(
                            self.base("hook")
                                .with("module", module.path.clone())
                                .with("function", hook.function)
                                .with("address", hex_address(hook.address))
                                .with("hook_kind", hook.kind.as_str())
                                .maybe("target", hook.target.map(hex_address))
                                .with("target_module", target_module)
                                .maybe("target_class", target_class)
                                .with("expected_runtime_change", is_player_image)
                                .observe(ID),
                        );
                    }
                }
                Err(reason) => {
                    if reason != NotCompared::FileUnreadable || !is_player_image {
                        self.rows.push(
                            self.base("code_change")
                                .with("module", module.path.clone())
                                .with("base", hex_address(module.base))
                                .with("not_compared", reason.as_str())
                                .with("expected_runtime_change", is_player_image)
                                .observe(ID),
                        );
                    }
                }
            }
        }

        // Strings, flag assignments and identifiers.
        let (scanned, unreadable, strings, flags, identifiers) = self.scan(&regions, &map);
        self.base("summary")
            .with("modules", map.modules().len())
            .with("bytes_scanned", scanned)
            .with("bytes_unreadable", unreadable)
            .with("modules_compared", compared)
            .with("modules_changed", changed)
            .with("hooks", hooks)
            .with("strings", strings)
            .with("flag_values", flags)
            .with("identifiers", identifiers)
    }

    /// Scans readable private and mapped memory. Returns bytes scanned, bytes unreadable, and how many
    /// strings, flag values and identifiers were kept.
    #[allow(clippy::too_many_lines)]
    fn scan(
        &mut self,
        regions: &[MemoryRegion],
        map: &ModuleMap,
    ) -> (u64, u64, usize, usize, usize) {
        let mut per_category: BTreeMap<StringCategory, usize> = BTreeMap::new();
        let mut seen_text: BTreeSet<(StringCategory, String)> = BTreeSet::new();
        let mut seen_flags: BTreeSet<(String, String)> = BTreeSet::new();
        let mut identifiers: BTreeMap<String, Vec<(u64, &'static str, String)>> = BTreeMap::new();
        let mut scanned = 0_u64;
        let mut unreadable = 0_u64;
        let mut strings = 0_usize;
        let mut flags = 0_usize;
        let candidates: Vec<&MemoryRegion> = regions
            .iter()
            .filter(|r| r.is_readable() && r.kind != RegionKind::Image)
            .collect();
        for region in candidates {
            if scanned >= MAX_SCAN_BYTES {
                self.stopped.get_or_insert("scan_limit");
                break;
            }
            if self.out_of_time() {
                break;
            }
            let region_kind = region.kind.as_str();
            let permissions = region.permissions();
            let size = region.size.min(MAX_SCAN_BYTES - scanned);
            let mut rows = Vec::new();
            let (read, missing) = read_chunks(self.reader, region.base, size, |at, bytes| {
                for found in memory::scan_strings(bytes, at, 6, 4096) {
                    if found.category == StringCategory::FlagAssignment {
                        continue;
                    }
                    if found.category == StringCategory::FlagIdentifier {
                        if is_network_flag(&found.text) {
                            identifiers.entry(found.text.clone()).or_default().push((
                                found.address,
                                found.encoding.as_str(),
                                region_kind.to_owned(),
                            ));
                        }
                        continue;
                    }
                    let count = per_category.entry(found.category).or_default();
                    if *count >= MAX_STRINGS_PER_CATEGORY
                        || !seen_text.insert((found.category, found.text.clone()))
                    {
                        continue;
                    }
                    *count += 1;
                    rows.push(
                        Fields::new()
                            .with(DISCRIMINATOR, "string")
                            .with("address", hex_address(found.address))
                            .with("region_kind", region_kind)
                            .with("permissions", permissions.clone())
                            .with("encoding", found.encoding.as_str())
                            .with("length", found.length)
                            .with("text", found.text)
                            .with("category", found.category.as_str())
                            .maybe(
                                "owner_module",
                                map.owner(found.address)
                                    .map(|m| crate::location::last_segment(&m.path).to_owned()),
                            )
                            .with("method", "categorised_string_scan"),
                    );
                }
                for assignment in memory::flag_assignments(bytes, at, MAX_FLAG_VALUES) {
                    if seen_flags.len() >= MAX_FLAG_VALUES
                        || !seen_flags.insert((assignment.name.clone(), assignment.value.clone()))
                    {
                        continue;
                    }
                    rows.push(
                        Fields::new()
                            .with(DISCRIMINATOR, "flag_value")
                            .with("address", hex_address(assignment.address))
                            .with("region_kind", region_kind)
                            .with("encoding", assignment.encoding.as_str())
                            .with("flag_kind", crate::fastflags::flag_kind(&assignment.name))
                            .with("flag", assignment.name)
                            .with("value", assignment.value)
                            .with("value_source", "json_text_in_memory")
                            .with("method", "json_assignment_scan"),
                    );
                }
            });
            scanned += read;
            unreadable += missing;
            for row in rows {
                let row = row.with("pid", self.process.pid);
                let row = match (row.0.get("flag").cloned(), row.0.get("value").cloned()) {
                    (Some(flag), Some(value))
                        if row.0.get(DISCRIMINATOR) == Some(&"flag_value".into()) =>
                    {
                        flags += 1;
                        comparison_fields(
                            row,
                            self.reference,
                            flag.as_str().unwrap_or_default(),
                            value.as_str().unwrap_or_default(),
                        )
                    }
                    _ => {
                        strings += 1;
                        row
                    }
                };
                self.rows.push(row.observe(ID));
            }
        }

        // Pointers to the identifiers, in the readable private memory already scanned.
        let mut targets: BTreeMap<u64, usize> = BTreeMap::new();
        for hits in identifiers.values() {
            for (address, _, _) in hits.iter().take(4) {
                targets.insert(*address, 0);
            }
        }
        let width = match self.reader.pointer_width() {
            Some(PointerWidth::Bits32) => 4,
            _ => 8,
        };
        let mut searched = 0_u64;
        if !targets.is_empty() {
            for region in regions
                .iter()
                .filter(|r| r.is_readable() && r.kind == RegionKind::Private)
            {
                if searched >= MAX_POINTER_BYTES || self.out_of_time() {
                    break;
                }
                let size = region.size.min(MAX_POINTER_BYTES - searched);
                let (read, _) = read_chunks(self.reader, region.base, size, |_, bytes| {
                    for (target, count) in &mut targets {
                        *count += memory::count_pointers(bytes, *target, width);
                    }
                });
                searched += read;
            }
        }
        let mut kept = 0_usize;
        for (name, hits) in identifiers {
            if kept >= MAX_IDENTIFIERS {
                break;
            }
            for (address, encoding, region_kind) in hits.into_iter().take(4) {
                kept += 1;
                let mut row = self
                    .base("identifier")
                    .with("flag", name.clone())
                    .with("address", hex_address(address))
                    .with("encoding", encoding)
                    .with("region_kind", region_kind)
                    .with("value_interpretation", "not_established")
                    .with("method", "identifier_scan");
                if let Some(count) = targets.get(&address) {
                    row = row.with("pointers", *count);
                }
                self.rows.push(row.observe(ID));
            }
        }
        (scanned, unreadable, strings, flags, kept)
    }
}

impl Collector for RobloxMemory {
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
        self.collect_with(host, &CollectContext::none())
    }

    #[allow(clippy::too_many_lines)]
    fn collect_with(&self, host: &dyn Host, context: &CollectContext<'_>) -> CollectorRun {
        if host.platform() != bope_host::Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let processes = match host.running_processes() {
            Ok(list) => list,
            Err(error) => return unmeasured(ID, crate::common::reason(host, &error)),
        };
        let by_pid: BTreeMap<u32, &ProcessRecord> = processes.iter().map(|p| (p.pid, p)).collect();
        let players: Vec<&ProcessRecord> = processes
            .iter()
            .filter(|p| roblox_edition(p).is_some())
            .collect();
        let deadline = Instant::now() + BUDGET;
        let assessor = Assessor::new(host);
        let mut observations = Vec::new();
        let mut refused: Vec<UnmeasuredReason> = Vec::new();
        let mut opened = 0_usize;
        let mut stopped = None;
        for process in &players {
            context.note(&format!("reading Roblox player {}", process.pid));
            let (checks, confidence) = identity(host, process);
            let parent = process
                .parent_pid
                .and_then(|p| by_pid.get(&p))
                .and_then(|parent| match (parent.started_at, process.started_at) {
                    (Some(a), Some(b)) if a > b => None,
                    _ => Some(parent.name.clone()),
                });
            let mut row = Fields::new()
                .with(DISCRIMINATOR, "player")
                .with("pid", process.pid)
                .with("name", process.name.clone())
                .maybe("edition", roblox_edition(process))
                .maybe("path", process.path.clone())
                .time("started_at", process.started_at)
                .maybe("parent_name", parent)
                .with("identity_checks", checks.join(","))
                .with("identity_confidence", confidence);
            if let Some(path) = process.path.as_deref() {
                row = hash_and_signature(host, path, row).0;
                if let Ok(Some(at)) = host.signing_time(path) {
                    row = row.time("signed_at", Some(at));
                }
                if let Ok(Some(bytes)) = host.read_file_at(path, 0, bope_host::MAX_READ_AT_BYTES)
                    && let Ok(image) = bope_parsers::pe::parse(&bytes)
                {
                    let version = image.version.clone().unwrap_or_default();
                    row = row
                        .with("machine", image.machine.as_str())
                        .maybe(
                            "file_version",
                            version.file_version.or(version.fixed_file_version),
                        )
                        .maybe("product", version.product_name)
                        .maybe("company", version.company_name);
                }
            }
            match host.open_process_memory(process.pid) {
                Ok(reader) => {
                    opened += 1;
                    let mut player = Player {
                        host,
                        process,
                        reader: reader.as_ref(),
                        assessor: &assessor,
                        reference: self.reference.as_deref(),
                        deadline,
                        context,
                        rows: Vec::new(),
                        stopped: None,
                    };
                    let summary = player.read();
                    let complete = player.stopped.is_none();
                    stopped = stopped.or(player.stopped);
                    observations.push(
                        row.with("access", "opened")
                            .maybe("pointer_width", width_word(reader.pointer_width()))
                            .observe(ID),
                    );
                    observations.push(
                        summary
                            .with("complete", complete)
                            .maybe("stopped_by", player.stopped)
                            .observe(ID),
                    );
                    observations.append(&mut player.rows);
                }
                Err(error) => {
                    let reason = crate::common::reason(host, &error);
                    refused.push(reason);
                    observations.push(
                        row.with(
                            "access",
                            if reason == UnmeasuredReason::ReadFailed {
                                "failed"
                            } else {
                                "refused"
                            },
                        )
                        .observe(ID),
                    );
                }
            }
        }
        observations.insert(
            0,
            Fields::new()
                .with(DISCRIMINATOR, "players")
                .with("players_running", players.len())
                .with("complete", stopped.is_none())
                .maybe("stopped_by", stopped)
                .observe(ID),
        );

        // A place no player could be read for is a gap, so no rule says "not found" about memory
        // nobody read: no player running, every player refused, or the budget stopped the reads.
        let place_reason = if players.is_empty() {
            Some(UnmeasuredReason::SourceAbsent)
        } else if opened == 0 {
            refused.first().copied()
        } else if stopped.is_some() {
            Some(UnmeasuredReason::BudgetSpent)
        } else {
            None
        };
        let discriminator_gaps = place_reason
            .map(|reason| {
                INTERNAL_PLACES
                    .iter()
                    .map(|place| DiscriminatorGaps {
                        discriminator: DISCRIMINATOR.to_owned(),
                        value: serde_json::Value::from(*place),
                        gaps: [
                            "integrity_class",
                            "finding",
                            "bytes_differing",
                            "hook_kind",
                            "category",
                            "flag",
                            "comparison",
                        ]
                        .iter()
                        .map(|f| ((*f).to_owned(), reason))
                        .collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

/// Observations of one scope.
pub fn of_scope<'a>(observations: &'a [Observation], scope: &str) -> Vec<&'a Observation> {
    observations
        .iter()
        .filter(|o| o.fields.get(DISCRIMINATOR).and_then(|v| v.as_str()) == Some(scope))
        .collect()
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    fn fixture() -> FixtureHost {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts/roblox-memory");
        FixtureHost::load(&dir).unwrap()
    }

    fn observations(run: &CollectorRun) -> (&[Observation], &[DiscriminatorGaps]) {
        match run {
            CollectorRun::Measured {
                observations,
                discriminator_gaps,
                ..
            } => (observations, discriminator_gaps),
            CollectorRun::Unmeasured { .. } => panic!("{run:?}"),
        }
    }

    #[test]
    fn the_player_is_identified_and_a_refused_instance_says_so() {
        let run = RobloxMemory::default().collect(&fixture());
        let (observations, gaps) = observations(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let players = of_scope(observations, "player");
        assert_eq!(players.len(), 2);
        let opened = players.iter().find(|o| o.fields["pid"] == 1200).unwrap();
        assert_eq!(opened.fields["access"], "opened");
        assert_eq!(opened.fields["identity_confidence"], "high");
        assert_eq!(
            opened.fields["identity_checks"],
            "name,path,signature_valid,signer_roblox"
        );
        assert_eq!(opened.fields["parent_name"], "explorer.exe");
        let refused = players.iter().find(|o| o.fields["pid"] == 1400).unwrap();
        assert_eq!(refused.fields["access"], "refused");
    }

    #[test]
    fn a_hook_into_hand_mapped_memory_is_found_with_where_it_goes() {
        let run = RobloxMemory::default().collect(&fixture());
        let (observations, _) = observations(&run);
        let hooks = of_scope(observations, "hook");
        let helper = hooks
            .iter()
            .find(|o| o.fields["module"].as_str().unwrap().ends_with("helper.dll"))
            .expect("the jump written over helper.dll's export is found");
        assert_eq!(helper.fields["function"], "Run");
        assert_eq!(helper.fields["hook_kind"], "jmp_rel32");
        assert_eq!(helper.fields["target"], "0x7ff600001000");
        assert_eq!(helper.fields["target_module"], "unbacked_private");
        assert_eq!(helper.fields["expected_runtime_change"], false);
        let regions = of_scope(observations, "region");
        assert!(
            regions
                .iter()
                .any(|o| o.fields["finding"] == "hand_mapped_image")
        );
        assert!(
            regions
                .iter()
                .any(|o| o.fields["finding"] == "unlisted_image")
        );
        let changes = of_scope(observations, "code_change");
        let player_change = changes
            .iter()
            .find(|o| {
                o.fields["module"]
                    .as_str()
                    .unwrap()
                    .ends_with("RobloxPlayerBeta.exe")
            })
            .unwrap();
        assert_eq!(player_change.fields["expected_runtime_change"], true);
    }

    #[test]
    fn strings_flags_and_identifiers_are_kept_by_category_and_chat_is_not() {
        let run = RobloxMemory::default().collect(&fixture());
        let (observations, _) = observations(&run);
        let strings = of_scope(observations, "string");
        let categories: BTreeSet<&str> = strings
            .iter()
            .map(|o| o.fields["category"].as_str().unwrap())
            .collect();
        assert!(categories.contains("executor_function"), "{categories:?}");
        assert!(categories.contains("injection_api"));
        assert!(categories.contains("module_path"));
        let json = serde_json::to_string(observations).unwrap();
        assert!(!json.contains("chat line"), "uncategorised text was kept");
        let flags = of_scope(observations, "flag_value");
        let physics = flags
            .iter()
            .find(|o| o.fields["flag"] == "DFIntS2PhysicsSenderRate")
            .unwrap();
        assert_eq!(physics.fields["value"], "60");
        assert_eq!(physics.fields["comparison"], "no_reference");
        let identifiers = of_scope(observations, "identifier");
        assert!(
            identifiers
                .iter()
                .any(|o| o.fields["flag"] == "DFIntS2PhysicsSenderRate"
                    && o.fields["value_interpretation"] == "not_established")
        );
    }

    #[test]
    fn with_a_reference_the_flag_values_are_compared() {
        let mut text = String::from("{");
        for index in 0..bope_parsers::fflag_reference::MIN_ENTRIES {
            text.push_str("\"FFlagFiller");
            text.push_str(&index.to_string());
            text.push_str("\": true,");
        }
        text.push_str("\"DFIntS2PhysicsSenderRate\": 15}");
        let snapshot = ReferenceSnapshot {
            reference: bope_parsers::fflag_reference::parse(text.as_bytes()).unwrap(),
            revision: "abc123".to_owned(),
            commit_date: None,
            fetched_at: "2026-10-16T00:00:00Z".to_owned(),
            source_url: "https://example.invalid".to_owned(),
            revision_kind: "commit".to_owned(),
            reference_client_version: None,
        };
        let run = RobloxMemory::new(Some(Arc::new(snapshot))).collect(&fixture());
        let (observations, _) = observations(&run);
        let physics = of_scope(observations, "flag_value")
            .into_iter()
            .find(|o| o.fields["flag"] == "DFIntS2PhysicsSenderRate")
            .unwrap();
        assert_eq!(physics.fields["comparison"], "differs");
        assert_eq!(physics.fields["reference_value"], "15");
        assert_eq!(physics.fields["reference_revision"], "abc123");
    }

    #[test]
    fn with_no_player_running_every_internal_place_is_source_absent() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nprocesses:\n  - { pid: 4, name: System }\n",
            "inline",
        )
        .unwrap();
        let run = RobloxMemory::default().collect(&host);
        let (observations, gaps) = observations(&run);
        assert_eq!(
            of_scope(observations, "players")[0].fields["players_running"],
            0
        );
        assert_eq!(gaps.len(), INTERNAL_PLACES.len());
        assert!(gaps.iter().all(|g| {
            g.gaps
                .values()
                .all(|r| *r == UnmeasuredReason::SourceAbsent)
        }));
    }
}
