// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The modules every running process has loaded, assessed for integrity, and the executable memory no
//! module accounts for (B.O.P.E, ADR 0134).
//!
//! Each process the account may open is opened for reading only
//! ([`bope_host::MemorySource::open_process_memory`]). Of each: its modules with where they are mapped,
//! its committed regions, and the first page of each private executable allocation. A module file is
//! assessed once however many processes load it ([`crate::integrity::Assessor`]), those outside the
//! Windows folder first. Rows, told apart by `scope`:
//!
//! - `summary` — every count, and the number of modules in each integrity class;
//! - `process` — each process opened: its modules, private executable regions, and the two kinds of
//!   executable memory below;
//! - `module` — each module file whose class needs reading (as `file_inventory` decides), with which
//!   processes load it;
//! - `allocation` — private executable memory that begins with a PE header: an image the loader did
//!   not map, which is what manual mapping leaves;
//! - `unlisted_image` — an image mapping whose allocation the loader does not list as a module: an image
//!   mapped by hand, or a module unlinked from the loader's lists.
//!
//! **What this does not say.** Who put anything there. Private executable memory is what every
//! just-in-time compiler (browsers, .NET, Java, Lua engines), many overlays and anti-cheat software
//! allocate. A protected process — and Roblox's own player, whose anti-cheat strips the access — is
//! refused, and that refusal is counted, never worked around.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{Host, Platform, PointerWidth, SourceError};

use crate::common::{Fields, unmeasured};
use crate::integrity::{Assessor, IntegrityClass};
use crate::procmem::{ModuleMap, executable_allocations, hex_address, unlisted_images};
use crate::{CollectContext, Collector, Field, location};

/// Collector id.
pub const ID: &str = "process_modules";
const DISCRIMINATOR: &str = "scope";

/// How long the reads and assessments may take.
pub const BUDGET: Duration = Duration::from_secs(150);
/// Most regions walked per process.
const MAX_REGIONS: usize = 200_000;
/// Most private executable allocations read per process.
const MAX_ALLOCATIONS: usize = 4_096;
/// Most module rows.
const MAX_MODULE_ROWS: usize = 2_000;
/// Most processes named beside a module.
const MAX_LOADED_BY: usize = 8;

static FIELDS: [Field; 71] = [
    Field::text("address"),
    Field::text("allocation_base"),
    Field::number("allocations_with_image"),
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
    Field::number("exports"),
    Field::text("extension"),
    Field::text("file_description"),
    Field::text("file_version"),
    Field::boolean("holds_image"),
    Field::number("imported_dlls"),
    Field::text("injection_imports"),
    Field::text("integrity_class"),
    Field::text("integrity_reasons"),
    Field::boolean("is_dll"),
    Field::text("limitations"),
    Field::text("loaded_by"),
    Field::text("location_kind"),
    Field::text("machine"),
    Field::text("mapped_file"),
    Field::number("modules"),
    Field::number("modules_assessed"),
    Field::number("modules_not_assessed"),
    Field::number("modules_unique"),
    Field::text("name"),
    Field::text("original_filename"),
    Field::number("overlay_bytes"),
    Field::boolean("partial_structure"),
    Field::text("path"),
    Field::text("pe_anomalies"),
    Field::number("pe_timestamp"),
    Field::text("permissions"),
    Field::number("pid"),
    Field::text("pointer_width"),
    Field::number("private_executable_regions"),
    Field::text("process_name"),
    Field::number("processes"),
    Field::number("processes_failed"),
    Field::number("processes_listed"),
    Field::number("processes_opened"),
    Field::number("processes_refused"),
    Field::text("product"),
    Field::number("rows_withheld"),
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
    Field::number("subsystem"),
    Field::number("tls_callbacks"),
    Field::number("unlisted_images"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `process_modules` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessModules;

fn width_word(width: Option<PointerWidth>) -> Option<&'static str> {
    width.map(|w| match w {
        PointerWidth::Bits32 => "32",
        PointerWidth::Bits64 => "64",
    })
}

impl Collector for ProcessModules {
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
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let processes = match host.running_processes() {
            Ok(list) => list,
            Err(error) => return unmeasured(ID, crate::common::reason(host, &error)),
        };
        let deadline = Instant::now() + BUDGET;
        let mut observations = Vec::new();
        let mut refused = 0_u64;
        let mut failed = 0_u64;
        let mut opened = 0_u64;
        let mut stopped = None;
        // Module path (lower-cased) → (path as read, process names).
        let mut loaded: BTreeMap<String, (String, BTreeSet<String>)> = BTreeMap::new();
        let mut totals = (0_u64, 0_u64, 0_u64);
        for process in &processes {
            if context.cancelled() {
                stopped = Some("cancelled");
                break;
            }
            if Instant::now() >= deadline {
                stopped = Some("budget");
                break;
            }
            let reader = match host.open_process_memory(process.pid) {
                Ok(reader) => reader,
                Err(SourceError::AccessDenied) => {
                    refused += 1;
                    continue;
                }
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };
            opened += 1;
            let modules = reader.modules().unwrap_or_default();
            for module in &modules {
                loaded
                    .entry(module.path.to_ascii_lowercase())
                    .or_insert_with(|| (module.path.clone(), BTreeSet::new()))
                    .1
                    .insert(process.name.clone());
            }
            let map = ModuleMap::new(modules);
            let (regions, _) = reader.regions(MAX_REGIONS).unwrap_or_default();
            let allocations = executable_allocations(reader.as_ref(), &regions, MAX_ALLOCATIONS);
            let with_image: Vec<_> = allocations.iter().filter(|a| a.holds_image).collect();
            let unlisted = unlisted_images(&regions, &map);
            totals.0 += allocations.len() as u64;
            totals.1 += with_image.len() as u64;
            totals.2 += unlisted.len() as u64;
            for allocation in &with_image {
                observations.push(
                    Fields::new()
                        .with(DISCRIMINATOR, "allocation")
                        .with("pid", process.pid)
                        .with("process_name", process.name.clone())
                        .with("address", hex_address(allocation.region.base))
                        .with("size", allocation.region.size)
                        .with("permissions", allocation.region.permissions())
                        .with("holds_image", true)
                        .observe(ID),
                );
            }
            for image in &unlisted {
                observations.push(
                    Fields::new()
                        .with(DISCRIMINATOR, "unlisted_image")
                        .with("pid", process.pid)
                        .with("process_name", process.name.clone())
                        .with("address", hex_address(image.allocation_base))
                        .maybe("mapped_file", image.mapped_file.clone())
                        .observe(ID),
                );
            }
            observations.push(
                Fields::new()
                    .with(DISCRIMINATOR, "process")
                    .with("pid", process.pid)
                    .with("name", process.name.clone())
                    .maybe("path", process.path.clone())
                    .time("started_at", process.started_at)
                    .maybe("pointer_width", width_word(reader.pointer_width()))
                    .with("modules", map.modules().len())
                    .with("private_executable_regions", allocations.len())
                    .with("allocations_with_image", with_image.len())
                    .with("unlisted_images", unlisted.len())
                    .observe(ID),
            );
        }
        context.note("assessing the modules processes have loaded");

        let assessor = Assessor::new(host);
        // Modules outside the Windows folder first: fewer, and the ones a reader needs.
        let mut order: Vec<&(String, BTreeSet<String>)> = loaded.values().collect();
        order.sort_by_key(|(path, _)| (assessor.under_windows(path), path.to_ascii_lowercase()));
        let mut classes: BTreeMap<IntegrityClass, u64> = BTreeMap::new();
        let mut assessed = 0_u64;
        let mut module_rows = 0_usize;
        let mut withheld = 0_u64;
        for (path, by) in order {
            if context.cancelled() {
                stopped = Some("cancelled");
                break;
            }
            if Instant::now() >= deadline {
                stopped.get_or_insert("budget");
                break;
            }
            let assessment = assessor.assess(path);
            assessed += 1;
            *classes.entry(assessment.class).or_default() += 1;
            let place = location::classify(path);
            let reported = match assessment.class {
                IntegrityClass::MaliciousCorroborated
                | IntegrityClass::IntegrityCompromised
                | IntegrityClass::Suspicious
                | IntegrityClass::Inconclusive => true,
                IntegrityClass::Unknown | IntegrityClass::NotVerified => {
                    place.is_user_writable() || place == location::LocationKind::OtherDrivePath
                }
                IntegrityClass::ValidSignature | IntegrityClass::VerifiedReference => false,
            };
            if !reported {
                continue;
            }
            if module_rows >= MAX_MODULE_ROWS {
                withheld += 1;
                continue;
            }
            module_rows += 1;
            observations.push(
                assessment
                    .fields
                    .with(DISCRIMINATOR, "module")
                    .with("path", path.clone())
                    .with("processes", by.len())
                    .with(
                        "loaded_by",
                        by.iter()
                            .take(MAX_LOADED_BY)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                    .observe(ID),
            );
        }

        let complete = stopped.is_none();
        let mut summary = Fields::new()
            .with(DISCRIMINATOR, "summary")
            .with("complete", complete)
            .maybe("stopped_by", stopped)
            .with("processes_listed", processes.len())
            .with("processes_opened", opened)
            .with("processes_refused", refused)
            .with("processes_failed", failed)
            .with("modules_unique", loaded.len())
            .with("modules_assessed", assessed)
            .with(
                "modules_not_assessed",
                (loaded.len() as u64).saturating_sub(assessed),
            )
            .with("private_executable_regions", totals.0)
            .with("allocations_with_image", totals.1)
            .with("unlisted_images", totals.2)
            .with("rows_withheld", withheld);
        for class in IntegrityClass::ALL {
            summary = summary.with(
                &format!("class_{}", class.as_str()),
                classes.get(&class).copied().unwrap_or(0),
            );
        }
        let mut all = vec![summary.observe(ID)];
        all.append(&mut observations);

        let mut discriminator_gaps = Vec::new();
        if !complete {
            discriminator_gaps.push(gap("module", UnmeasuredReason::BudgetSpent));
        }
        if opened == 0 && refused > 0 {
            let reason = crate::common::reason(host, &SourceError::AccessDenied);
            for place in ["module", "allocation", "unlisted_image"] {
                discriminator_gaps.push(gap(place, reason));
            }
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations: all,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

fn gap(place: &str, reason: UnmeasuredReason) -> DiscriminatorGaps {
    DiscriminatorGaps {
        discriminator: DISCRIMINATOR.to_owned(),
        value: serde_json::Value::from(place),
        gaps: [
            "integrity_class",
            "holds_image",
            "mapped_file",
            "address",
            "path",
        ]
        .iter()
        .map(|f| ((*f).to_owned(), reason))
        .collect(),
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

    #[test]
    fn modules_are_assessed_once_and_hand_mapped_images_are_named() {
        let run = ProcessModules.collect(&fixture());
        let CollectorRun::Measured {
            observations,
            discriminator_gaps,
            ..
        } = &run
        else {
            panic!("{run:?}")
        };
        assert!(discriminator_gaps.is_empty(), "{discriminator_gaps:?}");
        let summary = of_scope(observations, "summary")[0];
        assert_eq!(summary.fields["processes_refused"], 2);
        assert_eq!(summary.fields["allocations_with_image"], 1);
        assert_eq!(summary.fields["unlisted_images"], 1);
        let modules = of_scope(observations, "module");
        let helper = modules
            .iter()
            .find(|o| o.fields["name"] == "helper.dll")
            .expect("the unsigned module in the profile is listed");
        assert_eq!(helper.fields["integrity_class"], "unknown");
        assert_eq!(helper.fields["processes"], 1);
        let allocation = of_scope(observations, "allocation")[0];
        assert_eq!(allocation.fields["address"], "0x7ff600000000");
        assert_eq!(allocation.fields["permissions"], "rwx");
    }
}
