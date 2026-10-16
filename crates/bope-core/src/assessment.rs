// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The assessment: a reading of the evidence for a checker, kept apart from the evidence itself
//! (B.O.P.E, ADR 0100).
//!
//! The upstream design shows evidence and never a verdict. B.O.P.E Scanner adds this layer on top of
//! it, because a checker in a screenshare needs to know where to look first. It is built **only** from
//! the report the engine already froze and from each rule's declared `level`, and it changes nothing
//! in the report. Its rules are deliberately conservative:
//!
//! - Every category gets one of five states — `ok`, `info`, `warn`, `flag`, `not_checked` — where
//!   `ok` means "the checks ran and found none of the indicators they define", **never** "clean".
//! - Evidence from the **same source** counts once, however many rules matched it: two rules on one
//!   collector, or on collectors that read the same underlying listing, are one source
//!   ([`source_family`]). Corroboration needs different sources.
//! - The overall conclusion is one of five, none of which states innocence or guilt
//!   ([`Conclusion`]). Missing logs, empty folders and absent sources are never counted as
//!   indicators: they are `not_found` or `unmeasured` in the evidence, which this layer never reads
//!   as a finding.
//! - Every supporting item lists the times its observations carry, and pairs of items from different
//!   sources whose times fall close together are listed as **temporal proximity**, with the gap — a
//!   prompt to look, not a claim that one caused the other.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bundle::Bundle;
use crate::model::{EvidenceState, Report, UnmeasuredReason};

/// What a `found` result means to the assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Context that is not suspicious on its own.
    Info,
    /// An anomaly that deserves a person's review.
    Warn,
    /// A specific indicator with relevant evidence.
    Flag,
}

impl Level {
    /// Stable identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Flag => "flag",
        }
    }
}

/// The state of one category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    /// No rule of the category could look.
    NotChecked,
    /// The rules looked and found none of their indicators.
    Ok,
    /// Only context was found.
    Info,
    /// An anomaly that deserves review.
    Warn,
    /// A specific indicator with relevant evidence.
    Flag,
}

/// The overall reading. There is deliberately no "clean" and no "guilty".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    /// No indicator was found in the sources that were examined. Says nothing about sources that were
    /// not, nor about what a software check cannot see (another PC, DMA hardware, a reinstalled OS).
    NoSuspiciousEvidence,
    /// Too much could not be examined for the absence of indicators to mean much.
    Inconclusive,
    /// One source shows something a person should review.
    ManualReview,
    /// Indicators from two or more independent sources.
    Corroborated,
    /// A specific indicator corroborated by at least one other independent source.
    HighConfidence,
}

/// One category's state, with what produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryAssessment {
    /// Category id (see [`CATEGORIES`]).
    pub category: String,
    /// Its state.
    pub state: ModuleState,
    /// Rules of the category that were `found`, with their level.
    pub found: Vec<FoundRule>,
    /// Rules that looked (found or not found).
    pub measured: usize,
    /// Rules that could not look.
    pub unmeasured: usize,
    /// Whether some rules looked and others could not: an `ok` here covers only the part that looked.
    pub partial: bool,
}

/// A rule that was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundRule {
    /// Rule id.
    pub rule_id: String,
    /// The collector that read it.
    pub collector: String,
    /// Its level.
    pub level: Level,
    /// The source family it belongs to, for independence.
    pub source: String,
    /// How many observations matched.
    pub observations: usize,
    /// The earliest and latest time its observations carry, RFC 3339 UTC, when they carry any.
    pub earliest: Option<String>,
    /// See `earliest`.
    pub latest: Option<String>,
    /// For a rule over a correlation (`roblox_trace`), the families of the sources its observations
    /// were built from; they stand in for `source` when independence is counted (ADR 0123).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

impl FoundRule {
    /// The families this item counts as.
    pub fn families(&self) -> Vec<&str> {
        if self.sources.is_empty() {
            vec![self.source.as_str()]
        } else {
            self.sources.iter().map(String::as_str).collect()
        }
    }
}

/// Two supporting items from different sources whose times are close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proximity {
    /// One rule.
    pub a: String,
    /// The other.
    pub b: String,
    /// The smallest gap between any time of one and any time of the other, in seconds.
    pub seconds: i64,
}

/// The assessment of one report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    /// One entry per category, in [`CATEGORIES`] order.
    pub categories: Vec<CategoryAssessment>,
    /// The overall reading.
    pub conclusion: Conclusion,
    /// Found rules at `warn` or `flag`, which are what the conclusion rests on.
    pub supporting: Vec<FoundRule>,
    /// How many independent sources have a `warn` or `flag`.
    pub independent_sources: usize,
    /// How many of those have a `flag`.
    pub flag_sources: usize,
    /// Supporting items from different sources within [`PROXIMITY_SECONDS`] of each other.
    pub proximity: Vec<Proximity>,
    /// Facts about the scan that limit what the conclusion can mean, as stable keys the UI translates:
    /// `not_elevated`, `standard_tier`, `categories_not_checked`, `software_only`.
    pub caveats: Vec<String>,
}

/// The categories, in display order.
pub const CATEGORIES: [&str; 15] = [
    "roblox_tools",
    "roblox",
    "fastflags",
    "processes_memory",
    "execution",
    "files",
    "persistence",
    "drivers",
    "macros_peripherals",
    "usb_devices",
    "browser_scripts",
    "network",
    "system_logs",
    "firmware_boot",
    "other",
];

/// Two times closer than this are listed as temporal proximity: two hours, which absorbs ordinary
/// clock drift between sources and still separates one evening from the next.
pub const PROXIMITY_SECONDS: i64 = 2 * 60 * 60;

/// The category a collector's rules fall under unless a rule says otherwise.
pub fn default_category(collector: &str) -> &'static str {
    match collector {
        "roblox_trace" => "roblox_tools",
        "fastflags" => "fastflags",
        "roblox" | "roblox_process" | "executor_footprint" => "roblox",
        "process" => "processes_memory",
        "prefetch" | "bam" | "pca" | "userassist" | "shimcache" | "feature_usage" | "muicache"
        | "shell_mru" | "amcache" | "shortcuts" | "srum" | "shellbags" => "execution",
        "user_files" | "usn" | "fivem_dir" | "fivem_servers" | "roblox_files" | "mft"
        | "recycle_bin" => "files",
        "autostart" | "hijack" | "defender_exclusion" | "wmi_subscription" => "persistence",
        "driver_service" => "drivers",
        "usb_device" | "pci_device" => "usb_devices",
        "browser_ext" | "powershell_text" => "browser_scripts",
        "net_config" | "net_adapter" => "network",
        "evtx" | "windows_start" | "windows_service" => "system_logs",
        "posture" | "machine_identity" => "firmware_boot",
        _ => "other",
    }
}

/// The source family of a collector: collectors that read the same underlying record are one source.
pub fn source_family(collector: &str) -> &'static str {
    match collector {
        "process" | "roblox_process" => "process_snapshot",
        "user_files" | "executor_footprint" | "roblox" | "fivem_dir" | "roblox_files" => {
            "file_listing"
        }
        "evtx" | "windows_start" => "event_logs",
        // The Recycle Bin's `$I` files are their own record, not a folder listing (ADR 0131).
        "recycle_bin" => "recycle_bin",
        "windows_service" => "service_control_manager",
        "posture" | "machine_identity" => "firmware",
        other => match other {
            "prefetch" => "prefetch",
            "bam" => "bam",
            "pca" => "pca",
            "userassist" => "userassist",
            "shimcache" => "shimcache",
            "feature_usage" => "feature_usage",
            "muicache" => "muicache",
            "shell_mru" => "shell_mru",
            "usn" => "usn",
            "autostart" => "autostart",
            "hijack" => "hijack",
            "defender_exclusion" => "defender_exclusion",
            "driver_service" => "driver_service",
            "usb_device" => "usb_device",
            "pci_device" => "pci_device",
            "browser_ext" => "browser_ext",
            "powershell_text" => "powershell_text",
            "net_config" => "net_config",
            "net_adapter" => "net_adapter",
            "installed_programs" => "installed_programs",
            "amcache" => "amcache",
            "srum" => "srum",
            "mft" => "mft",
            "shellbags" => "shellbags",
            "wmi_subscription" => "wmi",
            "shortcuts" => "shortcuts",
            "fastflags" => "client_config",
            "roblox_trace" => "roblox_trace",
            _ => "other",
        },
    }
}

/// Every time an observation carries in a field the report declares a timestamp.
fn times_of(report: &Report, collector: &str, state: &EvidenceState) -> Vec<jiff::Timestamp> {
    let EvidenceState::Found { observations } = state else {
        return Vec::new();
    };
    let fields = report.timestamp_fields.get(collector);
    observations
        .iter()
        .flat_map(|o| {
            o.fields.iter().filter_map(|(name, value)| {
                let declared = fields.is_none_or(|f| f.iter().any(|d| d == name));
                if !declared {
                    return None;
                }
                value.as_str()?.parse::<jiff::Timestamp>().ok()
            })
        })
        .collect()
}

/// The families named in a correlation's observations (`families: "prefetch, bam"`), empty for an
/// ordinary rule.
fn derived_families(observations: &[crate::model::Observation]) -> Vec<String> {
    let set: BTreeSet<String> = observations
        .iter()
        .filter(|o| o.collector == "roblox_trace")
        .filter_map(|o| o.fields.get("families").and_then(|v| v.as_str()))
        .flat_map(|f| f.split(", ").map(str::to_owned).collect::<Vec<_>>())
        .filter(|f| !f.is_empty())
        .collect();
    set.into_iter().collect()
}

/// Assesses one report against the bundle that produced it.
#[allow(clippy::too_many_lines)]
pub fn assess(report: &Report, bundle: &Bundle) -> Assessment {
    let rules: BTreeMap<&str, &crate::rules::Rule> = bundle
        .rules()
        .iter()
        .filter(|s| !s.rule.is_timeline_selector())
        .map(|s| (s.rule.id.as_str(), &s.rule))
        .collect();

    let mut per_category: BTreeMap<String, CategoryAssessment> = CATEGORIES
        .iter()
        .map(|c| {
            (
                (*c).to_owned(),
                CategoryAssessment {
                    category: (*c).to_owned(),
                    state: ModuleState::NotChecked,
                    found: Vec::new(),
                    measured: 0,
                    unmeasured: 0,
                    partial: false,
                },
            )
        })
        .collect();
    let mut times: BTreeMap<String, Vec<jiff::Timestamp>> = BTreeMap::new();

    for evidence in &report.evidence {
        let Some(rule) = rules.get(evidence.rule_id.as_str()) else {
            continue;
        };
        let category = rule.assessment_category();
        let entry = per_category
            .entry(category.clone())
            .or_insert_with(|| CategoryAssessment {
                category: category.clone(),
                state: ModuleState::NotChecked,
                found: Vec::new(),
                measured: 0,
                unmeasured: 0,
                partial: false,
            });
        match &evidence.state {
            EvidenceState::Found { observations } => {
                entry.measured += 1;
                let mut stamps = times_of(report, &evidence.collector, &evidence.state);
                stamps.sort();
                entry.found.push(FoundRule {
                    rule_id: evidence.rule_id.clone(),
                    collector: evidence.collector.clone(),
                    level: rule.assessment_level(),
                    source: source_family(&evidence.collector).to_owned(),
                    observations: observations.len(),
                    earliest: stamps.first().map(ToString::to_string),
                    latest: stamps.last().map(ToString::to_string),
                    sources: derived_families(observations),
                });
                times.insert(evidence.rule_id.clone(), stamps);
            }
            EvidenceState::NotFound { .. } => entry.measured += 1,
            EvidenceState::Unmeasured { reason, .. } => {
                // A full-scan source the player did not agree to is not "could not check": it was
                // never part of this scan, and the caveat `standard_tier` says so once.
                if *reason != UnmeasuredReason::NotConsented {
                    entry.unmeasured += 1;
                }
            }
        }
    }

    for entry in per_category.values_mut() {
        let top = entry.found.iter().map(|f| f.level).max();
        entry.state = match top {
            Some(Level::Flag) => ModuleState::Flag,
            Some(Level::Warn) => ModuleState::Warn,
            Some(Level::Info) => ModuleState::Info,
            None if entry.measured > 0 => ModuleState::Ok,
            None => ModuleState::NotChecked,
        };
        entry.partial = entry.measured > 0 && entry.unmeasured > 0;
    }

    let mut categories: Vec<CategoryAssessment> = CATEGORIES
        .iter()
        .filter_map(|c| per_category.remove(*c))
        .collect();
    categories.extend(per_category.into_values());

    let supporting: Vec<FoundRule> = categories
        .iter()
        .flat_map(|c| c.found.iter())
        .filter(|f| f.level >= Level::Warn)
        .cloned()
        .collect();
    let warn_sources: BTreeSet<&str> = supporting.iter().flat_map(FoundRule::families).collect();
    let flag_sources: BTreeSet<&str> = supporting
        .iter()
        .filter(|f| f.level == Level::Flag)
        .flat_map(FoundRule::families)
        .collect();

    let not_checked = categories
        .iter()
        .filter(|c| c.state == ModuleState::NotChecked)
        .count();
    let conclusion = if !flag_sources.is_empty() && warn_sources.len() >= 2 {
        Conclusion::HighConfidence
    } else if warn_sources.len() >= 2 {
        Conclusion::Corroborated
    } else if warn_sources.len() == 1 {
        Conclusion::ManualReview
    } else if not_checked * 3 >= categories.len() || report.header.elevated == Some(false) {
        Conclusion::Inconclusive
    } else {
        Conclusion::NoSuspiciousEvidence
    };

    let mut proximity = Vec::new();
    for (i, a) in supporting.iter().enumerate() {
        for b in supporting.iter().skip(i + 1) {
            let fa = a.families();
            if b.families().iter().any(|f| fa.contains(f)) {
                continue;
            }
            let (Some(ta), Some(tb)) = (times.get(&a.rule_id), times.get(&b.rule_id)) else {
                continue;
            };
            let gap = ta
                .iter()
                .flat_map(|x| {
                    tb.iter()
                        .map(move |y| (x.as_second() - y.as_second()).abs())
                })
                .min();
            if let Some(seconds) = gap.filter(|s| *s <= PROXIMITY_SECONDS) {
                proximity.push(Proximity {
                    a: a.rule_id.clone(),
                    b: b.rule_id.clone(),
                    seconds,
                });
            }
        }
    }

    let mut caveats = vec!["software_only".to_owned()];
    if report.header.elevated != Some(true) {
        caveats.push("not_elevated".to_owned());
    }
    if report.header.scan_tier == crate::model::ScanTier::Standard {
        caveats.push("standard_tier".to_owned());
    }
    if not_checked > 0 {
        caveats.push("categories_not_checked".to_owned());
    }

    Assessment {
        categories,
        conclusion,
        independent_sources: warn_sources.len(),
        flag_sources: flag_sources.len(),
        supporting,
        proximity,
        caveats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_merge_collectors_that_read_one_record() {
        assert_eq!(source_family("process"), source_family("roblox_process"));
        assert_eq!(
            source_family("user_files"),
            source_family("executor_footprint")
        );
        assert_ne!(source_family("prefetch"), source_family("bam"));
    }

    #[test]
    fn every_category_a_collector_maps_to_is_listed() {
        for collector in [
            "roblox",
            "process",
            "prefetch",
            "user_files",
            "autostart",
            "driver_service",
            "usb_device",
            "browser_ext",
            "net_config",
            "evtx",
            "posture",
            "installed_programs",
        ] {
            assert!(
                CATEGORIES.contains(&default_category(collector)),
                "{collector}"
            );
        }
    }

    #[test]
    fn levels_order_from_info_to_flag() {
        assert!(Level::Flag > Level::Warn && Level::Warn > Level::Info);
        assert!(ModuleState::Flag > ModuleState::Warn && ModuleState::Ok > ModuleState::NotChecked);
    }
}
