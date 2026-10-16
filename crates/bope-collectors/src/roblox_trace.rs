// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Roblox tool traces, correlated across every source the scan read (B.O.P.E, ADR 0123).
//!
//! This is the one collector that reads no artifact of its own. It runs **after** the others, over
//! their observations, and does three things:
//!
//! 1. **Hits** (`scope: hit`): every observation whose name, path or parent folder matches the tool
//!    catalog ([`crate::catalog`]) becomes one hit, labelled with the **evidence class** its source
//!    can support — `execution` (Prefetch, BAM, PCA, `UserAssist`, `FeatureUsage`), `resource_usage`
//!    (SRUM recording CPU time, which counts as execution), `inventory` (`ShimCache`, Amcache),
//!    `reference` (shortcuts, Explorer lists, `ShellBags`, Open/Save dialog, `MuiCache`, a SRUM id with
//!    no CPU time), `file_history` (the change journal), `deleted` (the Recycle Bin, a journal deletion,
//!    a Master File Table record no longer in use), `current_file`, `archive_content`,
//!    `executor_layout`, `executor_scripts`, `installation`, `persistence`, `running`,
//!    `process_interaction` (a module loaded into the Roblox player from the tool's folder) and
//!    `client_configuration`. A hit from a history source whose path is drive-rooted is checked:
//!    `exists` says whether something is at that path **now** — never that it was deleted.
//! 2. **Tools** (`scope: tool`): hits grouped by catalog entry, with the independent source
//!    **families** that saw it (two collectors reading one record count once, as in
//!    `bope_core::assessment`), the classes, the earliest and latest time, and a `status`:
//!    - `info` — a legitimate launcher or utility, a generic term, a partial name (`strap`/`trap`), or
//!      an ambiguous name (`Solara`, `Wave`, `Synapse`) with no Roblox context;
//!    - `suspected` — an executor or injector name with Roblox context, seen by one family, with
//!      nothing showing it ran;
//!    - `detected` — the same, plus execution, an executor layout, executor-only scripts, or a module
//!      in the Roblox player;
//!    - `corroborated` — `detected` and seen by two or more independent families.
//! 3. **Sources** (`scope: source`): for each source a hit could come from, whether it was
//!    `measured`, `not_measured` (with the reason), `not_applicable` (a full-scan source in a standard
//!    scan) or `error` — so a tool seen nowhere is read against what could be looked at.
//!
//! A status is a summary of evidence for a reviewer, never a verdict: names can be copied, files can
//! be renamed, and temporal proximity between two hits says nothing about cause.

use std::collections::{BTreeMap, BTreeSet};

use bope_core::assessment::source_family;
use bope_core::model::{CollectorRun, Observation, UnmeasuredReason};
use bope_host::{Host, Platform};

use crate::catalog::{self, Match, MatchKind, Tool, ToolKind};
use crate::common::{Fields, unmeasured};
use crate::{Collector, Field, location};

/// This collector's id.
pub const ID: &str = "roblox_trace";
const DISCRIMINATOR: &str = "scope";
/// Most hits kept, and most existence checks made.
pub const MAX_HITS: usize = 1_000;
const MAX_EXISTS_CHECKS: usize = 400;

static FIELDS: [Field; 28] = [
    Field::text("classes"),
    Field::boolean("common_legitimate"),
    Field::boolean("deleted"),
    Field::text("display"),
    Field::text("evidence_class"),
    Field::boolean("execution"),
    Field::boolean("exists"),
    Field::text("families"),
    Field::number("families_count"),
    Field::text("family"),
    Field::timestamp("first_seen"),
    Field::number("hits"),
    Field::boolean("interaction"),
    Field::timestamp("last_seen"),
    Field::text("match_kind"),
    Field::text("matched_on"),
    Field::boolean("missing_now"),
    Field::text("name"),
    Field::text("path"),
    Field::text("reason"),
    Field::boolean("roblox_context"),
    Field::text("scope"),
    Field::text("source"),
    Field::text("state"),
    Field::text("status"),
    Field::timestamp("time"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
];

static REASONS: [UnmeasuredReason; 1] = [UnmeasuredReason::NotWindows];

/// Every source a hit can come from, with the evidence class it supports and the field holding its
/// time. Sources with more than one kind of row refine the class per row in [`class_of`].
const SOURCES: [(&str, &str, &str); 23] = [
    ("prefetch", "execution", "last_run"),
    ("bam", "execution", "last_run"),
    ("pca", "execution", "last_run"),
    ("userassist", "execution", "last_run"),
    ("feature_usage", "execution", ""),
    ("muicache", "reference", ""),
    ("shimcache", "inventory", "file_modified"),
    ("amcache", "inventory", "key_written"),
    ("srum", "resource_usage", "last_seen"),
    ("shortcuts", "reference", "modified"),
    ("shell_mru", "reference", ""),
    ("shellbags", "reference", "modified"),
    ("usn", "file_history", "last_seen"),
    ("mft", "file_history", "si_modified"),
    ("roblox_files", "current_file", "modified"),
    ("user_files", "current_file", "modified"),
    ("executor_footprint", "executor_layout", "modified"),
    ("installed_programs", "installation", ""),
    ("autostart", "persistence", ""),
    ("wmi_subscription", "persistence", ""),
    ("process", "running", "started_at"),
    ("roblox_process", "running", "started_at"),
    ("fastflags", "client_configuration", "modified"),
];

/// The `roblox_trace` collector. Its [`Collector::collect`] sees no other run, so it reports an
/// empty correlation; [`crate::scan`] calls [`correlate`] with the runs instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct RobloxTrace;

impl Collector for RobloxTrace {
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
        correlate(host, &[])
    }
}

/// One hit.
#[derive(Debug, Clone)]
struct Hit {
    tool: &'static Tool,
    kind: MatchKind,
    matched_on: &'static str,
    class: &'static str,
    source: String,
    name: String,
    path: Option<String>,
    time: Option<jiff::Timestamp>,
    exists: Option<bool>,
    roblox_context: bool,
}

fn text<'a>(o: &'a Observation, field: &str) -> Option<&'a str> {
    o.fields
        .get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn flag(o: &Observation, field: &str) -> bool {
    o.fields.get(field).and_then(serde_json::Value::as_bool) == Some(true)
}

fn number(o: &Observation, field: &str) -> u64 {
    o.fields
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// The independent source family of one hit. A file the Master File Table lists as in use is the same
/// record a folder listing reads, so it counts with the listing and never as a second family
/// (ADR 0125).
fn hit_family(source: &str, class: &str) -> &'static str {
    if source == "mft" && class == "current_file" {
        "file_listing"
    } else {
        source_family(source)
    }
}

/// The class a row of `collector` supports, refining the source's default by the row's own scope.
fn class_of(collector: &str, default: &'static str, o: &Observation) -> Option<&'static str> {
    Some(match collector {
        "roblox_files" => match text(o, "scope") {
            Some("recycled") => "deleted",
            Some("archive_entry" | "archive") => "archive_content",
            _ => "current_file",
        },
        "executor_footprint" => match text(o, "scope") {
            Some("layout") => "executor_layout",
            Some("autoexec_script") if number(o, "distinct_markers") > 0 => "executor_scripts",
            Some("autoexec_script" | "binary" | "named_folder") => "current_file",
            _ => return None,
        },
        "usn" => {
            if text(o, "location") != Some("named") {
                return None;
            }
            if number(o, "deleted") > 0 {
                "deleted"
            } else {
                "file_history"
            }
        }
        "roblox_process" => match text(o, "scope") {
            Some("roblox_module") => "process_interaction",
            Some("user_location_process") => "running",
            _ => return None,
        },
        "mft" => match text(o, "scope") {
            Some("entry") if flag(o, "in_use") => "current_file",
            Some("entry") => "deleted",
            _ => return None,
        },
        "wmi_subscription" => match text(o, "scope") {
            Some("consumer" | "filter") if !flag(o, "known_default") => "persistence",
            _ => return None,
        },
        "srum" => match text(o, "scope") {
            Some("app") if flag(o, "used_cpu") => "resource_usage",
            Some("app") => "reference",
            _ => return None,
        },
        "amcache" => match text(o, "scope") {
            Some("file" | "shortcut") => "inventory",
            _ => return None,
        },
        "fastflags" => match text(o, "location") {
            Some("bootstrapper" | "tool_folder") => "client_configuration",
            _ => return None,
        },
        _ => default,
    })
}

/// The best catalog match for one row: a `tool_id` the source already set, else its name, else the
/// folder it is in. A generic term or partial in the name gives way to a specific folder name.
fn match_row(o: &Observation, name: &str, path: Option<&str>) -> Option<(Match, &'static str)> {
    if let Some(id) = text(o, "tool_id")
        && let Some(tool) = catalog::by_id(id)
    {
        let kind = match text(o, "match_kind") {
            Some("weak_partial") => MatchKind::WeakPartial,
            Some("generic_term") => MatchKind::GenericTerm,
            Some("ambiguous_alias") => MatchKind::AmbiguousAlias,
            _ => MatchKind::KnownTool,
        };
        return Some((
            Match {
                tool,
                kind,
                alias: "",
            },
            "source",
        ));
    }
    let by_name = catalog::match_name(name).into_iter().next();
    let parent = path.and_then(|p| {
        let trimmed = location::strip_nt_prefix(p);
        let mut parts = trimmed.rsplit(['\\', '/']);
        parts.next();
        parts.next()
    });
    let by_parent = parent
        .and_then(|p| catalog::match_name(p).into_iter().next())
        .filter(|m| m.kind >= MatchKind::AmbiguousAlias);
    match (by_name, by_parent) {
        (Some(n), Some(p)) if p.kind > n.kind => Some((p, "parent_folder")),
        (Some(n), _) => Some((n, "name")),
        (None, Some(p)) => Some((p, "parent_folder")),
        (None, None) => None,
    }
}

/// A path without its drive letter or `\Device\HarddiskVolumeN` prefix, lower-cased, so the two
/// spellings Windows artifacts use for one file compare equal.
fn volume_relative(path: &str) -> String {
    let lower = location::strip_nt_prefix(path).to_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\device\harddiskvolume") {
        return rest
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .to_owned();
    }
    if lower.as_bytes().get(1) == Some(&b':') {
        return lower.get(2..).unwrap_or_default().to_owned();
    }
    lower
}

/// Whether a path is one this program can ask about today.
fn checkable(path: &str) -> bool {
    let p = location::strip_nt_prefix(path);
    p.len() > 3 && p.as_bytes().get(1) == Some(&b':') && p.as_bytes().get(2) == Some(&b'\\')
}

/// Correlates `runs`. Called by [`crate::scan`] after every other collector.
#[allow(clippy::too_many_lines)]
pub fn correlate(host: &dyn Host, runs: &[CollectorRun]) -> CollectorRun {
    if host.platform() != Platform::Windows {
        return unmeasured(ID, UnmeasuredReason::NotWindows);
    }
    let mut hits: Vec<Hit> = Vec::new();
    let mut sources: Vec<Observation> = Vec::new();
    // Folders holding an executor's layout: anything under them has Roblox context, and a row there
    // that names no tool belongs to the tool the folder is named after, or to an unnamed executor.
    let mut layouts: Vec<String> = Vec::new();
    let mut layout_tools: Vec<(String, Match)> = Vec::new();
    for run in runs {
        if let CollectorRun::Measured {
            collector,
            observations,
            ..
        } = run
            && collector == "executor_footprint"
        {
            for o in observations
                .iter()
                .filter(|o| text(o, "scope") == Some("layout"))
            {
                let Some(path) = text(o, "path") else {
                    continue;
                };
                let relative = volume_relative(path);
                let named = catalog::match_name(location::last_segment(path))
                    .into_iter()
                    .find(|m| m.kind >= MatchKind::AmbiguousAlias);
                let owner = named.unwrap_or(Match {
                    tool: catalog::by_id("unnamed_executor").unwrap_or(&catalog::TOOLS[0]),
                    kind: MatchKind::KnownTool,
                    alias: "",
                });
                layout_tools.push((relative.clone(), owner));
                layouts.push(relative);
            }
        }
    }
    let mut exists_checks = 0;
    for (collector, default_class, time_field) in SOURCES {
        let run = runs.iter().find(|r| match r {
            CollectorRun::Measured { collector: c, .. }
            | CollectorRun::Unmeasured { collector: c, .. } => c == collector,
        });
        let (state, reason) = match run {
            None => ("not_measured", Some("collector_unavailable")),
            Some(CollectorRun::Unmeasured { reason, .. }) => match reason {
                UnmeasuredReason::NotConsented => ("not_applicable", Some(reason.as_str())),
                UnmeasuredReason::ReadFailed => ("error", Some(reason.as_str())),
                other => ("not_measured", Some(other.as_str())),
            },
            Some(CollectorRun::Measured { .. }) => ("measured", None),
        };
        sources.push(
            Fields::new()
                .with(DISCRIMINATOR, "source")
                .with("source", collector)
                .with("family", source_family(collector))
                .with("state", state)
                .maybe("reason", reason)
                .observe(ID),
        );
        let Some(CollectorRun::Measured { observations, .. }) = run else {
            continue;
        };
        for o in observations {
            if hits.len() >= MAX_HITS {
                break;
            }
            let Some(class) = class_of(collector, default_class, o) else {
                continue;
            };
            let path = text(o, "target_path")
                .or_else(|| text(o, "path"))
                .or_else(|| text(o, "install_location"))
                .map(str::to_owned);
            let name = text(o, "name")
                .map(str::to_owned)
                .or_else(|| text(o, "owner").map(str::to_owned))
                .or_else(|| {
                    path.as_deref()
                        .map(|p| location::last_segment(p).to_owned())
                });
            let Some(name) = name else {
                continue;
            };
            let match_name = if collector == "fastflags" {
                text(o, "owner").unwrap_or(&name).to_owned()
            } else {
                name.clone()
            };
            let in_layout_tool = path.as_deref().map(volume_relative).and_then(|p| {
                layout_tools
                    .iter()
                    .filter(|(l, _)| p == *l || p.starts_with(&format!("{l}\\")))
                    .max_by_key(|(l, _)| l.len())
                    .map(|(_, m)| *m)
            });
            let direct = match_row(o, &match_name, path.as_deref())
                .filter(|(m, _)| m.kind >= MatchKind::AmbiguousAlias || in_layout_tool.is_none());
            let Some((found, matched_on)) =
                direct.or_else(|| in_layout_tool.map(|m| (m, "executor_layout")))
            else {
                continue;
            };
            let relative = path.as_deref().map(volume_relative);
            let in_layout = relative
                .as_deref()
                .is_some_and(|p| layouts.iter().any(|l| p.starts_with(l.as_str())));
            let roblox_context = flag(o, "roblox_context")
                || found.tool.roblox_specific && found.kind == MatchKind::KnownTool
                || path.as_deref().is_some_and(catalog::path_mentions_roblox)
                || in_layout
                || matches!(
                    class,
                    "executor_layout" | "executor_scripts" | "process_interaction"
                )
                || collector == "fastflags";
            let historical = matches!(
                class,
                "execution" | "inventory" | "reference" | "resource_usage"
            );
            let exists = if historical
                && exists_checks < MAX_EXISTS_CHECKS
                && let Some(p) = path.as_deref().filter(|p| checkable(p))
            {
                exists_checks += 1;
                host.times(location::strip_nt_prefix(p))
                    .ok()
                    .map(|t| t.is_some())
            } else {
                None
            };
            let time = if time_field.is_empty() {
                None
            } else {
                text(o, time_field)
                    .or_else(|| text(o, "deleted_at"))
                    .and_then(|t| t.parse().ok())
            };
            let time = time.or_else(|| text(o, "deleted_at").and_then(|t| t.parse().ok()));
            hits.push(Hit {
                tool: found.tool,
                kind: found.kind,
                matched_on,
                class,
                source: collector.to_owned(),
                name,
                path,
                time,
                exists,
                roblox_context,
            });
        }
    }

    let mut observations = Vec::new();
    for h in &hits {
        observations.push(
            Fields::new()
                .with(DISCRIMINATOR, "hit")
                .with("tool_id", h.tool.id)
                .with("tool_kind", h.tool.kind.as_str())
                .with("display", h.tool.display)
                .with("match_kind", h.kind.as_str())
                .with("matched_on", h.matched_on)
                .with("evidence_class", h.class)
                .with("source", h.source.clone())
                .with("family", hit_family(&h.source, h.class))
                .with("name", h.name.clone())
                .maybe("path", h.path.clone())
                .maybe("exists", h.exists)
                .with("roblox_context", h.roblox_context)
                .with("common_legitimate", h.tool.common_legitimate)
                .time("time", h.time)
                .observe(ID),
        );
    }

    let mut by_tool: BTreeMap<&'static str, Vec<&Hit>> = BTreeMap::new();
    for h in &hits {
        by_tool.entry(h.tool.id).or_default().push(h);
    }
    for (id, group) in &by_tool {
        let Some(tool) = catalog::by_id(id) else {
            continue;
        };
        observations.push(summary(tool, group));
    }
    observations.extend(sources);
    CollectorRun::Measured {
        collector: ID.to_owned(),
        observations,
        gaps: BTreeMap::new(),
        discriminator_gaps: Vec::new(),
    }
}

/// One tool's summary row.
fn summary(tool: &'static Tool, group: &[&Hit]) -> Observation {
    let context = group.iter().any(|h| h.roblox_context);
    // A file name seen with Roblox context lends it to the same name seen elsewhere: `SOLARA.EXE` in
    // Prefetch is the `Solara.exe` inside an executor's folder when that folder is on this PC.
    let contextual: BTreeSet<String> = group
        .iter()
        .filter(|h| h.roblox_context)
        .map(|h| location::last_segment(&h.name).to_lowercase())
        .collect();
    // Hits that count toward independence: a name that stands on its own, or one with context.
    let counted: Vec<&&Hit> = group
        .iter()
        .filter(|h| {
            h.kind >= MatchKind::AmbiguousAlias
                && (h.roblox_context
                    || h.kind == MatchKind::KnownTool
                    || contextual.contains(&location::last_segment(&h.name).to_lowercase()))
        })
        .collect();
    let families: BTreeSet<&str> = counted
        .iter()
        .map(|h| hit_family(&h.source, h.class))
        .collect();
    let classes: BTreeSet<&str> = group.iter().map(|h| h.class).collect();
    let counted_classes: BTreeSet<&str> = counted.iter().map(|h| h.class).collect();
    let execution = counted_classes.contains("execution")
        || counted_classes.contains("running")
        || counted_classes.contains("resource_usage");
    let interaction = counted_classes.contains("process_interaction");
    let strong_layout =
        counted_classes.contains("executor_layout") || counted_classes.contains("executor_scripts");
    let deleted = group.iter().any(|h| h.class == "deleted");
    let missing_now = group.iter().any(|h| h.exists == Some(false));
    let times: Vec<jiff::Timestamp> = group.iter().filter_map(|h| h.time).collect();
    let status = if !tool.kind.is_cheat_capable() || tool.common_legitimate || counted.is_empty() {
        "info"
    } else if !context && !tool.roblox_specific {
        // A general injector with nothing tying it to Roblox.
        if execution { "suspected" } else { "info" }
    } else if interaction || execution || strong_layout {
        if families.len() >= 2 {
            "corroborated"
        } else {
            "detected"
        }
    } else {
        "suspected"
    };
    let families_text: Vec<&str> = families.iter().copied().collect();
    let classes_text: Vec<&str> = classes.iter().copied().collect();
    Fields::new()
        .with(DISCRIMINATOR, "tool")
        .with("tool_id", tool.id)
        .with("tool_kind", tool.kind.as_str())
        .with("display", tool.display)
        .with("status", status)
        .with("hits", group.len())
        .with("families", families_text.join(", "))
        .with("families_count", families.len())
        .with("classes", classes_text.join(", "))
        .with("execution", execution)
        .with("interaction", interaction)
        .with("deleted", deleted)
        .with("missing_now", missing_now)
        .with("roblox_context", context)
        .with("common_legitimate", tool.common_legitimate)
        .with(
            "match_kind",
            group
                .iter()
                .map(|h| h.kind)
                .max()
                .unwrap_or(MatchKind::WeakPartial)
                .as_str(),
        )
        .time("first_seen", times.iter().min().copied())
        .time("last_seen", times.iter().max().copied())
        .observe(ID)
}

/// What kind a tool is, for reports that only have the id.
pub fn tool_kind(id: &str) -> Option<ToolKind> {
    catalog::by_id(id).map(|t| t.kind)
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    fn obs(collector: &str, fields: &[(&str, serde_json::Value)]) -> Observation {
        Observation {
            collector: collector.to_owned(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        }
    }

    fn measured(collector: &str, observations: Vec<Observation>) -> CollectorRun {
        CollectorRun::Measured {
            collector: collector.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps: Vec::new(),
        }
    }

    fn host() -> FixtureHost {
        FixtureHost::from_yaml_str(
            "platform: windows\nfilesystem:\n  'C:\\Users\\a\\AppData\\Local\\Bloxstrap':\n    - { name: Bloxstrap.exe }\n",
            "inline",
        )
        .unwrap()
    }

    fn tools(run: &CollectorRun) -> BTreeMap<String, Observation> {
        let CollectorRun::Measured { observations, .. } = run else {
            panic!("{run:?}");
        };
        observations
            .iter()
            .filter(|o| o.fields["scope"] == "tool")
            .map(|o| (o.fields["tool_id"].as_str().unwrap().to_owned(), o.clone()))
            .collect()
    }

    #[test]
    fn an_executor_seen_by_two_families_with_execution_is_corroborated_and_missing_now() {
        let runs = vec![
            measured(
                "prefetch",
                vec![obs(
                    "prefetch",
                    &[
                        ("name", "SOLARA.EXE".into()),
                        ("last_run", "2026-10-14T20:00:00Z".into()),
                    ],
                )],
            ),
            measured(
                "bam",
                vec![obs(
                    "bam",
                    &[
                        ("name", "Solara.exe".into()),
                        (
                            "path",
                            r"\Device\HarddiskVolume3\Users\a\Downloads\Solara\Solara.exe".into(),
                        ),
                        ("last_run", "2026-10-14T20:01:00Z".into()),
                    ],
                )],
            ),
            measured(
                "shortcuts",
                vec![obs(
                    "shortcuts",
                    &[
                        ("name", "Solara.lnk".into()),
                        (
                            "target_path",
                            r"C:\Users\a\Downloads\Solara\Solara.exe".into(),
                        ),
                        ("tool_id", "solara".into()),
                        ("match_kind", "ambiguous_alias".into()),
                    ],
                )],
            ),
            measured(
                "executor_footprint",
                vec![obs(
                    "executor_footprint",
                    &[
                        ("scope", "layout".into()),
                        ("name", "Solara".into()),
                        ("path", r"C:\Users\a\Downloads\Solara".into()),
                    ],
                )],
            ),
        ];
        let run = correlate(&host(), &runs);
        let t = tools(&run);
        let solara = &t["solara"];
        assert_eq!(solara.fields["status"], "corroborated");
        assert_eq!(solara.fields["execution"], true);
        assert_eq!(solara.fields["missing_now"], true, "{run:?}");
        assert_eq!(solara.fields["first_seen"], "2026-10-14T20:00:00Z");
        assert!(solara.fields["families_count"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn srum_cpu_time_counts_as_execution_and_a_freed_mft_record_as_deleted() {
        let runs = vec![
            measured(
                "srum",
                vec![
                    obs("srum", &[("scope", "database".into())]),
                    obs(
                        "srum",
                        &[
                            ("scope", "app".into()),
                            ("name", "Fluxus.exe".into()),
                            (
                                "path",
                                r"\Device\HarddiskVolume3\Users\a\Downloads\Solara\Fluxus.exe"
                                    .into(),
                            ),
                            ("used_cpu", true.into()),
                            ("tool_id", "fluxus".into()),
                            ("match_kind", "known_tool".into()),
                            ("last_seen", "2026-10-14T21:00:00Z".into()),
                        ],
                    ),
                ],
            ),
            measured(
                "mft",
                vec![obs(
                    "mft",
                    &[
                        ("scope", "entry".into()),
                        ("in_use", false.into()),
                        ("name", "Fluxus.exe".into()),
                        ("path", r"C:\Users\a\Downloads\Solara\Fluxus.exe".into()),
                        ("tool_id", "fluxus".into()),
                        ("match_kind", "known_tool".into()),
                        ("si_modified", "2026-10-14T19:00:00Z".into()),
                    ],
                )],
            ),
        ];
        let run = correlate(&host(), &runs);
        let fluxus = &tools(&run)["fluxus"];
        assert_eq!(fluxus.fields["execution"], true);
        assert_eq!(fluxus.fields["deleted"], true);
        assert_eq!(fluxus.fields["status"], "corroborated");
        assert_eq!(fluxus.fields["families"], "mft, srum");
        let CollectorRun::Measured { observations, .. } = &run else {
            panic!()
        };
        for source in ["srum", "mft", "shellbags", "wmi_subscription"] {
            assert!(
                observations
                    .iter()
                    .any(|o| o.fields["scope"] == "source" && o.fields["source"] == source),
                "{source}"
            );
        }
    }

    #[test]
    fn an_in_use_mft_entry_is_the_same_family_as_the_folder_listing() {
        let runs = vec![
            measured(
                "roblox_files",
                vec![obs(
                    "roblox_files",
                    &[
                        ("scope", "file".into()),
                        ("name", "Fluxus.exe".into()),
                        ("path", r"C:\Users\a\Downloads\Fluxus.exe".into()),
                    ],
                )],
            ),
            measured(
                "mft",
                vec![obs(
                    "mft",
                    &[
                        ("scope", "entry".into()),
                        ("in_use", true.into()),
                        ("name", "Fluxus.exe".into()),
                        ("path", r"C:\Users\a\Downloads\Fluxus.exe".into()),
                    ],
                )],
            ),
            measured(
                "shellbags",
                vec![obs(
                    "shellbags",
                    &[
                        ("list", "shellbag".into()),
                        ("name", "Fluxus".into()),
                        ("path", r"E:\Ferramentas\Solara".into()),
                    ],
                )],
            ),
        ];
        let run = correlate(&host(), &runs);
        let fluxus = &tools(&run)["fluxus"];
        assert_eq!(fluxus.fields["families"], "file_listing, shellbags");
        assert_eq!(fluxus.fields["execution"], false);
    }

    #[test]
    fn an_ambiguous_name_alone_is_info_and_bloxstrap_is_info_even_when_run() {
        let runs = vec![
            measured(
                "prefetch",
                vec![
                    obs("prefetch", &[("name", "WAVE.EXE".into())]),
                    obs("prefetch", &[("name", "BLOXSTRAP.EXE".into())]),
                ],
            ),
            measured(
                "bam",
                vec![obs(
                    "bam",
                    &[
                        ("name", "Bloxstrap.exe".into()),
                        (
                            "path",
                            r"C:\Users\a\AppData\Local\Bloxstrap\Bloxstrap.exe".into(),
                        ),
                    ],
                )],
            ),
        ];
        let t = tools(&correlate(&host(), &runs));
        assert_eq!(t["wave"].fields["status"], "info");
        assert_eq!(t["bloxstrap"].fields["status"], "info");
        assert_eq!(t["bloxstrap"].fields["execution"], true);
        assert_eq!(t["bloxstrap"].fields["missing_now"], false);
    }

    #[test]
    fn a_known_executor_name_in_one_listing_is_suspected_and_a_module_in_roblox_is_detected() {
        let runs = vec![
            measured(
                "roblox_files",
                vec![obs(
                    "roblox_files",
                    &[
                        ("scope", "file".into()),
                        ("name", "KRNL.exe".into()),
                        ("path", r"C:\Users\a\Desktop\KRNL.exe".into()),
                        ("tool_id", "krnl".into()),
                        ("match_kind", "ambiguous_alias".into()),
                        ("roblox_context", true.into()),
                    ],
                )],
            ),
            measured(
                "roblox_process",
                vec![obs(
                    "roblox_process",
                    &[
                        ("scope", "roblox_module".into()),
                        ("name", "module.dll".into()),
                        ("path", r"C:\Users\a\AppData\Local\Fluxus\module.dll".into()),
                    ],
                )],
            ),
        ];
        let t = tools(&correlate(&host(), &runs));
        assert_eq!(t["krnl"].fields["status"], "suspected");
        assert_eq!(t["fluxus"].fields["status"], "detected");
        assert_eq!(t["fluxus"].fields["interaction"], true);
    }

    #[test]
    fn sources_say_what_could_not_be_looked_at() {
        let runs = vec![
            CollectorRun::Unmeasured {
                collector: "prefetch".to_owned(),
                reason: UnmeasuredReason::NotAdmin,
            },
            CollectorRun::Unmeasured {
                collector: "user_files".to_owned(),
                reason: UnmeasuredReason::NotConsented,
            },
        ];
        let CollectorRun::Measured { observations, .. } = correlate(&host(), &runs) else {
            panic!();
        };
        let state = |s: &str| {
            observations
                .iter()
                .find(|o| o.fields["scope"] == "source" && o.fields["source"] == s)
                .map(|o| o.fields["state"].as_str().unwrap().to_owned())
                .unwrap()
        };
        assert_eq!(state("prefetch"), "not_measured");
        assert_eq!(state("user_files"), "not_applicable");
        assert_eq!(state("bam"), "not_measured");
    }

    #[test]
    fn strap_partials_never_rise_above_info() {
        let runs = vec![measured(
            "roblox_files",
            vec![obs(
                "roblox_files",
                &[
                    ("scope", "file".into()),
                    ("name", "MyStrap.exe".into()),
                    ("path", r"C:\Users\a\Downloads\MyStrap.exe".into()),
                    ("tool_id", "strap_partial".into()),
                    ("match_kind", "weak_partial".into()),
                ],
            )],
        )];
        let t = tools(&correlate(&host(), &runs));
        assert_eq!(t["strap_partial"].fields["status"], "info");
    }

    #[test]
    fn rows_inside_an_unnamed_executor_layout_belong_to_it() {
        let runs = vec![measured(
            "executor_footprint",
            vec![
                obs(
                    "executor_footprint",
                    &[
                        ("scope", "layout".into()),
                        ("name", "ToolPack".into()),
                        ("path", r"C:\Users\a\Downloads\ToolPack".into()),
                    ],
                ),
                obs(
                    "executor_footprint",
                    &[
                        ("scope", "autoexec_script".into()),
                        ("name", "init.lua".into()),
                        (
                            "path",
                            r"C:\Users\a\Downloads\ToolPack\autoexec\init.lua".into(),
                        ),
                        ("distinct_markers", 3.into()),
                    ],
                ),
            ],
        )];
        let t = tools(&correlate(&host(), &runs));
        let unnamed = &t["unnamed_executor"];
        assert_eq!(unnamed.fields["status"], "detected");
        assert_eq!(unnamed.fields["hits"], 2);
        assert!(
            unnamed.fields["classes"]
                .as_str()
                .unwrap()
                .contains("executor_scripts")
        );
    }
}
