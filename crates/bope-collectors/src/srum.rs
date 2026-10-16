// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `SRUDB.dat`: which programs the System Resource Usage Monitor recorded using the PC's resources
//! (B.O.P.E, ADR 0124).
//!
//! The Diagnostic Policy Service keeps `%SystemRoot%\System32\sru\SRUDB.dat` open, so the live file
//! normally cannot be read. Like `amcache`, this collector tries it once and then reads the database
//! from the newest **existing** volume shadow copy; it never creates one, never replays transaction
//! logs and never writes anything. Reading shadow copies needs administrator rights.
//!
//! Kept: a summary (`scope: database`) and one row per application whose name matches the Roblox tool
//! catalog, whose path names Roblox, or whose path is in a folder the account can write to
//! (`scope: app`), with its CPU cycles, application-timeline duration and network byte totals summed
//! over the rows read and the first and last hour SRUM recorded it. Services, packaged apps and
//! programs elsewhere are counted, not listed. User SIDs are never read.
//!
//! **What a row means.** `used_cpu` is SRUM recording CPU time for that program: it ran in that hour.
//! A row with no CPU time says only that SRUM gave the program a number. SRUM writes about once an
//! hour, so times are hours, not starts; a shadow copy is older than the scan, and the newest hour
//! of the database (`newest_row`) bounds what it can show.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, SourceError};
use bope_parsers::{ese, srum};

use crate::amcache::newest_shadow;
use crate::catalog;
use crate::common::{Fields, env_folder, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "srum";
const DISCRIMINATOR: &str = "scope";
const RELATIVE: &str = r"System32\sru\SRUDB.dat";
/// Most application rows listed.
pub const MAX_APPS: usize = 500;
/// Most pages read from one database: 40 000 pages is 160 MiB of 4 KiB pages.
pub const MAX_PAGES: usize = 40_000;

static FIELDS: [Field; 33] = [
    Field::number("app_id"),
    Field::number("apps_listed"),
    Field::number("apps_total"),
    Field::number("background_cycles"),
    Field::number("bytes_received"),
    Field::number("bytes_sent"),
    Field::boolean("common_legitimate"),
    Field::boolean("dirty"),
    Field::timestamp("first_seen"),
    Field::number("foreground_cycles"),
    Field::text("id_type"),
    Field::timestamp("last_seen"),
    Field::text("location_kind"),
    Field::text("match_kind"),
    Field::text("name"),
    Field::number("names_not_read"),
    Field::number("network_rows"),
    Field::timestamp("newest_row").off_timeline(),
    Field::timestamp("oldest_row").off_timeline(),
    Field::number("page_size"),
    Field::boolean("partial"),
    Field::text("path"),
    Field::boolean("roblox_context"),
    Field::number("rows"),
    Field::text("scope"),
    Field::number("shadow_index"),
    Field::text("source"),
    Field::text("tables"),
    Field::number("timeline_ms"),
    Field::text("tool_id"),
    Field::text("tool_kind"),
    Field::number("usage_rows"),
    Field::boolean("used_cpu"),
];

static REASONS: [UnmeasuredReason; 6] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::BudgetSpent,
];

/// The `srum` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct Srum;

/// Reads the database at `path` through the host, page by page.
fn read(host: &dyn Host, path: &str) -> Result<srum::Srum, Option<SourceError>> {
    let mut error: Option<SourceError> = None;
    let result = srum::read(
        |offset, len| match host.read_file_at(path, offset, len) {
            Ok(Some(bytes)) => Some(bytes),
            Ok(None) => None,
            Err(e) => {
                error.get_or_insert(e);
                None
            }
        },
        ese::Limits {
            max_pages: MAX_PAGES,
            ..ese::Limits::default()
        },
    );
    match (result, error) {
        (Ok(parsed), _) => Ok(parsed),
        (Err(_), e) => Err(e),
    }
}

fn id_type(kind: u8) -> &'static str {
    match kind {
        0 => "application",
        1 => "service",
        _ => "package",
    }
}

impl Collector for Srum {
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
        let (parsed, source, shadow_index) = match host.file_size(&live) {
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(SourceError::Unsupported(_)) => {
                return unmeasured(ID, UnmeasuredReason::SourceAbsent);
            }
            other => {
                let live_read = if other.is_ok() {
                    read(host, &live)
                } else {
                    Err(other.err())
                };
                if let Ok(parsed) = live_read {
                    (parsed, "live", None)
                } else {
                    {
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
                        match read(host, &path) {
                            Ok(parsed) => (parsed, "shadow_copy", Some(n)),
                            Err(Some(SourceError::TooLarge { .. })) => {
                                return unmeasured(ID, UnmeasuredReason::BudgetSpent);
                            }
                            Err(Some(error)) => {
                                return unmeasured(ID, crate::common::reason(host, &error));
                            }
                            Err(None) => return unmeasured(ID, UnmeasuredReason::ReadFailed),
                        }
                    }
                }
            }
        };
        let mut observations = Vec::new();
        let mut listed = 0_usize;
        for app in parsed.apps.values() {
            if listed >= MAX_APPS {
                break;
            }
            let Some(name_or_path) = app.name.as_deref() else {
                continue;
            };
            let file = location::last_segment(name_or_path);
            let found = catalog::match_name(file).into_iter().next();
            let kind = location::classify_any(name_or_path);
            let roblox_context = catalog::path_mentions_roblox(name_or_path);
            let keep =
                found.is_some() || roblox_context || (app.id_type == 0 && kind.is_user_writable());
            if !keep {
                continue;
            }
            listed += 1;
            let is_path = name_or_path.contains('\\');
            let mut fields = Fields::new()
                .with(DISCRIMINATOR, "app")
                .with("app_id", app.id)
                .with("id_type", id_type(app.id_type))
                .with("name", file.to_owned())
                .maybe("path", is_path.then(|| name_or_path.to_owned()))
                .with(location::FIELD, kind.as_str())
                .with("roblox_context", roblox_context)
                .with("used_cpu", app.used_cpu())
                .with("usage_rows", app.usage_rows)
                .with("foreground_cycles", app.foreground_cycles)
                .with("background_cycles", app.background_cycles)
                .with("timeline_ms", app.timeline_ms)
                .with("network_rows", app.network_rows)
                .with("bytes_sent", app.bytes_sent)
                .with("bytes_received", app.bytes_received)
                .time("first_seen", app.first_seen)
                .time("last_seen", app.last_seen);
            if let Some(m) = found {
                fields = fields
                    .with("tool_id", m.tool.id)
                    .with("tool_kind", m.tool.kind.as_str())
                    .with("match_kind", m.kind.as_str())
                    .with("common_legitimate", m.tool.common_legitimate);
            }
            observations.push(fields.observe(ID));
        }
        let mut gaps = BTreeMap::new();
        if parsed.names_not_read > 0 {
            gaps.insert("path".to_owned(), UnmeasuredReason::Partial);
        }
        observations.insert(
            0,
            Fields::new()
                .with(DISCRIMINATOR, "database")
                .with("source", source)
                .maybe("shadow_index", shadow_index)
                .with("dirty", parsed.state != 3)
                .with("page_size", parsed.page_size)
                .with("tables", parsed.tables.join(", "))
                .with("apps_total", parsed.apps.len())
                .with("apps_listed", listed)
                .with("rows", parsed.rows)
                .with("names_not_read", parsed.names_not_read)
                .with("partial", parsed.partial)
                .time("oldest_row", parsed.oldest_row)
                .time("newest_row", parsed.newest_row)
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

    use super::*;

    fn database() -> String {
        crate::common::hex(&srum::build(
            4096,
            &[
                (
                    1,
                    0,
                    r"\Device\HarddiskVolume3\Users\a\AppData\Local\Solara\Solara.exe",
                ),
                (
                    2,
                    0,
                    r"\Device\HarddiskVolume3\Windows\System32\svchost.exe",
                ),
                (3, 1, "wuauserv"),
            ],
            &[(1, 46_000.5, 900), (2, 46_000.5, 5)],
        ))
    }

    fn run(yaml_tail: &str, elevated: bool) -> CollectorRun {
        let yaml = format!(
            "platform: windows\nelevated: {elevated}\nenv:\n  SystemRoot: 'C:\\Windows'\naccess_denied: ['C:\\Windows\\System32\\sru\\SRUDB.dat']\nfilesystem:\n  'C:\\Windows\\System32\\sru':\n    - {{ name: SRUDB.dat }}\n{yaml_tail}"
        );
        Srum.collect(&FixtureHost::from_yaml_str(&yaml, "inline").unwrap())
    }

    fn observations(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => panic!("{run:?}"),
        }
    }

    #[test]
    fn the_shadow_copy_database_lists_catalog_apps_that_used_the_cpu() {
        let tail = format!(
            "  '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3\\Windows\\System32\\sru':\n    - {{ name: SRUDB.dat, hex: '{}' }}\n",
            database()
        );
        let run = run(&tail, true);
        let all = observations(&run);
        assert_eq!(all[0].fields["source"], "shadow_copy");
        assert_eq!(all[0].fields["shadow_index"], 3);
        assert_eq!(all[0].fields["apps_total"], 3);
        assert_eq!(all[0].fields["apps_listed"], 1);
        let solara = &all[1];
        assert_eq!(solara.fields["tool_id"], "solara");
        assert_eq!(solara.fields["used_cpu"], true);
        assert_eq!(solara.fields["foreground_cycles"], 900);
        assert_eq!(solara.fields["location_kind"], "appdata_local");
        assert_eq!(solara.fields["first_seen"], "2025-12-09T12:00:00Z");
        assert_eq!(
            all.len(),
            2,
            "svchost and the service are counted, not listed"
        );
    }

    #[test]
    fn no_shadow_copy_is_absent_or_not_admin_and_garbage_is_read_failed() {
        assert_eq!(
            run("", true),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
        assert_eq!(run("", false), unmeasured(ID, UnmeasuredReason::NotAdmin));
        assert_eq!(
            Srum.collect(&NonWindowsHost),
            unmeasured(ID, UnmeasuredReason::NotWindows)
        );
        let tail = "  '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\sru':\n    - { name: SRUDB.dat, content: 'not a database' }\n";
        assert_eq!(
            run(tail, true),
            unmeasured(ID, UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn a_missing_database_is_source_absent() {
        let yaml = "platform: windows\nelevated: true\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  'C:\\Windows\\System32\\sru': []\n";
        assert_eq!(
            Srum.collect(&FixtureHost::from_yaml_str(yaml, "inline").unwrap()),
            unmeasured(ID, UnmeasuredReason::SourceAbsent)
        );
    }
}
