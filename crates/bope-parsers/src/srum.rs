// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The System Resource Usage Monitor database, `SRUDB.dat` (B.O.P.E, ADR 0124), read through
//! [`crate::ese`].
//!
//! Three tables are read, and of each only what tells which program used the PC's resources and when:
//!
//! - `SruDbIdMapTable` — the numbers SRUM uses for applications (`IdType` 0, 1, 2: a path, a service
//!   or a packaged app name). User SIDs (`IdType` 3) are **not** read.
//! - `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` (application resource usage): `TimeStamp`, `AppId`,
//!   `ForegroundCycleTime`, `BackgroundCycleTime`. Nothing about bytes read or written.
//! - `{5C8CF1C7-7257-4F13-B223-970EF5939312}` (application timeline, Windows 10 1607 and later):
//!   `TimeStamp`, `AppId`, `EndTime`, `DurationMS`.
//! - `{973F5D5C-1D90-4944-BE8E-24B94231A174}` (network usage): `TimeStamp`, `AppId`, `BytesSent`,
//!   `BytesRecvd` — totals only; the interface and the network profile are not read.
//!
//! **What a row means.** SRUM writes to this database about once an hour, so `TimeStamp` is when the
//! hour's figures were recorded, not when a program started. Cycle time above zero is CPU time the
//! program used in that hour: the program ran. An application id with no usage row says only that
//! SRUM gave it a number. Rows still in SRUM's memory or in the transaction logs are absent.

use std::collections::BTreeMap;

use crate::error::ParseError;
use crate::ese::{self, Database, Limits, Value};

/// The application resource usage table.
pub const APP_RESOURCE_USAGE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
/// The application timeline table.
pub const APP_TIMELINE: &str = "{5C8CF1C7-7257-4F13-B223-970EF5939312}";
/// The network usage table.
pub const NETWORK_USAGE: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
/// The table that maps SRUM's numbers to names.
pub const ID_MAP: &str = "SruDbIdMapTable";

/// One application as SRUM knows it, with its usage summed over every row read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct App {
    /// SRUM's number for it.
    pub id: i64,
    /// `IdType`: 0 application path, 1 service, 2 packaged application.
    pub id_type: u8,
    /// What `IdBlob` names: a path (often `\Device\HarddiskVolumeN\...`), a service or a package.
    /// `None` when the name is in the long-value tree or could not be decoded.
    pub name: Option<String>,
    /// Resource usage rows.
    pub usage_rows: u64,
    /// Sum of `ForegroundCycleTime`.
    pub foreground_cycles: u64,
    /// Sum of `BackgroundCycleTime`.
    pub background_cycles: u64,
    /// Timeline rows.
    pub timeline_rows: u64,
    /// Sum of `DurationMS` over timeline rows.
    pub timeline_ms: u64,
    /// Network usage rows.
    pub network_rows: u64,
    /// Sum of `BytesSent`.
    pub bytes_sent: u64,
    /// Sum of `BytesRecvd`.
    pub bytes_received: u64,
    /// Earliest `TimeStamp` of any row.
    pub first_seen: Option<jiff::Timestamp>,
    /// Latest `TimeStamp` of any row, or latest `EndTime` of a timeline row.
    pub last_seen: Option<jiff::Timestamp>,
}

impl App {
    /// Whether SRUM recorded CPU time for it.
    pub fn used_cpu(&self) -> bool {
        self.foreground_cycles > 0 || self.background_cycles > 0 || self.timeline_ms > 0
    }

    fn seen(&mut self, at: Option<jiff::Timestamp>) {
        if let Some(t) = at {
            self.first_seen = Some(self.first_seen.map_or(t, |f| f.min(t)));
            self.last_seen = Some(self.last_seen.map_or(t, |l| l.max(t)));
        }
    }
}

/// What was read from one database.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Srum {
    /// Database state from the file header (2 is a database copied while in use).
    pub state: u32,
    /// Page size.
    pub page_size: u32,
    /// Which of the four tables were present.
    pub tables: Vec<String>,
    /// Applications, by id.
    pub apps: BTreeMap<i64, App>,
    /// Usage, timeline and network rows read.
    pub rows: u64,
    /// Names stored in the long-value tree, not read.
    pub names_not_read: u64,
    /// A limit, an unreadable page or a value this reader does not decode left something out.
    pub partial: bool,
    /// Latest `TimeStamp` of any row.
    pub newest_row: Option<jiff::Timestamp>,
    /// Earliest `TimeStamp` of any row.
    pub oldest_row: Option<jiff::Timestamp>,
}

fn time(v: &Value) -> Option<jiff::Timestamp> {
    match v {
        Value::OleDate(d) => ese::ole_date(*d),
        Value::Int(ft) => u64::try_from(*ft)
            .ok()
            .and_then(crate::filetime::to_timestamp),
        _ => None,
    }
}

/// Reads `SRUDB.dat` through `read`, a callback returning the bytes at an offset.
#[allow(clippy::too_many_lines)]
pub fn read<R: FnMut(u64, usize) -> Option<Vec<u8>>>(
    read: R,
    limits: Limits,
) -> Result<Srum, ParseError> {
    let mut db = Database::open(read, limits)?;
    let mut out = Srum {
        state: db.header.state,
        page_size: db.header.page_size,
        ..Srum::default()
    };
    let tables = db.tables()?;
    let find = |name: &str| tables.iter().find(|t| t.name.eq_ignore_ascii_case(name));
    let Some(map) = find(ID_MAP) else {
        return Err(ParseError::Malformed {
            field: "table",
            detail: "no SruDbIdMapTable: not a SRUM database".to_owned(),
        });
    };
    out.tables.push(ID_MAP.to_owned());
    let mut names_not_read = 0;
    let mut apps: BTreeMap<i64, App> = BTreeMap::new();
    let walk = db.records(map, &mut |r| {
        let Some(id_type) = r
            .named("IdType")
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
        else {
            return true;
        };
        if id_type > 2 {
            return true; // 3 is a user SID: not read.
        }
        let Some(id) = r.named("IdIndex").as_i64() else {
            return true;
        };
        let name = match r.named("IdBlob") {
            Value::Bytes(b) => Some(ese::utf16(&b)).filter(|s| !s.is_empty()),
            Value::Text(t) => Some(t).filter(|s| !s.is_empty()),
            Value::LongValue => {
                names_not_read += 1;
                None
            }
            _ => None,
        };
        apps.insert(
            id,
            App {
                id,
                id_type,
                name,
                ..App::default()
            },
        );
        true
    });
    out.partial |= walk.limited || walk.bad_pages > 0;
    out.names_not_read = names_not_read;
    for (table_name, kind) in [
        (APP_RESOURCE_USAGE, 0_u8),
        (APP_TIMELINE, 1),
        (NETWORK_USAGE, 2),
    ] {
        let Some(table) = find(table_name) else {
            continue;
        };
        out.tables.push(table_name.to_owned());
        let mut rows = 0;
        let mut newest: Option<jiff::Timestamp> = None;
        let mut oldest: Option<jiff::Timestamp> = None;
        let walk = db.records(table, &mut |r| {
            let Some(app_id) = r.named("AppId").as_i64() else {
                return true;
            };
            rows += 1;
            let at = time(&r.named("TimeStamp"));
            if let Some(t) = at {
                newest = Some(newest.map_or(t, |n| n.max(t)));
                oldest = Some(oldest.map_or(t, |o| o.min(t)));
            }
            let app = apps.entry(app_id).or_insert_with(|| App {
                id: app_id,
                ..App::default()
            });
            app.seen(at);
            let n = |name: &str| r.named(name).as_u64().unwrap_or(0);
            match kind {
                0 => {
                    app.usage_rows += 1;
                    app.foreground_cycles = app
                        .foreground_cycles
                        .saturating_add(n("ForegroundCycleTime"));
                    app.background_cycles = app
                        .background_cycles
                        .saturating_add(n("BackgroundCycleTime"));
                }
                1 => {
                    app.timeline_rows += 1;
                    app.timeline_ms = app.timeline_ms.saturating_add(n("DurationMS"));
                    app.seen(time(&r.named("EndTime")));
                }
                _ => {
                    app.network_rows += 1;
                    app.bytes_sent = app.bytes_sent.saturating_add(n("BytesSent"));
                    app.bytes_received = app.bytes_received.saturating_add(n("BytesRecvd"));
                }
            }
            true
        });
        out.rows += rows;
        out.partial |= walk.limited || walk.bad_pages > 0;
        out.newest_row = match (out.newest_row, newest) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        out.oldest_row = match (out.oldest_row, oldest) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    out.apps = apps;
    Ok(out)
}

/// Builds a synthetic `SRUDB.dat` for tests in this workspace: `apps` as `(id, id_type, name)`, and
/// usage rows as `(app id, OLE date, foreground cycles)`.
pub fn build(page_size: u32, apps: &[(i32, u8, &str)], usage: &[(i32, f64, u64)]) -> Vec<u8> {
    use ese::{Cell, Column, coltyp};
    let col = |id: u32, name: &str, kind: u32| Column {
        id,
        name: name.to_owned(),
        kind,
        space: 0,
        codepage: 1200,
    };
    let map_columns = vec![
        col(1, "IdType", coltyp::UNSIGNED_BYTE),
        col(2, "IdIndex", coltyp::LONG),
        col(256, "IdBlob", coltyp::LONG_BINARY),
    ];
    let map_rows = apps
        .iter()
        .map(|(id, kind, name)| {
            vec![
                (1, Cell::Fixed(vec![*kind])),
                (2, Cell::Fixed(id.to_le_bytes().to_vec())),
                (
                    256,
                    Cell::Tagged(
                        name.encode_utf16().flat_map(u16::to_le_bytes).collect(),
                        0x01,
                    ),
                ),
            ]
        })
        .collect();
    let usage_columns = vec![
        col(1, "AutoIncId", coltyp::LONG),
        col(2, "TimeStamp", coltyp::DATE_TIME),
        col(3, "AppId", coltyp::LONG),
        col(4, "UserId", coltyp::LONG),
        col(5, "ForegroundCycleTime", coltyp::LONG_LONG),
        col(6, "BackgroundCycleTime", coltyp::LONG_LONG),
    ];
    let usage_rows = usage
        .iter()
        .enumerate()
        .map(|(i, (app, at, cycles))| {
            vec![
                (
                    1,
                    Cell::Fixed(i32::try_from(i).unwrap_or(0).to_le_bytes().to_vec()),
                ),
                (2, Cell::Fixed(at.to_le_bytes().to_vec())),
                (3, Cell::Fixed(app.to_le_bytes().to_vec())),
                (4, Cell::Fixed(1_i32.to_le_bytes().to_vec())),
                (5, Cell::Fixed(cycles.to_le_bytes().to_vec())),
                (6, Cell::Fixed(0_u64.to_le_bytes().to_vec())),
            ]
        })
        .collect();
    ese::build(
        page_size,
        &[
            (ID_MAP.to_owned(), map_columns, map_rows),
            (APP_RESOURCE_USAGE.to_owned(), usage_columns, usage_rows),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(file: &[u8]) -> impl FnMut(u64, usize) -> Option<Vec<u8>> + '_ {
        move |offset, len| {
            let start = usize::try_from(offset).ok()?.min(file.len());
            Some(file[start..(start + len).min(file.len())].to_vec())
        }
    }

    #[test]
    fn apps_are_named_and_their_usage_summed() {
        // 46 000.5 is 2025-12-09T12:00:00Z.
        let file = build(
            4096,
            &[
                (
                    5,
                    0,
                    r"\Device\HarddiskVolume3\Users\a\Downloads\Solara\Solara.exe",
                ),
                (6, 3, "S-1-5-21-not-read"),
            ],
            &[(5, 46_000.5, 100), (5, 46_001.5, 50), (7, 46_000.0, 0)],
        );
        let srum = read(reader(&file), Limits::default()).unwrap();
        assert_eq!(srum.state, 2);
        assert_eq!(srum.rows, 3);
        let app = &srum.apps[&5];
        assert_eq!(
            app.name.as_deref().unwrap(),
            r"\Device\HarddiskVolume3\Users\a\Downloads\Solara\Solara.exe"
        );
        assert_eq!(app.foreground_cycles, 150);
        assert!(app.used_cpu());
        assert_eq!(app.first_seen.unwrap().to_string(), "2025-12-09T12:00:00Z");
        assert_eq!(app.last_seen.unwrap().to_string(), "2025-12-10T12:00:00Z");
        assert!(!srum.apps.contains_key(&6), "a user SID is not read");
        assert!(srum.apps[&7].name.is_none());
        assert!(!srum.apps[&7].used_cpu());
    }

    #[test]
    fn a_database_without_the_id_map_is_not_srum() {
        let file = ese::build(4096, &[("Other".to_owned(), Vec::new(), Vec::new())]);
        assert!(read(reader(&file), Limits::default()).is_err());
    }
}
