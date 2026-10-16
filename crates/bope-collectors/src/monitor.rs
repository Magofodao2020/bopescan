// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The monitoring mode: read-only samples of the Roblox player taken at an interval the person
//! chose, while the person watches, and what changed between them (B.O.P.E, ADR 0137).
//!
//! A single scan sees one moment. A flag value set and then put back, a module loaded for a minute, a
//! block of executable memory that comes and goes — those are seen only by looking more than once. The
//! monitoring mode looks more than once, **only when the person starts it, only while the window or
//! the console that started it is open, and showing every change as it is seen**. It installs nothing,
//! starts nothing with Windows, sends nothing anywhere, and writes only where the person pointed (the
//! command line's `--out` file); the desktop keeps the session in memory for the next report.
//!
//! Each sample reads, for every player: whether it could be opened, its modules, its private
//! executable regions and unlisted image mappings, and the `FastFlag` assignments written as JSON text
//! in its private memory (at most [`MAX_SAMPLE_BYTES`]); and the hash and flag values of every settings
//! file `fastflags` finds. [`Session::record`] compares each sample with the one before and keeps the
//! changes as [`Event`]s, each with the time of the sample that saw it. A flag that comes back to a value
//! it had earlier in the session gives a `flag_value_restored` event naming both times.
//!
//! What it cannot see: a change made and undone between two samples. The interval bounds what was
//! looked at, and the session says so; nothing between samples is inferred.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use bope_host::{Host, RegionKind};
use bope_parsers::memory;
use serde::{Deserialize, Serialize};

use crate::fastflags::settings_files;
use crate::procmem::{
    ModuleMap, executable_allocations, hex_address, read_chunks, unlisted_images,
};
use crate::roblox_process::roblox_edition;

/// Most bytes of one player's memory read for flag values in one sample.
pub const MAX_SAMPLE_BYTES: u64 = 256 * 1024 * 1024;
/// Longest one sample may take.
pub const SAMPLE_BUDGET: Duration = Duration::from_secs(20);
/// Shortest interval between samples.
pub const MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Most events a session keeps; later ones are counted, not kept.
pub const MAX_EVENTS: usize = 5_000;
/// Most flag values kept per player per sample.
const MAX_FLAGS: usize = 2_000;
/// Most regions walked per player per sample.
const MAX_REGIONS: usize = 400_000;

/// One player at one sample.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayerSample {
    /// Process id.
    pub pid: u32,
    /// Its image path.
    pub path: Option<String>,
    /// Whether its memory could be opened.
    pub opened: bool,
    /// Module path (lower case) → base address.
    pub modules: BTreeMap<String, u64>,
    /// Bases of private executable regions.
    pub executable_regions: BTreeSet<u64>,
    /// Bases of image mappings the loader does not list.
    pub unlisted_images: BTreeSet<u64>,
    /// Flag → value, from JSON text in private memory.
    pub flags: BTreeMap<String, String>,
    /// The memory read stopped at the limit or the budget.
    pub partial: bool,
}

/// One settings file at one sample.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSample {
    /// Its SHA-256, when it could be read.
    pub sha256: Option<String>,
    /// Flag → value.
    pub flags: BTreeMap<String, String>,
}

/// One sample.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    /// When it was taken, RFC 3339.
    pub taken_at: String,
    /// Each player, by pid.
    pub players: BTreeMap<u32, PlayerSample>,
    /// Each settings file, by path.
    pub files: BTreeMap<String, FileSample>,
}

/// One change seen between two samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// When the sample that saw it was taken, RFC 3339.
    pub at: String,
    /// When the sample before it was taken: the change happened between the two.
    pub since: Option<String>,
    /// What changed: `player_started`, `player_exited`, `access_changed`, `module_loaded`,
    /// `module_unloaded`, `executable_region_appeared`, `executable_region_gone`,
    /// `unlisted_image_appeared`, `unlisted_image_gone`, `flag_value_changed`, `flag_value_restored`,
    /// `settings_file_changed`.
    pub event: String,
    /// The player, when it is about one.
    pub pid: Option<u32>,
    /// What it is about: a module path, an address, a flag, a file.
    pub subject: String,
    /// `memory` or a settings file's path, for flag events.
    pub source: Option<String>,
    /// The value before, when there is one.
    pub before: Option<String>,
    /// The value after, when there is one.
    pub after: Option<String>,
    /// For `flag_value_restored`: when the value first held was last seen before it changed.
    pub first_seen_at: Option<String>,
}

/// A monitoring session: its samples' times, its events, and what it could not see.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// When it started, RFC 3339.
    pub started_at: String,
    /// When the last sample was taken.
    pub last_sample_at: Option<String>,
    /// The interval asked for, in seconds.
    pub interval_seconds: u64,
    /// How many samples were taken.
    pub samples: u64,
    /// How many samples read a player's memory only partly.
    pub partial_samples: u64,
    /// The changes, in order.
    pub events: Vec<Event>,
    /// Changes seen after [`MAX_EVENTS`], counted only.
    pub events_dropped: u64,
    /// Every pid seen.
    pub players_seen: BTreeSet<u32>,
    /// Where the session came from: `desktop`, or `log:` and the file.
    pub origin: String,
    #[serde(skip)]
    last: Option<Sample>,
    /// (source, pid, flag) → the values held, in order, with the last time each was seen.
    #[serde(skip)]
    history: BTreeMap<(String, u32, String), Vec<(String, String)>>,
}

/// Takes one sample.
pub fn sample(host: &dyn Host, now: jiff::Timestamp) -> Sample {
    let deadline = Instant::now() + SAMPLE_BUDGET;
    let mut out = Sample {
        taken_at: now.to_string(),
        ..Sample::default()
    };
    for process in host.running_processes().unwrap_or_default() {
        if roblox_edition(&process).is_none() {
            continue;
        }
        let mut player = PlayerSample {
            pid: process.pid,
            path: process.path.clone(),
            ..PlayerSample::default()
        };
        if let Ok(reader) = host.open_process_memory(process.pid) {
            player.opened = true;
            let map = ModuleMap::new(reader.modules().unwrap_or_default());
            player.modules = map
                .modules()
                .iter()
                .map(|m| (m.path.to_ascii_lowercase(), m.base))
                .collect();
            let (regions, complete) = reader.regions(MAX_REGIONS).unwrap_or_default();
            player.partial |= !complete;
            player.executable_regions = executable_allocations(reader.as_ref(), &regions, 4096)
                .into_iter()
                .map(|a| a.region.base)
                .collect();
            player.unlisted_images = unlisted_images(&regions, &map)
                .into_iter()
                .map(|r| r.allocation_base)
                .collect();
            let mut scanned = 0_u64;
            for region in regions
                .iter()
                .filter(|r| r.is_readable() && r.kind == RegionKind::Private)
            {
                if scanned >= MAX_SAMPLE_BYTES || Instant::now() >= deadline {
                    player.partial = true;
                    break;
                }
                let size = region.size.min(MAX_SAMPLE_BYTES - scanned);
                let (read, _) = read_chunks(reader.as_ref(), region.base, size, |at, bytes| {
                    for a in memory::flag_assignments(bytes, at, MAX_FLAGS) {
                        if player.flags.len() < MAX_FLAGS {
                            player.flags.insert(a.name, a.value);
                        }
                    }
                });
                scanned += read;
            }
        }
        out.players.insert(process.pid, player);
    }
    for file in settings_files(host).files {
        let flags = host
            .read_file(&file.path)
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|v| v.as_object().cloned())
            .map(|object| {
                object
                    .iter()
                    .filter(|(k, _)| crate::fastflags::is_flag_name(k))
                    .filter_map(|(k, v)| Some((k.clone(), crate::roblox_flags::value_text(v)?)))
                    .collect()
            })
            .unwrap_or_default();
        out.files.insert(
            file.path.clone(),
            FileSample {
                sha256: host.file_sha256(&file.path).ok(),
                flags,
            },
        );
    }
    out
}

fn diff_sets(
    events: &mut Vec<(String, Option<u32>, String)>,
    pid: u32,
    before: &BTreeSet<u64>,
    after: &BTreeSet<u64>,
    appeared: &str,
    gone: &str,
) {
    for base in after.difference(before) {
        events.push((appeared.to_owned(), Some(pid), hex_address(*base)));
    }
    for base in before.difference(after) {
        events.push((gone.to_owned(), Some(pid), hex_address(*base)));
    }
}

impl Session {
    /// A new, empty session.
    pub fn new(started_at: jiff::Timestamp, interval: Duration, origin: &str) -> Self {
        Self {
            started_at: started_at.to_string(),
            interval_seconds: interval.as_secs(),
            origin: origin.to_owned(),
            ..Self::default()
        }
    }

    fn push(&mut self, event: Event) -> Option<Event> {
        if self.events.len() >= MAX_EVENTS {
            self.events_dropped += 1;
            return None;
        }
        self.events.push(event.clone());
        Some(event)
    }

    /// Records a flag value seen at `at`, and returns the events it gives.
    fn flag_seen(
        &mut self,
        key: (String, u32, String),
        value: &str,
        at: &str,
        since: Option<&str>,
    ) -> Vec<Event> {
        let pid = (key.1 != 0).then_some(key.1);
        let source = key.0.clone();
        let flag = key.2.clone();
        let values = self.history.entry(key).or_default();
        let mut out = Vec::new();
        match values.last_mut() {
            Some((last, seen)) if last == value => at.clone_into(seen),
            Some((last, _)) => {
                let before = last.clone();
                let restored_from = values
                    .iter()
                    .rev()
                    .skip(1)
                    .find(|(v, _)| v == value)
                    .map(|(_, seen)| seen.clone());
                values.push((value.to_owned(), at.to_owned()));
                let base = Event {
                    at: at.to_owned(),
                    since: since.map(str::to_owned),
                    event: "flag_value_changed".to_owned(),
                    pid,
                    subject: flag,
                    source: Some(source),
                    before: Some(before),
                    after: Some(value.to_owned()),
                    first_seen_at: None,
                };
                if let Some(first) = restored_from {
                    out.push(Event {
                        event: "flag_value_restored".to_owned(),
                        first_seen_at: Some(first),
                        ..base.clone()
                    });
                }
                out.insert(0, base);
            }
            None => values.push((value.to_owned(), at.to_owned())),
        }
        out
    }

    /// Compares `sample` with the one before and keeps what changed. Returns the new events, for the
    /// caller to show as they happen.
    #[allow(clippy::too_many_lines)]
    pub fn record(&mut self, sample: Sample) -> Vec<Event> {
        self.samples += 1;
        if sample.players.values().any(|p| p.partial) {
            self.partial_samples += 1;
        }
        self.players_seen.extend(sample.players.keys().copied());
        let at = sample.taken_at.clone();
        let since = self.last.as_ref().map(|s| s.taken_at.clone());
        let mut changes: Vec<(String, Option<u32>, String)> = Vec::new();
        let mut flag_events = Vec::new();
        if let Some(previous) = self.last.take() {
            for (pid, player) in &sample.players {
                let Some(before) = previous.players.get(pid) else {
                    changes.push((
                        "player_started".to_owned(),
                        Some(*pid),
                        player.path.clone().unwrap_or_default(),
                    ));
                    continue;
                };
                if before.opened != player.opened {
                    changes.push((
                        "access_changed".to_owned(),
                        Some(*pid),
                        if player.opened { "opened" } else { "refused" }.to_owned(),
                    ));
                }
                if !(before.opened && player.opened) {
                    continue;
                }
                for path in player.modules.keys() {
                    if !before.modules.contains_key(path) {
                        changes.push(("module_loaded".to_owned(), Some(*pid), path.clone()));
                    }
                }
                for path in before.modules.keys() {
                    if !player.modules.contains_key(path) {
                        changes.push(("module_unloaded".to_owned(), Some(*pid), path.clone()));
                    }
                }
                diff_sets(
                    &mut changes,
                    *pid,
                    &before.executable_regions,
                    &player.executable_regions,
                    "executable_region_appeared",
                    "executable_region_gone",
                );
                diff_sets(
                    &mut changes,
                    *pid,
                    &before.unlisted_images,
                    &player.unlisted_images,
                    "unlisted_image_appeared",
                    "unlisted_image_gone",
                );
            }
            for (pid, player) in &previous.players {
                if !sample.players.contains_key(pid) {
                    changes.push((
                        "player_exited".to_owned(),
                        Some(*pid),
                        player.path.clone().unwrap_or_default(),
                    ));
                }
            }
            for (path, file) in &sample.files {
                if previous
                    .files
                    .get(path)
                    .is_some_and(|before| before.sha256 != file.sha256)
                {
                    changes.push(("settings_file_changed".to_owned(), None, path.clone()));
                }
            }
        }
        for (pid, player) in &sample.players {
            for (flag, value) in &player.flags {
                flag_events.extend(self.flag_seen(
                    ("memory".to_owned(), *pid, flag.clone()),
                    value,
                    &at,
                    since.as_deref(),
                ));
            }
        }
        for (path, file) in &sample.files {
            for (flag, value) in &file.flags {
                flag_events.extend(self.flag_seen(
                    (path.clone(), 0, flag.clone()),
                    value,
                    &at,
                    since.as_deref(),
                ));
            }
        }
        let mut new = Vec::new();
        for (event, pid, subject) in changes {
            new.extend(self.push(Event {
                at: at.clone(),
                since: since.clone(),
                event,
                pid,
                subject,
                source: None,
                before: None,
                after: None,
                first_seen_at: None,
            }));
        }
        for event in flag_events {
            new.extend(self.push(event));
        }
        self.last_sample_at = Some(at);
        self.last = Some(sample);
        new
    }

    /// Reads a session back from a log the command line wrote: one JSON object per line, the first
    /// the session's header and the others events.
    pub fn from_log(text: &str, origin: &str) -> Option<Self> {
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let mut session: Self = serde_json::from_str(lines.next()?).ok()?;
        origin.clone_into(&mut session.origin);
        for line in lines {
            if let Ok(event) = serde_json::from_str::<Event>(line) {
                if session.events.len() < MAX_EVENTS {
                    session.events.push(event);
                }
            } else if let Ok(footer) = serde_json::from_str::<Self>(line) {
                session.samples = footer.samples;
                session.partial_samples = footer.partial_samples;
                session.last_sample_at = footer.last_sample_at;
                session.players_seen = footer.players_seen;
                session.events_dropped = footer.events_dropped;
            }
        }
        Some(session)
    }

    /// The session's header (or footer) line for a log: everything but the events.
    pub fn header_line(&self) -> String {
        let mut copy = self.clone();
        copy.events.clear();
        serde_json::to_string(&copy).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn player(flags: &[(&str, &str)], modules: &[&str]) -> PlayerSample {
        PlayerSample {
            pid: 1200,
            path: Some(r"C:\R\RobloxPlayerBeta.exe".to_owned()),
            opened: true,
            modules: modules.iter().map(|m| ((*m).to_owned(), 0x1000)).collect(),
            flags: flags
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..PlayerSample::default()
        }
    }

    fn at(time: &str, player: PlayerSample) -> Sample {
        Sample {
            taken_at: time.to_owned(),
            players: [(player.pid, player)].into(),
            files: BTreeMap::new(),
        }
    }

    #[test]
    fn a_flag_set_and_put_back_and_a_module_that_came_and_went_are_events() {
        let mut session = Session::new(
            "2026-10-16T10:00:00Z".parse().unwrap(),
            Duration::from_secs(30),
            "desktop",
        );
        let a = &[("DFIntS2PhysicsSenderRate", "15")];
        let b = &[("DFIntS2PhysicsSenderRate", "1")];
        assert!(
            session
                .record(at("2026-10-16T10:00:00Z", player(a, &["x"])))
                .is_empty()
        );
        let second = session.record(at("2026-10-16T10:00:30Z", player(b, &["x", "inject.dll"])));
        assert!(
            second
                .iter()
                .any(|e| e.event == "module_loaded" && e.subject == "inject.dll")
        );
        assert!(second.iter().any(|e| e.event == "flag_value_changed"
            && e.before.as_deref() == Some("15")
            && e.after.as_deref() == Some("1")
            && e.since.as_deref() == Some("2026-10-16T10:00:00Z")));
        let third = session.record(at("2026-10-16T10:01:00Z", player(a, &["x"])));
        let restored = third
            .iter()
            .find(|e| e.event == "flag_value_restored")
            .unwrap();
        assert_eq!(restored.after.as_deref(), Some("15"));
        assert_eq!(
            restored.first_seen_at.as_deref(),
            Some("2026-10-16T10:00:00Z")
        );
        assert!(third.iter().any(|e| e.event == "module_unloaded"));
        assert_eq!(session.samples, 3);
    }

    #[test]
    fn a_log_reads_back_into_the_same_session() {
        let mut session = Session::new(
            "2026-10-16T10:00:00Z".parse().unwrap(),
            Duration::from_secs(30),
            "cli",
        );
        session.record(at("2026-10-16T10:00:00Z", player(&[], &["x"])));
        let events = session.record(at("2026-10-16T10:00:30Z", player(&[], &["x", "y"])));
        let mut log = session.header_line();
        for event in &events {
            log.push('\n');
            log.push_str(&serde_json::to_string(event).unwrap());
        }
        log.push('\n');
        log.push_str(&session.header_line());
        let back = Session::from_log(&log, "log:x.jsonl").unwrap();
        assert_eq!(back.events, session.events);
        assert_eq!(back.samples, 2);
        assert_eq!(back.origin, "log:x.jsonl");
    }
}
