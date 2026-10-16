// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `bope-scanner-cli monitor`: the monitoring mode in a console (B.O.P.E, ADR 0137). It samples the
//! Roblox player at the interval asked for, prints every change as it sees it, and appends it to the
//! log file named — nothing else is written, nothing is sent, and it stops when the duration ends or
//! the console is closed (Ctrl+C). A later `scan --monitor-log FILE` puts the session in the report.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use bope_collectors::monitor::{self, Event, Session};
use bope_host::Host;

use crate::output::Lang;

fn describe(event: &Event) -> String {
    use std::fmt::Write as _;
    let mut line = format!("{}  {}", event.at, event.event);
    if let Some(pid) = event.pid {
        let _ = write!(line, "  pid {pid}");
    }
    let _ = write!(line, "  {}", event.subject);
    if let Some(source) = &event.source {
        let _ = write!(line, "  [{source}]");
    }
    match (&event.before, &event.after) {
        (Some(before), Some(after)) => {
            let _ = write!(line, "  {before} -> {after}");
        }
        (None, Some(after)) => {
            let _ = write!(line, "  = {after}");
        }
        _ => {}
    }
    if let Some(first) = &event.first_seen_at {
        let _ = write!(line, "  (value held earlier, last seen {first})");
    }
    line
}

/// Runs the monitoring mode.
pub fn run(
    host: &dyn Host,
    out: &Path,
    interval: Duration,
    duration: Duration,
    lang: Lang,
) -> anyhow::Result<()> {
    let interval = interval.max(monitor::MIN_INTERVAL);
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    let mut log = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out)
        .with_context(|| format!("could not create {} (it must not exist yet)", out.display()))?;
    let started = jiff::Timestamp::now();
    let mut session = Session::new(started, interval, "cli");
    writeln!(log, "{}", session.header_line())?;
    if lang == Lang::Pt {
        eprintln!(
            "Monitoramento iniciado: uma amostra a cada {}s por {}s. Somente leitura; nada é enviado. \
             Registro: {}. Ctrl+C para parar.",
            interval.as_secs(),
            duration.as_secs(),
            out.display()
        );
    } else {
        eprintln!(
            "Monitoring started: one sample every {}s for {}s. Read-only; nothing is sent. Log: {}. \
             Ctrl+C to stop.",
            interval.as_secs(),
            duration.as_secs(),
            out.display()
        );
    }
    let end = Instant::now() + duration;
    loop {
        let began = Instant::now();
        let sample = monitor::sample(host, jiff::Timestamp::now());
        let players = sample.players.len();
        for event in session.record(sample) {
            println!("{}", describe(&event));
            writeln!(log, "{}", serde_json::to_string(&event)?)?;
        }
        // The session's counters after each sample, so a log cut short by Ctrl+C still says how much
        // was watched.
        writeln!(log, "{}", session.header_line())?;
        log.flush()?;
        eprintln!(
            "{}  sample {}  players {players}",
            session.last_sample_at.as_deref().unwrap_or_default(),
            session.samples
        );
        if Instant::now() + interval > end {
            break;
        }
        std::thread::sleep(interval.saturating_sub(began.elapsed()));
    }
    Ok(())
}

/// A session read back from a log `run` wrote.
pub fn load(path: &Path) -> anyhow::Result<Session> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    Session::from_log(&text, &format!("log:{}", path.display()))
        .with_context(|| format!("{} is not a monitoring log", path.display()))
}

/// Where the log goes when the person names no file.
pub fn default_out() -> PathBuf {
    let stem = format!(
        "monitor-{}.jsonl",
        jiff::Timestamp::now().strftime("%Y%m%dT%H%M%SZ")
    );
    std::env::var_os("USERPROFILE")
        .map(|p| PathBuf::from(p).join("Documents").join("B.O.P.E Scanner"))
        .unwrap_or_default()
        .join(stem)
}
