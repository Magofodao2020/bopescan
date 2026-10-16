// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The monitoring mode in the window (B.O.P.E, ADR 0137): started and stopped by the person, shown
//! while it runs, kept in memory only, and included in the next report. It ends when the window closes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bope_collectors::monitor::{self, Event, Session};

#[derive(Default)]
struct Monitor {
    session: Mutex<Option<Session>>,
    running: AtomicBool,
    stop: AtomicBool,
}

fn state() -> &'static Monitor {
    static STATE: OnceLock<Monitor> = OnceLock::new();
    STATE.get_or_init(Monitor::default)
}

/// The session for the next scan: the one running or the last one, if any.
pub fn session() -> Option<Arc<Session>> {
    let guard = state().session.lock().ok()?;
    guard.clone().map(Arc::new)
}

/// What the monitoring panel shows.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MonitorStatus {
    /// A session is running now.
    pub running: bool,
    /// When it started.
    pub started_at: Option<String>,
    /// When the last sample was taken.
    pub last_sample_at: Option<String>,
    /// Seconds between samples.
    pub interval_seconds: u64,
    /// Samples taken.
    pub samples: u64,
    /// Samples that read a player's memory only partly.
    pub partial_samples: u64,
    /// Every change seen, newest last.
    pub events: Vec<Event>,
    /// Changes past the limit, counted only.
    pub events_dropped: u64,
}

/// Where monitoring is.
#[tauri::command]
pub fn monitor_status() -> MonitorStatus {
    let monitor = state();
    let guard = monitor.session.lock();
    let Some(session) = guard.as_ref().ok().and_then(|g| g.as_ref()) else {
        return MonitorStatus::default();
    };
    MonitorStatus {
        running: monitor.running.load(Ordering::SeqCst),
        started_at: Some(session.started_at.clone()),
        last_sample_at: session.last_sample_at.clone(),
        interval_seconds: session.interval_seconds,
        samples: session.samples,
        partial_samples: session.partial_samples,
        events: session.events.clone(),
        events_dropped: session.events_dropped,
    }
}

/// Starts a session, replacing the last one. Returns whether it started (one runs at a time).
#[tauri::command]
pub fn start_monitor(interval_seconds: u64) -> bool {
    let monitor = state();
    if monitor.running.swap(true, Ordering::SeqCst) {
        return false;
    }
    monitor.stop.store(false, Ordering::SeqCst);
    let interval = Duration::from_secs(interval_seconds).max(monitor::MIN_INTERVAL);
    if let Ok(mut guard) = monitor.session.lock() {
        *guard = Some(Session::new(jiff::Timestamp::now(), interval, "desktop"));
    }
    std::thread::spawn(move || {
        let host = crate::live_host();
        while !monitor.stop.load(Ordering::SeqCst) {
            let began = Instant::now();
            let sample = monitor::sample(host.as_ref(), jiff::Timestamp::now());
            if let Ok(mut guard) = monitor.session.lock()
                && let Some(session) = guard.as_mut()
            {
                session.record(sample);
            }
            // Sleep in short steps so Stop answers quickly.
            while began.elapsed() < interval && !monitor.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        monitor.running.store(false, Ordering::SeqCst);
    });
    true
}

/// Asks the running session to stop after its current sample. Its events stay for the next report.
#[tauri::command]
pub fn stop_monitor() {
    state().stop.store(true, Ordering::SeqCst);
}

/// Forgets the last session, so the next report holds none.
#[tauri::command]
pub fn clear_monitor() -> bool {
    let monitor = state();
    if monitor.running.load(Ordering::SeqCst) {
        return false;
    }
    if let Ok(mut guard) = monitor.session.lock() {
        *guard = None;
    }
    true
}
