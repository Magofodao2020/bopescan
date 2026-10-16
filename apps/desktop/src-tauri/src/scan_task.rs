// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The one scan this window may run, on a worker thread, with its progress and its cancellation
//! (B.O.P.E, ADR 0115).
//!
//! The UI asks for a scan to start, polls its status and may ask for it to stop. Stopping takes effect
//! between collectors — each collector bounds its own reads — and a stopped scan has no report at all,
//! so nothing half-measured can be shown or saved as if it were complete.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bope_collectors::scan::{self, Progress, ScanContext};
use bope_core::bundle::Bundle;
use bope_core::engine::SelfIdentity;
use bope_core::model::{Report, ScanTier};
use bope_core::provenance::Provenance;
use serde::Serialize;

/// Where a scan is.
#[derive(Debug, Clone)]
pub enum Phase {
    /// Nothing started yet.
    Idle,
    /// Running.
    Running {
        /// The tier chosen.
        tier: ScanTier,
    },
    /// Finished, with its frozen report.
    Done(Box<Report>),
    /// Stopped by the person; there is no report.
    Cancelled,
    /// The scan could not run at all.
    Failed(String),
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    steps: Vec<Progress>,
    started_at: Option<String>,
}

/// The shared state of the one scan.
#[derive(Debug, Clone)]
pub struct ScanSlot {
    inner: Arc<Mutex<Inner>>,
    cancel: Arc<AtomicBool>,
}

impl Default for ScanSlot {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                phase: Phase::Idle,
                steps: Vec::new(),
                started_at: None,
            })),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// What the UI polls.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    /// `idle`, `running`, `done`, `cancelled` or `failed`.
    pub state: &'static str,
    /// The collectors that have finished, in order.
    pub steps: Vec<Progress>,
    /// How many collectors this build has.
    pub total: usize,
    /// When the scan started, RFC 3339 UTC.
    pub started_at: Option<String>,
    /// Why it failed, when it did.
    pub message: Option<String>,
    /// The tier of the running scan.
    pub tier: Option<ScanTier>,
    /// The collector running now, while the scan runs and before the report is built; `None` when
    /// none is (not running, or building the report after the last one).
    pub current: Option<String>,
    /// Whether a stop was asked for and the scan has not stopped yet.
    pub cancel_requested: bool,
}

impl ScanSlot {
    /// Starts a scan at `tier` unless one is running; a new scan replaces a finished one. Returns
    /// whether it started.
    pub fn start(&self, tier: ScanTier, provenance: Provenance) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if matches!(inner.phase, Phase::Running { .. }) {
            return false;
        }
        let generated_at = jiff::Timestamp::now().to_string();
        inner.phase = Phase::Running { tier };
        inner.steps.clear();
        inner.started_at = Some(generated_at.clone());
        self.cancel.store(false, Ordering::SeqCst);
        drop(inner);

        let slot = self.clone();
        std::thread::spawn(move || {
            let outcome = run(&slot, tier, provenance, generated_at);
            if let Ok(mut inner) = slot.inner.lock() {
                inner.phase = outcome;
            }
        });
        true
    }

    /// Asks a running scan to stop before its next collector.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// The status the UI polls.
    pub fn status(&self) -> Status {
        let total = bope_collectors::all().len();
        let Ok(inner) = self.inner.lock() else {
            return Status {
                state: "failed",
                steps: Vec::new(),
                total,
                started_at: None,
                message: Some("state lock poisoned".to_owned()),
                tier: None,
                current: None,
                cancel_requested: false,
            };
        };
        let (state, message, tier) = match &inner.phase {
            Phase::Idle => ("idle", None, None),
            Phase::Running { tier } => ("running", None, Some(*tier)),
            Phase::Done(report) => ("done", None, Some(report.header.scan_tier)),
            Phase::Cancelled => ("cancelled", None, None),
            Phase::Failed(message) => ("failed", Some(message.clone()), None),
        };
        let running = matches!(inner.phase, Phase::Running { .. });
        let current = if !running {
            None
        } else if let Some(last) = inner.steps.last() {
            last.next.clone()
        } else {
            bope_collectors::all().first().map(|c| c.id().to_owned())
        };
        Status {
            state,
            steps: inner.steps.clone(),
            total,
            started_at: inner.started_at.clone(),
            message,
            tier,
            current,
            cancel_requested: running && self.cancel.load(Ordering::SeqCst),
        }
    }

    /// The finished report, when there is one.
    pub fn report(&self) -> Option<Report> {
        let inner = self.inner.lock().ok()?;
        match &inner.phase {
            Phase::Done(report) => Some((**report).clone()),
            _ => None,
        }
    }
}

fn run(slot: &ScanSlot, tier: ScanTier, provenance: Provenance, generated_at: String) -> Phase {
    let bundle = match Bundle::embedded() {
        Ok(bundle) => bundle,
        Err(error) => return Phase::Failed(error.to_string()),
    };
    // This program is in its own process list while it scans; the engine separates those traces
    // (ADR 0010).
    let self_identity = SelfIdentity {
        exe_path: std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
        exe_sha256: provenance.exe_sha256.clone(),
    };
    let context = ScanContext {
        provenance,
        generated_at,
        self_identity,
        tier,
    };
    let host = crate::live_host();
    let result = scan::run_with_progress(host.as_ref(), &bundle, context, &mut |step| {
        if let Ok(mut inner) = slot.inner.lock() {
            inner.steps.push(step);
        }
        !slot.cancel.load(Ordering::SeqCst)
    });
    match result {
        Ok(report) => Phase::Done(Box::new(report)),
        Err(scan::Cancelled) => Phase::Cancelled,
    }
}
