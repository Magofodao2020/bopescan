// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The `roblox_monitor` collector: the monitoring session the person ran, if any, in the report
//! (B.O.P.E, ADR 0137). The sampling itself is in [`crate::monitor`].

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform};

use crate::common::{Fields, unmeasured};
use crate::monitor::Session;
use crate::{Collector, Field};

/// Collector id.
pub const ID: &str = "roblox_monitor";
const DISCRIMINATOR: &str = "scope";

static FIELDS: [Field; 16] = [
    Field::text("after"),
    Field::timestamp("at").off_timeline(),
    Field::text("before"),
    Field::text("event"),
    Field::number("events"),
    Field::number("events_dropped"),
    Field::text("first_seen_at"),
    Field::number("interval_seconds"),
    Field::text("origin"),
    Field::number("partial_samples"),
    Field::number("pid"),
    Field::number("samples"),
    Field::text("scope"),
    Field::text("since"),
    Field::text("source"),
    Field::text("subject"),
];

static REASONS: [UnmeasuredReason; 2] =
    [UnmeasuredReason::NotWindows, UnmeasuredReason::SourceAbsent];

/// The `roblox_monitor` collector: the monitoring session, if the person ran one, in the report.
#[derive(Debug, Clone, Default)]
pub struct RobloxMonitor {
    session: Option<std::sync::Arc<Session>>,
}

impl RobloxMonitor {
    /// The collector, reporting `session` when there is one.
    pub fn new(session: Option<std::sync::Arc<Session>>) -> Self {
        Self { session }
    }
}

impl Collector for RobloxMonitor {
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
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        // No session: the person did not run the monitoring mode, so nothing was watched.
        let Some(session) = &self.session else {
            return unmeasured(ID, UnmeasuredReason::SourceAbsent);
        };
        let mut observations = vec![
            Fields::new()
                .with(DISCRIMINATOR, "session")
                .time("at", session.started_at.parse().ok())
                .maybe("since", session.last_sample_at.clone())
                .with("interval_seconds", session.interval_seconds)
                .with("samples", session.samples)
                .with("partial_samples", session.partial_samples)
                .with("events", session.events.len())
                .with("events_dropped", session.events_dropped)
                .with("origin", session.origin.clone())
                .observe(ID),
        ];
        for event in &session.events {
            observations.push(
                Fields::new()
                    .with(DISCRIMINATOR, "event")
                    .time("at", event.at.parse().ok())
                    .maybe("since", event.since.clone())
                    .with("event", event.event.clone())
                    .maybe("pid", event.pid)
                    .with("subject", event.subject.clone())
                    .maybe("source", event.source.clone())
                    .maybe("before", event.before.clone())
                    .maybe("after", event.after.clone())
                    .maybe("first_seen_at", event.first_seen_at.clone())
                    .observe(ID),
            );
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps: Vec::new(),
        }
    }
}
