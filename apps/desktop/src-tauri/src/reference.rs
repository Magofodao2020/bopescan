// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The `FastFlag` reference copy, from the window: its status, an update the person asks for, and the
//! automatic check the person can turn off (B.O.P.E, ADR 0136). A scan only reads the copy on disk.

use std::sync::Arc;

use bope_collectors::flag_reference::ReferenceSnapshot;
use bope_reference::{Outcome, RevisionKind, Status, Store, Trigger};

fn store() -> Option<Store> {
    bope_reference::default_dir().map(Store::new)
}

/// The copy held, as a scan takes it; `None` when there is none or it is damaged.
pub fn snapshot() -> Option<Arc<ReferenceSnapshot>> {
    let loaded = store()?.load().ok().flatten()?;
    let m = loaded.metadata;
    let kind = match m.revision_kind {
        RevisionKind::Commit => "commit",
        RevisionKind::Content => "content",
        RevisionKind::Import => "import",
    };
    Some(Arc::new(ReferenceSnapshot::new(
        loaded.reference,
        m.revision,
        kind.to_owned(),
        m.commit_date,
        m.commit_message.as_deref(),
        m.fetched_at,
        m.source_url,
    )))
}

/// What the reference panel shows.
#[tauri::command]
pub fn fflag_reference_status() -> Option<Status> {
    store().map(|s| bope_reference::status(&s))
}

/// The result of one update.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncResult {
    /// How it ended.
    pub outcome: Outcome,
    /// What happened.
    pub detail: String,
    /// The status after it.
    pub status: Option<Status>,
}

/// Asks GitHub for a newer copy: `automatic` when the window does it on its own schedule (at most every
/// six hours, and only while the person leaves it on), otherwise because the person pressed the button.
#[tauri::command]
pub async fn fflag_reference_sync(automatic: bool) -> Result<SyncResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let store = store().ok_or("no folder for the reference (LOCALAPPDATA is not set)")?;
        let trigger = if automatic {
            Trigger::Automatic
        } else {
            Trigger::Manual
        };
        let report = bope_reference::sync(
            &store,
            &bope_reference::WinHttp,
            trigger,
            jiff::Timestamp::now(),
        )
        .map_err(|e| e.to_string())?;
        Ok(SyncResult {
            outcome: report.outcome,
            detail: report.detail,
            status: Some(bope_reference::status(&store)),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
