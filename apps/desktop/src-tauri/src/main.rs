// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! B.O.P.E Scanner desktop app.
//!
//! Upstream scanned before any window existed (ADR 0001). B.O.P.E Scanner opens its hardened window
//! first, so the person can read what will be examined, choose the scan and consent **before** anything
//! is read, and then watch the scan's real progress and cancel it (B.O.P.E, ADR 0115). The scan still
//! runs entirely in Rust, on a worker thread, through the same `scan` function the CLI uses; the window
//! only asks for it to start or stop and reads the frozen report afterwards, so it cannot change what was
//! measured. The window's own `WebView2` processes are running while the scan reads the process list and
//! are reported as what they are.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod monitoring;
mod qr;
mod reference;
mod scan_task;
mod webview_hardening;

use bope_core::bundle::Bundle;
use bope_core::provenance::Provenance;
use bope_host::Host;

/// Everything the UI may ask for.
pub struct AppState {
    bundle: Bundle,
    provenance: Provenance,
    elevated: Option<bool>,
    platform: String,
    os_build: Option<String>,
    scan: scan_task::ScanSlot,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = Bundle::embedded()?;
    let provenance = Provenance::current();
    let host = live_host();
    let state = AppState {
        bundle,
        provenance,
        elevated: host.is_elevated(),
        platform: host.platform().as_str().to_owned(),
        os_build: host.os_build(),
        scan: scan_task::ScanSlot::default(),
    };

    // The folders earlier runs could not delete because they were stopped go first.
    webview_hardening::remove_stale_data_dirs(host.as_ref());
    let data_dir = webview_hardening::run_data_dir();
    let window_dir = data_dir.clone();
    let app = tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::start_scan,
            commands::cancel_scan,
            commands::scan_status,
            commands::report_header,
            commands::report_view,
            commands::rule_texts,
            commands::rule_meta,
            commands::time_fields,
            commands::age_texts,
            commands::relaunch_elevated,
            commands::code_links,
            commands::code_link_qr,
            commands::default_export_dir,
            commands::pick_export_dir,
            commands::export_report,
            reference::fflag_reference_status,
            reference::fflag_reference_sync,
            monitoring::monitor_status,
            monitoring::start_monitor,
            monitoring::stop_monitor,
            monitoring::clear_monitor
        ])
        .setup(move |app| {
            webview_hardening::build_main_window(app, &window_dir)?;
            Ok(())
        })
        .build(tauri::generate_context!())?;

    app.run(move |_handle, event| {
        if let tauri::RunEvent::Exit = event {
            webview_hardening::remove_data_dir(&data_dir);
        }
    });
    Ok(())
}

#[cfg(windows)]
pub(crate) fn live_host() -> Box<dyn Host + Send + Sync> {
    Box::new(bope_host_windows::LiveHost)
}

#[cfg(not(windows))]
pub(crate) fn live_host() -> Box<dyn Host + Send + Sync> {
    Box::new(bope_host::NonWindowsHost)
}
