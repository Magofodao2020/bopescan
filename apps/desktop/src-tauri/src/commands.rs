// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! IPC commands. They start, stop and observe the one scan and read its frozen report; the view is
//! built in `bope_core::view`, the assessment in `bope_core::assessment` and the saved formats in
//! `bope_core::export`.

// Tauri injects `State` by value; commands cannot take it by reference.
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;

use bope_core::bundle::BundleInfo;
use bope_core::export::{self, Format};
use bope_core::model::{ReportHeader, ScanTier};
use bope_core::provenance::REPOSITORY_URL;
use bope_core::rules::RuleText;
use bope_core::view::{self, ReportView};
use tauri::State;

use crate::AppState;
use crate::scan_task::Status;

/// One collector, as the start screen lists it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CollectorInfo {
    /// Its id.
    pub id: String,
    /// `standard` or `full`.
    pub tier: ScanTier,
    /// The category its rules fall under unless a rule says otherwise.
    pub category: String,
}

/// What the start screen shows before anything is read.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AppInfo {
    /// The program's version.
    pub version: String,
    /// Whether this is an official upstream build (it never is for a modified version).
    pub official: bool,
    /// The SHA-256 of this executable, when it could be read.
    pub exe_sha256: Option<String>,
    /// The rules bundle.
    pub rules: BundleInfo,
    /// Whether this process has administrator rights.
    pub elevated: Option<bool>,
    /// `windows` or `other`.
    pub platform: String,
    /// The Windows build.
    pub os_build: Option<String>,
    /// Every collector, in the order the scan runs them.
    pub collectors: Vec<CollectorInfo>,
}

/// Facts the start screen needs. Reads nothing from the machine beyond what the program read to start
/// (its own executable and whether it is elevated).
#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: state.provenance.version.clone(),
        official: state.provenance.official,
        exe_sha256: state.provenance.exe_sha256.clone(),
        rules: state.bundle.info().clone(),
        elevated: state.elevated,
        platform: state.platform.clone(),
        os_build: state.os_build.clone(),
        collectors: bope_collectors::all()
            .iter()
            .map(|c| CollectorInfo {
                id: c.id().to_owned(),
                tier: c.tier(),
                category: bope_core::assessment::default_category(c.id()).to_owned(),
            })
            .collect(),
    }
}

/// Starts the scan the person chose, after they agreed to it on screen. Returns whether it started:
/// one window runs one scan.
#[tauri::command]
pub fn start_scan(state: State<'_, AppState>, tier: ScanTier) -> bool {
    state.scan.start(tier, state.provenance.clone())
}

/// Asks the running scan to stop before its next collector.
#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) {
    state.scan.cancel();
}

/// Where the scan is: the collectors that finished, with what each found.
#[tauri::command]
pub fn scan_status(state: State<'_, AppState>) -> Status {
    state.scan.status()
}

/// Facts about the finished scan without evidence.
#[tauri::command]
pub fn report_header(state: State<'_, AppState>) -> Result<ReportHeader, String> {
    state
        .scan
        .report()
        .map(|report| report.header)
        .ok_or_else(|| "no finished scan".to_owned())
}

/// The finished report's view, with the assessment (B.O.P.E ADR 0100).
#[tauri::command]
pub fn report_view(state: State<'_, AppState>) -> Result<ReportView, String> {
    let report = state
        .scan
        .report()
        .ok_or_else(|| "no finished scan".to_owned())?;
    Ok(view::for_report(&report).with_assessment(&report, &state.bundle))
}

/// Rule text in `lang`, keyed by rule id.
#[tauri::command]
pub fn rule_texts(state: State<'_, AppState>, lang: &str) -> BTreeMap<String, RuleText> {
    state
        .bundle
        .rules()
        .iter()
        .filter_map(|sourced| {
            let id = &sourced.rule.id;
            state.bundle.text(id, lang).map(|text| (id.clone(), text))
        })
        .collect()
}

/// What the result panel needs to know about each rule besides its text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RuleMeta {
    /// The level the assessment reads a `found` at.
    pub level: bope_core::assessment::Level,
    /// The category it is shown under.
    pub category: String,
    /// The collector it reads.
    pub collector: String,
    /// Whether it is a timeline selector.
    pub selector: bool,
}

/// Level and category of every rule, keyed by rule id.
#[tauri::command]
pub fn rule_meta(state: State<'_, AppState>) -> BTreeMap<String, RuleMeta> {
    state
        .bundle
        .rules()
        .iter()
        .map(|sourced| {
            let rule = &sourced.rule;
            (
                rule.id.clone(),
                RuleMeta {
                    level: rule.assessment_level(),
                    category: rule.assessment_category(),
                    collector: rule.collector.clone(),
                    selector: rule.is_timeline_selector(),
                },
            )
        })
        .collect()
}

/// Every field each collector declares as a time, on the timeline or not, keyed by collector, so the
/// interface formats exactly those fields as times and never guesses one from a value's shape
/// (B.O.P.E, ADR 0132).
#[tauri::command]
pub fn time_fields() -> BTreeMap<String, Vec<String>> {
    bope_collectors::all()
        .iter()
        .map(|collector| {
            (
                collector.id().to_owned(),
                collector
                    .fields()
                    .iter()
                    .filter(|field| field.kind == bope_collectors::FieldKind::Timestamp)
                    .map(|field| field.name.to_owned())
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|(_, fields)| !fields.is_empty())
        .collect()
}

/// Each source's ordinary retention in `lang`, keyed by collector (ADR 0061).
#[tauri::command]
pub fn age_texts(
    state: State<'_, AppState>,
    lang: &str,
) -> BTreeMap<String, bope_core::ages::AgeTextView> {
    state
        .bundle
        .ages()
        .iter()
        .filter_map(|sourced| {
            let collector = &sourced.text.collector;
            state
                .bundle
                .age_text(collector, lang)
                .map(|text| (collector.clone(), text))
        })
        .collect()
}

/// What came of a request to restart with administrator rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevateOutcome {
    /// An elevated copy is starting and this one is closing.
    Started,
    /// The person dismissed the Windows prompt. A normal outcome, not a failure (ADR 0012).
    Declined,
    /// Windows did not start the elevated program.
    Failed,
}

/// Starts an elevated copy of this program and closes this one. Offered before any scan, so nothing
/// read is lost; the new copy shows the start screen again (ADR 0012).
#[tauri::command]
pub fn relaunch_elevated(app: tauri::AppHandle) -> ElevateOutcome {
    relaunch(&app)
}

#[cfg(windows)]
fn relaunch(app: &tauri::AppHandle) -> ElevateOutcome {
    use bope_host_windows::elevate::{self, ElevateError};

    let args: Vec<String> = std::env::args().skip(1).collect();
    match elevate::relaunch_elevated(&args) {
        Ok(()) => {
            // Exit through the handle, so the `RunEvent::Exit` handler still deletes this run's
            // WebView2 profile folder.
            app.exit(0);
            ElevateOutcome::Started
        }
        Err(ElevateError::Declined) => ElevateOutcome::Declined,
        Err(error) => {
            // Local stderr only (CONVENTIONS.md, section 4).
            eprintln!("relaunch with administrator rights failed: {error}");
            ElevateOutcome::Failed
        }
    }
}

#[cfg(not(windows))]
fn relaunch(_app: &tauri::AppHandle) -> ElevateOutcome {
    ElevateOutcome::Failed
}

/// Where this binary's code can be read (ADR 0045).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CodeLinks {
    /// The repository.
    pub repository: String,
    /// The commit of an official build, the repository otherwise.
    pub code: String,
    /// The commit whose code this binary is; `None` unless this is an official build.
    pub commit: Option<String>,
}

/// Where this binary's code can be read.
#[tauri::command]
pub fn code_links(state: State<'_, AppState>) -> CodeLinks {
    let provenance = &state.provenance;
    CodeLinks {
        repository: REPOSITORY_URL.to_owned(),
        code: provenance.code_url(),
        commit: provenance.code_commit().map(str::to_owned),
    }
}

/// A QR code of a link into the repository, as SVG text (ADR 0045).
#[tauri::command]
pub fn code_link_qr(url: &str) -> Option<String> {
    crate::qr::svg(url)
}

/// The folder reports are saved in unless the person picks another: `Documents\B.O.P.E Scanner` of
/// this account. Nothing is created until a report is saved.
#[tauri::command]
pub fn default_export_dir() -> Option<String> {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|p| !p.is_empty())
        .map(|profile| format!(r"{profile}\Documents\B.O.P.E Scanner"))
}

/// The folder the person picks in the Windows folder picker, or `None` when they cancel.
#[tauri::command]
pub async fn pick_export_dir() -> Option<String> {
    pick()
}

#[cfg(windows)]
fn pick() -> Option<String> {
    bope_host_windows::dialog::pick_folder("B.O.P.E Scanner — onde salvar o relatório")
}

#[cfg(not(windows))]
fn pick() -> Option<String> {
    None
}

/// One saved file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SavedFile {
    /// Where it was written.
    pub path: String,
    /// The SHA-256 of its bytes, also written beside it as `<file>.sha256`.
    pub sha256: String,
}

/// Saves the finished report's view in each of `formats` (`json`, `html`, `txt`, `pdf`), in `dir` —
/// which the person chose — with a `.sha256` file beside each (B.O.P.E, ADR 0116).
#[tauri::command]
pub fn export_report(
    state: State<'_, AppState>,
    lang: String,
    formats: Vec<String>,
    dir: String,
    time_zone: Option<String>,
) -> Result<Vec<SavedFile>, String> {
    let report = state
        .scan
        .report()
        .ok_or_else(|| "no finished scan".to_owned())?;
    let view = view::for_report(&report).with_assessment(&report, &state.bundle);
    let dir = std::path::PathBuf::from(dir.trim());
    if !dir.is_absolute() {
        return Err("choose an absolute folder".to_owned());
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let stem = export::file_stem(&view.header.generated_at);
    let mut saved = Vec::new();
    for name in formats {
        let format = Format::parse(&name).ok_or_else(|| format!("unknown format {name}"))?;
        // The zone the window shows times in, so the files say what the window said (ADR 0132).
        let exported =
            export::export_in_zone(&view, &state.bundle, &lang, format, time_zone.as_deref());
        let file_name = format!("{stem}.{}", exported.extension);
        let path = dir.join(&file_name);
        std::fs::write(&path, &exported.bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        std::fs::write(
            dir.join(format!("{file_name}.sha256")),
            export::sha256_line(&exported.sha256, &file_name),
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        saved.push(SavedFile {
            path: path.display().to_string(),
            sha256: exported.sha256,
        });
    }
    Ok(saved)
}
