// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The `FastFlag` reference copy: the `PCDesktopClient.json` file of the
//! `MaximumADHD/Roblox-FFlag-Tracker` repository, kept on this PC so a scan can compare the flag values
//! it observes with it (B.O.P.E, ADR 0136).
//!
//! # The one exception to "no network"
//!
//! This crate decides *when* to ask for a new copy, *what* to ask for, *whether* the answer is a valid
//! copy, and *where* the last valid copy is kept. It opens no connection: the caller hands it a
//! [`Transport`], which on Windows is the `WinHTTP` `GET` in `bope-host-windows::https_get`, the only
//! network call in the program. The requests go to two fixed addresses on GitHub and carry no data
//! about the PC, the scan or the person — only the conditional-request tags of the copy already held.
//! No scan ever waits for or triggers one: a scan reads the copy on disk, or none.
//!
//! # How a copy is replaced
//!
//! 1. Ask GitHub's API for the newest commit that touched the file, conditionally (`If-None-Match`), so
//!    an unchanged answer costs no rate limit. Same commit as the copy held: nothing to do.
//! 2. New commit: download the file *at that commit* from `raw.githubusercontent.com`.
//! 3. The API refused or failed (rate limit, proxy): download the file from `main` conditionally, and
//!    name the copy by its content hash, since the commit is then not known.
//! 4. Validate ([`bope_parsers::fflag_reference::parse`]): status 200, not HTML, a JSON object of at
//!    least `MIN_ENTRIES` scalar entries. Anything else is rejected and the copy held stays.
//! 5. Write the new copy under a new name, then switch the metadata to it with one rename, then remove
//!    the old copy. A crash at any step leaves either the old copy or the new one, never half of one.
//!
//! Every attempt, successful or not, is recorded in `sync-state.json`, and attempts are spaced: an
//! automatic one at most every [`AUTOMATIC_INTERVAL`], a manual one at most every [`MANUAL_INTERVAL`].

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bope_parsers::fflag_reference::{self, FlagReference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The repository the reference comes from.
pub const REPOSITORY: &str = "MaximumADHD/Roblox-FFlag-Tracker";
/// The file in it.
pub const FILE: &str = "PCDesktopClient.json";
/// The branch followed.
pub const BRANCH: &str = "main";
/// Host of GitHub's API.
pub const API_HOST: &str = "api.github.com";
/// Host of the raw files.
pub const RAW_HOST: &str = "raw.githubusercontent.com";
/// Largest answer accepted. The file was 1.1 MB on 2026-10-16.
pub const MAX_BODY: usize = 64 * 1024 * 1024;
/// Least time between two automatic attempts.
pub const AUTOMATIC_INTERVAL: Duration = Duration::from_hours(6);
/// Least time between two attempts of any kind.
pub const MANUAL_INTERVAL: Duration = Duration::from_secs(60);
/// Longest commit message kept.
const MAX_MESSAGE: usize = 300;

/// Path, on [`API_HOST`], of the newest commit touching [`FILE`] on [`BRANCH`].
pub fn api_path() -> String {
    format!("/repos/{REPOSITORY}/commits?sha={BRANCH}&path={FILE}&per_page=1")
}

/// Path, on [`RAW_HOST`], of [`FILE`] at `revision` (a commit or a branch).
pub fn raw_path(revision: &str) -> String {
    format!("/{REPOSITORY}/{revision}/{FILE}")
}

/// The address a copy at `revision` was read from.
pub fn raw_url(revision: &str) -> String {
    format!("https://{RAW_HOST}{}", raw_path(revision))
}

/// One HTTP answer, as the transport received it.
#[derive(Debug, Clone, Default)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The `ETag` header, when there was one.
    pub etag: Option<String>,
    /// The `Content-Type` header, when there was one.
    pub content_type: Option<String>,
    /// The body, at most [`MAX_BODY`] bytes.
    pub body: Vec<u8>,
}

/// Something that performs one HTTPS `GET`. The real one is `WinHTTP`; tests use a script.
pub trait Transport {
    /// `GET https://{host}{path}`, with `If-None-Match: {etag}` when given. An error is a failure to
    /// get any answer (no network, proxy refusal, TLS failure, timeout, a body over [`MAX_BODY`]).
    fn get(&self, host: &str, path: &str, if_none_match: Option<&str>) -> Result<Response, String>;
}

/// The `User-Agent` the requests carry: the program and its version, nothing about the PC.
pub fn user_agent() -> String {
    format!(
        "BOPE-Scanner/{} (FastFlag reference; +https://github.com/{REPOSITORY})",
        env!("CARGO_PKG_VERSION")
    )
}

/// The real transport: `WinHTTP` on Windows; on other platforms every request fails with a sentence
/// saying to import a copy instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinHttp;

impl Transport for WinHttp {
    fn get(&self, host: &str, path: &str, if_none_match: Option<&str>) -> Result<Response, String> {
        bope_host_windows::https_get::get(host, path, if_none_match, &user_agent(), MAX_BODY).map(
            |r| Response {
                status: r.status,
                etag: r.etag,
                content_type: r.content_type,
                body: r.body,
            },
        )
    }
}

/// Where the copy is kept by default: `%LOCALAPPDATA%\BOPE Scanner\fflag-reference` on Windows,
/// `$XDG_DATA_HOME/bope-scanner/fflag-reference` (or `~/.local/share/…`) elsewhere.
pub fn default_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        let local = std::env::var_os("LOCALAPPDATA")?;
        return Some(
            PathBuf::from(local)
                .join("BOPE Scanner")
                .join("fflag-reference"),
        );
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    Some(base.join("bope-scanner").join("fflag-reference"))
}

/// How a copy was named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionKind {
    /// The commit it was downloaded at.
    Commit,
    /// The SHA-256 of its content: downloaded from the branch while the commit was not known.
    Content,
    /// The SHA-256 of its content: imported from a file the person chose.
    Import,
}

/// What is known about the copy held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Name of the data file next to this metadata.
    pub file: String,
    /// SHA-256 of that file.
    pub sha256: String,
    /// How many entries it holds.
    pub entries: usize,
    /// Where it was read from: an address, or `file:` and the imported path.
    pub source_url: String,
    /// The commit, or `sha256:` and the first 16 hex digits of the content.
    pub revision: String,
    /// How [`Self::revision`] was obtained.
    pub revision_kind: RevisionKind,
    /// When the commit was made, RFC 3339, when known.
    #[serde(default)]
    pub commit_date: Option<String>,
    /// The commit's message (its first [`MAX_MESSAGE`] characters), when known.
    #[serde(default)]
    pub commit_message: Option<String>,
    /// When this copy was received, RFC 3339.
    pub fetched_at: String,
    /// The raw file's `ETag`, for the next conditional request.
    #[serde(default)]
    pub raw_etag: Option<String>,
    /// The API answer's `ETag`, for the next conditional request.
    #[serde(default)]
    pub api_etag: Option<String>,
}

/// How the last attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A new copy was validated and is now the one held.
    Updated,
    /// The source has not changed since the copy held.
    NotModified,
    /// An answer came but was not a valid copy; the copy held stays.
    Rejected,
    /// No answer came; the copy held stays.
    Failed,
    /// Not attempted: the last attempt was too recent.
    TooSoon,
}

impl Outcome {
    /// The snake-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::NotModified => "not_modified",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::TooSoon => "too_soon",
        }
    }
}

/// The record of attempts, kept apart from the copy so a failed attempt never touches it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// When the last attempt started, RFC 3339.
    #[serde(default)]
    pub last_attempt_at: Option<String>,
    /// How it ended.
    #[serde(default)]
    pub last_outcome: Option<Outcome>,
    /// What happened, in a sentence: the error, the rejection reason, or which route answered.
    #[serde(default)]
    pub last_detail: Option<String>,
    /// When an attempt last reached the source (updated or not modified), RFC 3339.
    #[serde(default)]
    pub last_success_at: Option<String>,
    /// When a file was last imported, RFC 3339. Imports do not space downloads.
    #[serde(default)]
    pub last_import_at: Option<String>,
}

/// What [`sync`] or [`import`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// How it ended.
    pub outcome: Outcome,
    /// What happened, in a sentence.
    pub detail: String,
}

/// Why the copy on disk could not be used.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Reading or writing the folder failed.
    #[error("reference folder: {0}")]
    Io(#[from] std::io::Error),
    /// The metadata is not valid JSON of the expected shape.
    #[error("reference metadata: {0}")]
    Metadata(#[from] serde_json::Error),
    /// The data file's hash is not the one the metadata records.
    #[error("the reference copy does not match its recorded SHA-256")]
    HashMismatch,
    /// The data file no longer parses as a reference.
    #[error("the reference copy is not valid: {0}")]
    Invalid(String),
}

/// A copy read from disk and checked.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// What is known about it.
    pub metadata: Metadata,
    /// The parsed reference.
    pub reference: FlagReference,
}

/// The folder the reference is kept in.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

const METADATA_FILE: &str = "reference.json";
const STATE_FILE: &str = "sync-state.json";

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('0'));
    }
    out
}

/// Writes `bytes` to `path` through a temporary file in the same folder and one rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("reference");
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

impl Store {
    /// The store in `dir`; nothing is created until a copy is saved.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The folder.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The metadata of the copy held, if there is one.
    pub fn metadata(&self) -> Result<Option<Metadata>, StoreError> {
        match fs::read(self.dir.join(METADATA_FILE)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The record of attempts; empty when there was none.
    pub fn state(&self) -> SyncState {
        fs::read(self.dir.join(STATE_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, state: &SyncState) -> Result<(), StoreError> {
        fs::create_dir_all(&self.dir)?;
        write_atomic(
            &self.dir.join(STATE_FILE),
            &serde_json::to_vec_pretty(state)?,
        )?;
        Ok(())
    }

    /// The copy held, read and checked: its hash must be the recorded one and it must still parse.
    pub fn load(&self) -> Result<Option<Loaded>, StoreError> {
        let Some(metadata) = self.metadata()? else {
            return Ok(None);
        };
        let bytes = fs::read(self.dir.join(&metadata.file))?;
        if sha256_hex(&bytes) != metadata.sha256 {
            return Err(StoreError::HashMismatch);
        }
        let reference =
            fflag_reference::parse(&bytes).map_err(|e| StoreError::Invalid(e.to_string()))?;
        Ok(Some(Loaded {
            metadata,
            reference,
        }))
    }

    /// Makes `bytes` the copy held: new data file, then the metadata switched to it, then the old file
    /// removed.
    fn replace(&self, bytes: &[u8], mut metadata: Metadata) -> Result<(), StoreError> {
        fs::create_dir_all(&self.dir)?;
        let previous = self.metadata().ok().flatten();
        metadata.sha256 = sha256_hex(bytes);
        metadata.file = format!("PCDesktopClient-{}.json", &metadata.sha256[..16]);
        write_atomic(&self.dir.join(&metadata.file), bytes)?;
        write_atomic(
            &self.dir.join(METADATA_FILE),
            &serde_json::to_vec_pretty(&metadata)?,
        )?;
        if let Some(previous) = previous
            && previous.file != metadata.file
        {
            let _ = fs::remove_file(self.dir.join(previous.file));
        }
        Ok(())
    }

    /// Records new conditional-request tags on the copy held, leaving the copy itself alone.
    fn retag(&self, metadata: &Metadata) -> Result<(), StoreError> {
        write_atomic(
            &self.dir.join(METADATA_FILE),
            &serde_json::to_vec_pretty(metadata)?,
        )?;
        Ok(())
    }
}

/// How an attempt was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// By the program, on its own schedule.
    Automatic,
    /// By the person, from the interface or the command line.
    Manual,
}

fn elapsed_since(at: Option<&str>, now: jiff::Timestamp) -> Option<Duration> {
    let at: jiff::Timestamp = at?.parse().ok()?;
    let span = now.duration_since(at);
    Duration::try_from(span).ok()
}

/// Whether an attempt started by `trigger` at `now` is allowed by the record of attempts.
pub fn due(state: &SyncState, trigger: Trigger, now: jiff::Timestamp) -> bool {
    let interval = match trigger {
        Trigger::Automatic => AUTOMATIC_INTERVAL,
        Trigger::Manual => MANUAL_INTERVAL,
    };
    elapsed_since(state.last_attempt_at.as_deref(), now).is_none_or(|e| e >= interval)
}

/// Why an answer is not a valid copy, or the parsed copy.
fn validate(response: &Response) -> Result<FlagReference, String> {
    if response.status != 200 {
        return Err(format!("status {}", response.status));
    }
    if response
        .content_type
        .as_deref()
        .is_some_and(|t| t.to_ascii_lowercase().starts_with("text/html"))
    {
        return Err("the answer is an HTML page".to_owned());
    }
    if response.body.len() > MAX_BODY {
        return Err("the answer is larger than the limit".to_owned());
    }
    fflag_reference::parse(&response.body).map_err(|e| e.to_string())
}

/// The newest commit, from the API's answer.
fn newest_commit(body: &[u8]) -> Option<(String, Option<String>, Option<String>)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let commit = value.as_array()?.first()?;
    let sha = commit.get("sha")?.as_str()?;
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let date = commit
        .pointer("/commit/committer/date")
        .and_then(|d| d.as_str())
        .map(str::to_owned);
    let message = commit
        .pointer("/commit/message")
        .and_then(|m| m.as_str())
        .map(|m| m.chars().take(MAX_MESSAGE).collect());
    Some((sha.to_ascii_lowercase(), date, message))
}

struct Attempt<'a> {
    store: &'a Store,
    held: Option<Metadata>,
    now: String,
}

impl Attempt<'_> {
    fn save(
        &self,
        response: &Response,
        reference: &FlagReference,
        source_url: String,
        revision: Option<(String, Option<String>, Option<String>)>,
        api_etag: Option<String>,
    ) -> Result<Report, StoreError> {
        let sha256 = sha256_hex(&response.body);
        let (revision, revision_kind, commit_date, commit_message) = match revision {
            Some((sha, date, message)) => (sha, RevisionKind::Commit, date, message),
            None => (
                format!("sha256:{}", &sha256[..16]),
                RevisionKind::Content,
                None,
                None,
            ),
        };
        if let Some(held) = &self.held
            && held.sha256 == sha256
        {
            // Same content under a new tag or commit: keep the copy, record what names it now.
            let mut held = held.clone();
            held.raw_etag = response.etag.clone().or(held.raw_etag);
            held.api_etag = api_etag.or(held.api_etag);
            if revision_kind == RevisionKind::Commit {
                held.revision = revision;
                held.revision_kind = revision_kind;
                held.commit_date = commit_date;
                held.commit_message = commit_message;
            }
            self.store.retag(&held)?;
            return Ok(Report {
                outcome: Outcome::NotModified,
                detail: "the source holds the same content as the copy held".to_owned(),
            });
        }
        let metadata = Metadata {
            file: String::new(),
            sha256: String::new(),
            entries: reference.len(),
            source_url,
            revision: revision.clone(),
            revision_kind,
            commit_date,
            commit_message,
            fetched_at: self.now.clone(),
            raw_etag: response.etag.clone(),
            api_etag: api_etag.or_else(|| self.held.as_ref().and_then(|h| h.api_etag.clone())),
        };
        self.store.replace(&response.body, metadata)?;
        Ok(Report {
            outcome: Outcome::Updated,
            detail: format!("{} entries at {revision}", reference.len()),
        })
    }

    /// The route through the API. `None` when the API gave no usable answer.
    fn through_api(&self, transport: &dyn Transport) -> Option<Result<Report, StoreError>> {
        let held_tag = self.held.as_ref().and_then(|h| h.api_etag.as_deref());
        let answer = transport.get(API_HOST, &api_path(), held_tag).ok()?;
        if answer.status == 304 && self.held.is_some() {
            return Some(Ok(Report {
                outcome: Outcome::NotModified,
                detail: "the API reports no new commit".to_owned(),
            }));
        }
        if answer.status != 200 {
            return None;
        }
        let commit = newest_commit(&answer.body)?;
        if let Some(held) = &self.held
            && held.revision_kind == RevisionKind::Commit
            && held.revision == commit.0
        {
            let mut held = held.clone();
            held.api_etag = answer.etag.or(held.api_etag);
            return Some(self.store.retag(&held).map(|()| Report {
                outcome: Outcome::NotModified,
                detail: format!("the newest commit is still {}", commit.0),
            }));
        }
        let file = match transport.get(RAW_HOST, &raw_path(&commit.0), None) {
            Ok(file) => file,
            Err(error) => {
                return Some(Ok(Report {
                    outcome: Outcome::Failed,
                    detail: format!("downloading commit {}: {error}", commit.0),
                }));
            }
        };
        Some(match validate(&file) {
            Ok(reference) => self.save(
                &file,
                &reference,
                raw_url(&commit.0),
                Some(commit),
                answer.etag,
            ),
            Err(reason) => Ok(Report {
                outcome: Outcome::Rejected,
                detail: format!("the file at commit {} was rejected: {reason}", commit.0),
            }),
        })
    }

    /// The route through the branch, when the API gave no usable answer.
    fn through_branch(&self, transport: &dyn Transport) -> Result<Report, StoreError> {
        let held_tag = self.held.as_ref().and_then(|h| h.raw_etag.as_deref());
        let answer = match transport.get(RAW_HOST, &raw_path(BRANCH), held_tag) {
            Ok(answer) => answer,
            Err(error) => {
                return Ok(Report {
                    outcome: Outcome::Failed,
                    detail: error,
                });
            }
        };
        if answer.status == 304 && self.held.is_some() {
            return Ok(Report {
                outcome: Outcome::NotModified,
                detail: "the file on the branch has not changed (the API did not answer)"
                    .to_owned(),
            });
        }
        match validate(&answer) {
            Ok(reference) => self.save(&answer, &reference, raw_url(BRANCH), None, None),
            Err(reason) => Ok(Report {
                outcome: Outcome::Rejected,
                detail: format!("the file on the branch was rejected: {reason}"),
            }),
        }
    }
}

fn record(
    store: &Store,
    mut state: SyncState,
    now: &str,
    report: Report,
) -> Result<Report, StoreError> {
    state.last_attempt_at = Some(now.to_owned());
    state.last_outcome = Some(report.outcome);
    state.last_detail = Some(report.detail.clone());
    if matches!(report.outcome, Outcome::Updated | Outcome::NotModified) {
        state.last_success_at = Some(now.to_owned());
    }
    store.save_state(&state)?;
    Ok(report)
}

/// Asks for a new copy, if one is due, and keeps it if it is valid. The copy held is never replaced
/// by anything that did not validate, and never removed.
pub fn sync(
    store: &Store,
    transport: &dyn Transport,
    trigger: Trigger,
    now: jiff::Timestamp,
) -> Result<Report, StoreError> {
    let now = now.round(jiff::Unit::Second).unwrap_or(now);
    let state = store.state();
    if !due(&state, trigger, now) {
        return Ok(Report {
            outcome: Outcome::TooSoon,
            detail: "the last attempt was too recent".to_owned(),
        });
    }
    let attempt = Attempt {
        store,
        // A copy whose metadata cannot be read is treated as absent: the next valid one replaces it.
        held: store.load().ok().flatten().map(|l| l.metadata),
        now: now.to_string(),
    };
    let report = match attempt.through_api(transport) {
        Some(report) => report?,
        None => attempt.through_branch(transport)?,
    };
    record(store, state, &attempt.now, report)
}

/// Makes a file the person chose the copy held, after the same validation as a download.
pub fn import(store: &Store, path: &Path, now: jiff::Timestamp) -> Result<Report, StoreError> {
    let bytes = fs::read(path)?;
    let response = Response {
        status: 200,
        body: bytes,
        ..Response::default()
    };
    let state = store.state();
    let now = now.round(jiff::Unit::Second).unwrap_or(now).to_string();
    let report = match validate(&response) {
        Ok(reference) => {
            let sha256 = sha256_hex(&response.body);
            let metadata = Metadata {
                file: String::new(),
                sha256: String::new(),
                entries: reference.len(),
                source_url: format!("file:{}", path.display()),
                revision: format!("sha256:{}", &sha256[..16]),
                revision_kind: RevisionKind::Import,
                commit_date: None,
                commit_message: None,
                fetched_at: now.clone(),
                raw_etag: None,
                api_etag: None,
            };
            store.replace(&response.body, metadata)?;
            Report {
                outcome: Outcome::Updated,
                detail: format!("{} entries imported", reference.len()),
            }
        }
        Err(reason) => Report {
            outcome: Outcome::Rejected,
            detail: format!("the file was rejected: {reason}"),
        },
    };
    let mut state = state;
    state.last_import_at = Some(now.clone());
    state.last_outcome = Some(report.outcome);
    state.last_detail = Some(report.detail.clone());
    store.save_state(&state)?;
    Ok(report)
}

pub use bope_parsers::fflag_reference::client_version_in;

/// The status the interface shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Status {
    /// Whether a valid copy is held.
    pub available: bool,
    /// Why not, when it is not: `never_synchronised`, or what was wrong with the copy.
    pub unavailable_reason: Option<String>,
    /// What is known about the copy held.
    pub metadata: Option<Metadata>,
    /// The Roblox client version the copy's commit names, when it names one.
    pub reference_client_version: Option<String>,
    /// The record of attempts.
    pub state: SyncState,
    /// Where the copy is kept.
    pub folder: String,
}

/// The status of the store.
pub fn status(store: &Store) -> Status {
    let state = store.state();
    let folder = store.dir.display().to_string();
    match store.load() {
        Ok(Some(loaded)) => Status {
            available: true,
            unavailable_reason: None,
            reference_client_version: loaded
                .metadata
                .commit_message
                .as_deref()
                .and_then(client_version_in),
            metadata: Some(loaded.metadata),
            state,
            folder,
        },
        Ok(None) => Status {
            available: false,
            unavailable_reason: Some("never_synchronised".to_owned()),
            state,
            folder,
            ..Status::default()
        },
        Err(error) => Status {
            available: false,
            unavailable_reason: Some(error.to_string()),
            state,
            folder,
            ..Status::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    fn tracker(extra: &str) -> Vec<u8> {
        let mut text = String::from("{");
        for index in 0..fflag_reference::MIN_ENTRIES {
            text.push_str("\"FFlagFiller");
            text.push_str(&index.to_string());
            text.push_str("\": true,");
        }
        if extra.is_empty() {
            text.pop();
        } else {
            text.push_str(extra);
        }
        text.push('}');
        text.into_bytes()
    }

    fn commits(sha: &str) -> Vec<u8> {
        format!(
            r#"[{{"sha":"{sha}","commit":{{"message":"0.695.0.6950777","committer":{{"date":"2026-10-15T10:00:00Z"}}}}}}]"#
        )
        .into_bytes()
    }

    /// Answers requests from a list, and records them.
    struct Script {
        answers: RefCell<VecDeque<Result<Response, String>>>,
        asked: RefCell<Vec<(String, String, Option<String>)>>,
    }

    impl Script {
        fn new(answers: Vec<Result<Response, String>>) -> Self {
            Self {
                answers: RefCell::new(answers.into()),
                asked: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for Script {
        fn get(&self, host: &str, path: &str, etag: Option<&str>) -> Result<Response, String> {
            self.asked.borrow_mut().push((
                host.to_owned(),
                path.to_owned(),
                etag.map(str::to_owned),
            ));
            self.answers
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err("no more answers".to_owned()))
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn ok(body: Vec<u8>, etag: &str) -> Result<Response, String> {
        Ok(Response {
            status: 200,
            etag: Some(etag.to_owned()),
            content_type: Some("text/plain; charset=utf-8".to_owned()),
            body,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn status_only(status: u16) -> Result<Response, String> {
        Ok(Response {
            status,
            ..Response::default()
        })
    }

    fn temp_store(name: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("bope-reference-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Store::new(dir)
    }

    fn at(text: &str) -> jiff::Timestamp {
        text.parse().unwrap()
    }

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn a_new_commit_is_downloaded_at_that_commit_and_kept() {
        let store = temp_store("commit");
        let script = Script::new(vec![
            ok(commits(SHA_A), "\"api1\""),
            ok(tracker("\"DFIntS2PhysicsSenderRate\": 15"), "\"raw1\""),
        ]);
        let report = sync(&store, &script, Trigger::Manual, at("2026-10-16T00:00:00Z")).unwrap();
        assert_eq!(report.outcome, Outcome::Updated, "{report:?}");
        let asked = script.asked.borrow();
        assert_eq!(asked[0].0, API_HOST);
        assert_eq!(asked[1].1, raw_path(SHA_A));
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.metadata.revision, SHA_A);
        assert_eq!(loaded.metadata.revision_kind, RevisionKind::Commit);
        assert_eq!(loaded.metadata.api_etag.as_deref(), Some("\"api1\""));
        assert_eq!(
            loaded
                .reference
                .lookup("DFIntS2PhysicsSenderRate")
                .unwrap()
                .value,
            "15"
        );
        let shown = status(&store);
        assert!(shown.available);
        assert_eq!(
            shown.reference_client_version.as_deref(),
            Some("0.695.0.6950777")
        );
        assert_eq!(shown.state.last_outcome, Some(Outcome::Updated));
    }

    #[test]
    fn an_unchanged_source_is_asked_conditionally_and_the_copy_stays() {
        let store = temp_store("unchanged");
        let first = Script::new(vec![
            ok(commits(SHA_A), "\"api1\""),
            ok(tracker(""), "\"raw1\""),
        ]);
        sync(&store, &first, Trigger::Manual, at("2026-10-16T00:00:00Z")).unwrap();
        let second = Script::new(vec![status_only(304)]);
        let report = sync(&store, &second, Trigger::Manual, at("2026-10-16T01:00:00Z")).unwrap();
        assert_eq!(report.outcome, Outcome::NotModified);
        assert_eq!(second.asked.borrow()[0].2.as_deref(), Some("\"api1\""));
        assert_eq!(store.load().unwrap().unwrap().metadata.revision, SHA_A);
    }

    #[test]
    fn an_html_page_or_a_short_file_never_replaces_the_copy_held() {
        let store = temp_store("rejected");
        let first = Script::new(vec![
            ok(commits(SHA_A), "\"api1\""),
            ok(tracker(""), "\"raw1\""),
        ]);
        sync(&store, &first, Trigger::Manual, at("2026-10-16T00:00:00Z")).unwrap();
        let html = Script::new(vec![
            ok(commits(SHA_B), "\"api2\""),
            Ok(Response {
                status: 200,
                etag: None,
                content_type: Some("text/html".to_owned()),
                body: b"<html>rate limited</html>".to_vec(),
            }),
        ]);
        let report = sync(&store, &html, Trigger::Manual, at("2026-10-16T02:00:00Z")).unwrap();
        assert_eq!(report.outcome, Outcome::Rejected);
        let short = Script::new(vec![
            ok(commits(SHA_B), "\"api2\""),
            ok(b"{}".to_vec(), "x"),
        ]);
        let report = sync(&store, &short, Trigger::Manual, at("2026-10-16T03:00:00Z")).unwrap();
        assert_eq!(report.outcome, Outcome::Rejected);
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.metadata.revision, SHA_A);
        assert_eq!(store.state().last_outcome, Some(Outcome::Rejected));
        assert_eq!(
            store.state().last_success_at.as_deref(),
            Some("2026-10-16T00:00:00Z")
        );
    }

    #[test]
    fn when_the_api_refuses_the_branch_is_read_and_named_by_content() {
        let store = temp_store("fallback");
        let script = Script::new(vec![status_only(403), ok(tracker(""), "\"raw1\"")]);
        let report = sync(&store, &script, Trigger::Manual, at("2026-10-16T00:00:00Z")).unwrap();
        assert_eq!(report.outcome, Outcome::Updated);
        assert_eq!(script.asked.borrow()[1].1, raw_path(BRANCH));
        let metadata = store.metadata().unwrap().unwrap();
        assert_eq!(metadata.revision_kind, RevisionKind::Content);
        assert!(metadata.revision.starts_with("sha256:"));
        // The next attempt sends the branch file's tag.
        let again = Script::new(vec![Err("offline".to_owned()), status_only(304)]);
        let report = sync(&store, &again, Trigger::Manual, at("2026-10-16T01:00:00Z")).unwrap();
        assert_eq!(report.outcome, Outcome::NotModified);
        assert_eq!(again.asked.borrow()[1].2.as_deref(), Some("\"raw1\""));
    }

    #[test]
    fn offline_keeps_the_last_valid_copy_and_attempts_are_spaced() {
        let store = temp_store("offline");
        let first = Script::new(vec![
            ok(commits(SHA_A), "\"api1\""),
            ok(tracker(""), "\"raw1\""),
        ]);
        sync(
            &store,
            &first,
            Trigger::Automatic,
            at("2026-10-16T00:00:00Z"),
        )
        .unwrap();
        let soon = Script::new(vec![]);
        let report = sync(
            &store,
            &soon,
            Trigger::Automatic,
            at("2026-10-16T05:00:00Z"),
        )
        .unwrap();
        assert_eq!(report.outcome, Outcome::TooSoon);
        assert!(soon.asked.borrow().is_empty());
        let offline = Script::new(vec![
            Err("no network".to_owned()),
            Err("no network".to_owned()),
        ]);
        let report = sync(
            &store,
            &offline,
            Trigger::Automatic,
            at("2026-10-16T07:00:00Z"),
        )
        .unwrap();
        assert_eq!(report.outcome, Outcome::Failed);
        assert!(status(&store).available);
    }

    #[test]
    fn never_synchronised_says_so_and_a_damaged_copy_is_not_used() {
        let store = temp_store("never");
        let shown = status(&store);
        assert!(!shown.available);
        assert_eq!(
            shown.unavailable_reason.as_deref(),
            Some("never_synchronised")
        );
        let file = store.dir().with_extension("import.json");
        fs::write(&file, tracker("")).unwrap();
        assert_eq!(
            import(&store, &file, at("2026-10-16T00:00:00Z"))
                .unwrap()
                .outcome,
            Outcome::Updated
        );
        let metadata = store.metadata().unwrap().unwrap();
        fs::write(store.dir().join(&metadata.file), b"{\"x\": 1}").unwrap();
        assert!(matches!(store.load(), Err(StoreError::HashMismatch)));
        assert!(!status(&store).available);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn a_client_version_is_read_from_a_commit_message() {
        assert_eq!(
            client_version_in("version-abc (0.695.0.6950777)").as_deref(),
            Some("0.695.0.6950777")
        );
        assert_eq!(client_version_in("Update flags"), None);
    }
}
