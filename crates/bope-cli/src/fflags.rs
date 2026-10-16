// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `bope-scanner-cli fflags`: the `FastFlag` reference copy — its status, a manual update from GitHub,
//! or an import from a file (B.O.P.E, ADR 0136). A scan never downloads anything; it reads the copy
//! these commands keep.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use bope_collectors::flag_reference::ReferenceSnapshot;
use bope_reference::{Outcome, RevisionKind, Store, Trigger};
use clap::Subcommand;

use crate::output::Lang;

/// What to do with the reference copy.
#[derive(Subcommand)]
pub enum Action {
    /// Show which copy is held, when it was fetched and how the last update went.
    Status,
    /// Ask GitHub for a newer copy now. The only command that uses the network.
    Sync,
    /// Use a `PCDesktopClient.json` file you downloaded yourself, after the same checks.
    Import {
        /// The file.
        file: PathBuf,
    },
}

/// The store in `dir`, or in the default folder.
pub fn store(dir: Option<&Path>) -> anyhow::Result<Store> {
    let dir = match dir {
        Some(dir) => dir.to_path_buf(),
        None => bope_reference::default_dir()
            .context("no folder for the FastFlag reference (LOCALAPPDATA is not set)")?,
    };
    Ok(Store::new(dir))
}

fn kind_word(kind: RevisionKind) -> &'static str {
    match kind {
        RevisionKind::Commit => "commit",
        RevisionKind::Content => "content",
        RevisionKind::Import => "import",
    }
}

/// The copy held, as the scan takes it; `None` when there is none or it is damaged.
pub fn snapshot(store: &Store) -> Option<Arc<ReferenceSnapshot>> {
    let loaded = store.load().ok().flatten()?;
    let m = loaded.metadata;
    Some(Arc::new(ReferenceSnapshot::new(
        loaded.reference,
        m.revision,
        kind_word(m.revision_kind).to_owned(),
        m.commit_date,
        m.commit_message.as_deref(),
        m.fetched_at,
        m.source_url,
    )))
}

fn outcome_word(outcome: Outcome, lang: Lang) -> &'static str {
    match (lang, outcome) {
        (Lang::Pt, Outcome::Updated) => "atualizada",
        (Lang::Pt, Outcome::NotModified) => "sem alterações",
        (Lang::Pt, Outcome::Rejected) => "resposta rejeitada (cópia anterior mantida)",
        (Lang::Pt, Outcome::Failed) => "falhou (cópia anterior mantida)",
        (Lang::Pt, Outcome::TooSoon) => "tentativa recente demais; tente em um minuto",
        (_, Outcome::Updated) => "updated",
        (_, Outcome::NotModified) => "not modified",
        (_, Outcome::Rejected) => "answer rejected (previous copy kept)",
        (_, Outcome::Failed) => "failed (previous copy kept)",
        (_, Outcome::TooSoon) => "last attempt too recent; try again in a minute",
    }
}

/// Runs one action and prints its result.
pub fn run(action: &Action, dir: Option<&Path>, lang: Lang) -> anyhow::Result<()> {
    let store = store(dir)?;
    let now = jiff::Timestamp::now();
    match action {
        Action::Status => {}
        Action::Sync => {
            let report =
                bope_reference::sync(&store, &bope_reference::WinHttp, Trigger::Manual, now)?;
            println!("{}: {}", outcome_word(report.outcome, lang), report.detail);
        }
        Action::Import { file } => {
            let report = bope_reference::import(&store, file, now)?;
            println!("{}: {}", outcome_word(report.outcome, lang), report.detail);
        }
    }
    print_status(&bope_reference::status(&store), lang);
    Ok(())
}

fn print_status(status: &bope_reference::Status, lang: Lang) {
    let pt = lang == Lang::Pt;
    let label = |pt_text: &'static str, en: &'static str| if pt { pt_text } else { en };
    println!("{}: {}", label("Pasta", "Folder"), status.folder);
    match &status.metadata {
        Some(m) => {
            println!(
                "{}: {} ({})",
                label("Revisão", "Revision"),
                m.revision,
                kind_word(m.revision_kind)
            );
            if let Some(date) = &m.commit_date {
                println!("{}: {date}", label("Data do commit", "Commit date"));
            }
            println!("{}: {}", label("Obtida em", "Fetched at"), m.fetched_at);
            println!("{}: {}", label("Entradas", "Entries"), m.entries);
            println!("{}: {}", label("Origem", "Source"), m.source_url);
            println!(
                "{}: {}",
                label(
                    "Versão do cliente no commit",
                    "Client version in the commit"
                ),
                status
                    .reference_client_version
                    .as_deref()
                    .unwrap_or(label("não informada", "not stated"))
            );
        }
        None => println!(
            "{}: {}",
            label("Referência", "Reference"),
            match status.unavailable_reason.as_deref() {
                Some("never_synchronised") => label(
                    "indisponível — nunca sincronizada",
                    "unavailable — never synchronised"
                ),
                Some(other) => other,
                None => "?",
            }
        ),
    }
    if let Some(at) = &status.state.last_import_at {
        println!("{}: {at}", label("Última importação", "Last import"));
    }
    if let Some(at) = &status.state.last_attempt_at {
        println!(
            "{}: {at} — {}{}",
            label("Última tentativa", "Last attempt"),
            status
                .state
                .last_outcome
                .map_or("?", |o| outcome_word(o, lang)),
            status
                .state
                .last_detail
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default()
        );
    }
}
