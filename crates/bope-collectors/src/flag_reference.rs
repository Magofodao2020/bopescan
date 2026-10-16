// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The `FastFlag` reference a scan compares with, as the caller loaded it (B.O.P.E, ADR 0136).
//!
//! The collectors never fetch or store it: the CLI and the desktop load the last valid copy the sync
//! kept and hand it in through `ScanContext`. A scan without one compares nothing and says so.

use bope_parsers::fflag_reference::{Comparison, FlagReference};

/// One loaded copy of the tracker's `PCDesktopClient.json`, with where it came from.
#[derive(Debug, Clone)]
pub struct ReferenceSnapshot {
    /// The parsed, validated reference.
    pub reference: FlagReference,
    /// The commit it was taken at, or `content:<sha256>` when the commit was not known.
    pub revision: String,
    /// When that commit was made, RFC 3339, when known.
    pub commit_date: Option<String>,
    /// When this copy was downloaded, RFC 3339.
    pub fetched_at: String,
    /// The address it came from.
    pub source_url: String,
    /// How the revision was obtained: `commit`, `content` or `import`.
    pub revision_kind: String,
    /// The Roblox client version the commit's message names, when it names one.
    pub reference_client_version: Option<String>,
}

impl ReferenceSnapshot {
    /// A snapshot of a copy the caller loaded and validated, with the client version its commit
    /// message names, if any.
    pub fn new(
        reference: FlagReference,
        revision: String,
        revision_kind: String,
        commit_date: Option<String>,
        commit_message: Option<&str>,
        fetched_at: String,
        source_url: String,
    ) -> Self {
        Self {
            reference,
            revision,
            commit_date,
            fetched_at,
            source_url,
            revision_kind,
            reference_client_version: commit_message
                .and_then(bope_parsers::fflag_reference::client_version_in),
        }
    }
}

/// The fields a comparison with the reference adds to an observation about one flag value.
pub fn comparison_fields(
    fields: crate::common::Fields,
    snapshot: Option<&ReferenceSnapshot>,
    name: &str,
    observed: &str,
) -> crate::common::Fields {
    let Some(snapshot) = snapshot else {
        return fields.with("comparison", "no_reference");
    };
    let fields = fields.with("reference_revision", snapshot.revision.clone());
    match snapshot.reference.compare(name, observed) {
        Comparison::Equal(reference) => fields
            .with("comparison", "equal")
            .with("reference_key", reference.key)
            .with("reference_value", reference.value),
        Comparison::Differs(reference) => fields
            .with("comparison", "differs")
            .with("reference_key", reference.key)
            .with("reference_value", reference.value),
        Comparison::NotInReference => fields.with("comparison", "not_in_reference"),
    }
}
