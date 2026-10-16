// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Small helpers the B.O.P.E collectors share, so each reads as what it collects.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, Observation, UnmeasuredReason};
use bope_host::{Host, SignatureCheck, SourceError};
use serde_json::Value;

/// Builds observation fields one at a time, skipping `None`.
#[derive(Debug, Default)]
pub struct Fields(pub BTreeMap<String, Value>);

impl Fields {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a value.
    #[must_use]
    pub fn with(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.0.insert(name.to_owned(), value.into());
        self
    }

    /// Adds a value when there is one.
    #[must_use]
    pub fn maybe(self, name: &str, value: Option<impl Into<Value>>) -> Self {
        match value {
            Some(value) => self.with(name, value),
            None => self,
        }
    }

    /// Adds a timestamp as RFC 3339 text when there is one.
    #[must_use]
    pub fn time(self, name: &str, value: Option<jiff::Timestamp>) -> Self {
        self.maybe(name, value.map(|t| t.to_string()))
    }

    /// The observation for `collector`.
    pub fn observe(self, collector: &str) -> Observation {
        Observation {
            collector: collector.to_owned(),
            fields: self.0,
        }
    }
}

/// A run that could not look.
pub fn unmeasured(collector: &str, reason: UnmeasuredReason) -> CollectorRun {
    CollectorRun::Unmeasured {
        collector: collector.to_owned(),
        reason,
    }
}

/// A run that looked, with no place-level gaps.
pub fn measured(
    collector: &str,
    observations: Vec<Observation>,
    gaps: BTreeMap<String, UnmeasuredReason>,
) -> CollectorRun {
    CollectorRun::Measured {
        collector: collector.to_owned(),
        observations,
        gaps,
        discriminator_gaps: Vec::new(),
    }
}

/// The word a signature check is reported as, the same words `fivem_dir` and `autostart` use.
pub fn signature_word(check: &SignatureCheck) -> &'static str {
    match check {
        SignatureCheck::Valid { .. } => "valid",
        SignatureCheck::NoEmbeddedSignature => "no_embedded_signature",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::UnverifiableOffline => "unverifiable_offline",
    }
}

/// Adds `sha256`, `signature`, `signer` and `signer_cert_sha256` for one file, omitting what could not
/// be read. Returns whether both reads answered.
pub fn hash_and_signature(host: &dyn Host, path: &str, fields: Fields) -> (Fields, bool) {
    let mut complete = true;
    let fields = if let Ok(hash) = host.file_sha256(path) {
        fields.with("sha256", hash)
    } else {
        complete = false;
        fields
    };
    let fields = if let Ok(check) = host.file_signature(path) {
        let fields = fields.with("signature", signature_word(&check));
        match check {
            SignatureCheck::Valid {
                signer,
                signer_cert_sha256,
            } => fields
                .with("signer", signer)
                .with("signer_cert_sha256", signer_cert_sha256),
            _ => fields,
        }
    } else {
        complete = false;
        fields
    };
    (fields, complete)
}

/// An environment variable that holds a drive-rooted folder, without its trailing separator.
pub fn env_folder(host: &dyn Host, name: &str) -> Option<String> {
    host.env_var(name)
        .filter(|value| crate::paths::is_drive_rooted(value))
        .map(|value| value.trim_end_matches(['\\', '/']).to_owned())
}

/// The profile folder of the account this program runs as.
pub fn user_profile(host: &dyn Host) -> Option<String> {
    env_folder(host, "USERPROFILE").or_else(|| {
        env_folder(host, "LOCALAPPDATA").and_then(|local| {
            local
                .to_ascii_lowercase()
                .ends_with(r"\appdata\local")
                .then(|| local[..local.len() - r"\AppData\Local".len()].to_owned())
        })
    })
}

/// Whether an error from a registry or file read that the run cannot continue past means
/// "not admin", "access denied" or "read failed", as every collector reports it.
pub fn reason(host: &dyn Host, error: &SourceError) -> UnmeasuredReason {
    crate::failure::reason_for(host, error)
}

/// Lowercase hex of `bytes`, for writing binary fixture values in tests.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Joins a folder and a name with one separator.
pub fn join(folder: &str, name: &str) -> String {
    format!(r"{}\{}", folder.trim_end_matches(['\\', '/']), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_skip_what_is_not_there() {
        let observation = Fields::new()
            .with("a", 1)
            .maybe("b", None::<String>)
            .maybe("c", Some("x"))
            .time("d", None)
            .observe("t");
        assert_eq!(observation.fields.len(), 2);
        assert_eq!(join(r"C:\a\", "b"), r"C:\a\b");
    }
}
