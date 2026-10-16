// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The reference values of Roblox's PC client settings, as the `MaximumADHD/Roblox-FFlag-Tracker`
//! repository's `PCDesktopClient.json` records them, and the comparison of an observed value with one
//! (B.O.P.E, ADR 0136).
//!
//! **What the file is.** The tracker records the settings Roblox's servers deliver to the Windows
//! desktop client on its live channel, roughly in real time. It is an external reference, not Roblox's
//! compiled defaults and not a guarantee of what any one client used: a flag can be absent from it and
//! still exist, can be present and unused by the build on a PC, can differ per place or per user
//! (`_PlaceFilter`, `_DataCenterFilter` suffixes), and changes between revisions. Every comparison made
//! here carries that, and a flag missing from the reference is never a difference.
//!
//! **Validation.** [`parse`] refuses anything that is not a JSON object of at least [`MIN_ENTRIES`]
//! scalar entries — an HTML error page, an empty body, a truncated download — so a caller never
//! replaces a good copy with a bad one.

use std::collections::BTreeMap;

use crate::error::ParseError;
use crate::memory::flag_base_name;

/// Fewest entries a tracker file must hold to be accepted. The live file held 23 293 on 2026-10-16;
/// a file a hundred times smaller is not that file.
pub const MIN_ENTRIES: usize = 1_000;

/// The kind of a reference value, as JSON typed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// `true` / `false`.
    Bool,
    /// A JSON number.
    Number,
    /// A JSON string.
    Text,
}

/// One reference entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceValue {
    /// The key as the tracker spells it.
    pub key: String,
    /// The value as text: `true`, `false`, a number as written, or a string's content.
    pub value: String,
    /// What JSON typed it as.
    pub kind: ValueKind,
}

/// The parsed reference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlagReference {
    by_key: BTreeMap<String, ReferenceValue>,
    by_base: BTreeMap<String, Vec<String>>,
}

/// How an observed value compares with the reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparison {
    /// The reference holds the flag and the values are equal after normalisation.
    Equal(ReferenceValue),
    /// The reference holds the flag and the values differ.
    Differs(ReferenceValue),
    /// The reference holds no entry for this flag. Not a difference: the tracker records what the
    /// servers deliver, not every flag a client knows.
    NotInReference,
}

/// Parses and validates a tracker file.
pub fn parse(bytes: &[u8]) -> Result<FlagReference, ParseError> {
    let trimmed = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or(&[][..], |start| &bytes[start..]);
    match trimmed.first() {
        None => {
            return Err(ParseError::Truncated {
                expected: 2,
                found: bytes.len(),
            });
        }
        Some(b'{') => {}
        Some(b'<') => {
            return Err(ParseError::Malformed {
                field: "body",
                detail: "an HTML page, not the tracker's JSON".to_owned(),
            });
        }
        Some(_) => {
            return Err(ParseError::Malformed {
                field: "body",
                detail: "not a JSON object".to_owned(),
            });
        }
    }
    let value: serde_json::Value =
        serde_json::from_slice(trimmed).map_err(|error| ParseError::Malformed {
            field: "json",
            detail: format!("line {}, column {}", error.line(), error.column()),
        })?;
    let serde_json::Value::Object(map) = value else {
        return Err(ParseError::Malformed {
            field: "json",
            detail: "the top level is not an object".to_owned(),
        });
    };
    let mut reference = FlagReference::default();
    let mut rejected = 0_usize;
    for (key, value) in map {
        let entry = match value {
            serde_json::Value::Bool(b) => (b.to_string(), ValueKind::Bool),
            serde_json::Value::Number(n) => (n.to_string(), ValueKind::Number),
            serde_json::Value::String(s) => (s, ValueKind::Text),
            _ => {
                rejected += 1;
                continue;
            }
        };
        reference.insert(ReferenceValue {
            key,
            value: entry.0,
            kind: entry.1,
        });
    }
    if reference.len() < MIN_ENTRIES {
        return Err(ParseError::Malformed {
            field: "entries",
            detail: format!(
                "{} scalar entries ({rejected} others), fewer than the {MIN_ENTRIES} a tracker file holds",
                reference.len()
            ),
        });
    }
    if rejected > reference.len() / 10 {
        return Err(ParseError::Malformed {
            field: "entries",
            detail: format!("{rejected} entries are not scalar values"),
        });
    }
    Ok(reference)
}

/// The name a key is indexed under besides itself: its base name without a kind prefix, when it has
/// one, else itself.
fn base_of(key: &str) -> &str {
    flag_base_name(key).unwrap_or(key)
}

/// A value as compared: booleans and their spellings fold to `true`/`false`, numbers to their
/// numeric value, text as written.
fn normalised(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("true") {
        return "true".to_owned();
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return "false".to_owned();
    }
    if let Ok(number) = trimmed.parse::<i64>() {
        return number.to_string();
    }
    if let Ok(number) = trimmed.parse::<f64>()
        && number.is_finite()
    {
        return format!("{number}");
    }
    trimmed.to_owned()
}

impl FlagReference {
    fn insert(&mut self, value: ReferenceValue) {
        self.by_base
            .entry(base_of(&value.key).to_owned())
            .or_default()
            .push(value.key.clone());
        self.by_key.insert(value.key.clone(), value);
    }

    /// How many entries it holds.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// The entry for `name`: the key as written, else one key sharing its base name — the tracker
    /// writes some flags with their `FFlag`/`DFInt` prefix and others without. When several keys share
    /// the base name the one with the same prefix wins, then the first in key order.
    pub fn lookup(&self, name: &str) -> Option<&ReferenceValue> {
        if let Some(found) = self.by_key.get(name) {
            return Some(found);
        }
        let keys = self.by_base.get(base_of(name))?;
        keys.iter()
            .find(|key| key.as_str() == name)
            .or_else(|| keys.first())
            .and_then(|key| self.by_key.get(key))
    }

    /// Compares `observed` for flag `name` with the reference.
    pub fn compare(&self, name: &str, observed: &str) -> Comparison {
        match self.lookup(name) {
            None => Comparison::NotInReference,
            Some(reference) if normalised(&reference.value) == normalised(observed) => {
                Comparison::Equal(reference.clone())
            }
            Some(reference) => Comparison::Differs(reference.clone()),
        }
    }

    /// Every entry, in key order.
    pub fn entries(&self) -> impl Iterator<Item = &ReferenceValue> {
        self.by_key.values()
    }
}

/// A Roblox client version (`0.695.0.6950777`) named in a commit message, when there is one.
pub fn client_version_in(message: &str) -> Option<String> {
    message
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find(|word| {
            let parts: Vec<&str> = word.split('.').collect();
            parts.len() == 4 && parts.iter().all(|p| !p.is_empty()) && parts[0] == "0"
        })
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn tracker(extra: &str) -> Vec<u8> {
        let mut text = String::from("{");
        for index in 0..MIN_ENTRIES {
            let _ = write!(text, "\"FFlagFiller{index}\": true,");
        }
        text.push_str(extra);
        text.push_str(
            "\"DFIntS2PhysicsSenderRate\": 15, \"AllowVideoPreRoll\": true, \"FStringX\": \"a;b\"}",
        );
        text.into_bytes()
    }

    #[test]
    fn the_tracker_parses_and_lookups_tolerate_prefixes() {
        let reference = parse(&tracker("")).unwrap();
        assert_eq!(reference.len(), MIN_ENTRIES + 3);
        assert_eq!(
            reference.lookup("DFIntS2PhysicsSenderRate").unwrap().value,
            "15"
        );
        assert_eq!(
            reference.lookup("FIntS2PhysicsSenderRate").unwrap().key,
            "DFIntS2PhysicsSenderRate"
        );
        assert_eq!(
            reference.lookup("FFlagAllowVideoPreRoll").unwrap().key,
            "AllowVideoPreRoll"
        );
        assert!(reference.lookup("FFlagNothing").is_none());
    }

    #[test]
    fn values_compare_after_normalising_spelling() {
        let reference = parse(&tracker("")).unwrap();
        assert!(matches!(
            reference.compare("DFIntS2PhysicsSenderRate", "15"),
            Comparison::Equal(_)
        ));
        assert!(matches!(
            reference.compare("DFIntS2PhysicsSenderRate", "60"),
            Comparison::Differs(_)
        ));
        assert!(matches!(
            reference.compare("FFlagAllowVideoPreRoll", "True"),
            Comparison::Equal(_)
        ));
        assert!(matches!(
            reference.compare("FStringX", "a;b"),
            Comparison::Equal(_)
        ));
        assert_eq!(
            reference.compare("FFlagUnknown", "true"),
            Comparison::NotInReference
        );
    }

    /// The real file, when `BOPE_TRACKER_FILE` names a downloaded copy; skipped otherwise.
    #[test]
    fn the_real_tracker_file_parses_when_one_is_given() {
        let Ok(path) = std::env::var("BOPE_TRACKER_FILE") else {
            return;
        };
        let reference = parse(&std::fs::read(path).unwrap()).unwrap();
        assert!(reference.len() > 10_000);
        assert!(reference.lookup("DFIntS2PhysicsSenderRate").is_some());
    }

    #[test]
    fn a_bad_download_is_refused() {
        assert!(parse(b"").is_err());
        assert!(parse(b"  <!DOCTYPE html><html>rate limited</html>").is_err());
        assert!(parse(b"[1,2,3]").is_err());
        assert!(parse(br#"{"FFlagA": true}"#).is_err());
        let truncated = tracker("");
        assert!(parse(&truncated[..truncated.len() / 2]).is_err());
        let mut nested = String::from("{");
        for index in 0..MIN_ENTRIES {
            let _ = write!(nested, "\"K{index}\": {{\"a\":1}},");
        }
        nested.push_str("\"x\": 1}");
        assert!(parse(nested.as_bytes()).is_err());
    }
}
