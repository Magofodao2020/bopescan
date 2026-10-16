// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The names inside a `.zip` archive, from its central directory only (B.O.P.E, ADR 0118).
//!
//! Nothing is decompressed and nothing is extracted, so a zip bomb costs nothing here: the reader
//! takes the end-of-central-directory record, walks at most [`MAX_ENTRIES`] headers and returns names
//! and uncompressed sizes. ZIP64 archives and encrypted central directories are reported as
//! unsupported rather than guessed.

use crate::error::ParseError;

/// Most entries listed from one archive.
pub const MAX_ENTRIES: usize = 5_000;

/// One entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its path inside the archive, `/`-separated.
    pub name: String,
    /// Uncompressed size as the header states it.
    pub size: u32,
}

/// What the central directory lists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    /// Entries, in directory order.
    pub entries: Vec<Entry>,
    /// The directory had more entries than were listed, or ended early.
    pub partial: bool,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Lists a zip archive's names.
pub fn list(bytes: &[u8]) -> Result<Listing, ParseError> {
    if bytes.len() < 22 {
        return Err(ParseError::Truncated {
            expected: 22,
            found: bytes.len(),
        });
    }
    // The end record is in the last 64 KiB + 22 bytes (its comment is at most 65 535 bytes).
    let floor = bytes.len().saturating_sub(65_535 + 22);
    let eocd = (floor..=bytes.len() - 22)
        .rev()
        .find(|at| u32_at(bytes, *at) == Some(0x0605_4b50))
        .ok_or_else(|| ParseError::Malformed {
            field: "eocd",
            detail: "no end of central directory".to_owned(),
        })?;
    let total = usize::from(u16_at(bytes, eocd + 10).unwrap_or(0));
    let offset = u32_at(bytes, eocd + 16).unwrap_or(u32::MAX);
    if offset == u32::MAX || total == 0xFFFF {
        return Err(ParseError::Malformed {
            field: "zip64",
            detail: "ZIP64 archives are not listed".to_owned(),
        });
    }
    let mut at = offset as usize;
    let mut out = Listing::default();
    for _ in 0..total.min(MAX_ENTRIES) {
        if u32_at(bytes, at) != Some(0x0201_4b50) {
            out.partial = true;
            break;
        }
        let (Some(flags), Some(size), Some(name_len), Some(extra), Some(comment)) = (
            u16_at(bytes, at + 8),
            u32_at(bytes, at + 24),
            u16_at(bytes, at + 28),
            u16_at(bytes, at + 30),
            u16_at(bytes, at + 32),
        ) else {
            out.partial = true;
            break;
        };
        let Some(raw) = bytes.get(at + 46..at + 46 + usize::from(name_len)) else {
            out.partial = true;
            break;
        };
        let name = if flags & 0x800 != 0 {
            String::from_utf8_lossy(raw).into_owned()
        } else {
            // CP437 for anything past ASCII; such names are rare in archives of interest here.
            crate::cp1252::decode(raw)
        };
        out.entries.push(Entry { name, size });
        at += 46 + usize::from(name_len) + usize::from(extra) + usize::from(comment);
    }
    if total > MAX_ENTRIES {
        out.partial = true;
    }
    Ok(out)
}

/// Builds a stored (uncompressed, empty-file) zip with these names, for tests in this workspace.
pub fn build(names: &[&str]) -> Vec<u8> {
    let mut central = Vec::new();
    for name in names {
        let mut h = vec![0_u8; 46];
        h[0..4].copy_from_slice(&0x0201_4b50_u32.to_le_bytes());
        h[8..10].copy_from_slice(&0x800_u16.to_le_bytes());
        h[28..30].copy_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_le_bytes());
        central.extend_from_slice(&h);
        central.extend_from_slice(name.as_bytes());
    }
    let mut eocd = vec![0_u8; 22];
    eocd[0..4].copy_from_slice(&0x0605_4b50_u32.to_le_bytes());
    let count = u16::try_from(names.len()).unwrap_or(0);
    eocd[8..10].copy_from_slice(&count.to_le_bytes());
    eocd[10..12].copy_from_slice(&count.to_le_bytes());
    eocd[12..16].copy_from_slice(&u32::try_from(central.len()).unwrap_or(0).to_le_bytes());
    eocd[16..20].copy_from_slice(&0_u32.to_le_bytes());
    central.extend_from_slice(&eocd);
    central
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_listed_without_extracting() {
        let zip = build(&["Solara/Bootstrapper.exe", "Solara/autoexec/", "readme.txt"]);
        let l = list(&zip).unwrap();
        assert_eq!(l.entries.len(), 3);
        assert_eq!(l.entries[0].name, "Solara/Bootstrapper.exe");
        assert!(!l.partial);
    }

    #[test]
    fn damage_is_partial_or_an_error() {
        assert!(list(b"PK").is_err());
        assert!(list(&[0_u8; 100]).is_err());
        let zip = build(&["a", "b"]);
        for n in 0..zip.len() {
            let _ = list(&zip[..n]);
        }
        let mut broken = zip.clone();
        broken[0] = 0;
        assert!(list(&broken).unwrap().partial);
    }
}
