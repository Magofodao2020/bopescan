// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Recycle Bin `$I` files (Windows Vista and later): where a deleted item was, how large it was and
//! when it was moved to the Recycle Bin (B.O.P.E, ADR 0118).
//!
//! Version 1 (Vista–8.1): 8-byte version, 8-byte size, 8-byte `FILETIME`, then a fixed 520-byte
//! UTF-16 path. Version 2 (Windows 10 and 11): the same three fields, a 4-byte character count, then
//! the path. Emptying the Recycle Bin removes the `$I` file too, so this only shows what is still in it.

use jiff::Timestamp;

use crate::error::ParseError;
use crate::filetime::to_timestamp;

/// One `$I` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recycled {
    /// The item's path before it was deleted.
    pub original_path: String,
    /// Its size in bytes, as recorded.
    pub size: u64,
    /// When it was moved to the Recycle Bin.
    pub deleted_at: Option<Timestamp>,
}

/// Parses one `$I` file.
pub fn parse(bytes: &[u8]) -> Result<Recycled, ParseError> {
    let read = |at: usize| -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
    };
    let (Some(version), Some(size), Some(time)) = (read(0), read(8), read(16)) else {
        return Err(ParseError::Truncated {
            expected: 24,
            found: bytes.len(),
        });
    };
    let raw = match version {
        1 => bytes.get(24..).ok_or(ParseError::Truncated {
            expected: 26,
            found: bytes.len(),
        })?,
        2 => {
            let count = bytes
                .get(24..28)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(ParseError::Truncated {
                    expected: 28,
                    found: bytes.len(),
                })? as usize;
            bytes
                .get(28..28 + count.saturating_mul(2))
                .ok_or(ParseError::Truncated {
                    expected: 28 + count * 2,
                    found: bytes.len(),
                })?
        }
        _ => {
            return Err(ParseError::Malformed {
                field: "version",
                detail: "not a $I version this parser reads".to_owned(),
            });
        }
    };
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    let original_path = String::from_utf16_lossy(&units);
    if original_path.is_empty() {
        return Err(ParseError::Malformed {
            field: "path",
            detail: "empty original path".to_owned(),
        });
    }
    Ok(Recycled {
        original_path,
        size,
        deleted_at: to_timestamp(time),
    })
}

/// Builds a version 2 `$I` file, for tests in this workspace.
pub fn build(path: &str, size: u64, deleted: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&2_u64.to_le_bytes());
    b.extend_from_slice(&size.to_le_bytes());
    b.extend_from_slice(&deleted.to_le_bytes());
    let units: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    b.extend_from_slice(&u32::try_from(units.len()).unwrap_or(0).to_le_bytes());
    for u in units {
        b.extend_from_slice(&u.to_le_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_2_is_read() {
        let r = parse(&build(
            r"C:\Users\a\Downloads\Solara.exe",
            1234,
            134_353_296_000_000_000,
        ))
        .unwrap();
        assert_eq!(r.original_path, r"C:\Users\a\Downloads\Solara.exe");
        assert_eq!(r.size, 1234);
        assert_eq!(
            r.deleted_at.map(|t| t.to_string()).as_deref(),
            Some("2026-10-01T12:00:00Z")
        );
    }

    #[test]
    fn damage_errors() {
        let good = build(r"C:\x", 1, 1);
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
        assert!(
            parse(&[
                9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ])
            .is_err()
        );
    }
}
