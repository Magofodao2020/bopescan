// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `AppCompatCache` ("`ShimCache`"): the Application Compatibility cache Windows keeps in
//! `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, value `AppCompatCache`
//! (B.O.P.E, ADR 0105).
//!
//! **What it is not.** On Windows 10 and 11 an entry says that the compatibility engine looked at the
//! file — which happens when a program is started, but also when Explorer shows a folder holding it,
//! when it is extracted, or when it is scanned. **It does not prove execution.** The time an entry
//! carries is the file's own last-modification time as the file system had it when the entry was
//! written, **not** when anything ran. Windows writes the cache to the registry at shutdown, so a file
//! seen since the last restart is usually not in the value yet. The entries are in most-recent-first
//! order, which is the only order they carry.
//!
//! Two layouts are decoded, recognised by the first `u32`:
//!
//! - `0x30` / `0x34` — Windows 10 and 11. Entries start at that offset; each is the signature `10ts`,
//!   an unknown `u32`, the length of the rest of the entry, a `u16` path length in bytes, the path in
//!   UTF-16LE, a `FILETIME`, a `u32` data length and that many bytes.
//! - `0x80` — Windows 8 and 8.1 (signature `00ts` or `10ts`), whose entries carry a package name and
//!   two flag words before the `FILETIME`.
//!
//! Any other first value — Windows 7's `0xBADC0FEE`, XP's `0xDEADBEEF` — is reported as
//! [`Format::Unsupported`] with the value, never guessed at.

use jiff::Timestamp;

use crate::error::ParseError;
use crate::filetime;

/// The layout the value was recognised as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Windows 10 or 11, with the header size it declared.
    Win10 {
        /// `0x30` or `0x34`.
        header: u32,
    },
    /// Windows 8 or 8.1.
    Win8,
    /// A first value this parser does not decode.
    Unsupported {
        /// The value as read.
        magic: u32,
    },
}

/// One cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimEntry {
    /// Zero-based position in the cache; 0 is the most recently inserted.
    pub position: usize,
    /// The path as Windows wrote it, often in NT form (`\??\C:\...`).
    pub path: String,
    /// The raw `FILETIME` of the file's last modification as recorded.
    pub modified_raw: u64,
    /// That time as UTC; `None` when zero or out of range.
    pub modified: Option<Timestamp>,
    /// Length of the opaque data blob that follows; its meaning is not documented.
    pub data_len: usize,
}

/// The decoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimCache {
    /// The layout recognised.
    pub format: Format,
    /// The entries that decoded, in cache order.
    pub entries: Vec<ShimEntry>,
    /// Why decoding stopped before the end of the value, when it did. The entries before that point
    /// are kept: a damaged tail is exactly when the surviving entries matter.
    pub stopped: Option<String>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
    }
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

fn time(raw: u64) -> Option<Timestamp> {
    if raw == 0 {
        None
    } else {
        filetime::to_timestamp(raw)
    }
}

/// Decodes the `AppCompatCache` value.
pub fn parse(bytes: &[u8]) -> Result<ShimCache, ParseError> {
    let magic = bytes
        .get(0..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ParseError::Truncated {
            expected: 4,
            found: bytes.len(),
        })?;
    match magic {
        0x30 | 0x34 => Ok(parse_entries(
            bytes,
            magic as usize,
            Format::Win10 { header: magic },
            false,
        )),
        0x80 => Ok(parse_entries(bytes, 0x80, Format::Win8, true)),
        other => Ok(ShimCache {
            format: Format::Unsupported { magic: other },
            entries: Vec::new(),
            stopped: None,
        }),
    }
}

fn parse_entries(bytes: &[u8], start: usize, format: Format, win8: bool) -> ShimCache {
    let mut cursor = Cursor { bytes, at: start };
    let mut entries = Vec::new();
    let mut stopped = None;
    if start > bytes.len() {
        return ShimCache {
            format,
            entries,
            stopped: Some(format!(
                "the header declares {start} bytes and the value has {}",
                bytes.len()
            )),
        };
    }
    while cursor.at < bytes.len() {
        let position = entries.len();
        let Some(signature) = cursor.take(4) else {
            stopped = Some(format!("entry {position}: truncated signature"));
            break;
        };
        if signature != b"10ts" && !(win8 && signature == b"00ts") {
            stopped = Some(format!("entry {position}: unknown signature"));
            break;
        }
        let (Some(_unknown), Some(entry_len)) = (cursor.u32(), cursor.u32()) else {
            stopped = Some(format!("entry {position}: truncated header"));
            break;
        };
        let Some(body) = cursor.take(entry_len as usize) else {
            stopped = Some(format!(
                "entry {position}: declares {entry_len} bytes past the end of the value"
            ));
            break;
        };
        let Some((path, modified_raw, data_len)) = parse_body(body, win8) else {
            stopped = Some(format!("entry {position}: body does not decode"));
            break;
        };
        entries.push(ShimEntry {
            position,
            path,
            modified_raw,
            modified: time(modified_raw),
            data_len,
        });
    }
    ShimCache {
        format,
        entries,
        stopped,
    }
}

fn parse_body(body: &[u8], win8: bool) -> Option<(String, u64, usize)> {
    let mut cursor = Cursor { bytes: body, at: 0 };
    let path_len = cursor.u16()? as usize;
    let path = utf16(cursor.take(path_len)?);
    if win8 {
        let package_len = cursor.u16()? as usize;
        cursor.take(package_len)?;
        cursor.u32()?; // insertion flags
        cursor.u32()?; // shim flags
    }
    let modified_raw = cursor.u64()?;
    let data_len = cursor.u32()? as usize;
    cursor.take(data_len)?;
    Some((path, modified_raw, data_len))
}

/// Builds a Windows 10 value from `(path, filetime, data)` entries, for tests and fixtures.
pub fn build_win10(entries: &[(&str, u64, &[u8])]) -> Vec<u8> {
    let mut out = vec![0_u8; 0x34];
    out[0..4].copy_from_slice(&0x34_u32.to_le_bytes());
    for (path, filetime, data) in entries {
        let path_bytes: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut body = Vec::new();
        body.extend_from_slice(
            &u16::try_from(path_bytes.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        body.extend_from_slice(&path_bytes);
        body.extend_from_slice(&filetime.to_le_bytes());
        body.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
        body.extend_from_slice(data);
        out.extend_from_slice(b"10ts");
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(&body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_windows_10_value_decodes_in_cache_order() {
        let value = build_win10(&[
            (
                r"\??\C:\Users\a\Downloads\tool.exe",
                134_353_296_000_000_000,
                &[1, 2, 3],
            ),
            (r"C:\Windows\System32\cmd.exe", 0, &[]),
        ]);
        let cache = parse(&value).unwrap();
        assert_eq!(cache.format, Format::Win10 { header: 0x34 });
        assert_eq!(cache.stopped, None);
        assert_eq!(cache.entries.len(), 2);
        assert_eq!(cache.entries[0].path, r"\??\C:\Users\a\Downloads\tool.exe");
        assert_eq!(
            cache.entries[0].modified.unwrap().to_string(),
            "2026-10-01T12:00:00Z"
        );
        assert_eq!(cache.entries[0].data_len, 3);
        assert_eq!(cache.entries[1].position, 1);
        assert_eq!(cache.entries[1].modified, None);
    }

    #[test]
    fn a_damaged_tail_keeps_the_entries_before_it() {
        let mut value = build_win10(&[(r"C:\a.exe", 1, &[]), (r"C:\b.exe", 2, &[])]);
        value.truncate(value.len() - 3);
        let cache = parse(&value).unwrap();
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.stopped.unwrap().contains("entry 1"));
    }

    #[test]
    fn windows_7_and_xp_are_named_not_guessed() {
        let mut value = vec![0_u8; 128];
        value[0..4].copy_from_slice(&0xBADC_0FEE_u32.to_le_bytes());
        assert_eq!(
            parse(&value).unwrap().format,
            Format::Unsupported { magic: 0xBADC_0FEE }
        );
        assert!(matches!(parse(&[1, 2]), Err(ParseError::Truncated { .. })));
    }

    #[test]
    fn a_windows_8_entry_skips_its_package_and_flags() {
        let mut value = vec![0_u8; 0x80];
        value[0..4].copy_from_slice(&0x80_u32.to_le_bytes());
        let path: Vec<u8> = "C:\\x.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut body = Vec::new();
        body.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
        body.extend_from_slice(&path);
        body.extend_from_slice(&4_u16.to_le_bytes());
        body.extend_from_slice(b"pk\0\0");
        body.extend_from_slice(&[0; 8]);
        body.extend_from_slice(&5_u64.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        value.extend_from_slice(b"00ts");
        value.extend_from_slice(&[0; 4]);
        value.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        value.extend_from_slice(&body);
        let cache = parse(&value).unwrap();
        assert_eq!(cache.format, Format::Win8);
        assert_eq!(cache.entries[0].path, "C:\\x.exe");
        assert_eq!(cache.entries[0].modified_raw, 5);
    }

    #[test]
    fn hostile_lengths_never_panic() {
        let mut value = build_win10(&[(r"C:\a.exe", 1, &[])]);
        // An entry length pointing far past the end.
        value[0x34 + 8..0x34 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        let cache = parse(&value).unwrap();
        assert!(cache.entries.is_empty());
        assert!(cache.stopped.is_some());
        let mut header_past_end = vec![0_u8; 8];
        header_past_end[0..4].copy_from_slice(&0x34_u32.to_le_bytes());
        assert!(parse(&header_past_end).unwrap().stopped.is_some());
    }
}
