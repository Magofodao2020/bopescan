// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `Amcache.hve` (Windows 10 and 11): the program files Windows inventoried, and shortcuts it saw
//! (B.O.P.E, ADR 0120).
//!
//! Reads `Root\InventoryApplicationFile` — one key per file, with `LowerCaseLongPath`, `Name`,
//! `FileId` (`0000` + SHA-1 of the file's first 31.4 MB), `Publisher`, `ProductName`, `Version`,
//! `LinkDate`, `Size` — and `Root\InventoryApplicationShortcut` (`ShortcutPath`, `ShortcutTargetPath`
//! when present). Each key's last-written time is kept beside it.
//!
//! **What it means.** An entry says Windows' inventory saw the file — usually because it ran, was
//! installed, or was scanned by the compatibility appraiser. It is **not** proof of execution on its
//! own, and the key's time is when the entry was written, not when the program ran.
//!
//! Older Windows 8.1 layouts (`Root\File\{volume}`) are not read: `layout_unsupported` says so.

use jiff::Timestamp;

use crate::error::ParseError;
use crate::regf::{Data, Hive};

/// One inventoried file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InventoryFile {
    /// `LowerCaseLongPath`.
    pub path: Option<String>,
    /// `Name`, or the file part of the path.
    pub name: Option<String>,
    /// SHA-1 from `FileId`, without the `0000` prefix.
    pub sha1: Option<String>,
    /// `Publisher`.
    pub publisher: Option<String>,
    /// `ProductName`.
    pub product: Option<String>,
    /// `Version` or `BinFileVersion`.
    pub version: Option<String>,
    /// `LinkDate` as Windows wrote it (`MM/DD/YYYY HH:MM:SS`, the PE header's link time).
    pub link_date: Option<String>,
    /// `Size`.
    pub size: Option<u64>,
    /// `IsOsComponent` is set.
    pub os_component: bool,
    /// When the key was last written.
    pub key_written: Option<Timestamp>,
}

/// One inventoried shortcut.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InventoryShortcut {
    /// `ShortcutPath`.
    pub path: Option<String>,
    /// When the key was last written.
    pub key_written: Option<Timestamp>,
}

/// What a hive held.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Amcache {
    /// Inventoried files.
    pub files: Vec<InventoryFile>,
    /// Inventoried shortcuts.
    pub shortcuts: Vec<InventoryShortcut>,
    /// The hive's own last-written time.
    pub hive_written: Option<Timestamp>,
    /// The hive's sequence numbers differ (see [`Hive::dirty`]).
    pub dirty: bool,
    /// Neither inventory key is there: an older layout, or an empty hive.
    pub layout_unsupported: bool,
}

/// Parses `Amcache.hve` bytes.
pub fn parse(bytes: &[u8]) -> Result<Amcache, ParseError> {
    let hive = Hive::parse(bytes)?;
    let mut out = Amcache {
        hive_written: hive.last_written,
        dirty: hive.dirty,
        ..Amcache::default()
    };
    let files = hive.path(hive.root(), r"Root\InventoryApplicationFile");
    let shortcuts = hive.path(hive.root(), r"Root\InventoryApplicationShortcut");
    out.layout_unsupported = files.is_none() && shortcuts.is_none();
    if let Some(files) = files {
        for key in hive.subkeys(files) {
            let mut f = InventoryFile {
                key_written: hive.last_written(key),
                ..InventoryFile::default()
            };
            for (name, data) in hive.values(key) {
                let text = data
                    .as_ref()
                    .and_then(Data::as_text)
                    .filter(|t| !t.is_empty());
                match name.as_str() {
                    "LowerCaseLongPath" => f.path = text,
                    "Name" => f.name = text,
                    "FileId" => {
                        f.sha1 = text.map(|t| t.strip_prefix("0000").unwrap_or(&t).to_owned());
                    }
                    "Publisher" => f.publisher = text,
                    "ProductName" => f.product = text,
                    "Version" => f.version = text.or(f.version.take()),
                    "BinFileVersion" => f.version = f.version.take().or(text),
                    "LinkDate" => f.link_date = text,
                    "Size" => f.size = text.and_then(|t| parse_size(&t)),
                    "IsOsComponent" => f.os_component = text.as_deref() == Some("1"),
                    _ => {}
                }
            }
            if f.name.is_none() {
                f.name = f
                    .path
                    .as_deref()
                    .and_then(|p| p.rsplit('\\').next())
                    .map(str::to_owned);
            }
            out.files.push(f);
        }
    }
    if let Some(shortcuts) = shortcuts {
        for key in hive.subkeys(shortcuts) {
            let path = hive
                .values(key)
                .into_iter()
                .find(|(n, _)| n == "ShortcutPath")
                .and_then(|(_, d)| d.and_then(|d| d.as_text()))
                // Older builds keep the path as the key name.
                .or_else(|| hive.name(key));
            out.shortcuts.push(InventoryShortcut {
                path,
                key_written: hive.last_written(key),
            });
        }
    }
    Ok(out)
}

fn parse_size(text: &str) -> Option<u64> {
    text.strip_prefix("0x").map_or_else(
        || text.parse().ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regf::build;

    #[test]
    fn files_and_shortcuts_are_read_with_their_key_times() {
        let bytes = build(&[
            (
                r"Root\InventoryApplicationFile\fflagmanager.exe|abc",
                134_353_296_000_000_000,
                &[
                    (
                        "LowerCaseLongPath",
                        r"c:\users\a\downloads\fflagmanager.exe",
                    ),
                    ("FileId", "0000da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                    ("Size", "0x1000"),
                    ("IsOsComponent", "0"),
                ],
            ),
            (
                r"Root\InventoryApplicationShortcut\x",
                1,
                &[("ShortcutPath", r"c:\users\a\desktop\fflag.lnk")],
            ),
        ]);
        let a = parse(&bytes).unwrap();
        assert!(!a.layout_unsupported);
        assert_eq!(a.files.len(), 1);
        let f = &a.files[0];
        assert_eq!(f.name.as_deref(), Some("fflagmanager.exe"));
        assert_eq!(
            f.sha1.as_deref(),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(f.size, Some(4096));
        assert_eq!(
            f.key_written.map(|t| t.to_string()).as_deref(),
            Some("2026-10-01T12:00:00Z")
        );
        assert_eq!(
            a.shortcuts[0].path.as_deref(),
            Some(r"c:\users\a\desktop\fflag.lnk")
        );
    }

    #[test]
    fn an_old_layout_is_said_not_guessed() {
        let bytes = build(&[(r"Root\File\{x}\1", 1, &[("15", r"c:\a.exe")])]);
        let a = parse(&bytes).unwrap();
        assert!(a.layout_unsupported);
        assert!(a.files.is_empty());
    }
}
