// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! A read-only reader of registry hive files (`regf`), enough to walk keys and read string, number
//! and small binary values (B.O.P.E, ADR 0120).
//!
//! Used for `Amcache.hve`, which Windows keeps open exclusively, so it is read from a copy Windows
//! already made (a shadow copy) rather than through the registry API. The reader:
//!
//! - follows the base block's root cell and the `lf`/`lh`/`li`/`ri` subkey lists and value lists;
//! - reads `nk` key names (ASCII or UTF-16) and last-written times, and `vk` values whose data is
//!   inline or in one cell; data split into `db` big-data segments is reported as absent, not guessed;
//! - never applies the transaction logs (`.LOG1`/`.LOG2`): a hive whose two sequence numbers differ
//!   is reported as `dirty`, meaning its newest changes may be missing from what is read here.
//!
//! Every offset is checked; a cell that points outside the file, loops, or has the wrong signature
//! ends that branch of the walk with no panic.

use jiff::Timestamp;

use crate::error::ParseError;
use crate::filetime::to_timestamp;

const BASE_BLOCK: usize = 4096;
/// Deepest key path the walker follows, and most cells it visits per list, so a hostile hive cannot
/// make it loop.
const MAX_DEPTH: usize = 16;
const MAX_LIST: usize = 200_000;

/// A parsed hive: its bytes and what the base block says.
#[derive(Debug)]
pub struct Hive<'a> {
    bytes: &'a [u8],
    root: usize,
    /// When the hive was last written, as the base block records it.
    pub last_written: Option<Timestamp>,
    /// The two sequence numbers differ: changes may be waiting in the transaction logs.
    pub dirty: bool,
}

/// One key.
#[derive(Debug, Clone, Copy)]
pub struct Key {
    cell: usize,
}

/// One value's data, as far as this reader decodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// `REG_SZ` / `REG_EXPAND_SZ`.
    Text(String),
    /// `REG_DWORD`.
    U32(u32),
    /// `REG_QWORD`.
    U64(u64),
    /// Anything else, or a type this reader does not decode, as bytes.
    Bytes(Vec<u8>),
}

impl Data {
    /// The value as text, converting numbers.
    pub fn as_text(&self) -> Option<String> {
        match self {
            Self::Text(t) => Some(t.clone()),
            Self::U32(v) => Some(v.to_string()),
            Self::U64(v) => Some(v.to_string()),
            Self::Bytes(_) => None,
        }
    }
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

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

impl<'a> Hive<'a> {
    /// Checks the base block and finds the root key.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < BASE_BLOCK + 32 {
            return Err(ParseError::Truncated {
                expected: BASE_BLOCK + 32,
                found: bytes.len(),
            });
        }
        if bytes.get(0..4) != Some(b"regf") {
            return Err(ParseError::Malformed {
                field: "signature",
                detail: "not a registry hive".to_owned(),
            });
        }
        let root_offset = u32_at(bytes, 36).unwrap_or(u32::MAX) as usize;
        let hive = Hive {
            bytes,
            root: BASE_BLOCK.saturating_add(root_offset),
            last_written: u64_at(bytes, 12).and_then(to_timestamp),
            dirty: u32_at(bytes, 4) != u32_at(bytes, 8),
        };
        if hive.cell_data(hive.root).and_then(|d| d.get(0..2)) != Some(b"nk") {
            return Err(ParseError::Malformed {
                field: "root",
                detail: "root cell is not a key".to_owned(),
            });
        }
        Ok(hive)
    }

    /// The root key.
    pub fn root(&self) -> Key {
        Key { cell: self.root }
    }

    /// The data of the cell at absolute offset `at` (after its 4-byte size).
    fn cell_data(&self, at: usize) -> Option<&'a [u8]> {
        let size = i32::from_le_bytes(self.bytes.get(at..at.checked_add(4)?)?.try_into().ok()?);
        // Allocated cells have a negative size.
        let len = usize::try_from(size.checked_neg()?).ok()?;
        if len < 4 {
            return None;
        }
        self.bytes.get(at + 4..at.checked_add(len)?)
    }

    fn cell_at_offset(&self, offset: u32) -> Option<&'a [u8]> {
        if offset == u32::MAX {
            return None;
        }
        self.cell_data(BASE_BLOCK.checked_add(offset as usize)?)
    }

    /// A key's name.
    pub fn name(&self, key: Key) -> Option<String> {
        let nk = self.cell_data(key.cell)?;
        let flags = u16_at(nk, 2)?;
        let len = usize::from(u16_at(nk, 72)?);
        let raw = nk.get(76..76 + len)?;
        Some(if flags & 0x20 != 0 {
            raw.iter().map(|b| char::from(*b)).collect()
        } else {
            utf16(raw)
        })
    }

    /// When the key was last written.
    pub fn last_written(&self, key: Key) -> Option<Timestamp> {
        let nk = self.cell_data(key.cell)?;
        u64_at(nk, 4).and_then(to_timestamp)
    }

    /// The key's subkeys, in the order the hive lists them.
    pub fn subkeys(&self, key: Key) -> Vec<Key> {
        let Some(nk) = self.cell_data(key.cell) else {
            return Vec::new();
        };
        let Some(list) = u32_at(nk, 28) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        self.collect_list(list, &mut out, 0);
        out
    }

    fn collect_list(&self, offset: u32, out: &mut Vec<Key>, depth: usize) {
        if depth > 2 || out.len() >= MAX_LIST {
            return;
        }
        let Some(list) = self.cell_at_offset(offset) else {
            return;
        };
        let Some(count) = u16_at(list, 2).map(usize::from) else {
            return;
        };
        let (stride, nested) = match list.get(0..2) {
            Some(b"lf" | b"lh") => (8, false),
            Some(b"li") => (4, false),
            Some(b"ri") => (4, true),
            _ => return,
        };
        for i in 0..count {
            let Some(child) = u32_at(list, 4 + i * stride) else {
                return;
            };
            if nested {
                self.collect_list(child, out, depth + 1);
            } else if let Some(at) = BASE_BLOCK.checked_add(child as usize)
                && self.cell_data(at).and_then(|d| d.get(0..2)) == Some(b"nk")
            {
                out.push(Key { cell: at });
            }
            if out.len() >= MAX_LIST {
                return;
            }
        }
    }

    /// The subkey of `key` named `name`, compared without case.
    pub fn child(&self, key: Key, name: &str) -> Option<Key> {
        self.subkeys(key)
            .into_iter()
            .find(|k| self.name(*k).is_some_and(|n| n.eq_ignore_ascii_case(name)))
    }

    /// The key at a backslash path below `key`.
    pub fn path(&self, key: Key, path: &str) -> Option<Key> {
        path.split('\\')
            .filter(|p| !p.is_empty())
            .take(MAX_DEPTH)
            .try_fold(key, |k, part| self.child(k, part))
    }

    /// Every value of `key` by name, with the data this reader decodes.
    pub fn values(&self, key: Key) -> Vec<(String, Option<Data>)> {
        let Some(nk) = self.cell_data(key.cell) else {
            return Vec::new();
        };
        let (Some(count), Some(list_offset)) = (u32_at(nk, 36), u32_at(nk, 40)) else {
            return Vec::new();
        };
        let Some(list) = self.cell_at_offset(list_offset) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..(count as usize).min(4096) {
            let Some(vk) = u32_at(list, i * 4).and_then(|o| self.cell_at_offset(o)) else {
                break;
            };
            if vk.get(0..2) != Some(b"vk") {
                continue;
            }
            if let Some(value) = self.value(vk) {
                out.push(value);
            }
        }
        out
    }

    fn value(&self, vk: &[u8]) -> Option<(String, Option<Data>)> {
        let name_len = usize::from(u16_at(vk, 2)?);
        let size_raw = u32_at(vk, 4)?;
        let data_offset = u32_at(vk, 8)?;
        let kind = u32_at(vk, 12)?;
        let flags = u16_at(vk, 16)?;
        let raw_name = vk.get(20..20 + name_len)?;
        let name = if flags & 1 != 0 {
            raw_name.iter().map(|b| char::from(*b)).collect()
        } else {
            utf16(raw_name)
        };
        let inline = size_raw & 0x8000_0000 != 0;
        let size = (size_raw & 0x7FFF_FFFF) as usize;
        let bytes: Option<Vec<u8>> = if inline {
            data_offset
                .to_le_bytes()
                .get(..size.min(4))
                .map(<[u8]>::to_vec)
        } else if size > 16_344 {
            // Big data (`db`) is not followed: absent rather than half-read.
            None
        } else {
            self.cell_at_offset(data_offset)
                .and_then(|d| d.get(..size))
                .map(<[u8]>::to_vec)
        };
        let data = bytes.map(|b| match kind {
            1 | 2 => Data::Text(utf16(&b)),
            4 if b.len() >= 4 => Data::U32(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            11 if b.len() >= 8 => Data::U64(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ])),
            _ => Data::Bytes(b),
        });
        Some((name, data))
    }
}

/// One key for [`build`]: its backslash path below the root, its last-written `FILETIME`, and its
/// `(value name, REG_SZ text)` pairs.
pub type BuildKey<'a> = (&'a str, u64, &'a [(&'a str, &'a str)]);

/// Builds a small hive in memory, for tests in this workspace.
#[allow(clippy::too_many_lines)]
pub fn build(keys: &[BuildKey<'_>]) -> Vec<u8> {
    // A tree of paths.
    #[derive(Default)]
    struct Node {
        name: String,
        written: u64,
        values: Vec<(String, String)>,
        children: Vec<Node>,
    }
    fn insert(node: &mut Node, parts: &[&str], written: u64, values: &[(&str, &str)]) {
        let Some((first, rest)) = parts.split_first() else {
            node.written = written;
            node.values = values
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect();
            return;
        };
        let at = if let Some(i) = node.children.iter().position(|c| c.name == *first) {
            i
        } else {
            node.children.push(Node {
                name: (*first).to_owned(),
                ..Node::default()
            });
            node.children.len() - 1
        };
        insert(&mut node.children[at], rest, written, values);
    }
    fn cell(data: &mut Vec<u8>, body: &[u8]) -> u32 {
        let offset = u32::try_from(data.len()).unwrap_or(0);
        let mut len = body.len() + 4;
        len = len.div_ceil(8) * 8;
        let size = -i32::try_from(len).unwrap_or(0);
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(body);
        data.resize(offset as usize + len, 0);
        offset
    }
    fn write(node: &Node, data: &mut Vec<u8>) -> u32 {
        let children: Vec<u32> = node.children.iter().map(|c| write(c, data)).collect();
        let list = if children.is_empty() {
            u32::MAX
        } else {
            let mut body = b"li".to_vec();
            body.extend_from_slice(&u16::try_from(children.len()).unwrap_or(0).to_le_bytes());
            for c in &children {
                body.extend_from_slice(&c.to_le_bytes());
            }
            cell(data, &body)
        };
        let mut value_cells = Vec::new();
        for (name, text) in &node.values {
            let utf: Vec<u8> = text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            let data_cell = cell(data, &utf);
            let mut vk = b"vk".to_vec();
            vk.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_le_bytes());
            vk.extend_from_slice(&u32::try_from(utf.len()).unwrap_or(0).to_le_bytes());
            vk.extend_from_slice(&data_cell.to_le_bytes());
            vk.extend_from_slice(&1_u32.to_le_bytes());
            vk.extend_from_slice(&1_u16.to_le_bytes());
            vk.extend_from_slice(&0_u16.to_le_bytes());
            vk.extend_from_slice(name.as_bytes());
            value_cells.push(cell(data, &vk));
        }
        let values = if value_cells.is_empty() {
            u32::MAX
        } else {
            let body: Vec<u8> = value_cells.iter().flat_map(|v| v.to_le_bytes()).collect();
            cell(data, &body)
        };
        let mut nk = vec![0_u8; 76];
        nk[0..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&0x20_u16.to_le_bytes());
        nk[4..12].copy_from_slice(&node.written.to_le_bytes());
        nk[20..24].copy_from_slice(&u32::try_from(children.len()).unwrap_or(0).to_le_bytes());
        nk[28..32].copy_from_slice(&list.to_le_bytes());
        nk[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[36..40].copy_from_slice(&u32::try_from(node.values.len()).unwrap_or(0).to_le_bytes());
        nk[40..44].copy_from_slice(&values.to_le_bytes());
        nk[72..74].copy_from_slice(&u16::try_from(node.name.len()).unwrap_or(0).to_le_bytes());
        nk.extend_from_slice(node.name.as_bytes());
        cell(data, &nk)
    }
    let mut root = Node {
        name: "ROOT".to_owned(),
        ..Node::default()
    };
    for (path, written, values) in keys {
        let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
        insert(&mut root, &parts, *written, values);
    }
    // hbin header is 32 bytes; cells follow.
    let mut data = vec![0_u8; 32];
    data[0..4].copy_from_slice(b"hbin");
    let root_offset = write(&root, &mut data);
    let mut file = vec![0_u8; BASE_BLOCK];
    file[0..4].copy_from_slice(b"regf");
    file[4..8].copy_from_slice(&1_u32.to_le_bytes());
    file[8..12].copy_from_slice(&1_u32.to_le_bytes());
    file[36..40].copy_from_slice(&root_offset.to_le_bytes());
    file.extend_from_slice(&data);
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_keys_and_reads_values() {
        let bytes = build(&[
            (
                r"Root\InventoryApplicationFile\a.exe|1",
                134_353_296_000_000_000,
                &[("LowerCaseLongPath", r"c:\users\a\downloads\a.exe")],
            ),
            (r"Root\InventoryApplicationFile\b.exe|2", 0, &[]),
        ]);
        let hive = Hive::parse(&bytes).unwrap();
        assert!(!hive.dirty);
        let files = hive
            .path(hive.root(), r"Root\InventoryApplicationFile")
            .unwrap();
        let keys = hive.subkeys(files);
        assert_eq!(keys.len(), 2);
        assert_eq!(hive.name(keys[0]).as_deref(), Some("a.exe|1"));
        assert_eq!(
            hive.last_written(keys[0]).map(|t| t.to_string()).as_deref(),
            Some("2026-10-01T12:00:00Z")
        );
        assert_eq!(
            hive.values(keys[0]),
            vec![(
                "LowerCaseLongPath".to_owned(),
                Some(Data::Text(r"c:\users\a\downloads\a.exe".to_owned()))
            )]
        );
        assert!(hive.path(hive.root(), r"Root\Nothing").is_none());
    }

    #[test]
    fn damaged_hives_error_or_stop_never_panic() {
        assert!(Hive::parse(b"regf").is_err());
        assert!(Hive::parse(&vec![0_u8; 5000]).is_err());
        let bytes = build(&[(r"Root\X\Y", 1, &[("A", "b")])]);
        for n in (0..bytes.len()).step_by(7) {
            if let Ok(h) = Hive::parse(&bytes[..n]) {
                let _ = h.path(h.root(), r"Root\X\Y").map(|k| h.values(k));
            }
        }
        // Flip bytes through the cells.
        for i in (BASE_BLOCK..bytes.len()).step_by(3) {
            let mut b = bytes.clone();
            b[i] ^= 0xFF;
            if let Ok(h) = Hive::parse(&b)
                && let Some(k) = h.path(h.root(), r"Root\X")
            {
                for c in h.subkeys(k) {
                    let _ = (h.name(c), h.values(c), h.last_written(c));
                }
            }
        }
    }
}
