// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows shell items and item ID lists (`PIDLs`), as `ShellBags` and the common file dialog's
//! `OpenSavePidlMRU` store them (B.O.P.E, ADR 0126).
//!
//! Decoded: root folders (by class id), volumes (`C:\`), file entries (folder or file, the short name,
//! the long name from the `0xBEEF0004` extension block, the FAT times and, from extension version 7,
//! the NTFS file reference) and network locations. Anything else is kept as its class type byte, never
//! guessed. Layout from the public shell item documentation (libyal/libfwsi, "Windows Shell Item
//! format").
//!
//! A shell item's times are the folder's or file's own FAT times **when the item was made** — two
//! seconds of precision — not when it was opened.

use crate::error::ParseError;

/// Most items read from one list.
pub const MAX_ITEMS: usize = 64;

/// One decoded shell item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellItem {
    /// A root folder, by class id, with a label when the class id is a known one.
    Root {
        /// Class id, `{xxxxxxxx-...}` upper case.
        guid: String,
        /// What the path shows for it: `%USERPROFILE%`, `Network`, … or the class id.
        label: String,
    },
    /// A volume, `C:\`.
    Volume {
        /// The volume's name as stored, `C:\`.
        name: String,
    },
    /// A file or folder.
    File(FileEntry),
    /// A network location, `\\server\share`.
    Network {
        /// The location.
        location: String,
    },
    /// An item of a class this reader does not decode.
    Other {
        /// Class type byte.
        class: u8,
    },
}

/// A file entry shell item.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileEntry {
    /// Whether it is a folder.
    pub directory: bool,
    /// The long name when stored, else the short name.
    pub name: String,
    /// Last write time.
    pub modified: Option<jiff::Timestamp>,
    /// Creation time, from the extension block.
    pub created: Option<jiff::Timestamp>,
    /// Last access time, from the extension block.
    pub accessed: Option<jiff::Timestamp>,
    /// NTFS record number of the file or folder, from extension version 7 and later.
    pub mft_record: Option<u64>,
    /// NTFS sequence number with it.
    pub mft_sequence: Option<u16>,
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

/// A FAT date and time (date in the low 16 bits) as a timestamp. `None` for zero or impossible
/// values.
pub fn fat_time(value: u32) -> Option<jiff::Timestamp> {
    let date = value & 0xFFFF;
    let time = value >> 16;
    if date == 0 {
        return None;
    }
    let year = i16::try_from(1980 + (date >> 9)).ok()?;
    let month = i8::try_from((date >> 5) & 0x0F).ok()?;
    let day = i8::try_from(date & 0x1F).ok()?;
    let hour = i8::try_from(time >> 11).ok()?;
    let minute = i8::try_from((time >> 5) & 0x3F).ok()?;
    let second = i8::try_from((time & 0x1F) * 2).ok()?;
    jiff::civil::DateTime::new(year, month, day, hour, minute, second, 0)
        .ok()?
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|z| z.timestamp())
}

/// Formats 16 bytes as a class id.
pub fn guid(b: &[u8]) -> Option<String> {
    let d1 = u32_at(b, 0)?;
    let d2 = u16_at(b, 4)?;
    let d3 = u16_at(b, 6)?;
    let d4 = b.get(8..16)?;
    Some(format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    ))
}

fn root_label(guid: &str) -> Option<&'static str> {
    Some(match guid {
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" => "",
        "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" => "%USERPROFILE%",
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" => "Network",
        "{031E4825-7B94-4DC3-B131-E946B44C8DD5}" => "Libraries",
        "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" => "OneDrive",
        "{645FF040-5081-101B-9F08-00AA002F954E}" => "Recycle Bin",
        "{26EE0668-A00A-44D7-9371-BEB064C98683}" => "Control Panel",
        "{679F85CB-0220-4080-B29B-5540CC05AAB6}" => "Quick access",
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" => "Desktop",
        "{374DE290-123F-4565-9164-39C4925E467B}" => "Downloads",
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" => "Documents",
        _ => return None,
    })
}

fn ascii_z(b: &[u8]) -> String {
    b.iter()
        .take_while(|c| **c != 0)
        .map(|c| char::from(*c))
        .collect()
}

fn utf16_z(b: &[u8]) -> (String, usize) {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .take_while(|u| *u != 0)
        .collect();
    let used = (units.len() + 1) * 2;
    (String::from_utf16_lossy(&units), used)
}

fn file_entry(item: &[u8], class: u8) -> Option<FileEntry> {
    let mut entry = FileEntry {
        directory: class & 0x01 != 0,
        modified: u32_at(item, 8).and_then(fat_time),
        ..FileEntry::default()
    };
    let unicode = class & 0x04 != 0;
    let name_at = 14;
    let rest = item.get(name_at..)?;
    let (short, used) = if unicode {
        utf16_z(rest)
    } else {
        let s = ascii_z(rest);
        let used = s.len() + 1;
        (s, used)
    };
    entry.name = short;
    // The extension block starts on a 2-byte boundary after the short name.
    let mut at = name_at + used;
    at += at % 2;
    if let Some(ext) = item.get(at..)
        && u32_at(ext, 4) == Some(0xBEEF_0004)
    {
        let version = u16_at(ext, 2).unwrap_or(0);
        entry.created = u32_at(ext, 8).and_then(fat_time);
        entry.accessed = u32_at(ext, 12).and_then(fat_time);
        if version >= 7
            && let Some(reference) = u64_at(ext, 20)
        {
            let record = reference & 0x0000_FFFF_FFFF_FFFF;
            if record != 0 {
                entry.mft_record = Some(record);
                entry.mft_sequence = u16::try_from(reference >> 48).ok();
            }
        }
        let long_at = match version {
            3..=6 => Some(20),
            7 => Some(38),
            8 => Some(42),
            9.. => Some(46),
            _ => None,
        };
        if let Some(long_at) = long_at
            && let Some(bytes) = ext.get(long_at..ext.len().saturating_sub(2))
        {
            let (long, _) = utf16_z(bytes);
            if !long.is_empty() && long.chars().all(|c| !c.is_control()) {
                entry.name = long;
            }
        }
    }
    Some(entry)
}

/// Decodes one shell item: its bytes **without** the 2-byte size that precedes it in a list.
pub fn item(item_with_size: &[u8]) -> ShellItem {
    let Some(&class) = item_with_size.get(2) else {
        return ShellItem::Other { class: 0 };
    };
    match class {
        0x1F => match item_with_size.get(4..20).and_then(guid) {
            Some(g) => ShellItem::Root {
                label: root_label(&g).map_or_else(|| g.clone(), str::to_owned),
                guid: g,
            },
            None => ShellItem::Other { class },
        },
        0x20..=0x2F => ShellItem::Volume {
            name: ascii_z(item_with_size.get(3..).unwrap_or_default()),
        },
        0x30..=0x3F => {
            file_entry(item_with_size, class).map_or(ShellItem::Other { class }, ShellItem::File)
        }
        0x41..=0x4F => ShellItem::Network {
            location: ascii_z(item_with_size.get(5..).unwrap_or_default()),
        },
        _ => ShellItem::Other { class },
    }
}

/// Splits an item ID list into its items (each with its size prefix) and decodes them.
pub fn list(bytes: &[u8]) -> Result<Vec<ShellItem>, ParseError> {
    let mut out = Vec::new();
    let mut at = 0;
    while out.len() < MAX_ITEMS {
        let Some(size) = u16_at(bytes, at) else {
            break;
        };
        let size = usize::from(size);
        if size == 0 {
            break;
        }
        let Some(raw) = bytes.get(at..at + size) else {
            return Err(ParseError::Truncated {
                expected: at + size,
                found: bytes.len(),
            });
        };
        if size < 3 {
            return Err(ParseError::Malformed {
                field: "item_size",
                detail: "a shell item shorter than its header".to_owned(),
            });
        }
        out.push(item(raw));
        at += size;
    }
    Ok(out)
}

/// The text one item adds to a path, or `None` for an item that adds nothing readable.
pub fn segment(item: &ShellItem) -> Option<String> {
    match item {
        ShellItem::Root { label, .. } if label.is_empty() => None,
        ShellItem::Root { label, .. } => Some(label.clone()),
        ShellItem::Volume { name } => Some(name.trim_end_matches('\\').to_owned()),
        ShellItem::File(f) => Some(f.name.clone()),
        ShellItem::Network { location } => Some(location.clone()),
        ShellItem::Other { class } => Some(format!("<0x{class:02X}>")),
    }
}

/// Joins items into a path, `C:\Users\a\Downloads`.
pub fn path(items: &[ShellItem]) -> String {
    let mut out = String::new();
    for s in items.iter().filter_map(segment) {
        if !out.is_empty() && !out.ends_with('\\') {
            out.push('\\');
        }
        out.push_str(&s);
    }
    out
}

/// Encodes a volume item, for tests in this workspace.
pub fn build_volume(letter: char) -> Vec<u8> {
    let mut b = vec![0_u8, 0, 0x2F];
    b.extend_from_slice(format!("{letter}:\\").as_bytes());
    b.resize(25, 0);
    let size = u16::try_from(b.len()).unwrap_or(0).to_le_bytes();
    b[0..2].copy_from_slice(&size);
    b
}

/// Encodes a folder item with an extension block of version 9 carrying `name` and an NTFS
/// reference, for tests in this workspace. `fat` is the FAT date/time of all three times.
pub fn build_folder(name: &str, fat: u32, mft_record: u64) -> Vec<u8> {
    let short: String = name.chars().filter(char::is_ascii).take(12).collect();
    let mut b = vec![0_u8, 0, 0x31, 0];
    b.extend_from_slice(&0_u32.to_le_bytes());
    b.extend_from_slice(&fat.to_le_bytes());
    b.extend_from_slice(&0x10_u16.to_le_bytes());
    b.extend_from_slice(short.as_bytes());
    b.push(0);
    if b.len() % 2 == 1 {
        b.push(0);
    }
    let ext_start = b.len();
    let mut ext = vec![0_u8; 46];
    ext[2..4].copy_from_slice(&9_u16.to_le_bytes());
    ext[4..8].copy_from_slice(&0xBEEF_0004_u32.to_le_bytes());
    ext[8..12].copy_from_slice(&fat.to_le_bytes());
    ext[12..16].copy_from_slice(&fat.to_le_bytes());
    ext[20..28].copy_from_slice(&(mft_record | (3_u64 << 48)).to_le_bytes());
    for u in name.encode_utf16().chain(std::iter::once(0)) {
        ext.extend_from_slice(&u.to_le_bytes());
    }
    ext.extend_from_slice(&u16::try_from(ext_start).unwrap_or(0).to_le_bytes());
    let ext_len = u16::try_from(ext.len()).unwrap_or(0).to_le_bytes();
    ext[0..2].copy_from_slice(&ext_len);
    b.extend_from_slice(&ext);
    let size = u16::try_from(b.len()).unwrap_or(0).to_le_bytes();
    b[0..2].copy_from_slice(&size);
    b
}

/// Encodes the "My Computer" root item, for tests in this workspace.
pub fn build_my_computer() -> Vec<u8> {
    let mut b = vec![20_u8, 0, 0x1F, 0x50];
    b.extend_from_slice(&[
        0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30,
        0x9D,
    ]);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-01 12:30:10: date (46 << 9) | (10 << 5) | 1, time (12 << 11) | (30 << 5) | 5.
    const FAT: u32 = ((46 << 9) | (10 << 5) | 1) | (((12 << 11) | (30 << 5) | 5) << 16);

    #[test]
    fn a_pidl_of_my_computer_a_volume_and_folders_reads_as_a_path() {
        let mut pidl = build_my_computer();
        pidl.extend(build_volume('D'));
        pidl.extend(build_folder("Executores Roblox", FAT, 4242));
        pidl.extend(build_folder("Solara", FAT, 4243));
        pidl.extend([0, 0]);
        let items = list(&pidl).unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(path(&items), r"D:\Executores Roblox\Solara");
        let ShellItem::File(f) = &items[3] else {
            panic!("{:?}", items[3])
        };
        assert!(f.directory);
        assert_eq!(f.mft_record, Some(4243));
        assert_eq!(f.mft_sequence, Some(3));
        assert_eq!(f.modified.unwrap().to_string(), "2026-10-01T12:30:10Z");
        assert_eq!(f.created, f.modified);
    }

    #[test]
    fn a_root_class_id_is_labelled_and_garbage_is_an_error_or_other() {
        let mut users = vec![20_u8, 0, 0x1F, 0];
        users.extend_from_slice(&[
            0x47, 0x1A, 0x03, 0x59, 0x72, 0x3F, 0xA7, 0x44, 0x89, 0xC5, 0x55, 0x95, 0xFE, 0x6B,
            0x30, 0xEE,
        ]);
        assert_eq!(segment(&item(&users)).unwrap(), "%USERPROFILE%");
        assert!(list(&[50, 0, 1, 2]).is_err());
        assert!(list(&[2, 0]).is_err());
        assert_eq!(item(&[4, 0, 0x99, 0]), ShellItem::Other { class: 0x99 });
        assert_eq!(fat_time(0), None);
        assert_eq!(fat_time(0xFFFF_FFFF), None);
    }
}
