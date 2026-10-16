// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows minidump files (`.dmp`, signature `MDMP`), as Windows Error Reporting and crash handlers
//! write them (B.O.P.E, ADR 0135).
//!
//! A dump that already exists on the PC is a copy of part of a process's memory at the moment it was
//! written, which can be long before the scan. Read here: the header's time, which process it was and
//! when it started (`MiscInfoStream`), its modules (`ModuleListStream`), and where each captured memory
//! range is in the file (`MemoryListStream`, `Memory64ListStream`), so a caller can hand those bytes to
//! [`crate::memory`]. No thread context, stack or exception record is interpreted.
//!
//! Format: Microsoft's `minidumpapiset.h` (`MINIDUMP_HEADER`, `MINIDUMP_DIRECTORY`,
//! `MINIDUMP_MEMORY_LIST`, `MINIDUMP_MEMORY64_LIST`, `MINIDUMP_MODULE_LIST`, `MINIDUMP_MISC_INFO`).

use crate::error::ParseError;

/// Most streams, modules and memory ranges read from one dump.
pub const MAX_ENTRIES: usize = 65_536;

/// One stream directory entry: `(stream type, data size, data offset)`.
pub type StreamEntry = (u32, u32, u32);

/// One captured memory range and where its bytes are in the dump file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRange {
    /// The virtual address the bytes were at in the process.
    pub address: u64,
    /// How many bytes were captured.
    pub size: u64,
    /// Where they start in the file.
    pub file_offset: u64,
}

/// One module the process had loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpModule {
    /// Base address.
    pub base: u64,
    /// `SizeOfImage`.
    pub size: u32,
    /// The image's `TimeDateStamp`.
    pub timestamp: u32,
    /// The image's `CheckSum`.
    pub checksum: u32,
    /// The full path as the dump spells it.
    pub name: String,
}

/// What a minidump says about the process it captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Minidump {
    /// When the dump was written, seconds since 1970 (`MINIDUMP_HEADER.TimeDateStamp`).
    pub written_at: u32,
    /// `MINIDUMP_HEADER.Flags` (`MINIDUMP_TYPE`).
    pub flags: u64,
    /// The process id, when the misc-info stream records it.
    pub process_id: Option<u32>,
    /// When the process was created, seconds since 1970, when recorded.
    pub process_created_at: Option<u32>,
    /// Loaded modules.
    pub modules: Vec<DumpModule>,
    /// Captured memory.
    pub memory: Vec<MemoryRange>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    let mut array = [0_u8; 8];
    array.copy_from_slice(slice);
    Some(u64::from_le_bytes(array))
}

/// The header and stream directory of a dump: the first bytes of the file are enough, so a caller can
/// read only those (`header_bytes` long) before deciding to read more. Returns `(stream type, data
/// size, data offset)` per stream.
pub fn streams(bytes: &[u8]) -> Result<(u32, u64, Vec<StreamEntry>), ParseError> {
    if bytes.len() < 32 {
        return Err(ParseError::Truncated {
            expected: 32,
            found: bytes.len(),
        });
    }
    if bytes.get(..4) != Some(b"MDMP") {
        return Err(ParseError::Malformed {
            field: "signature",
            detail: "not a minidump (no MDMP signature)".to_owned(),
        });
    }
    let count = u32_at(bytes, 8).unwrap_or(0);
    let directory = u32_at(bytes, 12).unwrap_or(0);
    let written_at = u32_at(bytes, 20).unwrap_or(0);
    let flags = u64_at(bytes, 24).unwrap_or(0);
    let mut list = Vec::new();
    for index in 0..usize::try_from(count).unwrap_or(0).min(MAX_ENTRIES) {
        let at = usize::try_from(directory)
            .unwrap_or(usize::MAX)
            .saturating_add(index * 12);
        let (Some(kind), Some(size), Some(rva)) = (
            u32_at(bytes, at),
            u32_at(bytes, at + 4),
            u32_at(bytes, at + 8),
        ) else {
            break;
        };
        list.push((kind, size, rva));
    }
    Ok((written_at, flags, list))
}

/// How many bytes from the start of a dump [`parse`] needs to read everything but the captured memory
/// itself: the end of the furthest stream other than the memory data, and of module names.
pub fn metadata_extent(bytes: &[u8]) -> Result<u64, ParseError> {
    let (_, _, list) = streams(bytes)?;
    Ok(list
        .iter()
        .map(|(_, size, rva)| u64::from(*rva) + u64::from(*size))
        .max()
        .unwrap_or(32))
}

fn utf16_string(bytes: &[u8], rva: u32) -> Option<String> {
    let at = usize::try_from(rva).ok()?;
    let length = usize::try_from(u32_at(bytes, at)?).ok()?.min(2048);
    let data = bytes.get(at + 4..at + 4 + length)?;
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Parses a dump's header, modules, process facts and memory list. `bytes` may be only the first
/// [`metadata_extent`] bytes of the file: the memory ranges are located, not read.
pub fn parse(bytes: &[u8]) -> Result<Minidump, ParseError> {
    let (written_at, flags, list) = streams(bytes)?;
    let mut dump = Minidump {
        written_at,
        flags,
        process_id: None,
        process_created_at: None,
        modules: Vec::new(),
        memory: Vec::new(),
    };
    for (kind, size, rva) in list {
        let at = usize::try_from(rva).unwrap_or(usize::MAX);
        match kind {
            // ModuleListStream: count, then MINIDUMP_MODULE (108 bytes) each.
            4 => {
                let count = u32_at(bytes, at).unwrap_or(0);
                for index in 0..usize::try_from(count).unwrap_or(0).min(MAX_ENTRIES) {
                    let module = at + 4 + index * 108;
                    let (Some(base), Some(size), Some(checksum), Some(timestamp), Some(name_rva)) = (
                        u64_at(bytes, module),
                        u32_at(bytes, module + 8),
                        u32_at(bytes, module + 12),
                        u32_at(bytes, module + 16),
                        u32_at(bytes, module + 20),
                    ) else {
                        break;
                    };
                    dump.modules.push(DumpModule {
                        base,
                        size,
                        timestamp,
                        checksum,
                        name: utf16_string(bytes, name_rva).unwrap_or_default(),
                    });
                }
            }
            // MemoryListStream: count, then MINIDUMP_MEMORY_DESCRIPTOR (16 bytes) each.
            5 => {
                let count = u32_at(bytes, at).unwrap_or(0);
                for index in 0..usize::try_from(count).unwrap_or(0).min(MAX_ENTRIES) {
                    let descriptor = at + 4 + index * 16;
                    let (Some(address), Some(data_size), Some(data_rva)) = (
                        u64_at(bytes, descriptor),
                        u32_at(bytes, descriptor + 8),
                        u32_at(bytes, descriptor + 12),
                    ) else {
                        break;
                    };
                    dump.memory.push(MemoryRange {
                        address,
                        size: u64::from(data_size),
                        file_offset: u64::from(data_rva),
                    });
                }
            }
            // Memory64ListStream: count (u64), base RVA (u64), then (start, size) pairs; the data
            // follows contiguously from the base.
            9 => {
                let count = u64_at(bytes, at).unwrap_or(0);
                let mut offset = u64_at(bytes, at + 8).unwrap_or(0);
                for index in 0..usize::try_from(count).unwrap_or(0).min(MAX_ENTRIES) {
                    let descriptor = at + 16 + index * 16;
                    let (Some(address), Some(data_size)) =
                        (u64_at(bytes, descriptor), u64_at(bytes, descriptor + 8))
                    else {
                        break;
                    };
                    dump.memory.push(MemoryRange {
                        address,
                        size: data_size,
                        file_offset: offset,
                    });
                    offset = offset.saturating_add(data_size);
                }
            }
            // MiscInfoStream: SizeOfInfo, Flags1, ProcessId, ProcessCreateTime, …
            15 if size >= 24 => {
                let flags1 = u32_at(bytes, at + 4).unwrap_or(0);
                if flags1 & 0x1 != 0 {
                    dump.process_id = u32_at(bytes, at + 8);
                }
                if flags1 & 0x2 != 0 {
                    dump.process_created_at = u32_at(bytes, at + 12);
                }
            }
            _ => {}
        }
    }
    Ok(dump)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut file = vec![0_u8; 0x200];
        file[..4].copy_from_slice(b"MDMP");
        file[4..8].copy_from_slice(&0xa793_u32.to_le_bytes());
        file[8..12].copy_from_slice(&3_u32.to_le_bytes());
        file[12..16].copy_from_slice(&0x20_u32.to_le_bytes());
        file[20..24].copy_from_slice(&1_760_000_000_u32.to_le_bytes());
        // Directory at 0x20: modules at 0x60, memory64 at 0x100, misc at 0x180.
        let entries: [(u32, u32, u32); 3] = [(4, 4 + 108, 0x60), (9, 32, 0x100), (15, 24, 0x180)];
        for (index, (kind, size, rva)) in entries.iter().enumerate() {
            let at = 0x20 + index * 12;
            file[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            file[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
            file[at + 8..at + 12].copy_from_slice(&rva.to_le_bytes());
        }
        file[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
        file[0x64..0x6c].copy_from_slice(&0x7ff6_0000_0000_u64.to_le_bytes());
        file[0x6c..0x70].copy_from_slice(&0x1000_u32.to_le_bytes());
        file[0x78..0x7c].copy_from_slice(&0x1e0_u32.to_le_bytes()); // name RVA
        let name: Vec<u8> = "C:\\R\\RobloxPlayerBeta.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        file[0x1e0..0x1e4].copy_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
        file.resize(0x1e4 + name.len(), 0);
        file[0x1e4..].copy_from_slice(&name);
        file[0x100..0x108].copy_from_slice(&1_u64.to_le_bytes());
        file[0x108..0x110].copy_from_slice(&0x1000_u64.to_le_bytes());
        file[0x110..0x118].copy_from_slice(&0x2000_0000_u64.to_le_bytes());
        file[0x118..0x120].copy_from_slice(&0x40_u64.to_le_bytes());
        file[0x180..0x184].copy_from_slice(&24_u32.to_le_bytes());
        file[0x184..0x188].copy_from_slice(&3_u32.to_le_bytes());
        file[0x188..0x18c].copy_from_slice(&4321_u32.to_le_bytes());
        file[0x18c..0x190].copy_from_slice(&1_759_990_000_u32.to_le_bytes());
        file
    }

    #[test]
    fn a_dump_reads_its_process_modules_and_memory() {
        let bytes = sample();
        let dump = parse(&bytes).unwrap();
        assert_eq!(dump.written_at, 1_760_000_000);
        assert_eq!(dump.process_id, Some(4321));
        assert_eq!(dump.process_created_at, Some(1_759_990_000));
        assert_eq!(dump.modules.len(), 1);
        assert_eq!(dump.modules[0].name, "C:\\R\\RobloxPlayerBeta.exe");
        assert_eq!(
            dump.memory,
            vec![MemoryRange {
                address: 0x2000_0000,
                size: 0x40,
                file_offset: 0x1000
            }]
        );
        assert!(metadata_extent(&bytes).unwrap() >= 0x198);
    }

    #[test]
    fn anything_else_is_an_error_never_a_panic() {
        assert!(parse(b"MDMP").is_err());
        assert!(parse(&[0_u8; 64]).is_err());
        let base = sample();
        for at in 0..base.len() {
            let mut bytes = base.clone();
            bytes[at] ^= 0xa5;
            let _ = parse(&bytes);
        }
        for cut in 0..base.len() {
            let _ = parse(&base[..cut]);
        }
    }
}
