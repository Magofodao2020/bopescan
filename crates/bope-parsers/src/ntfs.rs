// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! NTFS metadata: the boot sector, Master File Table (`$MFT`) file records and the data runs that say
//! where the `$MFT` itself lies on the volume (B.O.P.E, ADR 0125).
//!
//! A file record is read for its **metadata** only: whether it is in use, whether it is a folder, its
//! sequence number, the `$STANDARD_INFORMATION` and `$FILE_NAME` times, its names and parent folder,
//! and its data size. No file content is read, and a record that is not in use is reported as what it
//! is — the metadata NTFS left in a record it may reuse at any time — never as a recovered file.
//!
//! Layout from the public NTFS documentation (libyal/libfsntfs, "New Technologies File System (NTFS)").

use crate::error::ParseError;
use crate::filetime;

/// The record number of the volume's root folder.
pub const ROOT_RECORD: u64 = 5;
/// Attribute types read.
const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

/// What the boot sector says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boot {
    /// Bytes per sector.
    pub sector_size: u32,
    /// Bytes per cluster.
    pub cluster_size: u64,
    /// Cluster number of the start of `$MFT`.
    pub mft_cluster: u64,
    /// Bytes per file record.
    pub record_size: u32,
    /// Sectors on the volume.
    pub total_sectors: u64,
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

fn malformed(field: &'static str, detail: &str) -> ParseError {
    ParseError::Malformed {
        field,
        detail: detail.to_owned(),
    }
}

/// Parses an NTFS boot sector.
pub fn boot(bytes: &[u8]) -> Result<Boot, ParseError> {
    if bytes.len() < 512 {
        return Err(ParseError::Truncated {
            expected: 512,
            found: bytes.len(),
        });
    }
    if bytes.get(3..11) != Some(b"NTFS    ".as_slice()) {
        return Err(malformed("oem_id", "not an NTFS boot sector"));
    }
    let sector_size = u32::from(u16_at(bytes, 11).unwrap_or(0));
    let per_cluster = bytes.get(13).copied().unwrap_or(0);
    if !matches!(sector_size, 512 | 1024 | 2048 | 4096) || per_cluster == 0 {
        return Err(malformed("geometry", "sector or cluster size out of range"));
    }
    // Values above 0x80 are a negative power of two (clusters of 64 KiB and up).
    let cluster_size = if per_cluster <= 0x80 {
        u64::from(sector_size) * u64::from(per_cluster)
    } else {
        let shift = 256_u32 - u32::from(per_cluster);
        1_u64.checked_shl(shift).unwrap_or(0)
    };
    if cluster_size == 0 || cluster_size > 2 * 1024 * 1024 {
        return Err(malformed("cluster_size", "cluster size out of range"));
    }
    let raw: i8 = bytes.get(64).map_or(0, |b| i8::from_le_bytes([*b]));
    let record_size = if raw > 0 {
        u64::from(raw.unsigned_abs()) * cluster_size
    } else {
        1_u64
            .checked_shl(u32::from(raw.unsigned_abs()))
            .unwrap_or(0)
    };
    if !(256..=65_536).contains(&record_size) {
        return Err(malformed("record_size", "file record size out of range"));
    }
    Ok(Boot {
        sector_size,
        cluster_size,
        mft_cluster: u64_at(bytes, 48).unwrap_or(0),
        record_size: u32::try_from(record_size).unwrap_or(1024),
        total_sectors: u64_at(bytes, 40).unwrap_or(0),
    })
}

/// Applies the update sequence ("fixups") to a file record in place. `false` when the record's
/// sector ends do not carry the update sequence number, which is a torn or damaged record.
pub fn apply_fixups(record: &mut [u8], sector_size: u32) -> bool {
    let (Some(offset), Some(count)) = (u16_at(record, 4), u16_at(record, 6)) else {
        return false;
    };
    let (offset, count) = (usize::from(offset), usize::from(count));
    let Ok(sector) = usize::try_from(sector_size) else {
        return false;
    };
    if count < 2 || sector < 2 || offset + count * 2 > record.len() {
        return false;
    }
    let Some(usn) = u16_at(record, offset) else {
        return false;
    };
    for i in 1..count {
        let end = i * sector;
        if end > record.len() || end < 2 {
            return false;
        }
        if u16_at(record, end - 2) != Some(usn) {
            return false;
        }
        let Some(fix) = record
            .get(offset + i * 2..offset + i * 2 + 2)
            .map(<[u8]>::to_vec)
        else {
            return false;
        };
        if let Some(slot) = record.get_mut(end - 2..end) {
            slot.copy_from_slice(&fix);
        }
    }
    true
}

/// One `$FILE_NAME` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    /// Parent folder's record number.
    pub parent: u64,
    /// Parent folder's sequence number, as this name recorded it.
    pub parent_sequence: u16,
    /// The name.
    pub name: String,
    /// 0 POSIX, 1 Win32, 2 DOS (8.3), 3 Win32 and DOS.
    pub namespace: u8,
    /// Creation time as this attribute recorded it.
    pub created: Option<jiff::Timestamp>,
    /// Last write time as this attribute recorded it.
    pub modified: Option<jiff::Timestamp>,
}

/// What one file record says.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileRecord {
    /// Record number.
    pub number: u64,
    /// Sequence number: incremented each time the record is reused.
    pub sequence: u16,
    /// The record holds a live file or folder.
    pub in_use: bool,
    /// The record is a folder.
    pub directory: bool,
    /// Non-zero for an extension record of another file.
    pub base_record: u64,
    /// `$STANDARD_INFORMATION` creation time.
    pub si_created: Option<jiff::Timestamp>,
    /// `$STANDARD_INFORMATION` last write time.
    pub si_modified: Option<jiff::Timestamp>,
    /// `$STANDARD_INFORMATION` record change time.
    pub si_changed: Option<jiff::Timestamp>,
    /// `$FILE_NAME` attributes, as stored.
    pub names: Vec<FileName>,
    /// Size of the unnamed `$DATA` stream, when stated.
    pub size: Option<u64>,
    /// Data runs of the unnamed `$DATA` stream, when it is non-resident: `(cluster, clusters)`.
    pub runs: Vec<(u64, u64)>,
}

impl FileRecord {
    /// The name a person would see: the Win32 one before the DOS short one.
    pub fn best_name(&self) -> Option<&FileName> {
        self.names.iter().min_by_key(|n| match n.namespace {
            1 | 3 => 0,
            0 => 1,
            _ => 2,
        })
    }
}

fn time_at(b: &[u8], at: usize) -> Option<jiff::Timestamp> {
    u64_at(b, at).and_then(filetime::to_timestamp)
}

/// Decodes a data run list into `(cluster, clusters)` pairs. A sparse run (no offset) is skipped.
pub fn data_runs(bytes: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = 0;
    let mut cluster: i64 = 0;
    while let Some(&header) = bytes.get(at) {
        if header == 0 || out.len() > 65_536 {
            break;
        }
        let len_size = usize::from(header & 0x0F);
        let off_size = usize::from(header >> 4);
        if len_size == 0 || len_size > 8 || off_size > 8 {
            break;
        }
        let Some(len_bytes) = bytes.get(at + 1..at + 1 + len_size) else {
            break;
        };
        let mut length = [0_u8; 8];
        length[..len_size].copy_from_slice(len_bytes);
        let length = u64::from_le_bytes(length);
        let Some(off_bytes) = bytes.get(at + 1 + len_size..at + 1 + len_size + off_size) else {
            break;
        };
        at += 1 + len_size + off_size;
        if off_size == 0 {
            continue;
        }
        let negative = off_bytes.last().is_some_and(|b| b & 0x80 != 0);
        let mut offset = if negative { [0xFF_u8; 8] } else { [0_u8; 8] };
        offset[..off_size].copy_from_slice(off_bytes);
        cluster = cluster.wrapping_add(i64::from_le_bytes(offset));
        if let Ok(start) = u64::try_from(cluster) {
            out.push((start, length));
        }
    }
    out
}

/// Parses one file record whose fixups were already applied. `None` when it is not a `FILE` record.
pub fn record(bytes: &[u8], number: u64) -> Option<FileRecord> {
    if bytes.get(0..4) != Some(b"FILE".as_slice()) {
        return None;
    }
    let flags = u16_at(bytes, 22)?;
    let mut out = FileRecord {
        number,
        sequence: u16_at(bytes, 16)?,
        in_use: flags & 0x01 != 0,
        directory: flags & 0x02 != 0,
        base_record: u64_at(bytes, 32)? & 0x0000_FFFF_FFFF_FFFF,
        ..FileRecord::default()
    };
    let used = usize::try_from(u32_at(bytes, 24)?).ok()?.min(bytes.len());
    let mut at = usize::from(u16_at(bytes, 20)?);
    for _ in 0..64 {
        let kind = u32_at(bytes, at)?;
        if kind == ATTR_END {
            break;
        }
        let length = usize::try_from(u32_at(bytes, at + 4)?).ok()?;
        if length < 16 || at + length > used {
            break;
        }
        let attr = bytes.get(at..at + length)?;
        let non_resident = attr.get(8).copied()? != 0;
        let name_length = attr.get(9).copied()?;
        if non_resident {
            if kind == ATTR_DATA && name_length == 0 {
                out.size = u64_at(attr, 48);
                let runs_at = usize::from(u16_at(attr, 32)?);
                if u64_at(attr, 16) == Some(0) {
                    out.runs = data_runs(attr.get(runs_at..).unwrap_or_default());
                }
            }
        } else {
            let content_length = usize::try_from(u32_at(attr, 16)?).ok()?;
            let content_at = usize::from(u16_at(attr, 20)?);
            let content = attr.get(content_at..content_at.checked_add(content_length)?);
            match (kind, content) {
                (ATTR_STANDARD_INFORMATION, Some(c)) => {
                    out.si_created = time_at(c, 0);
                    out.si_modified = time_at(c, 8);
                    out.si_changed = time_at(c, 16);
                }
                (ATTR_FILE_NAME, Some(c)) => {
                    let parent = u64_at(c, 0)?;
                    let chars = usize::from(c.get(64).copied()?);
                    let raw = c.get(66..66 + chars * 2)?;
                    let units: Vec<u16> = raw
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_le_bytes(*p))
                        .collect();
                    out.names.push(FileName {
                        parent: parent & 0x0000_FFFF_FFFF_FFFF,
                        parent_sequence: u16::try_from(parent >> 48).unwrap_or(0),
                        name: String::from_utf16_lossy(&units),
                        namespace: c.get(65).copied()?,
                        created: time_at(c, 8),
                        modified: time_at(c, 16),
                    });
                }
                (ATTR_DATA, Some(c)) if name_length == 0 => {
                    out.size = u64::try_from(c.len()).ok();
                }
                _ => {}
            }
        }
        at += length;
    }
    Some(out)
}

/// One record to write with [`build_volume`]: number, name, parent, in use, folder, and the
/// `$STANDARD_INFORMATION` and `$FILE_NAME` creation times as `FILETIME`s.
#[derive(Debug, Clone)]
pub struct BuildRecord {
    /// Record number (16 and up for ordinary files).
    pub number: u64,
    /// Name.
    pub name: String,
    /// Parent folder's record number.
    pub parent: u64,
    /// In use.
    pub in_use: bool,
    /// Folder.
    pub directory: bool,
    /// `$STANDARD_INFORMATION` creation time.
    pub si_created: u64,
    /// `$FILE_NAME` creation time.
    pub fn_created: u64,
}

const BUILD_SECTOR: usize = 512;
const BUILD_CLUSTER: usize = 4096;
const BUILD_RECORD: usize = 1024;
const BUILD_MFT_CLUSTER: u64 = 4;

fn encode_record(
    number: u64,
    in_use: bool,
    directory: bool,
    si_created: u64,
    names: &[(u64, &str, u64)],
    runs: Option<(u64, u64)>,
) -> Vec<u8> {
    let mut r = vec![0_u8; BUILD_RECORD];
    r[0..4].copy_from_slice(b"FILE");
    r[4..6].copy_from_slice(&48_u16.to_le_bytes());
    let usa_count = u16::try_from(BUILD_RECORD / BUILD_SECTOR + 1).unwrap_or(3);
    r[6..8].copy_from_slice(&usa_count.to_le_bytes());
    r[16..18].copy_from_slice(&1_u16.to_le_bytes());
    r[20..22].copy_from_slice(&56_u16.to_le_bytes());
    let flags = u16::from(in_use) | (u16::from(directory) << 1);
    r[22..24].copy_from_slice(&flags.to_le_bytes());
    r[28..32].copy_from_slice(&u32::try_from(BUILD_RECORD).unwrap_or(0).to_le_bytes());
    r[44..48].copy_from_slice(&u32::try_from(number).unwrap_or(0).to_le_bytes());
    let mut at = 56;
    let mut put = |r: &mut Vec<u8>, kind: u32, content: &[u8]| {
        let len = (24 + content.len()).div_ceil(8) * 8;
        r[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        r[at + 4..at + 8].copy_from_slice(&u32::try_from(len).unwrap_or(0).to_le_bytes());
        r[at + 16..at + 20]
            .copy_from_slice(&u32::try_from(content.len()).unwrap_or(0).to_le_bytes());
        r[at + 20..at + 22].copy_from_slice(&24_u16.to_le_bytes());
        r[at + 24..at + 24 + content.len()].copy_from_slice(content);
        at += len;
    };
    let mut si = vec![0_u8; 48];
    for i in 0..4 {
        si[i * 8..i * 8 + 8].copy_from_slice(&si_created.to_le_bytes());
    }
    put(&mut r, ATTR_STANDARD_INFORMATION, &si);
    for (parent, name, fn_created) in names {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut c = vec![0_u8; 66 + units.len() * 2];
        c[0..8].copy_from_slice(&(parent | (1_u64 << 48)).to_le_bytes());
        for i in 0..4 {
            c[8 + i * 8..16 + i * 8].copy_from_slice(&fn_created.to_le_bytes());
        }
        c[64] = u8::try_from(units.len()).unwrap_or(0);
        c[65] = 1;
        for (i, u) in units.iter().enumerate() {
            c[66 + i * 2..68 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        put(&mut r, ATTR_FILE_NAME, &c);
    }
    if let Some((cluster, clusters)) = runs {
        // A non-resident unnamed $DATA with one run.
        let mut runlist = vec![0x44_u8];
        runlist.extend_from_slice(&u32::try_from(clusters).unwrap_or(0).to_le_bytes());
        runlist.extend_from_slice(&u32::try_from(cluster).unwrap_or(0).to_le_bytes());
        runlist.push(0);
        let len = (64 + runlist.len()).div_ceil(8) * 8;
        r[at..at + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        r[at + 4..at + 8].copy_from_slice(&u32::try_from(len).unwrap_or(0).to_le_bytes());
        r[at + 8] = 1;
        r[at + 24..at + 32].copy_from_slice(&(clusters - 1).to_le_bytes());
        r[at + 32..at + 34].copy_from_slice(&64_u16.to_le_bytes());
        let bytes = clusters * u64::try_from(BUILD_CLUSTER).unwrap_or(4096);
        r[at + 40..at + 48].copy_from_slice(&bytes.to_le_bytes());
        r[at + 48..at + 56].copy_from_slice(&bytes.to_le_bytes());
        r[at + 56..at + 64].copy_from_slice(&bytes.to_le_bytes());
        r[at + 64..at + 64 + runlist.len()].copy_from_slice(&runlist);
        at += len;
    }
    r[at..at + 4].copy_from_slice(&ATTR_END.to_le_bytes());
    let used = u32::try_from(at + 8).unwrap_or(0);
    r[24..28].copy_from_slice(&used.to_le_bytes());
    // Update sequence: number 1 at 48, the last two bytes of each sector saved after it.
    r[48..50].copy_from_slice(&1_u16.to_le_bytes());
    for i in 1..usize::from(usa_count) {
        let end = i * BUILD_SECTOR;
        let saved = [r[end - 2], r[end - 1]];
        r[48 + i * 2..50 + i * 2].copy_from_slice(&saved);
        r[end - 2..end].copy_from_slice(&1_u16.to_le_bytes());
    }
    r
}

/// Builds a small NTFS volume image holding `$MFT` (record 0), the root folder (record 5) and
/// `records`. For tests in this workspace.
pub fn build_volume(records: &[BuildRecord]) -> Vec<u8> {
    let last = records.iter().map(|r| r.number).max().unwrap_or(16).max(16);
    let mft_records = (last + 1).div_ceil(4) * 4;
    let mft_clusters = mft_records * u64::try_from(BUILD_RECORD).unwrap_or(1024)
        / u64::try_from(BUILD_CLUSTER).unwrap_or(4096);
    let clusters = BUILD_MFT_CLUSTER + mft_clusters + 1;
    let mut volume = vec![0_u8; usize::try_from(clusters).unwrap_or(0) * BUILD_CLUSTER];
    volume[3..11].copy_from_slice(b"NTFS    ");
    volume[11..13].copy_from_slice(&u16::try_from(BUILD_SECTOR).unwrap_or(512).to_le_bytes());
    volume[13] = u8::try_from(BUILD_CLUSTER / BUILD_SECTOR).unwrap_or(8);
    let sectors = u64::try_from(volume.len() / BUILD_SECTOR).unwrap_or(0);
    volume[40..48].copy_from_slice(&sectors.to_le_bytes());
    volume[48..56].copy_from_slice(&BUILD_MFT_CLUSTER.to_le_bytes());
    volume[64] = 0xF6; // 2^10 = 1024-byte records
    volume[510] = 0x55;
    volume[511] = 0xAA;
    let base = usize::try_from(BUILD_MFT_CLUSTER).unwrap_or(4) * BUILD_CLUSTER;
    let mut place = |number: u64, bytes: Vec<u8>| {
        let at = base + usize::try_from(number).unwrap_or(0) * BUILD_RECORD;
        if let Some(slot) = volume.get_mut(at..at + BUILD_RECORD) {
            slot.copy_from_slice(&bytes);
        }
    };
    place(
        0,
        encode_record(
            0,
            true,
            false,
            0,
            &[(ROOT_RECORD, "$MFT", 0)],
            Some((BUILD_MFT_CLUSTER, mft_clusters)),
        ),
    );
    place(
        ROOT_RECORD,
        encode_record(ROOT_RECORD, true, true, 0, &[(ROOT_RECORD, ".", 0)], None),
    );
    for r in records {
        place(
            r.number,
            encode_record(
                r.number,
                r.in_use,
                r.directory,
                r.si_created,
                &[(r.parent, r.name.as_str(), r.fn_created)],
                None,
            ),
        );
    }
    volume
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_volume_reads_back_its_boot_sector_mft_runs_and_records() {
        let volume = build_volume(&[
            BuildRecord {
                number: 20,
                name: "Users".to_owned(),
                parent: ROOT_RECORD,
                in_use: true,
                directory: true,
                si_created: 134_000_000_000_000_000,
                fn_created: 134_000_000_000_000_000,
            },
            BuildRecord {
                number: 21,
                name: "Solara.exe".to_owned(),
                parent: 20,
                in_use: false,
                directory: false,
                si_created: 133_000_000_000_000_000,
                fn_created: 134_000_000_000_000_000,
            },
        ]);
        let boot = boot(&volume).unwrap();
        assert_eq!(boot.cluster_size, 4096);
        assert_eq!(boot.record_size, 1024);
        let at = usize::try_from(boot.mft_cluster * boot.cluster_size).unwrap();
        let mut zero = volume[at..at + 1024].to_vec();
        assert!(apply_fixups(&mut zero, boot.sector_size));
        let mft = record(&zero, 0).unwrap();
        assert_eq!(mft.runs, vec![(4, 6)]);
        let mut r = volume[at + 21 * 1024..at + 22 * 1024].to_vec();
        assert!(apply_fixups(&mut r, 512));
        let file = record(&r, 21).unwrap();
        assert!(!file.in_use);
        assert_eq!(file.best_name().unwrap().name, "Solara.exe");
        assert_eq!(file.best_name().unwrap().parent, 20);
        assert!(file.si_created < file.best_name().unwrap().created);
    }

    #[test]
    fn a_torn_record_fails_its_fixups_and_garbage_parses_to_nothing() {
        let volume = build_volume(&[]);
        let at = 4 * 4096;
        let mut r = volume[at..at + 1024].to_vec();
        r[510] ^= 0xFF;
        assert!(!apply_fixups(&mut r, 512));
        assert!(record(&[0xAA; 1024], 3).is_none());
        let mut junk = b"FILE".to_vec();
        junk.extend(std::iter::repeat_n(0xFF, 1020));
        let _ = record(&junk, 1);
        assert!(boot(&[0; 512]).is_err());
    }

    #[test]
    fn data_runs_follow_signed_relative_offsets() {
        // 0x21: 1 length byte, 2 offset bytes. Run 1: 16 clusters at 0x1000; run 2: 8 at 0x1000-0x100.
        let runs = data_runs(&[0x21, 0x10, 0x00, 0x10, 0x21, 0x08, 0x00, 0xFF, 0x00]);
        assert_eq!(runs, vec![(0x1000, 16), (0x0F00, 8)]);
    }
}
