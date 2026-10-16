// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Reads a file, or a raw volume, at an offset (B.O.P.E, ADR 0124).
//!
//! `std::fs::File::open` asks Windows for `GENERIC_READ` with every share mode, so the service that
//! owns a file keeps writing it and nothing is locked. A volume is opened the same way through its
//! device path `\\.\C:`; that needs administrator rights, and reads are aligned here to
//! [`VOLUME_ALIGN`] because a volume handle accepts only whole sectors. No `unsafe` is needed.

use std::io::{Read as _, Seek as _, SeekFrom};

use bope_host::{MAX_READ_AT_BYTES, RandomReadSource, SourceError};

use crate::LiveHost;

/// Sector alignment of a raw volume read: a multiple of both 512-byte and 4 KiB sectors.
pub const VOLUME_ALIGN: u64 = 4096;

/// The aligned range that covers `[offset, offset + len)`, as `(start, length, skip)`.
pub fn aligned(offset: u64, len: usize) -> (u64, usize, usize) {
    let start = offset - offset % VOLUME_ALIGN;
    let skip = usize::try_from(offset - start).unwrap_or(0);
    let wanted = skip.saturating_add(len);
    let align = usize::try_from(VOLUME_ALIGN).unwrap_or(4096);
    let length = wanted.div_ceil(align) * align;
    (start, length, skip)
}

fn read_exact_or_end(file: &mut std::fs::File, len: usize) -> Result<Vec<u8>, SourceError> {
    let mut out = vec![0_u8; len];
    let mut filled = 0;
    while filled < len {
        match file.read(&mut out[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SourceError::from_io(&e)),
        }
    }
    out.truncate(filled);
    Ok(out)
}

impl RandomReadSource for LiveHost {
    fn file_size(&self, path: &str) -> Result<Option<u64>, SourceError> {
        match std::fs::metadata(path) {
            Ok(m) if m.is_file() => Ok(Some(m.len())),
            Ok(_) => Err(SourceError::Failed(format!("not a file: {path}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SourceError::from_io(&e)),
        }
    }

    fn read_file_at(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>, SourceError> {
        if len > MAX_READ_AT_BYTES {
            return Err(SourceError::TooLarge {
                limit: MAX_READ_AT_BYTES,
            });
        }
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(SourceError::from_io(&e)),
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| SourceError::from_io(&e))?;
        read_exact_or_end(&mut file, len).map(Some)
    }

    fn read_volume_at(
        &self,
        volume: char,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, SourceError> {
        if len > MAX_READ_AT_BYTES {
            return Err(SourceError::TooLarge {
                limit: MAX_READ_AT_BYTES,
            });
        }
        if !volume.is_ascii_alphabetic() {
            return Err(SourceError::Unsupported(format!(
                "not a drive letter: {volume}"
            )));
        }
        let device = format!(r"\\.\{}:", volume.to_ascii_uppercase());
        let mut file = std::fs::File::open(&device).map_err(|e| SourceError::from_io(&e))?;
        let (start, length, skip) = aligned(offset, len);
        file.seek(SeekFrom::Start(start))
            .map_err(|e| SourceError::from_io(&e))?;
        let bytes = read_exact_or_end(&mut file, length)?;
        Ok(bytes
            .get(skip..)
            .map(|rest| rest[..rest.len().min(len)].to_vec())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_is_widened_to_whole_sectors() {
        assert_eq!(aligned(0, 512), (0, 4096, 0));
        assert_eq!(aligned(5000, 100), (4096, 4096, 904));
        assert_eq!(aligned(4000, 200), (0, 8192, 4000));
    }
}
