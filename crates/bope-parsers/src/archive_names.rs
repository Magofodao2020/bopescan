// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The names inside a `.rar` (RAR 4 and RAR 5) or `.7z` archive, from its headers only
//! (B.O.P.E, ADR 0128) — the counterpart of [`crate::zip_names`].
//!
//! **Nothing is extracted.** A RAR archive's file headers lie between the packed data; they are read
//! one at a time and the data between them is skipped by its stated size, never read. A 7z archive's
//! names are in its end header, which 7-Zip usually compresses with LZMA: that header — and nothing
//! else — is decompressed, with the declared size capped at [`MAX_HEADER_BYTES`] and the output
//! refused past it, so a crafted header cannot become a decompression bomb.
//!
//! Like the ESE reader, the parser is handed a callback that returns the bytes at an offset, so an
//! archive larger than the host's whole-file limit can still be listed.
//!
//! Reported rather than guessed: encrypted headers (`-hp`, 7z header encryption), a header compressed
//! with a method other than LZMA or LZMA2, a RAR 4 Unicode name (its ASCII part is kept), and anything
//! a limit cut short (`partial`).

use crate::error::ParseError;

/// Most entries listed from one archive.
pub const MAX_ENTRIES: usize = 5_000;
/// Largest 7z end header read or decompressed.
pub const MAX_HEADER_BYTES: u64 = 16 * 1024 * 1024;
/// Most RAR blocks walked.
pub const MAX_BLOCKS: usize = 20_000;

const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";

/// Which archive format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RAR 1.5–4.x.
    Rar4,
    /// RAR 5.
    Rar5,
    /// 7z.
    SevenZip,
}

impl Format {
    /// The word reports use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rar4 => "rar4",
            Self::Rar5 => "rar5",
            Self::SevenZip => "7z",
        }
    }
}

/// One entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its path inside the archive, `/`-separated.
    pub name: String,
    /// Unpacked size as the header states it.
    pub size: u64,
    /// Whether it is a folder.
    pub directory: bool,
    /// Whether this entry's data is encrypted (its name is not).
    pub encrypted: bool,
}

/// What an archive's headers list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The format.
    pub format: Format,
    /// Entries, in header order.
    pub entries: Vec<Entry>,
    /// The headers themselves are encrypted, so no name can be read.
    pub encrypted_headers: bool,
    /// More entries than were listed, a limit or a damaged header ended the listing early.
    pub partial: bool,
}

/// Which format `head` (the first bytes of a file) starts with.
pub fn detect(head: &[u8]) -> Option<Format> {
    if head.starts_with(RAR5) {
        Some(Format::Rar5)
    } else if head.starts_with(RAR4) {
        Some(Format::Rar4)
    } else if head.starts_with(SEVEN_ZIP) {
        Some(Format::SevenZip)
    } else {
        None
    }
}

fn malformed(field: &'static str, detail: &str) -> ParseError {
    ParseError::Malformed {
        field,
        detail: detail.to_owned(),
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

fn clean(name: &str) -> String {
    name.replace('\\', "/")
}

/// Lists an archive read through `read`, a callback returning the bytes at an offset.
pub fn list<R: FnMut(u64, usize) -> Option<Vec<u8>>>(
    mut read: R,
    file_size: u64,
) -> Result<Listing, ParseError> {
    let head = read(0, 32).ok_or_else(|| malformed("header", "could not be read"))?;
    match detect(&head) {
        Some(Format::Rar4) => rar4(&mut read, file_size),
        Some(Format::Rar5) => rar5(&mut read, file_size),
        Some(Format::SevenZip) => seven_zip(&mut read, file_size, &head),
        None => Err(malformed("signature", "not a RAR or 7z archive")),
    }
}

#[allow(clippy::unnecessary_wraps)] // one signature for every format `list` dispatches to
fn rar4(
    read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
    file_size: u64,
) -> Result<Listing, ParseError> {
    let mut out = Listing {
        format: Format::Rar4,
        entries: Vec::new(),
        encrypted_headers: false,
        partial: false,
    };
    let mut at = u64::try_from(RAR4.len()).unwrap_or(7);
    for _ in 0..MAX_BLOCKS {
        if at + 7 > file_size {
            return Ok(out);
        }
        let Some(base) = read(at, 7).filter(|b| b.len() == 7) else {
            out.partial = true;
            return Ok(out);
        };
        let kind = base[2];
        let flags = u16_at(&base, 3).unwrap_or(0);
        let head_size = u64::from(u16_at(&base, 5).unwrap_or(0));
        if head_size < 7 {
            out.partial = true;
            return Ok(out);
        }
        let header = read(at, usize::try_from(head_size).unwrap_or(0)).unwrap_or_default();
        if u64::try_from(header.len()).unwrap_or(0) < head_size {
            out.partial = true;
            return Ok(out);
        }
        let mut add_size = if flags & 0x8000 != 0 {
            u64::from(u32_at(&header, 7).unwrap_or(0))
        } else {
            0
        };
        match kind {
            0x73 if flags & 0x0080 != 0 => {
                out.encrypted_headers = true;
                return Ok(out);
            }
            0x74 => {
                let pack = u64::from(u32_at(&header, 7).unwrap_or(0));
                let unpack = u64::from(u32_at(&header, 11).unwrap_or(0));
                let name_size = usize::from(u16_at(&header, 26).unwrap_or(0));
                let (high_pack, high_unpack, name_at) = if flags & 0x100 != 0 {
                    (
                        u64::from(u32_at(&header, 32).unwrap_or(0)),
                        u64::from(u32_at(&header, 36).unwrap_or(0)),
                        40,
                    )
                } else {
                    (0, 0, 32)
                };
                add_size = pack | (high_pack << 32);
                let raw = header.get(name_at..name_at + name_size).unwrap_or_default();
                // A Unicode name is the ASCII form, a NUL, then an encoded form; the ASCII part is kept.
                let ascii: Vec<u8> = raw.iter().copied().take_while(|b| *b != 0).collect();
                let name = if flags & 0x200 != 0 {
                    String::from_utf8_lossy(&ascii).into_owned()
                } else {
                    crate::cp1252::decode(&ascii)
                };
                if out.entries.len() >= MAX_ENTRIES {
                    out.partial = true;
                    return Ok(out);
                }
                out.entries.push(Entry {
                    name: clean(&name),
                    size: unpack | (high_unpack << 32),
                    directory: flags & 0xE0 == 0xE0,
                    encrypted: flags & 0x04 != 0,
                });
            }
            0x7B => return Ok(out),
            _ => {}
        }
        at = at.saturating_add(head_size).saturating_add(add_size);
    }
    out.partial = true;
    Ok(out)
}

/// A RAR 5 variable-length integer at `at`: its value and length.
fn vint(b: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for i in 0..10 {
        let byte = *b.get(at + i)?;
        value |= u64::from(byte & 0x7F).checked_shl(u32::try_from(7 * i).ok()?)?;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

#[allow(clippy::unnecessary_wraps)] // one signature for every format `list` dispatches to
fn rar5(
    read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
    file_size: u64,
) -> Result<Listing, ParseError> {
    let mut out = Listing {
        format: Format::Rar5,
        entries: Vec::new(),
        encrypted_headers: false,
        partial: false,
    };
    let mut at = u64::try_from(RAR5.len()).unwrap_or(8);
    for _ in 0..MAX_BLOCKS {
        if at + 7 > file_size {
            return Ok(out);
        }
        let Some(first) = read(at, 16) else {
            out.partial = true;
            return Ok(out);
        };
        let Some((head_size, vlen)) = vint(&first, 4) else {
            out.partial = true;
            return Ok(out);
        };
        if head_size == 0 || head_size > 2 * 1024 * 1024 {
            out.partial = true;
            return Ok(out);
        }
        let total = 4 + vlen + usize::try_from(head_size).unwrap_or(0);
        let header = read(at, total).unwrap_or_default();
        if header.len() < total {
            out.partial = true;
            return Ok(out);
        }
        let mut p = 4 + vlen;
        let (kind, n) = vint(&header, p).unwrap_or((0, 1));
        p += n;
        let (flags, n) = vint(&header, p).unwrap_or((0, 1));
        p += n;
        if flags & 0x1 != 0 {
            p += vint(&header, p).map_or(1, |v| v.1);
        }
        let data_size = if flags & 0x2 != 0 {
            let (size, n) = vint(&header, p).unwrap_or((0, 1));
            p += n;
            size
        } else {
            0
        };
        match kind {
            4 => {
                out.encrypted_headers = true;
                return Ok(out);
            }
            2 => {
                let mut q = p;
                let field = |q: &mut usize| -> u64 {
                    let (v, n) = vint(&header, *q).unwrap_or((0, 1));
                    *q += n;
                    v
                };
                let file_flags = field(&mut q);
                let unpacked = field(&mut q);
                let _attributes = field(&mut q);
                if file_flags & 0x2 != 0 {
                    q += 4;
                }
                if file_flags & 0x4 != 0 {
                    q += 4;
                }
                let _compression = field(&mut q);
                let _host = field(&mut q);
                let name_len = usize::try_from(field(&mut q)).unwrap_or(0);
                let name = header
                    .get(q..q + name_len)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                // An encryption record (type 1) in the extra area marks the data as encrypted.
                let encrypted = flags & 0x1 != 0 && {
                    let extra_at = q + name_len;
                    vint(&header, extra_at + 1).is_some_and(|(t, _)| t == 1)
                };
                if out.entries.len() >= MAX_ENTRIES {
                    out.partial = true;
                    return Ok(out);
                }
                out.entries.push(Entry {
                    name: clean(&name),
                    size: unpacked,
                    directory: file_flags & 0x1 != 0,
                    encrypted,
                });
            }
            5 => return Ok(out),
            _ => {}
        }
        at = at
            .saturating_add(u64::try_from(total).unwrap_or(0))
            .saturating_add(data_size);
    }
    out.partial = true;
    Ok(out)
}

/// A cursor over a 7z header.
struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, ParseError> {
        let v = *self
            .b
            .get(self.at)
            .ok_or_else(|| malformed("7z_header", "ended early"))?;
        self.at += 1;
        Ok(v)
    }

    /// 7z's `NUMBER`: the first byte's leading ones say how many bytes follow.
    fn number(&mut self) -> Result<u64, ParseError> {
        let first = self.byte()?;
        let mut mask = 0x80_u8;
        let mut value: u64 = 0;
        for i in 0..8 {
            if first & mask == 0 {
                let high = u64::from(first & mask.wrapping_sub(1));
                return Ok(value | (high << (8 * i)));
            }
            value |= u64::from(self.byte()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    fn count(&mut self, limit: u64) -> Result<usize, ParseError> {
        let n = self.number()?;
        if n > limit {
            return Err(malformed("7z_header", "a count beyond any real archive"));
        }
        usize::try_from(n).map_err(|_| malformed("7z_header", "count"))
    }

    fn skip(&mut self, n: usize) -> Result<&[u8], ParseError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| malformed("7z_header", "size"))?;
        let s = self
            .b
            .get(self.at..end)
            .ok_or_else(|| malformed("7z_header", "ended early"))?;
        self.at = end;
        Ok(s)
    }

    fn bits(&mut self, n: usize) -> Result<Vec<bool>, ParseError> {
        let bytes = self.skip(n.div_ceil(8))?;
        Ok((0..n)
            .map(|i| bytes.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0))
            .collect())
    }

    fn digests(&mut self, n: usize) -> Result<(), ParseError> {
        let all = self.byte()?;
        let defined = if all == 0 {
            self.bits(n)?
        } else {
            vec![true; n]
        };
        let present = defined.iter().filter(|d| **d).count();
        self.skip(present * 4)?;
        Ok(())
    }
}

/// One folder's coder, as far as the end header needs it.
struct Coder {
    id: Vec<u8>,
    props: Vec<u8>,
}

/// What a `StreamsInfo` says, as far as decoding an encoded header needs it.
#[derive(Default)]
struct Streams {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    coders: Vec<Coder>,
    unpack_size: u64,
}

#[allow(clippy::too_many_lines)]
fn streams_info(c: &mut Cursor<'_>) -> Result<Streams, ParseError> {
    let mut s = Streams::default();
    let mut folders = 0;
    let mut outs_per_folder: Vec<usize> = Vec::new();
    loop {
        match c.byte()? {
            0x00 => return Ok(s),
            0x06 => {
                s.pack_pos = c.number()?;
                let n = c.count(1_000_000)?;
                loop {
                    match c.byte()? {
                        0x00 => break,
                        0x09 => {
                            for _ in 0..n {
                                s.pack_sizes.push(c.number()?);
                            }
                        }
                        0x0A => c.digests(n)?,
                        _ => return Err(malformed("7z_header", "pack info")),
                    }
                }
            }
            0x07 => {
                if c.byte()? != 0x0B {
                    return Err(malformed("7z_header", "unpack info"));
                }
                folders = c.count(1_000_000)?;
                if c.byte()? != 0 {
                    return Err(malformed("7z_header", "external folders"));
                }
                for f in 0..folders {
                    let coders = c.count(64)?;
                    let (mut ins, mut outs) = (0_usize, 0_usize);
                    for _ in 0..coders {
                        let flags = c.byte()?;
                        let id = c.skip(usize::from(flags & 0x0F))?.to_vec();
                        if flags & 0x10 != 0 {
                            ins += c.count(64)?;
                            outs += c.count(64)?;
                        } else {
                            ins += 1;
                            outs += 1;
                        }
                        let props = if flags & 0x20 != 0 {
                            let n = c.count(1024)?;
                            c.skip(n)?.to_vec()
                        } else {
                            Vec::new()
                        };
                        if f == 0 {
                            s.coders.push(Coder { id, props });
                        }
                    }
                    let pairs = outs.saturating_sub(1);
                    for _ in 0..pairs {
                        c.number()?;
                        c.number()?;
                    }
                    let packed = ins.saturating_sub(pairs);
                    if packed > 1 {
                        for _ in 0..packed {
                            c.number()?;
                        }
                    }
                    outs_per_folder.push(outs);
                }
                if c.byte()? != 0x0C {
                    return Err(malformed("7z_header", "unpack sizes"));
                }
                for (f, outs) in outs_per_folder.iter().enumerate() {
                    for o in 0..*outs {
                        let size = c.number()?;
                        // The folder's last output is its final, unpacked stream.
                        if f == 0 && o + 1 == *outs {
                            s.unpack_size = size;
                        }
                    }
                }
                loop {
                    match c.byte()? {
                        0x00 => break,
                        0x0A => c.digests(folders)?,
                        _ => return Err(malformed("7z_header", "unpack info")),
                    }
                }
            }
            0x08 => {
                let mut per_folder = vec![1_usize; folders];
                let mut kind = c.byte()?;
                if kind == 0x0D {
                    for n in &mut per_folder {
                        *n = c.count(1_000_000)?;
                    }
                    kind = c.byte()?;
                }
                if kind == 0x09 {
                    for n in &per_folder {
                        for _ in 1..*n {
                            c.number()?;
                        }
                    }
                    kind = c.byte()?;
                }
                if kind == 0x0A {
                    let streams: usize = per_folder.iter().sum();
                    c.digests(streams)?;
                    kind = c.byte()?;
                }
                if kind != 0x00 {
                    return Err(malformed("7z_header", "substreams"));
                }
            }
            _ => return Err(malformed("7z_header", "streams info")),
        }
    }
}

/// A `Write` that refuses to grow past `limit`.
struct Bounded {
    buf: Vec<u8>,
    limit: usize,
}

impl std::io::Write for Bounded {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.limit {
            return Err(std::io::Error::other("larger than the declared size"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Decodes an encoded 7z end header.
fn decode_header(
    read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
    file_size: u64,
    s: &Streams,
) -> Result<Result<Vec<u8>, &'static str>, ParseError> {
    let Some(coder) = s.coders.first() else {
        return Err(malformed("7z_header", "no coder"));
    };
    if s.coders.len() != 1 {
        return Ok(Err("filtered_header"));
    }
    let packed = s.pack_sizes.first().copied().unwrap_or(0);
    if packed > MAX_HEADER_BYTES || s.unpack_size > MAX_HEADER_BYTES {
        return Ok(Err("header_too_large"));
    }
    let start = 32_u64.saturating_add(s.pack_pos);
    if start.saturating_add(packed) > file_size {
        return Err(malformed("7z_header", "packed header beyond the file"));
    }
    let data = read(start, usize::try_from(packed).unwrap_or(0))
        .ok_or_else(|| malformed("7z_header", "could not be read"))?;
    let limit = usize::try_from(s.unpack_size).unwrap_or(0);
    let mut out = Bounded {
        buf: Vec::with_capacity(limit.min(1024 * 1024)),
        limit,
    };
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(Some(s.unpack_size)),
        memlimit: Some(64 * 1024 * 1024),
        allow_incomplete: false,
    };
    let result = match coder.id.as_slice() {
        [0x03, 0x01, 0x01] => {
            if coder.props.len() != 5 {
                return Err(malformed("7z_header", "LZMA properties"));
            }
            let mut input = coder.props.clone();
            input.extend_from_slice(&data);
            lzma_rs::lzma_decompress_with_options(&mut input.as_slice(), &mut out, &options)
        }
        [0x21] => lzma_rs::lzma2_decompress(&mut data.as_slice(), &mut out),
        [0x00] => {
            out.buf = data;
            Ok(())
        }
        [0x06, 0xF1, 0x07, 0x01] => return Ok(Err("encrypted")),
        _ => return Ok(Err("unsupported_method")),
    };
    match result {
        Ok(()) => Ok(Ok(out.buf)),
        Err(_) => Err(malformed(
            "7z_header",
            "the compressed header did not decode",
        )),
    }
}

fn files_info(c: &mut Cursor<'_>, out: &mut Listing) -> Result<(), ParseError> {
    let n = c.count(100_000_000)?;
    let mut names: Vec<String> = Vec::new();
    let mut empty_stream = vec![false; n.min(MAX_ENTRIES * 20)];
    let mut empty_file: Vec<bool> = Vec::new();
    let mut attributes: Vec<Option<u32>> = Vec::new();
    loop {
        let kind = c.number()?;
        if kind == 0 {
            break;
        }
        let size = usize::try_from(c.number()?).map_err(|_| malformed("7z_header", "size"))?;
        let data = c.skip(size)?;
        let mut d = Cursor { b: data, at: 0 };
        match kind {
            0x0E => empty_stream = d.bits(n)?,
            0x0F => {
                let empties = empty_stream.iter().filter(|e| **e).count();
                empty_file = d.bits(empties)?;
            }
            0x11 => {
                if d.byte()? != 0 {
                    return Err(malformed("7z_header", "external names"));
                }
                let units: Vec<u16> = data
                    .get(1..)
                    .unwrap_or_default()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| u16::from_le_bytes(*p))
                    .collect();
                for name in units.split(|u| *u == 0) {
                    if names.len() >= n || names.len() >= MAX_ENTRIES {
                        break;
                    }
                    names.push(String::from_utf16_lossy(name));
                }
            }
            0x15 => {
                let all = d.byte()?;
                let defined = if all == 0 { d.bits(n)? } else { vec![true; n] };
                if d.byte()? != 0 {
                    continue;
                }
                for def in defined {
                    attributes.push(if def {
                        let raw = d.skip(4)?;
                        u32_at(raw, 0)
                    } else {
                        None
                    });
                }
            }
            _ => {}
        }
    }
    let mut empty_index = 0;
    for (i, name) in names.iter().enumerate() {
        let empty = empty_stream.get(i).copied().unwrap_or(false);
        let is_empty_file = if empty {
            let f = empty_file.get(empty_index).copied().unwrap_or(false);
            empty_index += 1;
            f
        } else {
            false
        };
        let by_attribute = attributes.get(i).copied().flatten().map(|a| a & 0x10 != 0);
        out.entries.push(Entry {
            name: clean(name),
            size: 0,
            directory: by_attribute.unwrap_or(empty && !is_empty_file),
            encrypted: false,
        });
    }
    if n > out.entries.len() {
        out.partial = true;
    }
    Ok(())
}

fn seven_zip(
    read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
    file_size: u64,
    head: &[u8],
) -> Result<Listing, ParseError> {
    let mut out = Listing {
        format: Format::SevenZip,
        entries: Vec::new(),
        encrypted_headers: false,
        partial: false,
    };
    let offset = u64_at(head, 12).ok_or_else(|| malformed("7z_start", "short"))?;
    let size = u64_at(head, 20).ok_or_else(|| malformed("7z_start", "short"))?;
    if size == 0 {
        return Ok(out);
    }
    if size > MAX_HEADER_BYTES {
        out.partial = true;
        return Ok(out);
    }
    let start = 32_u64
        .checked_add(offset)
        .filter(|s| s.saturating_add(size) <= file_size)
        .ok_or_else(|| malformed("7z_start", "end header beyond the file"))?;
    let mut header = read(start, usize::try_from(size).unwrap_or(0))
        .ok_or_else(|| malformed("7z_header", "could not be read"))?;
    for _ in 0..4 {
        let mut c = Cursor { b: &header, at: 0 };
        match c.byte()? {
            0x17 => {
                let s = streams_info(&mut c)?;
                match decode_header(read, file_size, &s)? {
                    Ok(decoded) => header = decoded,
                    Err("encrypted") => {
                        out.encrypted_headers = true;
                        return Ok(out);
                    }
                    Err(_) => {
                        out.partial = true;
                        return Ok(out);
                    }
                }
            }
            0x01 => {
                loop {
                    match c.byte()? {
                        0x00 => break,
                        0x02 => loop {
                            let kind = c.number()?;
                            if kind == 0 {
                                break;
                            }
                            let n = usize::try_from(c.number()?).unwrap_or(usize::MAX);
                            c.skip(n)?;
                        },
                        0x03 | 0x04 => {
                            streams_info(&mut c)?;
                        }
                        0x05 => {
                            files_info(&mut c, &mut out)?;
                            break;
                        }
                        _ => return Err(malformed("7z_header", "header")),
                    }
                }
                return Ok(out);
            }
            _ => {
                return Err(malformed(
                    "7z_header",
                    "neither a header nor an encoded header",
                ));
            }
        }
    }
    out.partial = true;
    Ok(out)
}

/// Builds a RAR 4 archive listing `names` with no data, for tests in this workspace.
pub fn build_rar4(names: &[&str]) -> Vec<u8> {
    let mut b = RAR4.to_vec();
    b.extend_from_slice(&[0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]);
    for name in names {
        let directory = name.ends_with('/');
        let name = name.trim_end_matches('/').replace('/', "\\");
        let flags: u16 = if directory { 0xE0 } else { 0 };
        let size = u16::try_from(32 + name.len()).unwrap_or(0);
        let mut h = vec![0_u8, 0, 0x74];
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&3_u32.to_le_bytes()); // packed size: three bytes of data follow
        h.extend_from_slice(&7_u32.to_le_bytes());
        h.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0x30]);
        h.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_le_bytes());
        h.extend_from_slice(&0x20_u32.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&h);
        b.extend_from_slice(b"xyz");
    }
    b.extend_from_slice(&[0, 0, 0x7B, 0, 0x40, 7, 0]);
    b
}

fn push_vint(b: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = u8::try_from(v & 0x7F).unwrap_or(0);
        v >>= 7;
        if v == 0 {
            b.push(byte);
            return;
        }
        b.push(byte | 0x80);
    }
}

/// Builds a RAR 5 archive listing `names`, each with three bytes of data; `encrypted_headers` adds
/// an archive encryption header instead. For tests in this workspace.
pub fn build_rar5(names: &[&str], encrypted_headers: bool) -> Vec<u8> {
    let mut b = RAR5.to_vec();
    let block = |b: &mut Vec<u8>, body: &[u8], data: &[u8]| {
        let mut h = Vec::new();
        push_vint(&mut h, u64::try_from(body.len()).unwrap_or(0));
        h.extend_from_slice(body);
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&h);
        b.extend_from_slice(data);
    };
    if encrypted_headers {
        block(&mut b, &[4, 0, 0, 0, 0], &[]);
        return b;
    }
    block(&mut b, &[1, 0, 0], &[]);
    for name in names {
        let directory = name.ends_with('/');
        let name = name.trim_end_matches('/');
        let mut body = vec![2, 0x02];
        push_vint(&mut body, 3);
        push_vint(&mut body, u64::from(directory));
        push_vint(&mut body, 7);
        push_vint(&mut body, 0x20);
        push_vint(&mut body, 0);
        push_vint(&mut body, 2);
        push_vint(&mut body, u64::try_from(name.len()).unwrap_or(0));
        body.extend_from_slice(name.as_bytes());
        block(&mut b, &body, b"xyz");
    }
    block(&mut b, &[5, 0, 0], &[]);
    b
}

/// Builds a 7z archive listing `names` (a trailing `/` marks a folder), with its end header
/// LZMA-compressed when `compressed`. For tests in this workspace.
pub fn build_7z(names: &[&str], compressed: bool) -> Vec<u8> {
    let n = names.len();
    let mut header = vec![0x01, 0x05];
    header.push(u8::try_from(n).unwrap_or(0));
    // Every entry is an empty stream; folders are not empty files.
    header.push(0x0E);
    let bits = |pred: &dyn Fn(&str) -> bool| -> Vec<u8> {
        let mut v = vec![0_u8; n.div_ceil(8)];
        for (i, name) in names.iter().enumerate() {
            if pred(name) {
                v[i / 8] |= 0x80 >> (i % 8);
            }
        }
        v
    };
    let empty = bits(&|_| true);
    header.push(u8::try_from(empty.len()).unwrap_or(0));
    header.extend_from_slice(&empty);
    header.push(0x0F);
    let files = bits(&|s| !s.ends_with('/'));
    header.push(u8::try_from(files.len()).unwrap_or(0));
    header.extend_from_slice(&files);
    let mut name_data = vec![0_u8];
    for name in names {
        for u in name
            .trim_end_matches('/')
            .encode_utf16()
            .chain(std::iter::once(0))
        {
            name_data.extend_from_slice(&u.to_le_bytes());
        }
    }
    header.push(0x11);
    // 7z NUMBER: one byte below 0x80, else `10xxxxxx` with the high bits and one more byte.
    let len = name_data.len();
    let size = if len < 0x80 {
        vec![u8::try_from(len).unwrap_or(0)]
    } else {
        vec![
            0x80 | u8::try_from(len >> 8).unwrap_or(0),
            u8::try_from(len & 0xFF).unwrap_or(0),
        ]
    };
    header.extend_from_slice(&size);
    header.extend_from_slice(&name_data);
    header.extend_from_slice(&[0x00, 0x00]);
    let mut file = SEVEN_ZIP.to_vec();
    file.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
    let (body, end) = if compressed {
        let mut packed = Vec::new();
        let _ = lzma_rs::lzma_compress(&mut header.as_slice(), &mut packed);
        // `.lzma`: 5 property bytes, 8 size bytes, then the stream.
        let props = packed.get(..5).unwrap_or_default().to_vec();
        let stream = packed.get(13..).unwrap_or_default().to_vec();
        let mut end = vec![0x17, 0x06, 0x00, 0x01, 0x09];
        end.push(0x80 | u8::try_from(stream.len() >> 8).unwrap_or(0));
        end.push(u8::try_from(stream.len() & 0xFF).unwrap_or(0));
        end.extend_from_slice(&[
            0x00, 0x07, 0x0B, 0x01, 0x00, 0x01, 0x23, 0x03, 0x01, 0x01, 0x05,
        ]);
        end.extend_from_slice(&props);
        end.push(0x0C);
        end.push(0x80 | u8::try_from(header.len() >> 8).unwrap_or(0));
        end.push(u8::try_from(header.len() & 0xFF).unwrap_or(0));
        end.extend_from_slice(&[0x00, 0x00]);
        (stream, end)
    } else {
        (Vec::new(), header)
    };
    let offset = u64::try_from(body.len()).unwrap_or(0);
    let size = u64::try_from(end.len()).unwrap_or(0);
    file.extend_from_slice(&offset.to_le_bytes());
    file.extend_from_slice(&size.to_le_bytes());
    file.extend_from_slice(&0_u32.to_le_bytes());
    file.extend_from_slice(&body);
    file.extend_from_slice(&end);
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(file: &[u8]) -> impl FnMut(u64, usize) -> Option<Vec<u8>> + '_ {
        move |offset, len| {
            let start = usize::try_from(offset).ok()?.min(file.len());
            Some(file[start..(start + len).min(file.len())].to_vec())
        }
    }

    fn names(l: &Listing) -> Vec<(String, bool)> {
        l.entries
            .iter()
            .map(|e| (e.name.clone(), e.directory))
            .collect()
    }

    const NAMES: [&str; 3] = ["Solara/", "Solara/bin/Solara.exe", "Solara/autoexec/a.lua"];

    fn expected() -> Vec<(String, bool)> {
        vec![
            ("Solara".to_owned(), true),
            ("Solara/bin/Solara.exe".to_owned(), false),
            ("Solara/autoexec/a.lua".to_owned(), false),
        ]
    }

    #[test]
    fn every_format_lists_its_names_without_extracting() {
        for file in [
            build_rar4(&NAMES),
            build_rar5(&NAMES, false),
            build_7z(&NAMES, false),
            build_7z(&NAMES, true),
        ] {
            let size = u64::try_from(file.len()).unwrap();
            let listing = list(reader(&file), size).unwrap();
            assert_eq!(names(&listing), expected(), "{:?}", listing.format);
            assert!(!listing.partial && !listing.encrypted_headers);
        }
    }

    #[test]
    fn encrypted_headers_are_reported_and_garbage_is_an_error() {
        let file = build_rar5(&[], true);
        let listing = list(reader(&file), u64::try_from(file.len()).unwrap()).unwrap();
        assert!(listing.encrypted_headers);
        assert!(list(reader(b"PK\x03\x04 not rar"), 12).is_err());
        let mut bad = build_7z(&NAMES, true);
        let at = bad.len() - 8;
        bad[at] ^= 0x55;
        let _ = list(reader(&bad), u64::try_from(bad.len()).unwrap());
        let mut truncated = build_rar4(&NAMES);
        truncated.truncate(30);
        let l = list(reader(&truncated), 30).unwrap();
        assert!(l.entries.is_empty() || l.partial);
    }

    #[test]
    fn a_declared_header_size_past_the_cap_is_never_decoded() {
        let mut file = build_7z(&NAMES, false);
        file[20..28].copy_from_slice(&(MAX_HEADER_BYTES + 1).to_le_bytes());
        let l = list(reader(&file), u64::MAX).unwrap();
        assert!(l.partial && l.entries.is_empty());
    }
}
