// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! A bounded, read-only reader for Extensible Storage Engine (ESE, "Jet Blue") database files
//! (B.O.P.E, ADR 0124): enough of the format to list the tables in the catalog and read the fixed,
//! variable and tagged columns of their records. Written from the public format description
//! (libyal/libesedb, "Extensible Storage Engine (ESE) Database File (EDB) format") and checked
//! against dissect.esedb's reading of records.
//!
//! **Not this crate's usual `&[u8]` contract, on purpose.** An ESE file (`SRUDB.dat`) is often far larger
//! than the 64 MiB a host reads in one piece, so the reader is handed a callback that returns the bytes
//! at an offset — supplied by the collector, which reads through the host. The reader itself still does
//! no I/O, keeps no global state and never panics.
//!
//! What it does **not** do, and says so through [`Walk`] instead of guessing:
//! - replay transaction logs: a database copied while in use ("dirty shutdown") is read as its pages
//!   stand, and records still only in the logs are absent;
//! - read values stored in a separate long-value tree ([`Value::LongValue`]), multi-valued columns
//!   ([`Value::Unsupported`]) or XPRESS9/XPRESS10 compression;
//! - verify page checksums.
//!
//! Every walk is bounded by [`Limits`]: pages read, depth and records.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::ParseError;

/// The file header's signature, `0x89ABCDEF`.
pub const SIGNATURE: u32 = 0x89AB_CDEF;
/// The catalog's root page (`pgnoFDPMSO`).
pub const CATALOG_ROOT: u32 = 4;

const PAGE_LEAF: u32 = 0x2;
const PAGE_SPACE_TREE: u32 = 0x20;
const PAGE_INDEX: u32 = 0x40;
const PAGE_LONG_VALUE: u32 = 0x80;
const PAGE_NEW_RECORD_FORMAT: u32 = 0x2000;

const TAG_DELETED: u16 = 0x2;
const TAG_COMMON_KEY: u16 = 0x4;

const TAGFLD_COMPRESSED: u8 = 0x02;
const TAGFLD_SEPARATED: u8 = 0x04;
const TAGFLD_MULTI: u8 = 0x08;
const TAGFLD_TWO_VALUES: u8 = 0x10;
const TAGFLD_NULL: u8 = 0x20;

/// Column types (`JET_coltyp`).
pub mod coltyp {
    /// `JET_coltypBit`.
    pub const BIT: u32 = 1;
    /// `JET_coltypUnsignedByte`.
    pub const UNSIGNED_BYTE: u32 = 2;
    /// `JET_coltypShort`.
    pub const SHORT: u32 = 3;
    /// `JET_coltypLong`.
    pub const LONG: u32 = 4;
    /// `JET_coltypCurrency`.
    pub const CURRENCY: u32 = 5;
    /// `JET_coltypIEEESingle`.
    pub const SINGLE: u32 = 6;
    /// `JET_coltypIEEEDouble`.
    pub const DOUBLE: u32 = 7;
    /// `JET_coltypDateTime`: an OLE automation date, days since 1899-12-30 as a double.
    pub const DATE_TIME: u32 = 8;
    /// `JET_coltypBinary`.
    pub const BINARY: u32 = 9;
    /// `JET_coltypText`.
    pub const TEXT: u32 = 10;
    /// `JET_coltypLongBinary`.
    pub const LONG_BINARY: u32 = 11;
    /// `JET_coltypLongText`.
    pub const LONG_TEXT: u32 = 12;
    /// `JET_coltypUnsignedLong`.
    pub const UNSIGNED_LONG: u32 = 14;
    /// `JET_coltypLongLong`.
    pub const LONG_LONG: u32 = 15;
    /// `JET_coltypGUID`.
    pub const GUID: u32 = 16;
    /// `JET_coltypUnsignedShort`.
    pub const UNSIGNED_SHORT: u32 = 17;
}

/// The size of a fixed column of this type, or `None` for a type whose size the catalog states.
pub fn fixed_size(kind: u32) -> Option<usize> {
    Some(match kind {
        coltyp::BIT | coltyp::UNSIGNED_BYTE => 1,
        coltyp::SHORT | coltyp::UNSIGNED_SHORT => 2,
        coltyp::LONG | coltyp::SINGLE | coltyp::UNSIGNED_LONG => 4,
        coltyp::CURRENCY | coltyp::DOUBLE | coltyp::DATE_TIME | coltyp::LONG_LONG => 8,
        coltyp::GUID => 16,
        _ => return None,
    })
}

/// How far one walk may go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most pages read from the file over the life of one [`Database`].
    pub max_pages: usize,
    /// Most records handed to a visitor by one walk.
    pub max_records: usize,
    /// Deepest B+-tree followed.
    pub max_depth: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pages: 100_000,
            max_records: 2_000_000,
            max_depth: 16,
        }
    }
}

/// What the file header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// File format version, `0x620` for every ESE in use.
    pub version: u32,
    /// File format revision.
    pub revision: u32,
    /// Database state: 1 just created, 2 dirty shutdown, 3 clean shutdown, 4 being converted,
    /// 5 force detach.
    pub state: u32,
    /// Page size in bytes.
    pub page_size: u32,
}

impl Header {
    /// Whether the database was not shut down cleanly, so transaction logs may hold records the
    /// pages do not.
    pub fn dirty(&self) -> bool {
        self.state != 3
    }
}

/// One column of a table, from the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// Column identifier: 1–127 fixed, 128–255 variable, 256 and up tagged.
    pub id: u32,
    /// Column name.
    pub name: String,
    /// `JET_coltyp`.
    pub kind: u32,
    /// Size of a fixed column of a type with no implied size (`SpaceUsage`).
    pub space: u32,
    /// Code page of a text column (1200 is UTF-16).
    pub codepage: u32,
}

/// One table, from the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    /// Object identifier.
    pub objid: u32,
    /// Table name.
    pub name: String,
    /// Root page of its records.
    pub root: u32,
    /// Columns, by identifier.
    pub columns: Vec<Column>,
}

impl Table {
    /// The column named `name`, compared without case.
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }
}

/// A value read from a record.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// No value.
    Null,
    /// A signed integer of any width, or a boolean as 0/1.
    Int(i64),
    /// An unsigned integer of any width.
    UInt(u64),
    /// A floating point number.
    Float(f64),
    /// `JET_coltypDateTime`: an OLE automation date.
    OleDate(f64),
    /// Text, decoded.
    Text(String),
    /// Binary data, decompressed when it was compressed.
    Bytes(Vec<u8>),
    /// The value is in the table's separate long-value tree, which this reader does not follow.
    LongValue,
    /// A form this reader does not decode: what it is.
    Unsupported(&'static str),
}

impl Value {
    /// The value as an `i64`, for any integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            Self::UInt(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// The value as a `u64`, for any non-negative integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Int(v) => u64::try_from(*v).ok(),
            Self::UInt(v) => Some(*v),
            _ => None,
        }
    }
}

/// How a walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Walk {
    /// Records handed to the visitor.
    pub records: usize,
    /// Entries skipped because they were marked deleted.
    pub deleted: usize,
    /// Pages that could not be read or did not parse, skipped.
    pub bad_pages: usize,
    /// A limit ended the walk before the tree did.
    pub limited: bool,
}

/// One record: its raw bytes and how to find each column in them.
#[derive(Debug, Clone)]
pub struct Record<'t> {
    table: &'t Table,
    data: Vec<u8>,
    small_pages: bool,
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

fn malformed(field: &'static str, detail: &str) -> ParseError {
    ParseError::Malformed {
        field,
        detail: detail.to_owned(),
    }
}

impl Record<'_> {
    /// The raw bytes of `column` in this record, and the tagged-value flags when it is tagged.
    fn raw(&self, column: &Column) -> Option<(Vec<u8>, u8)> {
        let d = &self.data;
        let last_fixed = u32::from(*d.first()?);
        let last_var = u32::from(*d.get(1)?);
        let var_start = usize::from(u16_at(d, 2)?);
        if column.id < 128 {
            if column.id > last_fixed {
                return None;
            }
            let bitmap_len = usize::try_from(last_fixed.div_ceil(8)).ok()?;
            let bitmap_start = var_start.checked_sub(bitmap_len)?;
            let bit = usize::try_from(column.id - 1).ok()?;
            if d.get(bitmap_start + bit / 8)? & (1 << (bit % 8)) != 0 {
                return None;
            }
            let mut offset = 4_usize;
            for c in self
                .table
                .columns
                .iter()
                .filter(|c| c.id < column.id && c.id < 128)
            {
                offset += column_size(c);
            }
            let size = column_size(column);
            return d
                .get(offset..offset.checked_add(size)?)
                .map(|v| (v.to_vec(), 0));
        }
        let n_var = usize::try_from(last_var.saturating_sub(127)).ok()?;
        let var_data = var_start.checked_add(n_var * 2)?;
        if column.id < 256 {
            if column.id > last_var {
                return None;
            }
            let i = usize::try_from(column.id - 128).ok()?;
            let end = u16_at(d, var_start + i * 2)?;
            if end & 0x8000 != 0 {
                return None;
            }
            let start = if i == 0 {
                0
            } else {
                u16_at(d, var_start + (i - 1) * 2)? & 0x7FFF
            };
            let (start, end) = (usize::from(start), usize::from(end & 0x7FFF));
            return d
                .get(var_data + start..var_data + end)
                .map(|v| (v.to_vec(), 0));
        }
        let last_end = if n_var > 0 {
            usize::from(u16_at(d, var_start + (n_var - 1) * 2)? & 0x7FFF)
        } else {
            0
        };
        let tagged = var_data.checked_add(last_end)?;
        let first = u32_at(d, tagged)?;
        let mask: u16 = if self.small_pages { 0x1FFF } else { 0x7FFF };
        let count = usize::from(u16::try_from(first >> 16).ok()? & mask) / 4;
        let entry = |i: usize| -> Option<(u32, u16)> {
            let v = u32_at(d, tagged + i * 4)?;
            Some((v & 0xFFFF, u16::try_from(v >> 16).ok()?))
        };
        for i in 0..count {
            let (id, raw_offset) = entry(i)?;
            if id != column.id {
                continue;
            }
            let offset = usize::from(raw_offset & mask);
            let end = if i + 1 < count {
                usize::from(entry(i + 1)?.1 & mask)
            } else {
                d.len().checked_sub(tagged)?
            };
            let (has_flags, null_small) = if self.small_pages {
                (raw_offset & 0x4000 != 0, raw_offset & 0x2000 != 0)
            } else {
                (true, false)
            };
            if null_small {
                return None;
            }
            let flags = if has_flags {
                *d.get(tagged + offset)?
            } else {
                0
            };
            if flags & TAGFLD_NULL != 0 {
                return None;
            }
            let start = offset + usize::from(has_flags);
            let value = d.get(tagged + start..tagged + end.max(start))?;
            return Some((value.to_vec(), flags));
        }
        None
    }

    /// The value of `column` in this record.
    pub fn get(&self, column: &Column) -> Value {
        let Some((raw, flags)) = self.raw(column) else {
            return Value::Null;
        };
        if flags & TAGFLD_SEPARATED != 0 {
            return Value::LongValue;
        }
        if flags & (TAGFLD_MULTI | TAGFLD_TWO_VALUES) != 0 {
            return Value::Unsupported("multi_value");
        }
        let raw = if flags & TAGFLD_COMPRESSED != 0 {
            match decompress(&raw) {
                Ok(bytes) => bytes,
                Err(what) => return Value::Unsupported(what),
            }
        } else {
            raw
        };
        decode(column, &raw)
    }

    /// The value of the column named `name`, or `Null` when the table has no such column.
    pub fn named(&self, name: &str) -> Value {
        self.table
            .column(name)
            .map_or(Value::Null, |column| self.get(column))
    }
}

fn column_size(c: &Column) -> usize {
    fixed_size(c.kind).unwrap_or_else(|| usize::try_from(c.space).unwrap_or(0))
}

/// Decodes the bytes of one value by its column's type.
fn decode(column: &Column, raw: &[u8]) -> Value {
    let int = |n: usize| -> Option<[u8; 8]> {
        let mut out = [0_u8; 8];
        out.get_mut(..n)?.copy_from_slice(raw.get(..n)?);
        Some(out)
    };
    let value = match column.kind {
        coltyp::BIT => raw.first().map(|b| Value::Int(i64::from(*b != 0))),
        coltyp::UNSIGNED_BYTE => raw.first().map(|b| Value::UInt(u64::from(*b))),
        coltyp::SHORT => int(2).map(|b| Value::Int(i64::from(i16::from_le_bytes([b[0], b[1]])))),
        coltyp::UNSIGNED_SHORT => {
            int(2).map(|b| Value::UInt(u64::from(u16::from_le_bytes([b[0], b[1]]))))
        }
        coltyp::LONG => {
            int(4).map(|b| Value::Int(i64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))))
        }
        coltyp::UNSIGNED_LONG => {
            int(4).map(|b| Value::UInt(u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))))
        }
        coltyp::CURRENCY | coltyp::LONG_LONG => int(8).map(|b| Value::Int(i64::from_le_bytes(b))),
        coltyp::SINGLE => {
            int(4).map(|b| Value::Float(f64::from(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))))
        }
        coltyp::DOUBLE => int(8).map(|b| Value::Float(f64::from_le_bytes(b))),
        coltyp::DATE_TIME => int(8).map(|b| Value::OleDate(f64::from_le_bytes(b))),
        coltyp::TEXT | coltyp::LONG_TEXT => Some(Value::Text(text(raw, column.codepage))),
        _ => Some(Value::Bytes(raw.to_vec())),
    };
    value.unwrap_or(Value::Unsupported("short_value"))
}

/// Text in the column's code page: UTF-16LE for 1200, otherwise single-byte text read as Latin-1.
pub fn text(raw: &[u8], codepage: u32) -> String {
    if codepage == 1200 && raw.len().is_multiple_of(2) {
        utf16(raw)
    } else {
        raw.iter()
            .take_while(|b| **b != 0)
            .map(|b| char::from(*b))
            .collect()
    }
}

/// UTF-16LE up to the first NUL, lossily.
pub fn utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Decompresses a compressed tagged value: 7-bit ASCII, 7-bit Unicode or XPRESS (plain LZ77).
pub fn decompress(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let Some(first) = raw.first() else {
        return Err("empty_compressed_value");
    };
    match first >> 3 {
        1 => Ok(seven_bit(raw.get(1..).unwrap_or_default(), false)),
        2 => Ok(seven_bit(raw.get(1..).unwrap_or_default(), true)),
        3 => {
            let size = usize::from(u16_at(raw, 1).ok_or("short_xpress_header")?);
            lzxpress(raw.get(3..).unwrap_or_default(), size)
        }
        5 | 6 => Err("xpress9_or_xpress10"),
        _ => Ok(raw.to_vec()),
    }
}

/// 7-bit decompression, as dissect.util's `sevenbit.decompress` does it. `wide` widens each value to
/// a UTF-16LE code unit.
pub fn seven_bit(src: &[u8], wide: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut value: u32 = 0;
    let mut shift = 0;
    let mut push = |b: u32| {
        out.push(u8::try_from(b & 0x7F).unwrap_or(0));
        if wide {
            out.push(0);
        }
    };
    for byte in src {
        value |= u32::from(*byte) << shift;
        push(value);
        value >>= 7;
        shift += 1;
        if shift == 7 {
            push(value);
            value >>= 7;
            shift = 0;
        }
    }
    out
}

/// Plain LZ77 "LZXPRESS" decompression ([MS-XCA] 2.4), bounded to `limit` output bytes.
pub fn lzxpress(src: &[u8], limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(64 * 1024));
    let mut at = 0;
    let mut flags: u32 = 0;
    let mut flag_count = 0;
    let mut half_byte: Option<usize> = None;
    let byte = |i: usize| src.get(i).copied().ok_or("xpress_truncated");
    while at < src.len() {
        if flag_count == 0 {
            flags = u32_at(src, at).ok_or("xpress_truncated")?;
            at += 4;
            flag_count = 32;
        }
        flag_count -= 1;
        if flags & (1 << flag_count) == 0 {
            if at >= src.len() {
                break;
            }
            out.push(byte(at)?);
            at += 1;
        } else {
            if at >= src.len() {
                break;
            }
            let m = usize::from(u16_at(src, at).ok_or("xpress_truncated")?);
            at += 2;
            let offset = m / 8 + 1;
            let mut length = m % 8;
            if length == 7 {
                if let Some(h) = half_byte.take() {
                    length = usize::from(byte(h)? >> 4);
                } else {
                    half_byte = Some(at);
                    length = usize::from(byte(at)? & 0x0F);
                    at += 1;
                }
                if length == 15 {
                    length = usize::from(byte(at)?);
                    at += 1;
                    if length == 255 {
                        length = usize::from(u16_at(src, at).ok_or("xpress_truncated")?);
                        at += 2;
                        if length == 0 {
                            length = usize::try_from(u32_at(src, at).ok_or("xpress_truncated")?)
                                .map_err(|_| "xpress_length")?;
                            at += 4;
                        }
                        length = length.checked_sub(22).ok_or("xpress_length")?;
                    }
                    length += 15;
                }
                length += 7;
            }
            length += 3;
            if offset > out.len() {
                return Err("xpress_offset");
            }
            for _ in 0..length {
                let b = out[out.len() - offset];
                out.push(b);
            }
        }
        if out.len() > limit {
            return Err("xpress_too_large");
        }
    }
    Ok(out)
}

/// Converts an OLE automation date to a timestamp in whole seconds, UTC.
pub fn ole_date(days: f64) -> Option<jiff::Timestamp> {
    if !days.is_finite() || !(1.0..=2_958_465.0).contains(&days) {
        return None;
    }
    // 25 569 days from 1899-12-30 to 1970-01-01.
    let seconds = ((days - 25_569.0) * 86_400.0).round();
    #[allow(clippy::cast_possible_truncation)]
    jiff::Timestamp::from_second(seconds as i64).ok()
}

/// A parsed page.
struct Page {
    flags: u32,
    next: u32,
    data: Vec<u8>,
    tags: Vec<(usize, usize, u16)>,
    small: bool,
}

impl Page {
    fn entry(&self, i: usize) -> Option<(&[u8], u16)> {
        let (offset, size, flags) = *self.tags.get(i)?;
        Some((self.data.get(offset..offset.checked_add(size)?)?, flags))
    }

    /// The data of entry `i` after its key, and its flags.
    fn entry_data(&self, i: usize) -> Option<(&[u8], u16)> {
        let (buf, flags) = self.entry(i)?;
        let mut at = 0;
        if flags & TAG_COMMON_KEY != 0 {
            at += 2;
        }
        let key = usize::from(u16_at(buf, at)? & 0x1FFF);
        at += 2 + key;
        Some((buf.get(at..)?, flags))
    }
}

/// An open database: its header and a callback that reads bytes at an offset.
pub struct Database<R> {
    read: R,
    /// What the file header says.
    pub header: Header,
    limits: Limits,
    pages_read: usize,
}

impl<R: FnMut(u64, usize) -> Option<Vec<u8>>> Database<R> {
    /// Reads and checks the file header.
    pub fn open(mut read: R, limits: Limits) -> Result<Self, ParseError> {
        let head =
            read(0, 668).ok_or_else(|| malformed("header", "the header could not be read"))?;
        if head.len() < 240 {
            return Err(ParseError::Truncated {
                expected: 240,
                found: head.len(),
            });
        }
        if u32_at(&head, 4) != Some(SIGNATURE) {
            return Err(malformed("signature", "not an ESE database"));
        }
        let header = Header {
            version: u32_at(&head, 8).unwrap_or(0),
            state: u32_at(&head, 52).unwrap_or(0),
            revision: u32_at(&head, 232).unwrap_or(0),
            page_size: u32_at(&head, 236).unwrap_or(0),
        };
        if !matches!(header.page_size, 2048 | 4096 | 8192 | 16_384 | 32_768) {
            return Err(malformed("page_size", "not a page size ESE uses"));
        }
        Ok(Self {
            read,
            header,
            limits,
            pages_read: 0,
        })
    }

    /// Pages read so far.
    pub fn pages_read(&self) -> usize {
        self.pages_read
    }

    fn page(&mut self, number: u32) -> Option<Page> {
        if self.pages_read >= self.limits.max_pages {
            return None;
        }
        self.pages_read += 1;
        let size = usize::try_from(self.header.page_size).ok()?;
        let offset = (u64::from(number) + 1) * u64::from(self.header.page_size);
        let buf = (self.read)(offset, size)?;
        if buf.len() != size {
            return None;
        }
        let small = size <= 8192;
        let header_len: usize = if small { 40 } else { 80 };
        if !small && u32_at(&buf, 64)? != number {
            return None;
        }
        let next = u32_at(&buf, 20)?;
        let mic_free = usize::from(u16_at(&buf, 32)?);
        let tag_state = u16_at(&buf, 34)?;
        let flags = u32_at(&buf, 36)?;
        let tag_count = usize::from(tag_state & 0x0FFF);
        let data = buf
            .get(header_len..header_len.checked_add(mic_free)?)?
            .to_vec();
        let mask: u16 = if small { 0x1FFF } else { 0x7FFF };
        let mut tags = Vec::with_capacity(tag_count);
        for i in 0..tag_count {
            let at = size.checked_sub((i + 1) * 4)?;
            let cb = u16_at(&buf, at)?;
            let ib = u16_at(&buf, at + 2)?;
            let (offset, length) = (usize::from(ib & mask), usize::from(cb & mask));
            let tag_flags = if small {
                ib >> 13
            } else {
                data.get(offset + 1).map_or(0, |b| u16::from(*b >> 5))
            };
            tags.push((offset, length, tag_flags));
        }
        Some(Page {
            flags,
            next,
            data,
            tags,
            small,
        })
    }

    /// Hands every live leaf entry of the tree rooted at `root` to `visit`, as its data and whether
    /// the page uses small-page tags.
    fn walk(&mut self, root: u32, visit: &mut dyn FnMut(&[u8], bool) -> bool) -> Walk {
        let mut walk = Walk::default();
        let mut seen = BTreeSet::new();
        let mut stack: Vec<(u32, u8)> = vec![(root, 0)];
        let mut last_leaf_next: Option<u32> = None;
        while let Some((number, depth)) = stack.pop() {
            if !seen.insert(number) {
                continue;
            }
            if depth > self.limits.max_depth || self.pages_read >= self.limits.max_pages {
                walk.limited = true;
                break;
            }
            let Some(page) = self.page(number) else {
                walk.bad_pages += 1;
                continue;
            };
            if page.flags & (PAGE_SPACE_TREE | PAGE_INDEX | PAGE_LONG_VALUE) != 0 {
                continue;
            }
            if page.flags & PAGE_LEAF != 0 {
                for i in 1..page.tags.len() {
                    let Some((data, flags)) = page.entry_data(i) else {
                        walk.bad_pages += 1;
                        continue;
                    };
                    if flags & TAG_DELETED != 0 {
                        walk.deleted += 1;
                        continue;
                    }
                    if walk.records >= self.limits.max_records {
                        walk.limited = true;
                        return walk;
                    }
                    walk.records += 1;
                    if !visit(data, page.small) {
                        walk.limited = true;
                        return walk;
                    }
                }
                if page.next != 0 {
                    last_leaf_next = Some(page.next);
                }
                if stack.is_empty()
                    && let Some(next) = last_leaf_next.take()
                    && !seen.contains(&next)
                {
                    stack.push((next, depth));
                }
            } else {
                // Children pushed in reverse so they are visited left to right.
                let mut children = Vec::new();
                for i in 1..page.tags.len() {
                    if let Some((data, _)) = page.entry_data(i)
                        && let Some(child) = u32_at(data, 0)
                    {
                        children.push(child);
                    }
                }
                for child in children.into_iter().rev() {
                    stack.push((child, depth + 1));
                }
            }
        }
        walk
    }

    /// Every table in the catalog with its columns.
    pub fn tables(&mut self) -> Result<Vec<Table>, ParseError> {
        let catalog = catalog_table();
        let mut rows: Vec<(u32, u16, u32, u32, u32, u32, String)> = Vec::new();
        let walk = self.walk(CATALOG_ROOT, &mut |data, small| {
            let record = Record {
                table: &catalog,
                data: data.to_vec(),
                small_pages: small,
            };
            let int = |n: &str| record.named(n).as_u64().and_then(|v| u32::try_from(v).ok());
            let name = match record.named("Name") {
                Value::Text(t) => t,
                _ => String::new(),
            };
            if let (Some(objid), Some(kind), Some(id), Some(coltyp_or_fdp)) = (
                int("ObjidTable"),
                int("Type").and_then(|t| u16::try_from(t).ok()),
                int("Id"),
                int("ColtypOrPgnoFDP"),
            ) {
                rows.push((
                    objid,
                    kind,
                    id,
                    coltyp_or_fdp,
                    int("SpaceUsage").unwrap_or(0),
                    int("PagesOrLocale").unwrap_or(0),
                    name,
                ));
            }
            true
        });
        if walk.records == 0 {
            return Err(malformed("catalog", "no catalog record could be read"));
        }
        let mut tables: BTreeMap<u32, Table> = BTreeMap::new();
        for (objid, kind, _, fdp, _, _, name) in &rows {
            if *kind == 1 {
                tables.insert(
                    *objid,
                    Table {
                        objid: *objid,
                        name: name.clone(),
                        root: *fdp,
                        columns: Vec::new(),
                    },
                );
            }
        }
        for (objid, kind, id, coltype, space, codepage, name) in rows {
            if kind == 2
                && let Some(table) = tables.get_mut(&objid)
            {
                table.columns.push(Column {
                    id,
                    name,
                    kind: coltype,
                    space,
                    codepage,
                });
            }
        }
        let mut out: Vec<Table> = tables.into_values().collect();
        for table in &mut out {
            table.columns.sort_by_key(|c| c.id);
        }
        Ok(out)
    }

    /// Hands every record of `table` to `visit`, until it returns `false`.
    pub fn records(&mut self, table: &Table, visit: &mut dyn FnMut(&Record<'_>) -> bool) -> Walk {
        let root = table.root;
        self.walk(root, &mut |data, small| {
            let record = Record {
                table,
                data: data.to_vec(),
                small_pages: small,
            };
            visit(&record)
        })
    }
}

/// The catalog's own columns, which every ESE database shares.
fn catalog_table() -> Table {
    let col = |id: u32, name: &str, kind: u32| Column {
        id,
        name: name.to_owned(),
        kind,
        space: 0,
        codepage: 1252,
    };
    Table {
        objid: 2,
        name: "MSysObjects".to_owned(),
        root: CATALOG_ROOT,
        columns: vec![
            col(1, "ObjidTable", coltyp::LONG),
            col(2, "Type", coltyp::SHORT),
            col(3, "Id", coltyp::LONG),
            col(4, "ColtypOrPgnoFDP", coltyp::LONG),
            col(5, "SpaceUsage", coltyp::LONG),
            col(6, "Flags", coltyp::LONG),
            col(7, "PagesOrLocale", coltyp::LONG),
            col(8, "RootFlag", coltyp::BIT),
            col(9, "RecordOffset", coltyp::SHORT),
            col(10, "LCMapFlags", coltyp::LONG),
            col(11, "KeyMost", coltyp::SHORT),
            col(12, "LVChunkMax", coltyp::LONG),
            col(128, "Name", coltyp::TEXT),
        ],
    }
}

/// What one value to write is, for [`build`].
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    /// A fixed column's bytes.
    Fixed(Vec<u8>),
    /// A variable column's bytes.
    Var(Vec<u8>),
    /// A tagged column's bytes and its flags byte.
    Tagged(Vec<u8>, u8),
}

/// Encodes one record from `(column id, cell)` pairs, as ESE lays it out. For tests in this workspace.
pub fn encode_record(columns: &[Column], cells: &[(u32, Cell)], small: bool) -> Vec<u8> {
    let last_fixed = columns
        .iter()
        .filter(|c| c.id < 128)
        .map(|c| c.id)
        .max()
        .unwrap_or(0);
    let mut fixed = Vec::new();
    let mut nulls = vec![0_u8; usize::try_from(last_fixed.div_ceil(8)).unwrap_or(0)];
    for c in columns.iter().filter(|c| c.id < 128) {
        let size = column_size(c);
        if let Some((_, Cell::Fixed(b))) = cells.iter().find(|(id, _)| *id == c.id) {
            let mut v = b.clone();
            v.resize(size, 0);
            fixed.extend_from_slice(&v);
        } else {
            fixed.extend(std::iter::repeat_n(0, size));
            let bit = usize::try_from(c.id - 1).unwrap_or(0);
            if let Some(n) = nulls.get_mut(bit / 8) {
                *n |= 1 << (bit % 8);
            }
        }
    }
    let last_var = columns
        .iter()
        .filter(|c| (128..256).contains(&c.id))
        .map(|c| c.id)
        .max()
        .unwrap_or(127);
    let mut offsets = Vec::new();
    let mut var_data = Vec::new();
    for id in 128..=last_var {
        match cells.iter().find(|(i, _)| *i == id) {
            Some((_, Cell::Var(b))) => {
                var_data.extend_from_slice(b);
                offsets.push(u16::try_from(var_data.len()).unwrap_or(0));
            }
            _ => offsets.push(u16::try_from(var_data.len()).unwrap_or(0) | 0x8000),
        }
    }
    let mut tagged: Vec<(u32, Vec<u8>, u8)> = cells
        .iter()
        .filter_map(|(id, c)| match c {
            Cell::Tagged(b, f) => Some((*id, b.clone(), *f)),
            _ => None,
        })
        .collect();
    tagged.sort_by_key(|t| t.0);
    let mut tag_array = Vec::new();
    let mut tag_data = Vec::new();
    let header = tagged.len() * 4;
    for (id, bytes, flags) in &tagged {
        let offset = u16::try_from(header + tag_data.len()).unwrap_or(0);
        let offset = if small { offset | 0x4000 } else { offset };
        tag_array.extend_from_slice(&u16::try_from(*id).unwrap_or(0).to_le_bytes());
        tag_array.extend_from_slice(&offset.to_le_bytes());
        tag_data.push(*flags);
        tag_data.extend_from_slice(bytes);
    }
    let var_start = 4 + fixed.len() + nulls.len();
    let mut out = vec![
        u8::try_from(last_fixed).unwrap_or(0),
        u8::try_from(last_var).unwrap_or(0),
    ];
    out.extend_from_slice(&u16::try_from(var_start).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&fixed);
    out.extend_from_slice(&nulls);
    for o in offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(&var_data);
    out.extend_from_slice(&tag_array);
    out.extend_from_slice(&tag_data);
    out
}

/// One table to write with [`build`]: name, columns and records.
pub type BuildTable = (String, Vec<Column>, Vec<Vec<(u32, Cell)>>);

/// Builds a database file holding `tables`, each on one leaf root page (one more page per table
/// when a page fills up, joined by `next`). For tests in this workspace; `page_size` 4096 or 32768.
#[allow(clippy::too_many_lines)]
pub fn build(page_size: u32, tables: &[BuildTable]) -> Vec<u8> {
    let size = usize::try_from(page_size).unwrap_or(4096);
    let small = size <= 8192;
    let header_len = if small { 40 } else { 80 };
    let catalog = catalog_table();
    // Logical pages: 1..=3 empty, 4 catalog, then one or more per table.
    let mut pages: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let make_page = |number: u32, entries: &[Vec<u8>], next: u32, flags: u32| -> Vec<u8> {
        let mut page = vec![0_u8; size];
        page[20..24].copy_from_slice(&next.to_le_bytes());
        page[36..40].copy_from_slice(&flags.to_le_bytes());
        if !small {
            page[64..68].copy_from_slice(&number.to_le_bytes());
        }
        let mut data = Vec::new();
        let mut tags = vec![(0_usize, 0_usize)];
        for e in entries {
            // Entry: local key size 0, then the record.
            let mut entry = vec![0_u8, 0];
            entry.extend_from_slice(e);
            tags.push((data.len(), entry.len()));
            data.extend_from_slice(&entry);
        }
        page[header_len..header_len + data.len()].copy_from_slice(&data);
        page[32..34].copy_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_le_bytes());
        page[34..36].copy_from_slice(&u16::try_from(tags.len()).unwrap_or(0).to_le_bytes());
        for (i, (offset, len)) in tags.iter().enumerate() {
            let at = size - (i + 1) * 4;
            page[at..at + 2].copy_from_slice(&u16::try_from(*len).unwrap_or(0).to_le_bytes());
            page[at + 2..at + 4]
                .copy_from_slice(&u16::try_from(*offset).unwrap_or(0).to_le_bytes());
        }
        page
    };
    let room = size - header_len - 64;
    let paginate = |first: u32, records: &[Vec<u8>], pages: &mut BTreeMap<u32, Vec<u8>>| -> u32 {
        let mut chunks: Vec<Vec<Vec<u8>>> = vec![Vec::new()];
        let mut used = 0;
        for r in records {
            let need = r.len() + 2 + 4;
            if used + need > room && !chunks.last().is_none_or(Vec::is_empty) {
                chunks.push(Vec::new());
                used = 0;
            }
            used += need;
            if let Some(last) = chunks.last_mut() {
                last.push(r.clone());
            }
        }
        let count = u32::try_from(chunks.len()).unwrap_or(1);
        for (i, chunk) in chunks.iter().enumerate() {
            let n = first + u32::try_from(i).unwrap_or(0);
            let next = if i + 1 < chunks.len() { n + 1 } else { 0 };
            let flags = PAGE_LEAF | PAGE_NEW_RECORD_FORMAT | u32::from(i == 0);
            pages.insert(n, make_page(n, chunk, next, flags));
        }
        count
    };
    let mut next_page = 5_u32;
    let mut catalog_rows = Vec::new();
    let mut table_pages = Vec::new();
    for (index, (name, columns, records)) in tables.iter().enumerate() {
        let objid = 100 + u32::try_from(index).unwrap_or(0);
        let encoded: Vec<Vec<u8>> = records
            .iter()
            .map(|cells| encode_record(columns, cells, small))
            .collect();
        table_pages.push((next_page, encoded));
        let le = |v: u32| v.to_le_bytes().to_vec();
        catalog_rows.push(vec![
            (1, Cell::Fixed(le(objid))),
            (2, Cell::Fixed(1_u16.to_le_bytes().to_vec())),
            (3, Cell::Fixed(le(objid))),
            (4, Cell::Fixed(le(next_page))),
            (128, Cell::Var(name.as_bytes().to_vec())),
        ]);
        for c in columns {
            catalog_rows.push(vec![
                (1, Cell::Fixed(le(objid))),
                (2, Cell::Fixed(2_u16.to_le_bytes().to_vec())),
                (3, Cell::Fixed(le(c.id))),
                (4, Cell::Fixed(le(c.kind))),
                (5, Cell::Fixed(le(c.space))),
                (7, Cell::Fixed(le(c.codepage))),
                (128, Cell::Var(c.name.as_bytes().to_vec())),
            ]);
        }
        // Reserve generously; pages are renumbered below.
        let estimate: usize = records.len() * 256 / room + 1;
        next_page += u32::try_from(estimate).unwrap_or(1) + 1;
    }
    let catalog_records: Vec<Vec<u8>> = catalog_rows
        .iter()
        .map(|cells| encode_record(&catalog.columns, cells, small))
        .collect();
    // The catalog gets page 4 and, when it overflows, pages after every table's.
    let overflow = next_page + 1000;
    {
        let mut tmp = BTreeMap::new();
        let n = paginate(overflow, &catalog_records, &mut tmp);
        if n == 1 {
            let page = tmp.remove(&overflow).unwrap_or_default();
            let mut fixed = page;
            if !small {
                fixed[64..68].copy_from_slice(&CATALOG_ROOT.to_le_bytes());
            }
            pages.insert(CATALOG_ROOT, fixed);
        } else {
            // Page 4 points at the first overflow page.
            pages.insert(
                CATALOG_ROOT,
                make_page(CATALOG_ROOT, &[], overflow, PAGE_LEAF | 1),
            );
            pages.extend(tmp);
        }
    }
    for (first, encoded) in &table_pages {
        paginate(*first, encoded, &mut pages);
    }
    let last = pages.keys().max().copied().unwrap_or(CATALOG_ROOT);
    let mut file = vec![0_u8; size * usize::try_from(last + 2).unwrap_or(0)];
    let mut head = vec![0_u8; size];
    head[4..8].copy_from_slice(&SIGNATURE.to_le_bytes());
    head[8..12].copy_from_slice(&0x620_u32.to_le_bytes());
    head[52..56].copy_from_slice(&2_u32.to_le_bytes());
    head[232..236].copy_from_slice(&0x11_u32.to_le_bytes());
    head[236..240].copy_from_slice(&page_size.to_le_bytes());
    file[..size].copy_from_slice(&head);
    file[size..2 * size].copy_from_slice(&head);
    for (n, page) in pages {
        let at = usize::try_from(n + 1).unwrap_or(0) * size;
        if let Some(slot) = file.get_mut(at..at + size) {
            slot.copy_from_slice(&page);
        }
    }
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

    fn col(id: u32, name: &str, kind: u32) -> Column {
        Column {
            id,
            name: name.to_owned(),
            kind,
            space: 0,
            codepage: 1200,
        }
    }

    fn sample(page_size: u32, rows: usize) -> Vec<u8> {
        let columns = vec![
            col(1, "IdType", coltyp::UNSIGNED_BYTE),
            col(2, "IdIndex", coltyp::LONG),
            col(3, "TimeStamp", coltyp::DATE_TIME),
            col(128, "Short", coltyp::TEXT),
            col(256, "IdBlob", coltyp::LONG_BINARY),
        ];
        let blob: Vec<u8> = "C:\\x\\Solara.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let records = (0..rows)
            .map(|i| {
                vec![
                    (1, Cell::Fixed(vec![0])),
                    (
                        2,
                        Cell::Fixed(i32::try_from(i).unwrap().to_le_bytes().to_vec()),
                    ),
                    (3, Cell::Fixed(46_000.5_f64.to_le_bytes().to_vec())),
                    (256, Cell::Tagged(blob.clone(), 0x01)),
                ]
            })
            .collect();
        build(
            page_size,
            &[("SruDbIdMapTable".to_owned(), columns, records)],
        )
    }

    #[test]
    fn a_built_database_lists_its_table_and_reads_every_column_kind() {
        for page_size in [4096, 32_768] {
            let file = sample(page_size, 3);
            let mut db = Database::open(reader(&file), Limits::default()).unwrap();
            assert!(db.header.dirty());
            let tables = db.tables().unwrap();
            let table = tables.iter().find(|t| t.name == "SruDbIdMapTable").unwrap();
            assert_eq!(table.columns.len(), 5);
            let mut seen = Vec::new();
            let walk = db.records(table, &mut |r| {
                seen.push((
                    r.named("IdType"),
                    r.named("IdIndex"),
                    r.named("TimeStamp"),
                    r.named("Short"),
                    r.named("IdBlob"),
                ));
                true
            });
            assert_eq!(walk.records, 3, "page size {page_size}");
            assert_eq!(seen[2].0, Value::UInt(0));
            assert_eq!(seen[2].1, Value::Int(2));
            assert_eq!(seen[2].2, Value::OleDate(46_000.5));
            assert_eq!(seen[2].3, Value::Null);
            let Value::Bytes(b) = &seen[0].4 else {
                panic!("{:?}", seen[0].4)
            };
            assert_eq!(utf16(b), "C:\\x\\Solara.exe");
        }
    }

    #[test]
    fn records_over_several_pages_are_all_read_and_the_page_limit_holds() {
        let file = sample(4096, 400);
        let mut db = Database::open(reader(&file), Limits::default()).unwrap();
        let tables = db.tables().unwrap();
        let walk = db.records(&tables[0], &mut |_| true);
        assert_eq!(walk.records, 400);
        let mut db = Database::open(
            reader(&file),
            Limits {
                max_pages: 3,
                ..Limits::default()
            },
        )
        .unwrap();
        let tables = db.tables().unwrap();
        let walk = db.records(&tables[0], &mut |_| true);
        assert!(walk.limited);
        assert!(walk.records < 400);
    }

    #[test]
    fn garbage_is_an_error_never_a_panic() {
        assert!(Database::open(reader(&[0_u8; 100]), Limits::default()).is_err());
        assert!(Database::open(reader(&[0xFF_u8; 4096]), Limits::default()).is_err());
        let mut file = sample(4096, 5);
        for (i, b) in file.iter_mut().enumerate().skip(4096 * 5) {
            *b = u8::try_from(i % 251).unwrap();
        }
        if let Ok(mut db) = Database::open(reader(&file), Limits::default())
            && let Ok(tables) = db.tables()
        {
            {
                for t in &tables {
                    let _ = db.records(t, &mut |r| {
                        for c in &t.columns {
                            let _ = r.get(c);
                        }
                        true
                    });
                }
            }
        }
    }

    #[test]
    fn seven_bit_and_xpress_values_decompress() {
        // "ab" packed 7 bits each: 0x61 | 0x62 << 7.
        let packed = [0x61_u8 | (0x62 << 7), 0x62 >> 1];
        assert_eq!(&seven_bit(&packed, false)[..2], b"ab");
        assert_eq!(&seven_bit(&packed, true)[..4], b"a\0b\0");
        // XPRESS: four literals, flag word all zero.
        let mut x = vec![0, 0, 0, 0];
        x.extend_from_slice(b"abcd");
        assert_eq!(lzxpress(&x, 100).unwrap(), b"abcd");
        // A match: "ab" then copy 4 from offset 2 → "ababab".
        let mut m = 0x2000_0000_u32.to_le_bytes().to_vec();
        m.extend_from_slice(b"ab");
        let token: u16 = (1 << 3) | 1; // offset 2, length 4
        m.extend_from_slice(&token.to_le_bytes());
        assert_eq!(lzxpress(&m, 100).unwrap(), b"ababab");
        assert!(lzxpress(&m, 3).is_err());
    }

    #[test]
    fn ole_dates_convert_to_utc_seconds() {
        assert_eq!(ole_date(25_569.0).unwrap().as_second(), 0);
        assert_eq!(ole_date(25_569.5).unwrap().as_second(), 43_200);
        assert!(ole_date(f64::NAN).is_none());
        assert!(ole_date(0.0).is_none());
    }
}
