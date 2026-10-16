// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Bytes copied out of a running process — or out of a crash dump — read as strings, `FastFlag`
//! assignments, inline hooks and differences from the file on disk (B.O.P.E, ADR 0134).
//!
//! Like every parser here this is pure: a collector reads the memory through the host and hands the
//! bytes in with the address they came from. Nothing here knows which process it was.
//!
//! **What is kept.** A process's memory holds whatever the program was handling — for a game client,
//! chat text and account names among it. So [`scan_strings`] returns only strings that fall in one of
//! the [`StringCategory`] categories, each cut to [`MAX_TEXT`] characters, and never a run of
//! uncategorised text. The categories are decided by the shape of the string (an API name, a flag
//! identifier, a path ending in `.dll`, a URL, a JSON flag assignment) and by short fixed lists of
//! executor-only Luau functions and process-injection APIs; a string is never kept because of where
//! it was found.
//!
//! **What a string does not show.** That anything used it. Executable images carry the names of the
//! APIs they import, anti-cheat software carries the names of what it looks for, and a game client's
//! own flag table carries every flag name. A string is a reason to look at what else was found beside
//! it, never a finding on its own.

/// The longest text kept for one string, in characters.
pub const MAX_TEXT: usize = 160;

/// How a string was encoded in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Encoding {
    /// Printable ASCII (UTF-8 continuation bytes of an identifiable sequence included).
    Ascii,
    /// UTF-16 little-endian, as Windows wide strings are.
    Utf16Le,
}

impl Encoding {
    /// Stable identifier used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf16le",
        }
    }
}

/// Why a string was kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StringCategory {
    /// A function only third-party Luau executors provide (`getgenv`, `hookfunction`, …), from
    /// [`crate::lua_markers::MARKERS`].
    ExecutorFunction,
    /// A Windows API used to put code into, or run code in, another process.
    InjectionApi,
    /// A `FastFlag` identifier: `FFlag…`, `DFInt…`, `SFString…`, `FLog…` and the other prefixes.
    FlagIdentifier,
    /// A JSON assignment to a flag identifier: `"DFIntS2PhysicsSenderRate": 15`.
    FlagAssignment,
    /// A path to a `.dll`, `.sys`, `.exe` or `.lua` file.
    ModulePath,
    /// An `http://` or `https://` address.
    Url,
    /// Luau source text that loads code from a string or the network (`loadstring(`, `HttpGet(`).
    ScriptLoader,
}

impl StringCategory {
    /// Stable identifier used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutorFunction => "executor_function",
            Self::InjectionApi => "injection_api",
            Self::FlagIdentifier => "flag_identifier",
            Self::FlagAssignment => "flag_assignment",
            Self::ModulePath => "module_path",
            Self::Url => "url",
            Self::ScriptLoader => "script_loader",
        }
    }
}

/// Windows APIs a process-injection or memory-patching tool calls on another process. Every one also
/// has ordinary uses — debuggers, profilers, anti-cheat, accessibility tools — and every executable
/// that imports one carries its name.
pub const INJECTION_APIS: [&str; 16] = [
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "NtQueueApcThread",
    "VirtualAllocEx",
    "NtAllocateVirtualMemory",
    "WriteProcessMemory",
    "NtWriteVirtualMemory",
    "VirtualProtectEx",
    "NtProtectVirtualMemory",
    "NtMapViewOfSection",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "LdrLoadDll",
];

/// One string kept from a block of memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundString {
    /// The address of its first byte.
    pub address: u64,
    /// How it was encoded.
    pub encoding: Encoding,
    /// Its length in characters, before [`MAX_TEXT`] cut it.
    pub length: usize,
    /// The text, at most [`MAX_TEXT`] characters.
    pub text: String,
    /// Why it was kept.
    pub category: StringCategory,
}

/// One `FastFlag` assignment found as JSON text in memory: `"Name": value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagAssignment {
    /// The address of the opening quote of the name.
    pub address: u64,
    /// How it was encoded.
    pub encoding: Encoding,
    /// The flag identifier as written.
    pub name: String,
    /// The value as written: a number, `true`/`false`, or the text of a JSON string without quotes.
    pub value: String,
}

/// Whether `name` is written the way Roblox `FastFlags` are: an optional `D` or `S` prefix, then
/// `FFlag`, `FInt`, `FString` or `FLog`, then at least one identifier character, and nothing but
/// ASCII letters, digits and `_`.
pub fn is_flag_identifier(name: &str) -> bool {
    let rest = name
        .strip_prefix("DF")
        .or_else(|| name.strip_prefix("SF"))
        .or_else(|| name.strip_prefix('F'));
    let Some(rest) = rest else {
        return false;
    };
    let tail = ["Flag", "Int", "String", "Log"]
        .iter()
        .find_map(|prefix| rest.strip_prefix(prefix));
    tail.is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 120
            && tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && tail
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

/// The name a flag identifier has without its kind prefix: `DFIntS2PhysicsSenderRate` →
/// `S2PhysicsSenderRate`. `None` when `name` is not a flag identifier.
pub fn flag_base_name(name: &str) -> Option<&str> {
    if !is_flag_identifier(name) {
        return None;
    }
    let rest = name
        .strip_prefix("DF")
        .or_else(|| name.strip_prefix("SF"))
        .or_else(|| name.strip_prefix('F'))?;
    ["Flag", "Int", "String", "Log"]
        .iter()
        .find_map(|prefix| rest.strip_prefix(prefix))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The category of one string, if it has one.
pub fn classify(text: &str) -> Option<StringCategory> {
    let trimmed = text.trim();
    if trimmed.len() < 4 {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("loadstring(")
        || lower.contains(":httpget(")
        || lower.contains(":httpgetasync(")
    {
        return Some(StringCategory::ScriptLoader);
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(StringCategory::Url);
    }
    if trimmed.contains('"') && flag_assignment_in(trimmed).is_some() {
        return Some(StringCategory::FlagAssignment);
    }
    if is_flag_identifier(trimmed) {
        return Some(StringCategory::FlagIdentifier);
    }
    if INJECTION_APIS.contains(&trimmed) {
        return Some(StringCategory::InjectionApi);
    }
    if crate::lua_markers::MARKERS
        .iter()
        .any(|marker| marker.len() >= 6 && *marker == trimmed && *marker != "request")
    {
        return Some(StringCategory::ExecutorFunction);
    }
    let has_separator = trimmed.contains('\\') || trimmed.contains('/');
    if has_separator
        && [".dll", ".sys", ".exe", ".lua", ".luau"]
            .iter()
            .any(|ext| lower.ends_with(ext))
        && (!lower.contains(' ') || lower.contains(":\\"))
    {
        return Some(StringCategory::ModulePath);
    }
    None
}

/// The first `"Name": value` in `text` whose name is a flag identifier.
fn flag_assignment_in(text: &str) -> Option<(usize, String, String)> {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(open) = text[from..].find('"').map(|i| i + from) {
        let name_start = open + 1;
        let close = text[name_start..].find('"').map(|i| i + name_start)?;
        let name = &text[name_start..close];
        if is_flag_identifier(name) {
            let mut at = close + 1;
            while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
                at += 1;
            }
            if bytes.get(at) == Some(&b':') {
                at += 1;
                while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
                    at += 1;
                }
                if let Some(value) = json_scalar(&text[at..]) {
                    return Some((open, name.to_owned(), value));
                }
            }
        }
        from = close + 1;
    }
    None
}

/// A JSON scalar at the start of `text`: a quoted string (its content), a number, `true` or `false`.
fn json_scalar(text: &str) -> Option<String> {
    if let Some(rest) = text.strip_prefix('"') {
        let end = rest.find('"')?;
        let value = &rest[..end];
        return (value.len() <= 256 && !value.contains('\n')).then(|| value.to_owned());
    }
    if text.starts_with("true") {
        return Some("true".to_owned());
    }
    if text.starts_with("false") {
        return Some("false".to_owned());
    }
    let end = text
        .bytes()
        .position(|b| !(b.is_ascii_digit() || b == b'-' || b == b'.'))
        .unwrap_or(text.len());
    let number = &text[..end];
    (!number.is_empty() && number.len() <= 24 && number.bytes().any(|b| b.is_ascii_digit()))
        .then(|| number.to_owned())
}

/// The runs of printable characters in `bytes` at least `min` long, as ASCII and as UTF-16LE, with
/// the address each starts at (`base` is the address of `bytes[0]`).
fn runs(bytes: &[u8], base: u64, min: usize, mut each: impl FnMut(u64, Encoding, String)) {
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t';
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        if printable(*byte) {
            start.get_or_insert(index);
        } else if let Some(s) = start.take()
            && index - s >= min
        {
            each(
                base.wrapping_add(s as u64),
                Encoding::Ascii,
                String::from_utf8_lossy(&bytes[s..index]).into_owned(),
            );
        }
    }
    if let Some(s) = start
        && bytes.len() - s >= min
    {
        each(
            base.wrapping_add(s as u64),
            Encoding::Ascii,
            String::from_utf8_lossy(&bytes[s..]).into_owned(),
        );
    }
    // UTF-16LE: printable ASCII code units, at both alignments.
    for alignment in 0..2 {
        let mut units: Vec<u16> = Vec::new();
        let mut unit_start = alignment;
        let mut index = alignment;
        while index + 1 < bytes.len() {
            let unit = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
            let keep = unit < 0x7f && printable(u8::try_from(unit).unwrap_or(0));
            if keep {
                if units.is_empty() {
                    unit_start = index;
                }
                units.push(unit);
            } else {
                if units.len() >= min {
                    each(
                        base.wrapping_add(unit_start as u64),
                        Encoding::Utf16Le,
                        String::from_utf16_lossy(&units),
                    );
                }
                units.clear();
            }
            index += 2;
        }
        if units.len() >= min {
            each(
                base.wrapping_add(unit_start as u64),
                Encoding::Utf16Le,
                String::from_utf16_lossy(&units),
            );
        }
    }
}

/// The categorised strings in `bytes`, at most `max` of them, in address order within each encoding.
///
/// `min` is the shortest run considered (6 is a good default: shorter runs are mostly instruction
/// bytes that happen to be printable).
pub fn scan_strings(bytes: &[u8], base: u64, min: usize, max: usize) -> Vec<FoundString> {
    let mut found = Vec::new();
    runs(bytes, base, min.max(4), |address, encoding, text| {
        if found.len() >= max {
            return;
        }
        let Some(category) = classify(&text) else {
            return;
        };
        let length = text.chars().count();
        // A long run keeps only the window around what made it interesting.
        let kept: String = if category == StringCategory::FlagAssignment {
            flag_assignment_in(&text)
                .map(|(at, _, _)| text[at..].chars().take(MAX_TEXT).collect())
                .unwrap_or_default()
        } else {
            text.chars().take(MAX_TEXT).collect()
        };
        found.push(FoundString {
            address,
            encoding,
            length,
            text: kept,
            category,
        });
    });
    found
}

/// Every `"FlagName": value` JSON assignment in `bytes`, ASCII and UTF-16LE, at most `max`.
pub fn flag_assignments(bytes: &[u8], base: u64, max: usize) -> Vec<FlagAssignment> {
    let mut found = Vec::new();
    runs(bytes, base, 8, |address, encoding, text| {
        let mut from = 0;
        while found.len() < max && from < text.len() {
            let Some((at, name, value)) = flag_assignment_in(&text[from..]) else {
                break;
            };
            let offset = from + at;
            let width = if encoding == Encoding::Utf16Le { 2 } else { 1 };
            found.push(FlagAssignment {
                address: address.wrapping_add((offset * width) as u64),
                encoding,
                name: name.clone(),
                value,
            });
            from = offset + name.len() + 2;
        }
    });
    found
}

/// Every place `needle` occurs in `bytes` as a whole identifier (not inside a longer one), as ASCII
/// and as UTF-16LE, with its address. Used to find a flag identifier the caller already knows.
pub fn find_identifier(bytes: &[u8], base: u64, needle: &str, max: usize) -> Vec<(u64, Encoding)> {
    let mut hits = Vec::new();
    let ascii = needle.as_bytes();
    if ascii.is_empty() {
        return hits;
    }
    let mut at = 0;
    while hits.len() < max && at + ascii.len() <= bytes.len() {
        if &bytes[at..at + ascii.len()] == ascii {
            let before = at.checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(at + ascii.len()).copied();
            if !before.is_some_and(is_identifier_byte) && !after.is_some_and(is_identifier_byte) {
                hits.push((base.wrapping_add(at as u64), Encoding::Ascii));
            }
            at += ascii.len();
        } else {
            at += 1;
        }
    }
    let wide: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut at = 0;
    while hits.len() < max && at + wide.len() <= bytes.len() {
        if bytes[at..at + wide.len()] == wide[..] {
            let before = at
                .checked_sub(2)
                .map(|i| u16::from_le_bytes([bytes[i], bytes[i + 1]]));
            let after = bytes
                .get(at + wide.len()..at + wide.len() + 2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]));
            let ident = |u: u16| u8::try_from(u).is_ok_and(is_identifier_byte);
            if !before.is_some_and(ident) && !after.is_some_and(ident) {
                hits.push((base.wrapping_add(at as u64), Encoding::Utf16Le));
            }
            at += wide.len();
        } else {
            at += 2;
        }
    }
    hits
}

/// How many aligned pointer-sized values in `bytes` equal `target`: references to an address, used to
/// tell a string that is pointed at from one that merely sits in a buffer.
pub fn count_pointers(bytes: &[u8], target: u64, width: usize) -> usize {
    match width {
        8 => bytes
            .as_chunks::<8>()
            .0
            .iter()
            .filter(|chunk| u64::from_le_bytes(**chunk) == target)
            .count(),
        4 => u32::try_from(target).map_or(0, |target| {
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|chunk| u32::from_le_bytes(**chunk) == target)
                .count()
        }),
        _ => 0,
    }
}

/// The kind of an inline hook: what a function's first bytes jump with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    /// `E9 rel32`.
    JmpRel32,
    /// `EB rel8`.
    JmpRel8,
    /// `FF 25 disp32` — on x64, an indirect jump through a RIP-relative pointer.
    JmpIndirect,
    /// `48 B8 imm64` / `49 BA imm64` … then `FF E0`/`41 FF E2`: a register loaded and jumped to.
    MovJmpRegister,
    /// `68 imm32 C3`: push and return.
    PushRet,
}

impl HookKind {
    /// Stable identifier used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JmpRel32 => "jmp_rel32",
            Self::JmpRel8 => "jmp_rel8",
            Self::JmpIndirect => "jmp_indirect",
            Self::MovJmpRegister => "mov_jmp_register",
            Self::PushRet => "push_ret",
        }
    }
}

/// The jump at the start of `code`, when it starts with one of the [`HookKind`] shapes, and the
/// address it goes to when that can be read from the bytes alone (`address` is that of `code[0]`).
pub fn jump_at(code: &[u8], address: u64) -> Option<(HookKind, Option<u64>)> {
    match code {
        [0xe9, a, b, c, d, ..] => {
            let rel = i32::from_le_bytes([*a, *b, *c, *d]);
            Some((
                HookKind::JmpRel32,
                Some(address.wrapping_add(5).wrapping_add_signed(i64::from(rel))),
            ))
        }
        [0xeb, rel, ..] => Some((
            HookKind::JmpRel8,
            Some(
                address
                    .wrapping_add(2)
                    .wrapping_add_signed(i64::from(i8::from_le_bytes([*rel]))),
            ),
        )),
        [0xff, 0x25, ..] => Some((HookKind::JmpIndirect, None)),
        [0x48 | 0x49, 0xb8..=0xbf, rest @ ..] if rest.len() >= 10 => {
            let mut imm = [0_u8; 8];
            imm.copy_from_slice(&rest[..8]);
            let tail = &rest[8..];
            let jumps = matches!(
                tail,
                [0xff, 0xe0..=0xe7, ..] | [0x41, 0xff, 0xe0..=0xe7, ..]
            );
            jumps.then(|| (HookKind::MovJmpRegister, Some(u64::from_le_bytes(imm))))
        }
        [0x68, a, b, c, d, 0xc3, ..] => Some((
            HookKind::PushRet,
            Some(u64::from(u32::from_le_bytes([*a, *b, *c, *d]))),
        )),
        _ => None,
    }
}

/// An inline hook: the bytes in memory start with a jump the file's bytes at the same place do not.
///
/// A file whose own code starts with a jump (an incremental-link thunk, a hot-patch stub) is never
/// reported, because the comparison is with the file.
pub fn inline_hook(memory: &[u8], disk: &[u8], address: u64) -> Option<(HookKind, Option<u64>)> {
    let found = jump_at(memory, address)?;
    let compared = memory.len().min(disk.len()).min(16);
    if compared < 2 || memory[..compared] == disk[..compared] {
        return None;
    }
    if jump_at(disk, address).is_some_and(|(kind, _)| kind == found.0) {
        return None;
    }
    Some(found)
}

/// The ranges where `actual` differs from `expected`, as `(offset, length)`, merging differences
/// closer than `gap` bytes, skipping offsets inside `ignore` ranges, and stopping at `max` ranges.
pub fn diff_ranges(
    expected: &[u8],
    actual: &[u8],
    ignore: &[(usize, usize)],
    gap: usize,
    max: usize,
) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let length = expected.len().min(actual.len());
    let ignored = |at: usize| {
        ignore
            .iter()
            .any(|(s, l)| at >= *s && at < s.saturating_add(*l))
    };
    let mut index = 0;
    while index < length {
        if expected[index] != actual[index] && !ignored(index) {
            match ranges.last_mut() {
                Some((start, len)) if index <= *start + *len + gap => *len = index + 1 - *start,
                _ => {
                    if ranges.len() >= max {
                        break;
                    }
                    ranges.push((index, 1));
                }
            }
        }
        index += 1;
    }
    ranges
}

/// Whether `bytes` start like a PE image header loaded in memory (`MZ`, then `PE\0\0` at `e_lfanew`
/// within the first page). Used on private executable memory, where an image the loader did not map
/// is the trace a manual-mapping injector leaves.
pub fn looks_like_mapped_pe(bytes: &[u8]) -> bool {
    if bytes.get(..2) != Some(b"MZ") {
        return false;
    }
    let Some(field) = bytes.get(0x3c..0x40) else {
        return false;
    };
    let offset = u32::from_le_bytes([field[0], field[1], field[2], field[3]]) as usize;
    offset < 0x1000 && bytes.get(offset..offset + 4) == Some(b"PE\0\0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_identifiers_follow_the_prefixes() {
        for name in [
            "FFlagDebugGraphicsPreferVulkan",
            "DFIntS2PhysicsSenderRate",
            "SFStringX",
            "FLogNetwork",
            "FInt1",
        ] {
            assert!(is_flag_identifier(name), "{name}");
        }
        for name in [
            "Flag",
            "FFlag",
            "fflagx",
            "DFIntS2Physics SenderRate",
            "FFlagé",
            "XFIntA",
        ] {
            assert!(!is_flag_identifier(name), "{name}");
        }
        assert_eq!(
            flag_base_name("DFIntS2PhysicsSenderRate"),
            Some("S2PhysicsSenderRate")
        );
        assert_eq!(flag_base_name("AllowVideoPreRoll"), None);
    }

    #[test]
    fn strings_are_kept_only_with_a_category() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0\0hello friend this is a chat line\0");
        bytes.extend_from_slice(b"VirtualAllocEx\0");
        bytes.extend_from_slice(b"\x01DFIntS2PhysicsSenderRate\0");
        bytes.extend_from_slice(br#"{"DFIntS2PhysicsSenderRate": 60, "FFlagX": true}"#);
        bytes.push(0);
        bytes.extend(
            "C:\\Users\\a\\x\\inject.dll"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(b"loadstring(game:HttpGet(\"https://x\"))()\0");
        let found = scan_strings(&bytes, 0x1000, 6, 100);
        let categories: Vec<StringCategory> = found.iter().map(|f| f.category).collect();
        assert!(!found.iter().any(|f| f.text.contains("chat")), "{found:?}");
        assert!(categories.contains(&StringCategory::InjectionApi));
        assert!(categories.contains(&StringCategory::FlagIdentifier));
        assert!(categories.contains(&StringCategory::FlagAssignment));
        assert!(categories.contains(&StringCategory::ModulePath));
        assert!(categories.contains(&StringCategory::ScriptLoader));
        let api = found
            .iter()
            .find(|f| f.category == StringCategory::InjectionApi)
            .unwrap();
        assert_eq!(api.address, 0x1000 + 35);
        let path = found
            .iter()
            .find(|f| f.category == StringCategory::ModulePath)
            .unwrap();
        assert_eq!(path.encoding, Encoding::Utf16Le);
    }

    #[test]
    fn flag_assignments_are_read_with_their_values_and_addresses() {
        let text =
            br#"xx{"DFIntS2PhysicsSenderRate":15,"FFlagA": false, "FStringB":"hi","Other":1}"#;
        let found = flag_assignments(text, 0x500, 10);
        let pairs: Vec<(&str, &str)> = found
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("DFIntS2PhysicsSenderRate", "15"),
                ("FFlagA", "false"),
                ("FStringB", "hi")
            ]
        );
        assert_eq!(found[0].address, 0x503);
        let wide: Vec<u8> = r#"{"FIntA": -3}"#.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let found = flag_assignments(&wide, 0, 10);
        assert_eq!(found[0].value, "-3");
        assert_eq!(found[0].address, 2);
        assert_eq!(found[0].encoding, Encoding::Utf16Le);
    }

    #[test]
    fn identifiers_are_found_whole_in_both_encodings() {
        let mut bytes = b"..DFIntS2PhysicsSenderRateX..DFIntS2PhysicsSenderRate\0\0\0".to_vec();
        bytes.extend(
            "DFIntS2PhysicsSenderRate"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let hits = find_identifier(&bytes, 0x10, "DFIntS2PhysicsSenderRate", 10);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0], (0x10 + 29, Encoding::Ascii));
        assert_eq!(hits[1].1, Encoding::Utf16Le);
    }

    #[test]
    fn pointers_to_an_address_are_counted() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x7ff6_1234_5678_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&0x7ff6_1234_5678_u64.to_le_bytes());
        assert_eq!(count_pointers(&bytes, 0x7ff6_1234_5678, 8), 2);
        assert_eq!(count_pointers(&bytes, 1, 4), 1);
    }

    #[test]
    fn a_jump_written_over_a_prologue_is_a_hook_and_one_from_the_file_is_not() {
        let disk = [0x48, 0x83, 0xec, 0x28, 0x90, 0x90];
        let memory = [0xe9, 0x10, 0x00, 0x00, 0x00, 0x90];
        let (kind, target) = inline_hook(&memory, &disk, 0x1000).unwrap();
        assert_eq!(kind, HookKind::JmpRel32);
        assert_eq!(target, Some(0x1015));
        assert!(inline_hook(&memory, &memory, 0x1000).is_none());
        let thunk = [0xe9, 0x20, 0x00, 0x00, 0x00, 0x90];
        assert!(inline_hook(&memory, &thunk, 0x1000).is_none());
        let movjmp = [0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xe0, 0x90];
        assert_eq!(
            inline_hook(&movjmp, &[0; 13], 0).unwrap(),
            (HookKind::MovJmpRegister, Some(0x0807_0605_0403_0201))
        );
        assert_eq!(
            jump_at(&[0x68, 1, 0, 0, 0, 0xc3], 0).unwrap().0,
            HookKind::PushRet
        );
        assert_eq!(jump_at(&[0xeb, 0xfe], 0x10).unwrap().1, Some(0x10));
    }

    #[test]
    fn differences_merge_and_ignored_ranges_are_skipped() {
        let expected = [0_u8; 64];
        let mut actual = [0_u8; 64];
        actual[3] = 1;
        actual[6] = 1;
        actual[30] = 1;
        actual[50] = 1;
        let ranges = diff_ranges(&expected, &actual, &[(48, 8)], 4, 10);
        assert_eq!(ranges, vec![(3, 4), (30, 1)]);
        assert_eq!(diff_ranges(&expected, &actual, &[], 0, 1).len(), 1);
    }

    #[test]
    fn a_mapped_pe_header_is_recognised() {
        let mut page = vec![0_u8; 0x200];
        page[..2].copy_from_slice(b"MZ");
        page[0x3c] = 0x80;
        page[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(looks_like_mapped_pe(&page));
        page[0x81] = 0;
        assert!(!looks_like_mapped_pe(&page));
        assert!(!looks_like_mapped_pe(b"MZ"));
    }

    #[test]
    fn noise_never_panics() {
        let mut state = 0x9e37_79b9_u32;
        let bytes: Vec<u8> = (0..65_536)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[1]
            })
            .collect();
        let _ = scan_strings(&bytes, u64::MAX - 10, 4, 1000);
        let _ = flag_assignments(&bytes, 0, 1000);
        let _ = find_identifier(&bytes, 0, "FFlagA", 10);
        let _ = diff_ranges(&bytes, &bytes[1..], &[], 3, 100);
        for start in 0..64 {
            let _ = jump_at(&bytes[start..], 0);
        }
    }
}
