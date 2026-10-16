// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Windows shortcut (`.lnk`) files, as `[MS-SHLLINK]` describes them (B.O.P.E, ADR 0119).
//!
//! What a shortcut keeps is where its target was when the shortcut was made or last resolved, and the
//! target's own times at that moment — so a shortcut on the Desktop or in `Recent` can name a program
//! that is no longer there.
//!
//! Read: the header (flags, the target's creation/access/write `FILETIME`s and size), the `LinkInfo`
//! local base path or network path with its suffix, and the relative path and working directory
//! strings. **Not kept:** the command-line arguments (only whether there are any), the description
//! text, the volume serial number and the label. The target ID list (shell items) is skipped: the
//! `LinkInfo` path says the same for every shortcut Explorer makes to a file.

use jiff::Timestamp;

use crate::error::ParseError;
use crate::filetime::to_timestamp;

const HEADER_SIZE: usize = 0x4C;
const CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const HAS_ID_LIST: u32 = 0x1;
const HAS_LINK_INFO: u32 = 0x2;
const HAS_NAME: u32 = 0x4;
const HAS_RELATIVE_PATH: u32 = 0x8;
const HAS_WORKING_DIR: u32 = 0x10;
const HAS_ARGUMENTS: u32 = 0x20;
const HAS_ICON: u32 = 0x40;
const IS_UNICODE: u32 = 0x80;

/// What one shortcut says about its target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shortcut {
    /// The target's full path from `LinkInfo` (local base path + suffix, or network name + suffix).
    pub target_path: Option<String>,
    /// The relative path string, when the shortcut has one.
    pub relative_path: Option<String>,
    /// The working directory string.
    pub working_dir: Option<String>,
    /// Whether the shortcut passes arguments. Their text is never returned.
    pub has_arguments: bool,
    /// The target's creation time when the shortcut was saved.
    pub target_created: Option<Timestamp>,
    /// The target's last-access time when the shortcut was saved.
    pub target_accessed: Option<Timestamp>,
    /// The target's last-write time when the shortcut was saved.
    pub target_modified: Option<Timestamp>,
    /// The target's size when the shortcut was saved (low 32 bits, as the format stores it).
    pub target_size: u32,
    /// Whether the target was on a network share.
    pub network: bool,
}

impl Shortcut {
    /// The best path the shortcut gives: the `LinkInfo` path, else the relative path.
    pub fn best_path(&self) -> Option<&str> {
        self.target_path
            .as_deref()
            .or(self.relative_path.as_deref())
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn time_at(b: &[u8], at: usize) -> Option<Timestamp> {
    u64_at(b, at).filter(|v| *v != 0).and_then(to_timestamp)
}

/// A NUL-terminated ANSI string starting at `at`.
fn ansi_z(b: &[u8], at: usize) -> Option<String> {
    let rest = b.get(at..)?;
    let end = rest.iter().position(|c| *c == 0)?;
    let text = crate::cp1252::decode(rest.get(..end)?);
    (!text.is_empty()).then_some(text)
}

/// A NUL-terminated UTF-16LE string starting at `at`.
fn utf16_z(b: &[u8], at: usize) -> Option<String> {
    let rest = b.get(at..)?;
    let units: Vec<u16> = rest
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    let text = String::from_utf16_lossy(&units);
    (!text.is_empty()).then_some(text)
}

fn malformed(field: &'static str, detail: &str) -> ParseError {
    ParseError::Malformed {
        field,
        detail: detail.to_owned(),
    }
}

/// Parses one `.lnk` file.
pub fn parse(bytes: &[u8]) -> Result<Shortcut, ParseError> {
    if bytes.len() < HEADER_SIZE {
        return Err(ParseError::Truncated {
            expected: HEADER_SIZE,
            found: bytes.len(),
        });
    }
    if u32_at(bytes, 0) != Some(0x4C) || bytes.get(4..20) != Some(&CLSID[..]) {
        return Err(malformed("header", "not a shell link"));
    }
    let flags = u32_at(bytes, 0x14).unwrap_or(0);
    let mut out = Shortcut {
        target_created: time_at(bytes, 0x1C),
        target_accessed: time_at(bytes, 0x24),
        target_modified: time_at(bytes, 0x2C),
        target_size: u32_at(bytes, 0x34).unwrap_or(0),
        has_arguments: flags & HAS_ARGUMENTS != 0,
        ..Shortcut::default()
    };
    let mut at = HEADER_SIZE;
    if flags & HAS_ID_LIST != 0 {
        let size = usize::from(u16_at(bytes, at).ok_or_else(|| truncated(bytes, at + 2))?);
        at += 2 + size;
    }
    if flags & HAS_LINK_INFO != 0 {
        let size = u32_at(bytes, at).ok_or_else(|| truncated(bytes, at + 4))? as usize;
        let info = bytes
            .get(at..at.saturating_add(size))
            .ok_or_else(|| truncated(bytes, at.saturating_add(size)))?;
        link_info(info, &mut out);
        at += size;
    }
    // StringData, in the order the format fixes. Each is a character count, then the characters.
    let unicode = flags & IS_UNICODE != 0;
    for (flag, slot) in [
        (HAS_NAME, 0),
        (HAS_RELATIVE_PATH, 1),
        (HAS_WORKING_DIR, 2),
        (HAS_ARGUMENTS, 3),
        (HAS_ICON, 4),
    ] {
        if flags & flag == 0 {
            continue;
        }
        let Some(count) = u16_at(bytes, at) else {
            break;
        };
        let count = usize::from(count);
        let len = if unicode { count * 2 } else { count };
        let Some(raw) = bytes.get(at + 2..at + 2 + len) else {
            break;
        };
        at += 2 + len;
        let text = if unicode {
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            crate::cp1252::decode(raw)
        };
        match slot {
            1 => out.relative_path = Some(text).filter(|t| !t.is_empty()),
            2 => out.working_dir = Some(text).filter(|t| !t.is_empty()),
            // The name (description), the arguments and the icon location are read past, not kept.
            _ => {}
        }
    }
    Ok(out)
}

fn truncated(bytes: &[u8], expected: usize) -> ParseError {
    ParseError::Truncated {
        expected,
        found: bytes.len(),
    }
}

fn link_info(info: &[u8], out: &mut Shortcut) {
    let (Some(header_size), Some(flags)) = (u32_at(info, 4), u32_at(info, 8)) else {
        return;
    };
    let offset = |at: usize| u32_at(info, at).map(|v| v as usize).filter(|v| *v != 0);
    let unicode = header_size >= 0x24;
    let suffix = if unicode {
        offset(0x20).and_then(|o| utf16_z(info, o))
    } else {
        None
    }
    .or_else(|| offset(0x18).and_then(|o| ansi_z(info, o)));
    if flags & 0x1 != 0 {
        let base = if unicode {
            offset(0x1C).and_then(|o| utf16_z(info, o))
        } else {
            None
        }
        .or_else(|| offset(0x10).and_then(|o| ansi_z(info, o)));
        if let Some(base) = base {
            out.target_path = Some(join(&base, suffix.as_deref()));
            return;
        }
    }
    if flags & 0x2 != 0
        && let Some(net) = offset(0x14)
    {
        // CommonNetworkRelativeLink: NetNameOffset at +8 from its start.
        let name = u32_at(info, net + 8)
            .map(|o| o as usize)
            .and_then(|o| ansi_z(info, net + o));
        if let Some(name) = name {
            out.network = true;
            out.target_path = Some(join(&name, suffix.as_deref()));
        }
    }
}

fn join(base: &str, suffix: Option<&str>) -> String {
    match suffix {
        Some(s) if !s.is_empty() => {
            if base.ends_with('\\') {
                format!("{base}{s}")
            } else {
                format!(r"{base}\{s}")
            }
        }
        _ => base.to_owned(),
    }
}

/// Builds a minimal shortcut with a local `LinkInfo` path, for tests in this workspace.
pub fn build_local(path: &str, target_write: u64, with_arguments: bool) -> Vec<u8> {
    let mut b = vec![0_u8; HEADER_SIZE];
    b[0] = 0x4C;
    b[4..20].copy_from_slice(&CLSID);
    let mut flags = HAS_LINK_INFO | IS_UNICODE;
    if with_arguments {
        flags |= HAS_ARGUMENTS;
    }
    b[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
    b[0x2C..0x34].copy_from_slice(&target_write.to_le_bytes());
    // LinkInfo with a 0x1C header (ANSI only), VolumeID of 0x10 bytes, then the path.
    let mut info = vec![0_u8; 0x1C];
    let volume = [0x10_u8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0];
    let volume_at = info.len();
    info.extend_from_slice(&volume);
    let base_at = info.len();
    info.extend_from_slice(path.as_bytes());
    info.push(0);
    let suffix_at = info.len();
    info.push(0);
    let size = u32::try_from(info.len()).unwrap_or(0);
    info[0..4].copy_from_slice(&size.to_le_bytes());
    info[4..8].copy_from_slice(&0x1C_u32.to_le_bytes());
    info[8..12].copy_from_slice(&1_u32.to_le_bytes());
    info[12..16].copy_from_slice(&u32::try_from(volume_at).unwrap_or(0).to_le_bytes());
    info[16..20].copy_from_slice(&u32::try_from(base_at).unwrap_or(0).to_le_bytes());
    info[24..28].copy_from_slice(&u32::try_from(suffix_at).unwrap_or(0).to_le_bytes());
    b.extend_from_slice(&info);
    if with_arguments {
        let args: Vec<u8> = "--secret"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b.extend_from_slice(&8_u16.to_le_bytes());
        b.extend_from_slice(&args);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_shortcut_gives_its_path_and_times_but_never_its_arguments() {
        let bytes = build_local(
            r"C:\Users\a\Downloads\Bloxstrap.exe",
            134_353_296_000_000_000,
            true,
        );
        let s = parse(&bytes).unwrap();
        assert_eq!(
            s.target_path.as_deref(),
            Some(r"C:\Users\a\Downloads\Bloxstrap.exe")
        );
        assert!(s.has_arguments);
        assert_eq!(
            s.target_modified.map(|t| t.to_string()).as_deref(),
            Some("2026-10-01T12:00:00Z")
        );
        assert!(!format!("{s:?}").contains("secret"));
    }

    #[test]
    fn anything_else_is_an_error_never_a_panic() {
        assert!(matches!(parse(b"short"), Err(ParseError::Truncated { .. })));
        assert!(matches!(
            parse(&[0_u8; 0x60]),
            Err(ParseError::Malformed { .. })
        ));
        let mut bytes = build_local(r"C:\x.exe", 0, false);
        bytes.truncate(0x50);
        assert!(parse(&bytes).is_err());
        // Every prefix of a valid file either parses or errors.
        let full = build_local(r"C:\Program Files\x\y.exe", 1, true);
        for n in 0..full.len() {
            let _ = parse(&full[..n]);
        }
    }
}
