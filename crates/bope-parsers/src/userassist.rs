// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `UserAssist`: what Explorer counts about programs and shortcuts a user started from the shell
//! (B.O.P.E, ADR 0104).
//!
//! Each value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
//! has a ROT13-encoded name — a path, or a known-folder GUID followed by the rest of a path — and binary
//! data. Two layouts are decoded:
//!
//! - **Windows 7 and later**, 72 bytes: a run count at offset 4, a focus count at 8, the focus time in
//!   milliseconds at 12, and the last time the entry was started as a `FILETIME` at 60.
//! - **Windows XP and Vista**, 16 bytes: a run count at offset 4 (which Windows started at 5) and the
//!   last start as a `FILETIME` at 8.
//!
//! What it shows is that Explorer launched or counted the entry for this account — a double-click, the
//! Start menu, a shortcut, the Run box. A program started from a console or by another program is
//! normally not counted, and Windows writes nothing at all here when "Track app launches" is turned
//! off. None of the bytes in the 72-byte layout between offset 16 and 60 have a documented meaning;
//! they are handed back unnamed.

use jiff::Timestamp;

use crate::error::ParseError;
use crate::filetime;

/// Subkey GUID whose entries are executable files.
pub const EXECUTABLES_GUID: &str = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
/// Subkey GUID whose entries are shortcut (`.lnk`) files.
pub const SHORTCUTS_GUID: &str = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

/// Known-folder GUIDs Windows writes at the start of a `UserAssist` name, with the folder's
/// `KNOWNFOLDERID` name. Only these are replaced; any other GUID is kept as written.
pub const KNOWN_FOLDERS: [(&str, &str); 15] = [
    ("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "CommonPrograms"),
    ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "System"),
    ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
    ("{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}", "RoamingAppData"),
    ("{6D809377-6AF0-444B-8957-A3773F02200E}", "ProgramFilesX64"),
    ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "ProgramFilesX86"),
    ("{905E63B6-C1BF-494E-B29C-65B732D3D21A}", "ProgramFiles"),
    ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "UserPinned"),
    ("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "Programs"),
    ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop"),
    ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "SystemX86"),
    ("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", "LocalAppData"),
    ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "Windows"),
    (
        "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}",
        "ProgramFilesCommon",
    ),
    ("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "Documents"),
];

/// Decodes ROT13, which `UserAssist` applies to ASCII letters of a value name and to nothing else.
pub fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            other => other,
        })
        .collect()
}

/// A decoded value name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAssistName {
    /// The name after ROT13, exactly as Windows wrote it.
    pub decoded: String,
    /// The `KNOWNFOLDERID` name when the decoded name starts with one of [`KNOWN_FOLDERS`].
    pub known_folder: Option<&'static str>,
    /// What follows the known folder (starting with `\`), or the whole name when there is none.
    pub rest: String,
}

/// Decodes one value name. Session bookkeeping values (`UEME_CTLSESSION`, `UEME_CTLCUACount:ctor`)
/// decode like any other; [`is_bookkeeping`] tells them apart.
pub fn decode_name(encoded: &str) -> UserAssistName {
    let decoded = rot13(encoded);
    for (guid, name) in KNOWN_FOLDERS {
        if decoded.len() >= guid.len()
            && decoded.is_char_boundary(guid.len())
            && decoded[..guid.len()].eq_ignore_ascii_case(guid)
        {
            return UserAssistName {
                rest: decoded[guid.len()..].to_owned(),
                known_folder: Some(name),
                decoded,
            };
        }
    }
    UserAssistName {
        rest: decoded.clone(),
        known_folder: None,
        decoded,
    }
}

/// Whether a decoded name is one of Explorer's own counters rather than a program.
pub fn is_bookkeeping(decoded: &str) -> bool {
    decoded.starts_with("UEME_CTL")
}

/// Which layout the data was decoded with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// 72 bytes, Windows 7 and later.
    Win7,
    /// 16 bytes, Windows XP and Vista.
    Xp,
}

/// One decoded value.
#[derive(Debug, Clone, PartialEq)]
pub struct UserAssistData {
    /// The layout recognised by length.
    pub layout: Layout,
    /// How many times Explorer counted a start. For the XP layout the stored value minus 5, as
    /// Windows started that counter at 5; never below zero.
    pub run_count: u32,
    /// How many times the program received focus (Windows 7 and later only).
    pub focus_count: Option<u32>,
    /// Milliseconds the program had focus (Windows 7 and later only).
    pub focus_ms: Option<u32>,
    /// The raw `FILETIME` of the last counted start; zero when Windows wrote none.
    pub last_run_raw: u64,
    /// That time as UTC, `None` when it is zero or out of range.
    pub last_run: Option<Timestamp>,
    /// Bytes past the documented fields, kept unnamed.
    pub unparsed: Vec<u8>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Decodes one value's data, recognising the layout by its length.
pub fn parse_data(bytes: &[u8]) -> Result<UserAssistData, ParseError> {
    let truncated = |expected| ParseError::Truncated {
        expected,
        found: bytes.len(),
    };
    match bytes.len() {
        72.. => {
            let run_count = u32_at(bytes, 4).ok_or_else(|| truncated(72))?;
            let focus_count = u32_at(bytes, 8);
            let focus_ms = u32_at(bytes, 12);
            let last_run_raw = u64_at(bytes, 60).ok_or_else(|| truncated(72))?;
            let mut unparsed = bytes.get(16..60).map(<[u8]>::to_vec).unwrap_or_default();
            unparsed.extend_from_slice(bytes.get(68..).unwrap_or_default());
            Ok(UserAssistData {
                layout: Layout::Win7,
                run_count,
                focus_count,
                focus_ms,
                last_run_raw,
                last_run: time(last_run_raw),
                unparsed,
            })
        }
        16..72 => {
            let stored = u32_at(bytes, 4).ok_or_else(|| truncated(16))?;
            let last_run_raw = u64_at(bytes, 8).ok_or_else(|| truncated(16))?;
            Ok(UserAssistData {
                layout: Layout::Xp,
                run_count: stored.saturating_sub(5),
                focus_count: None,
                focus_ms: None,
                last_run_raw,
                last_run: time(last_run_raw),
                unparsed: bytes.get(16..).map(<[u8]>::to_vec).unwrap_or_default(),
            })
        }
        _ => Err(truncated(16)),
    }
}

fn time(raw: u64) -> Option<Timestamp> {
    if raw == 0 {
        None
    } else {
        filetime::to_timestamp(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win7(run: u32, focus: u32, ms: u32, filetime: u64) -> Vec<u8> {
        let mut data = vec![0_u8; 72];
        data[4..8].copy_from_slice(&run.to_le_bytes());
        data[8..12].copy_from_slice(&focus.to_le_bytes());
        data[12..16].copy_from_slice(&ms.to_le_bytes());
        data[60..68].copy_from_slice(&filetime.to_le_bytes());
        data
    }

    #[test]
    fn rot13_round_trips_and_leaves_non_letters_alone() {
        assert_eq!(
            rot13(r"P:\Hfref\n\Qbjaybnqf\k.rkr"),
            r"C:\Users\a\Downloads\x.exe"
        );
        assert_eq!(rot13(&rot13("Ábc-123_{GUID}")), "Ábc-123_{GUID}");
    }

    #[test]
    fn a_known_folder_prefix_is_named_and_the_rest_kept() {
        let name = decode_name(&rot13(
            r"{374DE290-123F-4565-9164-39C4925E467B}\Tool\run.exe",
        ));
        assert_eq!(name.known_folder, Some("Downloads"));
        assert_eq!(name.rest, r"\Tool\run.exe");
        let plain = decode_name(&rot13(r"C:\Games\x.exe"));
        assert_eq!(plain.known_folder, None);
        assert_eq!(plain.rest, r"C:\Games\x.exe");
        assert!(is_bookkeeping(
            &decode_name(&rot13("UEME_CTLSESSION")).decoded
        ));
    }

    #[test]
    fn the_win7_layout_gives_counts_and_the_last_run() {
        // 2026-10-01T12:00:00Z
        let filetime = 134_353_296_000_000_000_u64;
        let data = parse_data(&win7(3, 7, 61_000, filetime)).unwrap();
        assert_eq!(data.layout, Layout::Win7);
        assert_eq!(data.run_count, 3);
        assert_eq!(data.focus_count, Some(7));
        assert_eq!(data.focus_ms, Some(61_000));
        assert_eq!(data.last_run.unwrap().to_string(), "2026-10-01T12:00:00Z");
        assert_eq!(data.unparsed.len(), 44 + 4);
    }

    #[test]
    fn a_zero_time_is_no_time_and_the_xp_count_starts_at_five() {
        assert_eq!(parse_data(&win7(1, 0, 0, 0)).unwrap().last_run, None);
        let mut xp = vec![0_u8; 16];
        xp[4..8].copy_from_slice(&7_u32.to_le_bytes());
        let data = parse_data(&xp).unwrap();
        assert_eq!((data.layout, data.run_count), (Layout::Xp, 2));
        let mut low = xp.clone();
        low[4..8].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(parse_data(&low).unwrap().run_count, 0);
    }

    #[test]
    fn short_or_hostile_data_is_an_error_never_a_panic() {
        assert!(matches!(
            parse_data(&[0; 15]),
            Err(ParseError::Truncated { .. })
        ));
        assert!(parse_data(&[]).is_err());
        let hostile = win7(u32::MAX, u32::MAX, u32::MAX, u64::MAX);
        let data = parse_data(&hostile).unwrap();
        assert_eq!(data.last_run, None);
        assert_eq!(data.last_run_raw, u64::MAX);
    }
}
