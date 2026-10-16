// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a collector may say about a path an artifact spelled.
//!
//! Two artifacts record the full path of a program that ran — PCA in a text line, BAM in the name of
//! a registry value — and both have to answer the same questions: which single field a rule can match
//! on, and what form the path is written in. They live here rather than in one collector because two
//! collectors answering the same question in two wordings is two things a rule author has to learn.
//! `pca` wrote them first (ADR 0020) and `bam` uses them unchanged (ADR 0023).

/// The form a recorded path is written in, reported beside it as `path_form` so a reader knows how
/// to read it: `drive` (`C:\…`), `device` (`\Device\HarddiskVolume3\…`, which names a volume and not
/// a drive letter) or `other` (a UNC path, an `\??\` path, or anything else).
pub fn path_form(path: &str) -> &'static str {
    if is_drive_rooted(path) {
        "drive"
    } else if path
        .get(..8)
        .is_some_and(|start| start.eq_ignore_ascii_case(r"\Device\"))
    {
        "device"
    } else {
        "other"
    }
}

/// Whether `path` is inside a user profile: below `Users`, `Documents and Settings` or its 8.3 short
/// name `DOCUME~<n>` on any drive, or below the machine's `ProfilesDirectory`, with at least one
/// folder (the profile's own) after the root (ADR 0049).
pub fn is_under_profile_root(path: &str, profiles_directory: Option<&str>) -> bool {
    if !is_drive_rooted(path) {
        return false;
    }
    let segments: Vec<&str> = path[3..]
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let fixed = segments.len() >= 2 && {
        let root = segments[0]
            .trim_end_matches(['.', ' '])
            .to_ascii_lowercase();
        root == "users"
            || root == "documents and settings"
            || root
                .strip_prefix("docume~")
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    };
    let machine = profiles_directory
        .filter(|dir| is_drive_rooted(dir) && !dir.contains('%'))
        .is_some_and(|dir| {
            let dir = dir.trim_end_matches(['\\', '/']);
            path.len() > dir.len() + 1
                && path.is_char_boundary(dir.len())
                && path[..dir.len()].eq_ignore_ascii_case(dir)
                && matches!(path.as_bytes()[dir.len()], b'\\' | b'/')
                && path
                    .as_bytes()
                    .get(dir.len() + 1)
                    .is_some_and(|b| !matches!(b, b'\\' | b'/'))
        });
    fixed || machine
}

/// The last segment of a Windows path, lower-cased.
///
/// Lower-cased so that `Cheat.exe` and `cheat.exe` reach a report, and a rule author, as one string.
/// It is no longer what makes a rule match: ADR 0025 made `match` fold ASCII case, so a rule naming
/// either spelling matches either. `path` is left exactly as the artifact spelled it, which is what
/// CONVENTIONS.md defines it as.
pub fn file_name(path: &str) -> Option<String> {
    let name = path.rsplit(['\\', '/']).next()?;
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// Whether a path starts `X:\` or `X:/`.
pub fn is_drive_rooted(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

/// Whether a drive-letter path, its separators already read as `\`, is a form this program refuses to
/// read as the file it appears to name (ADR 0048, R1; shared with `autostart` by ADR 0060): a `.` or
/// `..` segment, a repeated or trailing separator (an empty segment), a segment ending in `.` or a
/// space, a `:` past the drive (an alternate data stream), or `Documents and Settings` right after the
/// drive — a junction to `Users` on current Windows. The refusal stays because no such form was
/// measured, and this program does not read the file a spelling only appears to name.
pub fn is_refused_form(path: &str) -> bool {
    let mut segments = path.split('\\');
    segments.next(); // the drive segment, e.g. `C:` — not checked here
    for (index, segment) in segments.enumerate() {
        if is_unusable_segment(segment)
            || segment.is_empty()
            || segment.ends_with(['.', ' '])
            || segment.contains(':')
        {
            return true;
        }
        if index == 0 && segment.eq_ignore_ascii_case("Documents and Settings") {
            return true;
        }
    }
    false
}

/// Whether a path segment is `.` or `..` — never a real file or folder name, only a way to walk out
/// of the folder the rest of the path names.
pub fn is_unusable_segment(segment: &str) -> bool {
    segment == "." || segment == ".."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refused_forms_are_refused_and_an_ordinary_path_is_not() {
        for refused in [
            r"C:\Users\..\x.exe",
            r"C:\.\x.exe",
            r"C:\\x.exe",
            r"C:\x\",
            r"C:\Users.\x.exe",
            r"C:\Users \x.exe",
            r"C:\x.exe:stream",
            r"C:\Documents and Settings\bob\x.exe",
        ] {
            assert!(is_refused_form(refused), "{refused}");
        }
        assert!(!is_refused_form(r"C:\Program Files\Vendor\app.exe"));
        assert!(!is_refused_form(r"D:\Games\Documents and Settings\x.exe"));
    }

    #[test]
    fn a_path_form_says_how_the_path_is_written() {
        assert_eq!(path_form(r"C:\Users\a\x.exe"), "drive");
        assert_eq!(
            path_form(r"\Device\HarddiskVolume3\Users\a\x.exe"),
            "device"
        );
        assert_eq!(path_form(r"\\nas\share\x.exe"), "other");
        assert_eq!(path_form(""), "other");
    }

    #[test]
    fn a_profile_root_needs_a_profile_folder_after_it() {
        assert!(is_under_profile_root(r"C:\Users\a\x.exe", None));
        assert!(is_under_profile_root(r"d:/users/a", None));
        assert!(is_under_profile_root(r"C:\DOCUME~1\a\x.exe", None));
        assert!(is_under_profile_root(
            r"C:\Documents and Settings\a\x",
            None
        ));
        assert!(!is_under_profile_root(r"C:\Users", None));
        assert!(!is_under_profile_root(r"C:\Users\", None));
        assert!(!is_under_profile_root(r"C:\Program Files\x.exe", None));
        assert!(!is_under_profile_root(r"\\nas\Users\a", None));
        assert!(is_under_profile_root(
            r"E:\Profiles\a\x.exe",
            Some(r"E:\Profiles")
        ));
        assert!(!is_under_profile_root(
            r"E:\ProfilesX\a",
            Some(r"E:\Profiles")
        ));
        assert!(!is_under_profile_root(
            r"E:\Profiles\a",
            Some(r"%SystemDrive%\Profiles")
        ));
    }

    #[test]
    fn a_name_is_the_last_segment_lower_cased() {
        assert_eq!(
            file_name(r"C:\Users\alex\Game.EXE").as_deref(),
            Some("game.exe")
        );
        assert_eq!(
            file_name(r"\\nas\share\Tool.exe").as_deref(),
            Some("tool.exe")
        );
        assert_eq!(file_name("bare.exe").as_deref(), Some("bare.exe"));
        assert_eq!(file_name(r"C:\Users\alex\"), None);
    }

    /// The device path is the shape BAM is expected to write and the shape that walks straight past
    /// `redact_profile_paths`, so it is named here rather than left to a collector's own test.
    #[test]
    fn only_a_drive_rooted_path_is_emitted() {
        assert!(is_drive_rooted(r"C:\Users\alex\x.exe"));
        assert!(is_drive_rooted("d:/users/alex/x.exe"));
        assert!(!is_drive_rooted(r"\\nas\share\x.exe"));
        assert!(!is_drive_rooted(
            r"\Device\HarddiskVolume3\Users\alex\x.exe"
        ));
        assert!(!is_drive_rooted(r"\??\C:\Users\alex\x.exe"));
        assert!(!is_drive_rooted("C:"));
        assert!(!is_drive_rooted(""));
    }
}
