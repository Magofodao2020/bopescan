// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Where on the machine a path is, in words a rule can match (B.O.P.E, ADR 0101).
//!
//! The classification is by path **segments**, compared without ASCII case, so `C:\Users\a\Downloads`
//! and `D:\Users\a\Downloads` are both `user_downloads`. It never reads the machine. Several new
//! collectors emit it as `location_kind`, so a rule can ask "an executable that ran from a folder
//! every program may write to" without spelling out every profile layout.

/// Field name the collectors use.
pub const FIELD: &str = "location_kind";

/// The kinds, from most to least specific. A path matches the first that applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationKind {
    /// Under a `Temp` folder of a profile, or `C:\Windows\Temp`.
    Temp,
    /// Under a profile's `Downloads`.
    Downloads,
    /// Under a profile's `Desktop`.
    Desktop,
    /// Under a profile's `Documents`.
    Documents,
    /// Under `AppData\Local` (outside `Temp`).
    AppDataLocal,
    /// Under `AppData\Roaming`.
    AppDataRoaming,
    /// Elsewhere under a profile (`C:\Users\<name>\...`).
    ProfileOther,
    /// `C:\Users\Public` and its subfolders.
    Public,
    /// `C:\ProgramData`.
    ProgramData,
    /// Under `Program Files` or `Program Files (x86)`.
    ProgramFiles,
    /// Under `Windows` (outside `Temp`).
    Windows,
    /// The `$Recycle.Bin`.
    RecycleBin,
    /// A UNC path (`\\server\share`).
    Network,
    /// A drive-letter path that is none of the above.
    OtherDrivePath,
    /// Anything else: a device path, a bare name, an AUMID.
    Unknown,
}

impl LocationKind {
    /// Stable identifier used in observations and rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Temp => "temp",
            Self::Downloads => "user_downloads",
            Self::Desktop => "user_desktop",
            Self::Documents => "user_documents",
            Self::AppDataLocal => "appdata_local",
            Self::AppDataRoaming => "appdata_roaming",
            Self::ProfileOther => "user_profile",
            Self::Public => "users_public",
            Self::ProgramData => "programdata",
            Self::ProgramFiles => "program_files",
            Self::Windows => "windows",
            Self::RecycleBin => "recycle_bin",
            Self::Network => "network",
            Self::OtherDrivePath => "other",
            Self::Unknown => "unknown",
        }
    }

    /// Whether any program running as the user may write there without administrator rights.
    pub fn is_user_writable(self) -> bool {
        matches!(
            self,
            Self::Temp
                | Self::Downloads
                | Self::Desktop
                | Self::Documents
                | Self::AppDataLocal
                | Self::AppDataRoaming
                | Self::ProfileOther
                | Self::Public
                | Self::RecycleBin
        )
    }
}

/// Classifies a path that may be written as a volume device path (`\Device\HarddiskVolume3\Users\...`),
/// as SRUM and the change journal's readers write it (B.O.P.E, ADR 0124). The volume is read as a drive
/// only to find the folder kind; which drive it is stays unknown.
pub fn classify_any(path: &str) -> LocationKind {
    let lower = path.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\device\harddiskvolume") {
        let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
        if rest.starts_with('\\') {
            return classify(&format!("C:{rest}"));
        }
    }
    classify(path)
}

/// Strips the NT prefixes Windows artifacts write before a drive path: `\??\`, `\\?\`, `\\.\`.
pub fn strip_nt_prefix(path: &str) -> &str {
    for prefix in [r"\??\", r"\\?\", r"\\.\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
                return rest;
            }
            if let Some(unc) = rest.strip_prefix("UNC\\") {
                // `\\?\UNC\server\share` is `\\server\share`; returned without the leading `\\`,
                // which `classify` treats as network anyway through the `UNC\` form.
                return unc;
            }
        }
    }
    path
}

/// Classifies one path.
pub fn classify(path: &str) -> LocationKind {
    let raw = path.trim();
    if raw.starts_with(r"\\") && !raw.starts_with(r"\\?\") && !raw.starts_with(r"\\.\") {
        return LocationKind::Network;
    }
    if raw.to_ascii_uppercase().starts_with(r"\\?\UNC\") {
        return LocationKind::Network;
    }
    let path = strip_nt_prefix(raw);
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return LocationKind::Unknown;
    }
    let segments: Vec<String> = path[2..]
        .split(['\\', '/'])
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let first = segments.first().map(String::as_str);
    match first {
        Some("$recycle.bin") => return LocationKind::RecycleBin,
        Some("windows") => {
            return if segments.get(1).map(String::as_str) == Some("temp") {
                LocationKind::Temp
            } else {
                LocationKind::Windows
            };
        }
        Some("program files" | "program files (x86)") => return LocationKind::ProgramFiles,
        Some("programdata") => return LocationKind::ProgramData,
        Some("users" | "documents and settings") => {}
        _ => return LocationKind::OtherDrivePath,
    }
    let Some(profile) = segments.get(1) else {
        return LocationKind::OtherDrivePath;
    };
    if profile == "public" {
        return LocationKind::Public;
    }
    let rest: Vec<&str> = segments.iter().skip(2).map(String::as_str).collect();
    if rest.contains(&"temp") && rest.first() == Some(&"appdata") {
        return LocationKind::Temp;
    }
    match rest.as_slice() {
        ["downloads", ..] => LocationKind::Downloads,
        ["desktop", ..] | ["onedrive", "desktop", ..] => LocationKind::Desktop,
        ["documents", ..] | ["onedrive", "documents", ..] => LocationKind::Documents,
        ["appdata", "local", ..] => LocationKind::AppDataLocal,
        ["appdata", "roaming", ..] => LocationKind::AppDataRoaming,
        _ => LocationKind::ProfileOther,
    }
}

/// The last segment of a Windows path, or the whole text when it has no separator.
pub fn last_segment(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The extension of a file name, lower case, without the dot.
pub fn extension(name: &str) -> Option<String> {
    let name = last_segment(name);
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty() && ext.len() <= 8).then(|| ext.to_ascii_lowercase())
}

/// The program a command line starts: the quoted first token, or the text up to the first `.exe`
/// (or other executable extension) followed by a space or the end, or else the first token. Never
/// any argument (ADR 0060 section 4's rule, applied to the new collectors).
pub fn program_of_command(command: &str) -> String {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        return rest.split('"').next().unwrap_or_default().to_owned();
    }
    let lower = command.to_ascii_lowercase();
    for ext in [
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk", ".msc", ".cpl",
    ] {
        let mut from = 0;
        while let Some(found) = lower[from..].find(ext) {
            let end = from + found + ext.len();
            if end == command.len() || command.as_bytes()[end] == b' ' {
                return command[..end].to_owned();
            }
            from = end;
        }
    }
    command.split(' ').next().unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_folders_are_named_on_any_drive_and_in_any_case() {
        for (path, kind) in [
            (r"C:\Users\a\Downloads\x.exe", LocationKind::Downloads),
            (r"d:\USERS\a\downloads\sub\x.exe", LocationKind::Downloads),
            (
                r"\??\C:\Users\a\AppData\Local\Temp\x.exe",
                LocationKind::Temp,
            ),
            (
                r"C:\Users\a\AppData\Local\Roblox\Versions\v\RobloxPlayerBeta.exe",
                LocationKind::AppDataLocal,
            ),
            (
                r"C:\Users\a\AppData\Roaming\x\y.dll",
                LocationKind::AppDataRoaming,
            ),
            (r"C:\Users\a\OneDrive\Desktop\x.exe", LocationKind::Desktop),
            (r"C:\Users\a\Documents\x.ahk", LocationKind::Documents),
            (r"C:\Users\a\Games\x.exe", LocationKind::ProfileOther),
            (r"C:\Users\Public\x.exe", LocationKind::Public),
            (r"C:\Windows\System32\cmd.exe", LocationKind::Windows),
            (r"C:\Windows\Temp\x.exe", LocationKind::Temp),
            (
                r"C:\Program Files (x86)\Roblox\x.exe",
                LocationKind::ProgramFiles,
            ),
            (r"C:\ProgramData\x.exe", LocationKind::ProgramData),
            (r"C:\$Recycle.Bin\S-1\x.exe", LocationKind::RecycleBin),
            (r"\\server\share\x.exe", LocationKind::Network),
            (r"E:\Tools\x.exe", LocationKind::OtherDrivePath),
            (r"\Device\HarddiskVolume3\x.exe", LocationKind::Unknown),
            ("Microsoft.Windows.Explorer", LocationKind::Unknown),
        ] {
            assert_eq!(classify(path), kind, "{path}");
        }
        assert!(LocationKind::Downloads.is_user_writable());
        assert!(!LocationKind::ProgramFiles.is_user_writable());
    }

    #[test]
    fn a_folder_called_temp_outside_appdata_is_not_temp() {
        assert_eq!(
            classify(r"C:\Users\a\Documents\temp\x.exe"),
            LocationKind::Documents
        );
        assert_eq!(
            classify(r"C:\Users\a\temp\x.exe"),
            LocationKind::ProfileOther
        );
    }

    #[test]
    fn the_program_of_a_command_never_carries_an_argument() {
        assert_eq!(
            program_of_command(r#""C:\a b\x.exe" --secret 1"#),
            r"C:\a b\x.exe"
        );
        assert_eq!(
            program_of_command(r"C:\a b\x.exe --secret"),
            r"C:\a b\x.exe"
        );
        assert_eq!(program_of_command("notepad secret.txt"), "notepad");
        assert_eq!(
            program_of_command(r"C:\x.exe.bak\y.exe"),
            r"C:\x.exe.bak\y.exe"
        );
        assert_eq!(extension(r"C:\a\Script.LUA").as_deref(), Some("lua"));
        assert_eq!(extension(".gitignore"), None);
    }
}
