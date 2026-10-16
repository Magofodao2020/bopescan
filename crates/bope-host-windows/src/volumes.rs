// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Which drive letters are in use, of what kind, with what file system (B.O.P.E, ADR 0133).
//! `GetLogicalDrives`, `GetDriveTypeW` and `GetVolumeInformationW` only read; no volume is opened.

/// The kind `GetDriveTypeW` reports, from its documented values.
pub fn drive_kind(value: u32) -> bope_host::DriveKind {
    match value {
        2 => bope_host::DriveKind::Removable,
        3 => bope_host::DriveKind::Fixed,
        4 => bope_host::DriveKind::Network,
        5 => bope_host::DriveKind::CdRom,
        6 => bope_host::DriveKind::RamDisk,
        _ => bope_host::DriveKind::Unknown,
    }
}

#[cfg(windows)]
impl bope_host::VolumeSource for crate::LiveHost {
    #[allow(unsafe_code)]
    fn volumes(&self) -> Result<Vec<bope_host::Volume>, bope_host::SourceError> {
        use windows::Win32::Storage::FileSystem::{
            GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
        };
        use windows::core::PCWSTR;

        // SAFETY: takes nothing and returns a bit mask.
        let mask = unsafe { GetLogicalDrives() };
        if mask == 0 {
            return Err(bope_host::SourceError::Failed(
                "GetLogicalDrives returned no drive".to_owned(),
            ));
        }
        let mut volumes = Vec::new();
        for (bit, letter) in (b'A'..=b'Z').enumerate() {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let root = format!("{}:\\", char::from(letter));
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `wide` is a NUL-terminated root path that outlives the call.
            let kind = drive_kind(unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) });
            let mut name = vec![0_u16; 64];
            // A removable drive with no medium answers with an error; the drive is still listed.
            // SAFETY: as above, with a writable buffer for the file system name only.
            let filesystem = unsafe {
                GetVolumeInformationW(
                    PCWSTR(wide.as_ptr()),
                    None,
                    None,
                    None,
                    None,
                    Some(&mut name),
                )
            }
            .ok()
            .map(|()| crate::process::wide_to_string(&name))
            .filter(|text| !text.is_empty());
            volumes.push(bope_host::Volume {
                root,
                kind,
                filesystem,
            });
        }
        Ok(volumes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_drive_types_have_their_kinds() {
        assert_eq!(drive_kind(3), bope_host::DriveKind::Fixed);
        assert_eq!(drive_kind(2), bope_host::DriveKind::Removable);
        assert_eq!(drive_kind(4), bope_host::DriveKind::Network);
        assert_eq!(drive_kind(1), bope_host::DriveKind::Unknown);
    }
}
