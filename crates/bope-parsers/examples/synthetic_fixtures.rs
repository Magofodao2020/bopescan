// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Writes the synthetic binary fixtures the B.O.P.E fixture hosts read: an `SRUDB.dat` and a small NTFS
//! volume image for `roblox-tool-history` and `baseline-roblox-win11` (ADR 0124, ADR 0125); and, since
//! 0.11, one synthetic PE image (`bope_parsers::pe::synthetic_dll`) for `file-inventory` and
//! `roblox-memory`, its copy as the loader maps it at [`MODULE_BASE`] with a jump written over its
//! exported function, and its copy mapped by hand at [`INJECTED_BASE`] (ADR 0133, ADR 0134). Every
//! name, number and time is invented, and no instruction in the image does anything. Run from the repository root:
//!
//! ```text
//! cargo run -p bope-parsers --example synthetic_fixtures
//! ```

use std::path::Path;

use bope_parsers::ntfs::{self, BuildRecord};
use bope_parsers::{shell_items, srum};

/// 2026-10-14T20:00:00Z as an OLE automation date.
const OLE_2026_10_14_20H: f64 = 46_309.833_333_333_33;
/// 2026-10-09T17:00:00Z.
const OLE_2026_10_09_17H: f64 = 46_304.708_333_333_33;
/// 2026-10-14T19:58:00Z and 2026-10-01T10:00:00Z as FILETIMEs.
const FT_2026_10_14: u64 = 134_364_814_800_000_000;
const FT_2026_10_01: u64 = 134_353_224_000_000_000;

fn record(
    number: u64,
    name: &str,
    parent: u64,
    in_use: bool,
    directory: bool,
    si: u64,
    fname: u64,
) -> BuildRecord {
    BuildRecord {
        number,
        name: name.to_owned(),
        parent,
        in_use,
        directory,
        si_created: si,
        fn_created: fname,
    }
}

#[allow(clippy::too_many_lines, clippy::decimal_bitwise_operands)]
/// Where `roblox-memory`'s module is loaded.
const MODULE_BASE: u64 = 0x7ff6_1000_0000;
/// Where its private executable allocation is.
const INJECTED_BASE: u64 = 0x7ff6_0000_0000;

/// The synthetic image, its loaded and hooked copy, and a hand-mapped copy.
fn images(root: &Path) -> std::io::Result<()> {
    use bope_parsers::pe;
    let image = pe::synthetic_dll();
    std::fs::write(root.join("file-inventory").join("sample.dll"), &image)?;
    let host = root.join("roblox-memory");
    std::fs::create_dir_all(&host)?;
    std::fs::write(host.join("module.dll"), &image)?;
    let parsed = pe::parse(&image).map_err(std::io::Error::other)?;
    let mapped = pe::mapped_image(&parsed, &image, 1 << 20)
        .ok_or_else(|| std::io::Error::other("the synthetic image does not map"))?;
    let mut loaded = mapped.clone();
    pe::relocate(&parsed, &mut loaded, MODULE_BASE);
    // `Run`, at RVA 0x1000, now starts with a jump into the private allocation.
    let from = MODULE_BASE + 0x1000 + 5;
    let to = INJECTED_BASE + 0x1000;
    let relative =
        i32::try_from(to.cast_signed() - from.cast_signed()).map_err(std::io::Error::other)?;
    loaded[0x1000] = 0xe9;
    loaded[0x1001..0x1005].copy_from_slice(&relative.to_le_bytes());
    std::fs::write(host.join("module-memory.bin"), &loaded)?;
    std::fs::write(host.join("injected.bin"), &mapped)?;
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::decimal_bitwise_operands)]
fn main() -> std::io::Result<()> {
    let root = Path::new("fixtures/hosts");
    let history = root.join("roblox-tool-history");
    let baseline = root.join("baseline-roblox-win11");

    std::fs::write(
        history.join("SRUDB.dat"),
        srum::build(
            4096,
            &[
                (
                    10,
                    0,
                    r"\Device\HarddiskVolume3\Users\fixtureuser\Downloads\Fluxus\Fluxus.exe",
                ),
                (
                    11,
                    0,
                    r"\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\chrome.exe",
                ),
                (12, 3, "S-1-5-21-1000-2000-3000-1001"),
            ],
            &[
                (10, OLE_2026_10_14_20H, 5_000_000_000),
                (11, OLE_2026_10_14_20H, 9_000_000_000),
            ],
        ),
    )?;
    std::fs::write(
        baseline.join("SRUDB.dat"),
        srum::build(
            4096,
            &[
                (
                    20,
                    0,
                    r"\Device\HarddiskVolume3\Users\fixtureuser\AppData\Local\Roblox\Versions\version-0123456789abcdef\RobloxPlayerBeta.exe",
                ),
                (21, 0, r"\Device\HarddiskVolume3\Windows\explorer.exe"),
                (
                    22,
                    0,
                    r"\Device\HarddiskVolume3\Users\fixtureuser\AppData\Local\Bloxstrap\Bloxstrap.exe",
                ),
            ],
            &[
                (20, OLE_2026_10_09_17H, 7_000_000_000),
                (21, OLE_2026_10_09_17H, 1_000_000),
                (22, OLE_2026_10_09_17H, 300_000_000),
            ],
        ),
    )?;

    std::fs::write(
        history.join("volume-c.img"),
        ntfs::build_volume(&[
            record(
                16,
                "Users",
                ntfs::ROOT_RECORD,
                true,
                true,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            record(
                17,
                "fixtureuser",
                16,
                true,
                true,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            record(
                18,
                "Downloads",
                17,
                true,
                true,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            record(19, "Fluxus", 18, false, true, FT_2026_10_14, FT_2026_10_14),
            record(
                20,
                "Fluxus.exe",
                19,
                false,
                false,
                FT_2026_10_14,
                FT_2026_10_14,
            ),
            record(
                21,
                "ChromeSetup.exe",
                18,
                true,
                false,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
        ]),
    )?;
    std::fs::write(
        baseline.join("volume-c.img"),
        ntfs::build_volume(&[
            record(
                16,
                "Users",
                ntfs::ROOT_RECORD,
                true,
                true,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            record(
                17,
                "fixtureuser",
                16,
                true,
                true,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            record(18, "AppData", 17, true, true, FT_2026_10_01, FT_2026_10_01),
            record(19, "Local", 18, true, true, FT_2026_10_01, FT_2026_10_01),
            record(20, "Roblox", 19, true, true, FT_2026_10_01, FT_2026_10_01),
            record(
                21,
                "Bloxstrap",
                19,
                true,
                true,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            record(
                22,
                "Bloxstrap.exe",
                21,
                true,
                false,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            record(
                23,
                "Downloads",
                17,
                true,
                true,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
            // The installer, deleted after it ran: a freed record (ADR 0125).
            record(
                24,
                "BloxstrapInstaller.exe",
                23,
                false,
                false,
                FT_2026_10_01,
                FT_2026_10_01,
            ),
        ]),
    )?;
    // Shell items for the hosts' ShellBags and Open/Save lists, printed as the hex the YAML holds.
    let fat = ((46 << 9) | (10 << 5) | 14) | (((19 << 11) | (59 << 5)) << 16); // 2026-10-14 19:59:00
    let hex = |parts: &[Vec<u8>]| -> String {
        let mut bytes: Vec<u8> = parts.concat();
        bytes.extend([0, 0]);
        bytes.iter().fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
    };
    println!("my_computer: {}", hex(&[shell_items::build_my_computer()]));
    println!("volume_c: {}", hex(&[shell_items::build_volume('C')]));
    for name in [
        "Users",
        "fixtureuser",
        "Downloads",
        "Fluxus",
        "Roblox",
        "Documents",
        "AppData",
        "Local",
        "Bloxstrap",
    ] {
        println!(
            "{name}: {}",
            hex(&[shell_items::build_folder(name, fat, 0)])
        );
    }
    println!(
        "pidl_fluxus_exe: {}",
        hex(&[
            shell_items::build_my_computer(),
            shell_items::build_volume('C'),
            shell_items::build_folder("Users", fat, 0),
            shell_items::build_folder("fixtureuser", fat, 0),
            shell_items::build_folder("Downloads", fat, 0),
            shell_items::build_folder("Fluxus", fat, 0),
            shell_items::build_folder("Fluxus.exe", fat, 0),
        ])
    );
    println!(
        "pidl_bloxstrap_installer: {}",
        hex(&[
            shell_items::build_my_computer(),
            shell_items::build_volume('C'),
            shell_items::build_folder("Users", fat, 0),
            shell_items::build_folder("fixtureuser", fat, 0),
            shell_items::build_folder("Downloads", fat, 0),
            shell_items::build_folder("BloxstrapInstaller.exe", fat, 0),
        ])
    );
    images(root)
}
