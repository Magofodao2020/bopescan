// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Prints what `bope_parsers::pe` reads from each file named on the command line, for checking the
//! parser against real images: `cargo run -p bope-parsers --example pe_dump -- a.dll b.exe`.

use bope_parsers::pe;

fn main() {
    for path in std::env::args().skip(1) {
        println!("== {path}");
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                println!("  unreadable: {error}");
                continue;
            }
        };
        match pe::parse(&bytes) {
            Err(error) => println!("  not parsed: {error}"),
            Ok(image) => {
                println!(
                    "  {} pe32+={} dll={} subsystem={} entry={:#x} base={:#x} size={:#x}",
                    image.machine.as_str(),
                    image.pe32_plus,
                    image.is_dll,
                    image.subsystem,
                    image.entry_point_rva,
                    image.image_base,
                    image.size_of_image
                );
                println!(
                    "  checksum stored={:#x} computed={:#x} certificate={:?} overlay={} clr={}",
                    image.header_checksum,
                    image.computed_checksum,
                    image.certificate_table,
                    image.overlay_bytes,
                    image.clr
                );
                for section in &image.sections {
                    println!(
                        "  section {:<8} {} va={:#x} vsize={:#x} raw={:#x} entropy={:.2}",
                        section.name,
                        section.permissions(),
                        section.virtual_address,
                        section.virtual_size,
                        section.raw_size,
                        section.entropy.unwrap_or(0.0)
                    );
                }
                for dll in &image.imports {
                    println!(
                        "  import {} ({} functions{})",
                        dll.name,
                        dll.functions.len(),
                        if dll.delay_loaded { ", delay" } else { "" }
                    );
                }
                if let Some(exports) = &image.exports {
                    println!(
                        "  exports {:?}: {} of {}",
                        exports.dll_name,
                        exports.functions.len(),
                        exports.declared_functions
                    );
                }
                println!(
                    "  tls={} callbacks={} relocations={} other={}",
                    image.tls_present,
                    image.tls_callbacks.len(),
                    image.relocations.len(),
                    image.other_relocations
                );
                println!("  version {:?}", image.version);
                println!(
                    "  anomalies {:?}",
                    image
                        .anomalies
                        .iter()
                        .map(|a| a.as_str())
                        .collect::<Vec<_>>()
                );
                for problem in &image.problems {
                    println!("  problem: {problem}");
                }
            }
        }
    }
}
