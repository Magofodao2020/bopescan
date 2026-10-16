// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! What `process_modules` and `roblox_memory` both do with a process opened for reading (B.O.P.E,
//! ADR 0134): which module an address belongs to, executable memory that holds an image the loader
//! did not map, image mappings the loader does not list, and a module's code in memory compared with
//! its file.
//!
//! **Read-only.** Every byte comes from [`bope_host::ProcessMemory::read`]; nothing is written,
//! suspended or injected, and no thread is created in the process.
//!
//! **What a difference is and is not.** The file is laid out as the loader lays it out and relocated
//! to where the module is loaded, and the address tables the loader fills are skipped; what still
//! differs in an executable section was changed after loading. That is what an inline hook or a code
//! patch leaves — and also what overlays (Discord, Steam, NVIDIA, MSI Afterburner), anti-cheat
//! (Roblox's Hyperion among them), security products and hot patches leave. Who wrote the change is
//! not known from the bytes; where a hook jumps to is reported so a reader can see whose code it runs.

use bope_host::{Host, LoadedModule, MemoryRegion, ProcessMemory, RegionKind};
use bope_parsers::memory::{self, HookKind};
use bope_parsers::pe;

/// The most bytes of one module's code compared.
pub const MAX_CODE_BYTES: usize = 32 * 1024 * 1024;
/// The size of one read.
pub const CHUNK: usize = 1024 * 1024;
/// The most divergent ranges kept per module.
pub const MAX_RANGES: usize = 64;
/// The most hooks kept per module.
pub const MAX_HOOKS: usize = 64;

/// The modules of one process, sorted by base, for finding which one an address is in.
#[derive(Debug, Clone, Default)]
pub struct ModuleMap {
    modules: Vec<LoadedModule>,
}

impl ModuleMap {
    /// A map of `modules`.
    pub fn new(mut modules: Vec<LoadedModule>) -> Self {
        modules.sort_by_key(|m| m.base);
        Self { modules }
    }

    /// The module whose image contains `address`.
    pub fn owner(&self, address: u64) -> Option<&LoadedModule> {
        let index = self.modules.partition_point(|m| m.base <= address);
        let candidate = self.modules.get(index.checked_sub(1)?)?;
        (address < candidate.base.saturating_add(u64::from(candidate.size))).then_some(candidate)
    }

    /// Whether a module is loaded at exactly `base`.
    pub fn has_base(&self, base: u64) -> bool {
        self.modules.binary_search_by_key(&base, |m| m.base).is_ok()
    }

    /// Every module.
    pub fn modules(&self) -> &[LoadedModule] {
        &self.modules
    }
}

/// Reads `[base, base + size)` in chunks of [`CHUNK`], calling `each` with every chunk that read.
/// Returns how many bytes read and how many could not be.
pub fn read_chunks(
    process: &dyn ProcessMemory,
    base: u64,
    size: u64,
    mut each: impl FnMut(u64, &[u8]),
) -> (u64, u64) {
    let mut read = 0_u64;
    let mut unreadable = 0_u64;
    let mut at = base;
    let end = base.saturating_add(size);
    while at < end {
        let length = usize::try_from((end - at).min(CHUNK as u64)).unwrap_or(CHUNK);
        match process.read(at, length) {
            Ok(bytes) if !bytes.is_empty() => {
                read += bytes.len() as u64;
                if (bytes.len() as u64) < length as u64 {
                    unreadable += length as u64 - bytes.len() as u64;
                }
                each(at, &bytes);
            }
            _ => unreadable += length as u64,
        }
        at = at.saturating_add(length as u64);
    }
    (read, unreadable)
}

/// A private executable region holding something a reader should look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableAllocation {
    /// The region.
    pub region: MemoryRegion,
    /// Its first bytes are a PE image header: an image the loader did not map.
    pub holds_image: bool,
}

/// The committed private regions that are executable, with whether each starts with a PE header.
/// At most `max` are read.
pub fn executable_allocations(
    process: &dyn ProcessMemory,
    regions: &[MemoryRegion],
    max: usize,
) -> Vec<ExecutableAllocation> {
    regions
        .iter()
        .filter(|r| r.kind == RegionKind::Private && r.is_executable())
        .take(max)
        .map(|region| {
            // The header of a manually mapped image is at the allocation's base, which is this
            // region's base when it is the allocation's first region.
            let holds_image = region.base == region.allocation_base
                && process
                    .read(
                        region.base,
                        4096.min(usize::try_from(region.size).unwrap_or(4096)),
                    )
                    .is_ok_and(|bytes| memory::looks_like_mapped_pe(&bytes));
            ExecutableAllocation {
                region: region.clone(),
                holds_image,
            }
        })
        .collect()
}

/// Image mappings whose allocation the loader does not list as a module: an image mapped by hand
/// (`NtMapViewOfSection`) or a module unlinked from the loader's lists. One per allocation.
pub fn unlisted_images(regions: &[MemoryRegion], modules: &ModuleMap) -> Vec<MemoryRegion> {
    let mut seen = std::collections::BTreeSet::new();
    regions
        .iter()
        .filter(|r| r.kind == RegionKind::Image)
        .filter(|r| !modules.has_base(r.allocation_base))
        .filter(|r| seen.insert(r.allocation_base))
        .cloned()
        .collect()
}

/// An inline hook found at the start of an exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    /// The exported function.
    pub function: String,
    /// Its address.
    pub address: u64,
    /// The jump's shape.
    pub kind: HookKind,
    /// Where it jumps to, when that is in the bytes.
    pub target: Option<u64>,
}

/// One module's code in memory compared with its file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodeComparison {
    /// Executable sections compared.
    pub sections: usize,
    /// Bytes compared.
    pub bytes_compared: u64,
    /// Bytes that could not be read from memory.
    pub bytes_unreadable: u64,
    /// Bytes that differ, outside what the loader writes.
    pub bytes_differing: u64,
    /// The differing ranges as `(address, length)`, at most [`MAX_RANGES`].
    pub ranges: Vec<(u64, usize)>,
    /// Inline hooks at exported functions, at most [`MAX_HOOKS`].
    pub hooks: Vec<Hook>,
}

/// Why a module could not be compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCompared {
    /// The file could not be read.
    FileUnreadable,
    /// The file is not a PE image.
    NotAnImage,
    /// The file is larger than one read, or its image larger than the limit.
    TooLarge,
    /// The file's image size differs from the module's: a different file is on disk now.
    SizeDiffers,
}

impl NotCompared {
    /// Stable identifier used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileUnreadable => "file_unreadable",
            Self::NotAnImage => "file_not_an_image",
            Self::TooLarge => "too_large",
            Self::SizeDiffers => "file_differs_from_module",
        }
    }
}

/// Compares `module`'s executable sections in `process` with its file on `host`.
#[allow(clippy::too_many_lines)]
pub fn compare_module(
    host: &dyn Host,
    process: &dyn ProcessMemory,
    module: &LoadedModule,
) -> Result<CodeComparison, NotCompared> {
    let bytes = match host.read_file(&module.path) {
        Ok(Some(bytes)) => bytes,
        Err(bope_host::SourceError::TooLarge { .. }) => return Err(NotCompared::TooLarge),
        Ok(None) | Err(_) => return Err(NotCompared::FileUnreadable),
    };
    let image = pe::parse(&bytes).map_err(|_| NotCompared::NotAnImage)?;
    if image.size_of_image != module.size {
        return Err(NotCompared::SizeDiffers);
    }
    let mut expected =
        pe::mapped_image(&image, &bytes, MAX_CODE_BYTES * 4).ok_or(NotCompared::TooLarge)?;
    pe::relocate(&image, &mut expected, module.base);
    let ignore = pe::loader_written_ranges(&image);
    let mut result = CodeComparison::default();
    let mut budget = MAX_CODE_BYTES;
    for section in image
        .sections
        .iter()
        .filter(|s| s.is_executable() && !s.is_writable())
    {
        let start = usize::try_from(section.virtual_address).unwrap_or(usize::MAX);
        let length = usize::try_from(section.mapped_size())
            .unwrap_or(0)
            .min(budget)
            .min(expected.len().saturating_sub(start));
        if length == 0 {
            continue;
        }
        budget -= length;
        result.sections += 1;
        let section_ignore: Vec<(usize, usize)> = ignore
            .iter()
            .filter_map(|(rva, size)| {
                let end = rva + size;
                (end > start && *rva < start + length).then(|| {
                    (
                        rva.saturating_sub(start),
                        end.min(start + length) - rva.max(&start),
                    )
                })
            })
            .collect();
        let address = module.base.saturating_add(start as u64);
        let (_, unreadable) = read_chunks(process, address, length as u64, |at, actual| {
            let offset = usize::try_from(at - address).unwrap_or(0);
            let Some(wanted) = expected.get(start + offset..start + offset + actual.len()) else {
                return;
            };
            let chunk_ignore: Vec<(usize, usize)> = section_ignore
                .iter()
                .filter_map(|(s, l)| {
                    let end = s + l;
                    (end > offset && *s < offset + actual.len()).then(|| {
                        (
                            s.saturating_sub(offset),
                            end.min(offset + actual.len()) - s.max(&offset),
                        )
                    })
                })
                .collect();
            for (relative, len) in memory::diff_ranges(wanted, actual, &chunk_ignore, 8, MAX_RANGES)
            {
                result.bytes_differing += len as u64;
                if result.ranges.len() < MAX_RANGES {
                    result.ranges.push((at + relative as u64, len));
                }
            }
            result.bytes_compared += actual.len() as u64;
        });
        result.bytes_unreadable += unreadable;
    }
    if let Some(exports) = &image.exports {
        for export in &exports.functions {
            if result.hooks.len() >= MAX_HOOKS {
                break;
            }
            if export.forwarder.is_some() {
                continue;
            }
            let Some(name) = &export.name else { continue };
            let rva = usize::try_from(export.rva).unwrap_or(usize::MAX);
            let in_code = image
                .sections
                .iter()
                .any(|s| s.is_executable() && s.contains_rva(export.rva));
            let Some(disk) = expected.get(rva..rva + 16).filter(|_| in_code) else {
                continue;
            };
            let address = module.base.saturating_add(rva as u64);
            let Ok(live) = process.read(address, 16) else {
                continue;
            };
            if let Some((kind, target)) = memory::inline_hook(&live, disk, address) {
                result.hooks.push(Hook {
                    function: name.clone(),
                    address,
                    kind,
                    target,
                });
            }
        }
    }
    Ok(result)
}

/// `address` as `0x…` text, the way observations write addresses.
pub fn hex_address(address: u64) -> String {
    format!("{address:#x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(base: u64, size: u32, path: &str) -> LoadedModule {
        LoadedModule {
            base,
            size,
            path: path.to_owned(),
        }
    }

    #[test]
    fn an_address_belongs_to_the_module_whose_image_holds_it() {
        let map = ModuleMap::new(vec![
            module(0x2000, 0x1000, "b.dll"),
            module(0x1000, 0x800, "a.dll"),
        ]);
        assert_eq!(map.owner(0x1000).unwrap().path, "a.dll");
        assert_eq!(map.owner(0x17ff).unwrap().path, "a.dll");
        assert!(map.owner(0x1800).is_none());
        assert_eq!(map.owner(0x2fff).unwrap().path, "b.dll");
        assert!(map.owner(0x3000).is_none());
        assert!(map.owner(0x10).is_none());
        assert!(map.has_base(0x2000) && !map.has_base(0x2001));
    }

    #[test]
    fn an_image_region_no_module_owns_is_unlisted_once() {
        let region = |base: u64, allocation: u64, kind: RegionKind| MemoryRegion {
            base,
            size: 0x1000,
            allocation_base: allocation,
            protect: 0x20,
            allocation_protect: 0x80,
            kind,
            mapped_file: None,
        };
        let map = ModuleMap::new(vec![module(0x1000, 0x2000, "a.dll")]);
        let regions = vec![
            region(0x1000, 0x1000, RegionKind::Image),
            region(0x9000, 0x9000, RegionKind::Image),
            region(0xa000, 0x9000, RegionKind::Image),
            region(0xb000, 0xb000, RegionKind::Private),
        ];
        let unlisted = unlisted_images(&regions, &map);
        assert_eq!(unlisted.len(), 1);
        assert_eq!(unlisted[0].allocation_base, 0x9000);
    }
}
