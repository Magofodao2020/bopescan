// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Portable Executable (PE/COFF) images — `.exe`, `.dll`, `.sys`, `.ocx`, `.scr` and any file that is
//! one whatever its name — read from bytes (B.O.P.E, ADR 0133).
//!
//! What is read is what Microsoft's "PE Format" specification defines: the DOS and NT headers, the
//! section table, the import, export, TLS, base relocation, resource (version information only),
//! security and CLR directories. Nothing is executed, nothing is mapped by the operating system and no
//! code is disassembled: a file is bytes here.
//!
//! **Every count is bounded** ([`Limits`]) and every offset is checked before it is read, so a crafted
//! file costs at most those bounds and is never a panic. A part of the file that does not decode is
//! recorded in [`PeFile::problems`] and the rest is still returned — a damaged or deliberately malformed
//! header is exactly when the parts that did parse matter.
//!
//! **What this does not say.** That a file is malicious, or that it is legitimate. [`Anomaly`] names
//! structural facts that also occur in ordinary software: packers, installers, DRM, anti-cheat and
//! self-extracting archives produce most of them. A collector reports them beside the signature and the
//! hash, and a rule decides what to show.

use crate::error::ParseError;

/// Bounds on what one file may make this parser read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most sections read (the loader accepts 96).
    pub sections: usize,
    /// Most imported DLLs read.
    pub import_dlls: usize,
    /// Most function names read per imported DLL.
    pub import_functions: usize,
    /// Most exported functions read.
    pub exports: usize,
    /// Most base-relocation entries read.
    pub relocations: usize,
    /// Most TLS callbacks read.
    pub tls_callbacks: usize,
    /// Longest name read, in bytes.
    pub name_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sections: 96,
            import_dlls: 512,
            import_functions: 4_096,
            exports: 65_536,
            relocations: 2_000_000,
            tls_callbacks: 64,
            name_bytes: 512,
        }
    }
}

/// The machine a PE image is built for, from `IMAGE_FILE_HEADER.Machine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    /// `IMAGE_FILE_MACHINE_I386` (0x14c).
    X86,
    /// `IMAGE_FILE_MACHINE_AMD64` (0x8664).
    X64,
    /// `IMAGE_FILE_MACHINE_ARM64` (0xaa64).
    Arm64,
    /// `IMAGE_FILE_MACHINE_ARMNT` (0x1c4).
    Arm,
    /// Any other value, kept as read.
    Other(u16),
}

impl Machine {
    /// From the header value.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x014c => Self::X86,
            0x8664 => Self::X64,
            0xaa64 => Self::Arm64,
            0x01c4 => Self::Arm,
            other => Self::Other(other),
        }
    }

    /// Stable identifier used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
            Self::Arm => "arm",
            Self::Other(_) => "other",
        }
    }
}

/// One section header, with what its characteristics allow and the entropy of its raw bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    /// The 8-byte name, NULs removed, as text (non-UTF-8 bytes replaced).
    pub name: String,
    /// `VirtualAddress`: where the loader puts it, relative to the image base.
    pub virtual_address: u32,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `PointerToRawData`.
    pub raw_offset: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
    /// `Characteristics`.
    pub characteristics: u32,
    /// Shannon entropy of the raw bytes present in the file, in bits per byte (0–8); `None` when the
    /// section has no raw bytes in the file.
    pub entropy: Option<f64>,
}

impl Section {
    /// `IMAGE_SCN_MEM_EXECUTE` or `IMAGE_SCN_CNT_CODE`.
    pub fn is_executable(&self) -> bool {
        self.characteristics & (0x2000_0000 | 0x0000_0020) != 0
    }

    /// `IMAGE_SCN_MEM_WRITE`.
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// `IMAGE_SCN_MEM_READ`.
    pub fn is_readable(&self) -> bool {
        self.characteristics & 0x4000_0000 != 0
    }

    /// The size the loader maps: `VirtualSize`, or `SizeOfRawData` when that is zero.
    pub fn mapped_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    /// Whether `rva` falls inside the mapped section.
    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.virtual_address
            && u64::from(rva) < u64::from(self.virtual_address) + u64::from(self.mapped_size())
    }

    /// `"rwx"`-style permissions, `-` for each one not granted.
    pub fn permissions(&self) -> String {
        let mut text = String::with_capacity(3);
        text.push(if self.is_readable() { 'r' } else { '-' });
        text.push(if self.is_writable() { 'w' } else { '-' });
        text.push(if self.is_executable() { 'x' } else { '-' });
        text
    }
}

/// One imported DLL and the functions taken from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedDll {
    /// The DLL name as the import directory spells it.
    pub name: String,
    /// Function names, or `#<ordinal>` for an import by ordinal.
    pub functions: Vec<String>,
    /// Whether [`Limits::import_functions`] stopped the list.
    pub truncated: bool,
    /// Whether the entry is in the delay-load directory rather than the import directory.
    pub delay_loaded: bool,
}

/// One exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The name, when the function is exported by name.
    pub name: Option<String>,
    /// The ordinal (biased by the directory's `Base`).
    pub ordinal: u32,
    /// The function's RVA; for a forwarder, the RVA of the forwarder string.
    pub rva: u32,
    /// `DLL.Function` when the export forwards to another DLL.
    pub forwarder: Option<String>,
}

/// The export directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exports {
    /// The DLL's own name as the directory spells it.
    pub dll_name: Option<String>,
    /// `NumberOfFunctions`, as declared.
    pub declared_functions: u32,
    /// What was read, in ordinal order.
    pub functions: Vec<Export>,
    /// Whether [`Limits::exports`] stopped the list.
    pub truncated: bool,
}

/// One base-relocation fixup the loader applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    /// Where the fixup is, relative to the image base.
    pub rva: u32,
    /// How many bytes it rewrites: 4 (`HIGHLOW`) or 8 (`DIR64`). Other kinds are counted in
    /// [`PeFile::other_relocations`] and not listed.
    pub width: u8,
}

/// The strings of the version resource's first `StringFileInfo` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionInfo {
    /// `CompanyName`.
    pub company_name: Option<String>,
    /// `ProductName`.
    pub product_name: Option<String>,
    /// `FileDescription`.
    pub file_description: Option<String>,
    /// `FileVersion`.
    pub file_version: Option<String>,
    /// `ProductVersion`.
    pub product_version: Option<String>,
    /// `OriginalFilename`.
    pub original_filename: Option<String>,
    /// `InternalName`.
    pub internal_name: Option<String>,
    /// `LegalCopyright`.
    pub legal_copyright: Option<String>,
    /// The fixed file version (`VS_FIXEDFILEINFO`), `a.b.c.d`, when present.
    pub fixed_file_version: Option<String>,
}

/// A structural fact about an image that differs from what an ordinary linker writes. None is a
/// finding on its own (see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Anomaly {
    /// The entry point is not inside any section (and is not zero).
    EntryPointOutsideSections,
    /// The entry point is in a section the loader maps writable.
    EntryPointInWritableSection,
    /// A section is both writable and executable.
    WritableExecutableSection,
    /// A section is executable and holds no raw bytes in the file: it is filled at run time.
    ExecutableSectionWithoutRawData,
    /// An executable section's raw bytes have an entropy above 7.2 bits per byte: compressed or
    /// encrypted code.
    HighEntropyExecutableSection,
    /// The header's checksum is non-zero and differs from the one computed over the file.
    ChecksumMismatch,
    /// A section's raw bytes extend past the end of the file.
    SectionBeyondFile,
    /// `SizeOfImage` is smaller than the end of the last section.
    SizeOfImageTooSmall,
    /// Bytes follow the last section and the certificate table: an overlay.
    Overlay,
    /// The image declares TLS callbacks, which run before the entry point.
    TlsCallbacks,
    /// A DLL with no import directory at all: most DLLs import at least `kernel32`.
    DllWithoutImports,
}

impl Anomaly {
    /// Stable identifier used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EntryPointOutsideSections => "entry_point_outside_sections",
            Self::EntryPointInWritableSection => "entry_point_in_writable_section",
            Self::WritableExecutableSection => "writable_executable_section",
            Self::ExecutableSectionWithoutRawData => "executable_section_without_raw_data",
            Self::HighEntropyExecutableSection => "high_entropy_executable_section",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::SectionBeyondFile => "section_beyond_file",
            Self::SizeOfImageTooSmall => "size_of_image_too_small",
            Self::Overlay => "overlay",
            Self::TlsCallbacks => "tls_callbacks",
            Self::DllWithoutImports => "dll_without_imports",
        }
    }
}

/// A parsed PE image.
// Each flag is a separate fact a header states; none is a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq)]
pub struct PeFile {
    /// `IMAGE_FILE_HEADER.Machine`.
    pub machine: Machine,
    /// `PE32+` (64-bit optional header) rather than `PE32`.
    pub pe32_plus: bool,
    /// `IMAGE_FILE_HEADER.Characteristics`.
    pub characteristics: u16,
    /// `IMAGE_FILE_DLL` is set.
    pub is_dll: bool,
    /// `TimeDateStamp`, seconds since 1970 as the linker wrote it (reproducible builds write a hash).
    pub timestamp: u32,
    /// `Subsystem` (2 GUI, 3 console, 1 native — drivers).
    pub subsystem: u16,
    /// `DllCharacteristics`.
    pub dll_characteristics: u16,
    /// `AddressOfEntryPoint`.
    pub entry_point_rva: u32,
    /// `ImageBase`.
    pub image_base: u64,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// `CheckSum` as stored.
    pub header_checksum: u32,
    /// The checksum computed over the file the way `CheckSumMappedFile` does.
    pub computed_checksum: u32,
    /// The section table.
    pub sections: Vec<Section>,
    /// Imported DLLs, the import directory's first, then the delay-load directory's.
    pub imports: Vec<ImportedDll>,
    /// The export directory, when there is one.
    pub exports: Option<Exports>,
    /// Whether a TLS directory is present.
    pub tls_present: bool,
    /// TLS callback addresses as virtual addresses (image base included), as stored.
    pub tls_callbacks: Vec<u64>,
    /// `HIGHLOW` and `DIR64` fixups, in file order.
    pub relocations: Vec<Relocation>,
    /// Fixups of any other kind (padding `ABSOLUTE` entries excluded).
    pub other_relocations: u32,
    /// Whether [`Limits::relocations`] stopped the list.
    pub relocations_truncated: bool,
    /// The version resource, when there is one and it decoded.
    pub version: Option<VersionInfo>,
    /// The certificate table (Authenticode) as `(file offset, size)`, when the directory names one.
    pub certificate_table: Option<(u32, u32)>,
    /// Whether a CLR (.NET) header is present.
    pub clr: bool,
    /// Bytes after the last section and the certificate table.
    pub overlay_bytes: u64,
    /// Structural facts that differ from what an ordinary linker writes, sorted, each once.
    pub anomalies: Vec<Anomaly>,
    /// What did not decode, by part, so a damaged directory is reported rather than dropped.
    pub problems: Vec<String>,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    let mut array = [0_u8; 8];
    array.copy_from_slice(slice);
    Some(u64::from_le_bytes(array))
}

/// Whether `bytes` begin like a PE image: `MZ`, an `e_lfanew` inside the bytes and `PE\0\0` there.
///
/// Used to find images whatever their extension.
pub fn is_pe(bytes: &[u8]) -> bool {
    nt_offset(bytes).is_some()
}

fn nt_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let e_lfanew = usize::try_from(u32_at(bytes, 0x3c)?).ok()?;
    (bytes.get(e_lfanew..e_lfanew.checked_add(4)?)? == b"PE\0\0").then_some(e_lfanew)
}

/// Shannon entropy of `bytes` in bits per byte, `None` for no bytes.
pub fn entropy(bytes: &[u8]) -> Option<f64> {
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    #[allow(clippy::cast_precision_loss)]
    let total = bytes.len() as f64;
    let mut sum = 0.0_f64;
    for count in counts {
        if count > 0 {
            #[allow(clippy::cast_precision_loss)]
            let p = count as f64 / total;
            sum -= p * p.log2();
        }
    }
    Some(sum)
}

/// The PE checksum of `bytes` as `CheckSumMappedFile` computes it, the stored checksum at
/// `checksum_offset` counted as zero.
pub fn pe_checksum(bytes: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut index = 0;
    while index < bytes.len() {
        if index == checksum_offset {
            index += 4;
            continue;
        }
        let low = u64::from(bytes[index]);
        let high = bytes.get(index + 1).copied().map_or(0, u64::from);
        sum += low | (high << 8);
        sum = (sum & 0xffff) + (sum >> 16);
        index += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    // The file length is added to the folded 16-bit sum; a file over 4 GiB is not a PE image.
    #[allow(clippy::cast_possible_truncation)]
    let checksum = (sum as u32).wrapping_add(bytes.len() as u32);
    checksum
}

/// One data directory, `(rva, size)`.
type Directory = (u32, u32);

struct Image<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    size_of_headers: u32,
    limits: Limits,
}

impl Image<'_> {
    /// The file offset of `rva`: inside a section's raw bytes, or inside the headers.
    fn offset(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers {
            return usize::try_from(rva).ok();
        }
        let section = self.sections.iter().find(|s| {
            rva >= s.virtual_address
                && u64::from(rva)
                    < u64::from(s.virtual_address) + u64::from(s.raw_size.max(s.mapped_size()))
        })?;
        let delta = rva - section.virtual_address;
        if delta >= section.raw_size {
            return None;
        }
        usize::try_from(u64::from(section.raw_offset) + u64::from(delta)).ok()
    }

    fn u32_rva(&self, rva: u32) -> Option<u32> {
        u32_at(self.bytes, self.offset(rva)?)
    }

    fn u16_rva(&self, rva: u32) -> Option<u16> {
        u16_at(self.bytes, self.offset(rva)?)
    }

    fn u64_rva(&self, rva: u32) -> Option<u64> {
        u64_at(self.bytes, self.offset(rva)?)
    }

    /// A NUL-terminated ASCII string at `rva`, bounded.
    fn string(&self, rva: u32) -> Option<String> {
        let start = self.offset(rva)?;
        let rest = self.bytes.get(start..)?;
        let limit = rest.len().min(self.limits.name_bytes);
        let end = rest[..limit].iter().position(|b| *b == 0).unwrap_or(limit);
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }
}

/// Parses a PE image with the default [`Limits`].
pub fn parse(bytes: &[u8]) -> Result<PeFile, ParseError> {
    parse_with(bytes, Limits::default())
}

/// Parses a PE image within `limits`.
#[allow(clippy::too_many_lines)]
pub fn parse_with(bytes: &[u8], limits: Limits) -> Result<PeFile, ParseError> {
    if bytes.len() < 0x40 {
        return Err(ParseError::Truncated {
            expected: 0x40,
            found: bytes.len(),
        });
    }
    let nt = nt_offset(bytes).ok_or_else(|| ParseError::Malformed {
        field: "pe_signature",
        detail: "no MZ header leading to a PE signature".to_owned(),
    })?;
    let file_header = nt + 4;
    let truncated = |expected: usize| ParseError::Truncated {
        expected,
        found: bytes.len(),
    };
    let machine = u16_at(bytes, file_header).ok_or_else(|| truncated(file_header + 2))?;
    let section_count = u16_at(bytes, file_header + 2).ok_or_else(|| truncated(file_header + 4))?;
    let timestamp = u32_at(bytes, file_header + 4).ok_or_else(|| truncated(file_header + 8))?;
    let optional_size =
        u16_at(bytes, file_header + 16).ok_or_else(|| truncated(file_header + 18))?;
    let characteristics =
        u16_at(bytes, file_header + 18).ok_or_else(|| truncated(file_header + 20))?;
    let optional = file_header + 20;
    let magic = u16_at(bytes, optional).ok_or_else(|| truncated(optional + 2))?;
    let pe32_plus = match magic {
        0x20b => true,
        0x10b => false,
        other => {
            return Err(ParseError::Malformed {
                field: "optional_header",
                detail: format!("magic {other:#x} is neither PE32 nor PE32+"),
            });
        }
    };
    let need = |offset: usize| truncated(offset + 8);
    let entry_point_rva = u32_at(bytes, optional + 16).ok_or_else(|| need(optional + 16))?;
    let image_base = if pe32_plus {
        u64_at(bytes, optional + 24).ok_or_else(|| need(optional + 24))?
    } else {
        u64::from(u32_at(bytes, optional + 28).ok_or_else(|| need(optional + 28))?)
    };
    let size_of_image = u32_at(bytes, optional + 56).ok_or_else(|| need(optional + 56))?;
    let size_of_headers = u32_at(bytes, optional + 60).ok_or_else(|| need(optional + 60))?;
    let checksum_offset = optional + 64;
    let header_checksum = u32_at(bytes, checksum_offset).ok_or_else(|| need(checksum_offset))?;
    let subsystem = u16_at(bytes, optional + 68).ok_or_else(|| need(optional + 68))?;
    let dll_characteristics = u16_at(bytes, optional + 70).ok_or_else(|| need(optional + 70))?;
    let (rva_count_offset, directories_offset) = if pe32_plus {
        (optional + 108, optional + 112)
    } else {
        (optional + 92, optional + 96)
    };
    let declared_directories = u32_at(bytes, rva_count_offset).unwrap_or(0).min(16);
    let directory = |index: u32| -> Directory {
        if index >= declared_directories {
            return (0, 0);
        }
        let at = directories_offset + 8 * index as usize;
        if at + 8 > optional + usize::from(optional_size) {
            return (0, 0);
        }
        (
            u32_at(bytes, at).unwrap_or(0),
            u32_at(bytes, at + 4).unwrap_or(0),
        )
    };

    let mut problems = Vec::new();
    let section_table = optional + usize::from(optional_size);
    let mut sections = Vec::new();
    for index in 0..usize::from(section_count).min(limits.sections) {
        let at = section_table + 40 * index;
        let Some(header) = bytes.get(at..at + 40) else {
            problems.push(format!(
                "section table: header {index} is past the end of the file"
            ));
            break;
        };
        let name_end = header[..8].iter().position(|b| *b == 0).unwrap_or(8);
        let raw_offset = u32_at(header, 20).unwrap_or(0);
        let raw_size = u32_at(header, 16).unwrap_or(0);
        let raw = usize::try_from(raw_offset).ok().and_then(|start| {
            let end = start.checked_add(usize::try_from(raw_size).ok()?)?;
            bytes.get(start..end.min(bytes.len()))
        });
        sections.push(Section {
            name: String::from_utf8_lossy(&header[..name_end]).into_owned(),
            virtual_size: u32_at(header, 8).unwrap_or(0),
            virtual_address: u32_at(header, 12).unwrap_or(0),
            raw_size,
            raw_offset,
            characteristics: u32_at(header, 36).unwrap_or(0),
            entropy: raw.and_then(entropy),
        });
    }
    if usize::from(section_count) > limits.sections {
        problems.push(format!(
            "section table: {section_count} sections declared, {} read",
            limits.sections
        ));
    }

    let image = Image {
        bytes,
        sections,
        size_of_headers,
        limits,
    };
    let (imports_rva, _) = directory(1);
    let mut imports = read_imports(&image, imports_rva, false, &mut problems);
    let (delay_rva, _) = directory(13);
    imports.extend(read_imports(&image, delay_rva, true, &mut problems));
    let (export_rva, export_size) = directory(0);
    let exports = (export_rva != 0)
        .then(|| read_exports(&image, export_rva, export_size, &mut problems))
        .flatten();
    let (tls_rva, _) = directory(9);
    let tls_callbacks = if tls_rva == 0 {
        Vec::new()
    } else {
        read_tls(&image, tls_rva, pe32_plus, image_base, &mut problems)
    };
    let (reloc_rva, reloc_size) = directory(5);
    let (relocations, other_relocations, relocations_truncated) =
        read_relocations(&image, reloc_rva, reloc_size, &mut problems);
    let (resource_rva, _) = directory(2);
    let version = (resource_rva != 0)
        .then(|| read_version(&image, resource_rva))
        .flatten();
    // The certificate table's "RVA" is a file offset (PE Format, "The Attribute Certificate Table").
    let certificate_table = Some(directory(4)).filter(|(offset, size)| *offset != 0 && *size != 0);
    let (clr_rva, _) = directory(14);

    let computed_checksum = pe_checksum(bytes, checksum_offset);
    let end_of_sections = image
        .sections
        .iter()
        .map(|s| u64::from(s.raw_offset) + u64::from(s.raw_size))
        .filter(|end| *end <= bytes.len() as u64)
        .max()
        .unwrap_or(u64::from(size_of_headers));
    let end_of_data = certificate_table.map_or(end_of_sections, |(offset, size)| {
        end_of_sections.max(u64::from(offset) + u64::from(size))
    });
    let overlay_bytes = (bytes.len() as u64).saturating_sub(end_of_data);

    let is_dll = characteristics & 0x2000 != 0;
    let mut anomalies = Vec::new();
    let entry_section = image
        .sections
        .iter()
        .find(|s| s.contains_rva(entry_point_rva));
    if entry_point_rva != 0 {
        match entry_section {
            None => anomalies.push(Anomaly::EntryPointOutsideSections),
            Some(section) if section.is_writable() => {
                anomalies.push(Anomaly::EntryPointInWritableSection);
            }
            Some(_) => {}
        }
    }
    for section in &image.sections {
        if section.is_executable() && section.is_writable() {
            anomalies.push(Anomaly::WritableExecutableSection);
        }
        if section.is_executable() && section.raw_size == 0 && section.virtual_size > 0 {
            anomalies.push(Anomaly::ExecutableSectionWithoutRawData);
        }
        if section.is_executable() && section.entropy.is_some_and(|e| e > 7.2) {
            anomalies.push(Anomaly::HighEntropyExecutableSection);
        }
        if u64::from(section.raw_offset) + u64::from(section.raw_size) > bytes.len() as u64 {
            anomalies.push(Anomaly::SectionBeyondFile);
        }
    }
    let end_of_image = image
        .sections
        .iter()
        .map(|s| u64::from(s.virtual_address) + u64::from(s.mapped_size()))
        .max()
        .unwrap_or(0);
    if end_of_image > u64::from(size_of_image) {
        anomalies.push(Anomaly::SizeOfImageTooSmall);
    }
    if header_checksum != 0 && header_checksum != computed_checksum {
        anomalies.push(Anomaly::ChecksumMismatch);
    }
    if overlay_bytes > 0 {
        anomalies.push(Anomaly::Overlay);
    }
    if !tls_callbacks.is_empty() {
        anomalies.push(Anomaly::TlsCallbacks);
    }
    if is_dll && imports_rva == 0 && delay_rva == 0 && clr_rva == 0 {
        anomalies.push(Anomaly::DllWithoutImports);
    }
    anomalies.sort_unstable();
    anomalies.dedup();

    Ok(PeFile {
        machine: Machine::from_u16(machine),
        pe32_plus,
        characteristics,
        is_dll,
        timestamp,
        subsystem,
        dll_characteristics,
        entry_point_rva,
        image_base,
        size_of_image,
        size_of_headers,
        header_checksum,
        computed_checksum,
        sections: image.sections,
        imports,
        exports,
        tls_present: tls_rva != 0,
        tls_callbacks,
        relocations,
        other_relocations,
        relocations_truncated,
        version,
        certificate_table,
        clr: clr_rva != 0,
        overlay_bytes,
        anomalies,
        problems,
    })
}

fn read_imports(
    image: &Image<'_>,
    directory_rva: u32,
    delay: bool,
    problems: &mut Vec<String>,
) -> Vec<ImportedDll> {
    let mut dlls = Vec::new();
    if directory_rva == 0 {
        return dlls;
    }
    let pe32_plus = image
        .bytes
        .get(nt_offset(image.bytes).unwrap_or(0) + 24..)
        .and_then(|b| u16_at(b, 0))
        == Some(0x20b);
    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; IMAGE_DELAYLOAD_DESCRIPTOR is 32.
    let stride: u32 = if delay { 32 } else { 20 };
    let thunk_size: u32 = if pe32_plus { 8 } else { 4 };
    for index in 0..image.limits.import_dlls {
        let Some(at) = u32::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(stride))
            .and_then(|o| directory_rva.checked_add(o))
        else {
            break;
        };
        let (name_rva, thunks_rva) = if delay {
            // Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA, …
            (image.u32_rva(at + 4), image.u32_rva(at + 16))
        } else {
            // OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk.
            let original = image.u32_rva(at);
            let first = image.u32_rva(at + 16);
            (
                image.u32_rva(at + 12),
                match original {
                    Some(0) | None => first,
                    other => other,
                },
            )
        };
        let (Some(name_rva), Some(thunks_rva)) = (name_rva, thunks_rva) else {
            problems.push(format!(
                "{} directory: descriptor {index} could not be read",
                if delay { "delay import" } else { "import" }
            ));
            break;
        };
        if name_rva == 0 && thunks_rva == 0 {
            break;
        }
        let Some(name) = image.string(name_rva) else {
            problems.push(format!(
                "import directory: name of descriptor {index} unreadable"
            ));
            continue;
        };
        let mut functions = Vec::new();
        let mut truncated = false;
        for slot in 0..=image.limits.import_functions {
            if slot == image.limits.import_functions {
                truncated = true;
                break;
            }
            let Some(slot_rva) = u32::try_from(slot)
                .ok()
                .and_then(|s| s.checked_mul(thunk_size))
                .and_then(|o| thunks_rva.checked_add(o))
            else {
                break;
            };
            let value = if pe32_plus {
                image.u64_rva(slot_rva)
            } else {
                image.u32_rva(slot_rva).map(u64::from)
            };
            let Some(value) = value else { break };
            if value == 0 {
                break;
            }
            let by_ordinal = if pe32_plus {
                value & (1 << 63) != 0
            } else {
                value & (1 << 31) != 0
            };
            if by_ordinal {
                functions.push(format!("#{}", value & 0xffff));
            } else if let Ok(hint_rva) = u32::try_from(value & 0x7fff_ffff) {
                match image.string(hint_rva.saturating_add(2)) {
                    Some(function) => functions.push(function),
                    None => functions.push("?".to_owned()),
                }
            }
        }
        dlls.push(ImportedDll {
            name,
            functions,
            truncated,
            delay_loaded: delay,
        });
    }
    dlls
}

fn read_exports(
    image: &Image<'_>,
    rva: u32,
    size: u32,
    problems: &mut Vec<String>,
) -> Option<Exports> {
    let fields = |offset: u32| image.u32_rva(rva.checked_add(offset)?);
    let (
        Some(name_rva),
        Some(base),
        Some(count),
        Some(names),
        Some(function_table),
        Some(name_table),
        Some(ordinal_table),
    ) = (
        fields(12),
        fields(16),
        fields(20),
        fields(24),
        fields(28),
        fields(32),
        fields(36),
    )
    else {
        problems.push("export directory: header could not be read".to_owned());
        return None;
    };
    let mut by_index: Vec<Option<String>> = Vec::new();
    let read_count = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(image.limits.exports);
    by_index.resize(read_count, None);
    for index in 0..names.min(u32::try_from(image.limits.exports).unwrap_or(u32::MAX)) {
        let Some(name_pointer) = image.u32_rva(name_table.wrapping_add(index.wrapping_mul(4)))
        else {
            break;
        };
        let Some(ordinal_index) = image.u16_rva(ordinal_table.wrapping_add(index.wrapping_mul(2)))
        else {
            break;
        };
        if let (Some(slot), Some(name)) = (
            by_index.get_mut(usize::from(ordinal_index)),
            image.string(name_pointer),
        ) {
            *slot = Some(name);
        }
    }
    let mut list = Vec::new();
    for (index, name) in by_index.into_iter().enumerate() {
        let Some(index32) = u32::try_from(index).ok() else {
            break;
        };
        let Some(target) = image.u32_rva(function_table.wrapping_add(index32.wrapping_mul(4)))
        else {
            break;
        };
        if target == 0 {
            continue;
        }
        let forwarder = (target >= rva && target < rva.saturating_add(size))
            .then(|| image.string(target))
            .flatten();
        list.push(Export {
            name,
            ordinal: base.wrapping_add(index32),
            rva: target,
            forwarder,
        });
    }
    Some(Exports {
        dll_name: image.string(name_rva),
        declared_functions: count,
        functions: list,
        truncated: usize::try_from(count).unwrap_or(usize::MAX) > image.limits.exports,
    })
}

fn read_tls(
    image: &Image<'_>,
    rva: u32,
    pe32_plus: bool,
    image_base: u64,
    problems: &mut Vec<String>,
) -> Vec<u64> {
    // AddressOfCallBacks is the fourth pointer-sized field.
    let field = if pe32_plus { 24 } else { 12 };
    let pointer = if pe32_plus {
        image.u64_rva(rva.saturating_add(field))
    } else {
        image.u32_rva(rva.saturating_add(field)).map(u64::from)
    };
    let Some(list_va) = pointer else {
        problems.push("TLS directory: header could not be read".to_owned());
        return Vec::new();
    };
    let mut callbacks = Vec::new();
    if list_va == 0 {
        return callbacks;
    }
    let Some(callbacks_rva) = list_va
        .checked_sub(image_base)
        .and_then(|r| u32::try_from(r).ok())
    else {
        problems.push("TLS directory: callback list is outside the image".to_owned());
        return callbacks;
    };
    let width = if pe32_plus { 8 } else { 4 };
    for index in 0..image.limits.tls_callbacks {
        let Some(at) = u32::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(width))
            .and_then(|o| callbacks_rva.checked_add(o))
        else {
            break;
        };
        let value = if pe32_plus {
            image.u64_rva(at)
        } else {
            image.u32_rva(at).map(u64::from)
        };
        match value {
            Some(0) | None => break,
            Some(callback) => callbacks.push(callback),
        }
    }
    callbacks
}

fn read_relocations(
    image: &Image<'_>,
    rva: u32,
    size: u32,
    problems: &mut Vec<String>,
) -> (Vec<Relocation>, u32, bool) {
    let mut list = Vec::new();
    let mut other = 0_u32;
    if rva == 0 || size == 0 {
        return (list, other, false);
    }
    let mut offset = 0_u32;
    while offset.saturating_add(8) <= size {
        let Some(block_rva) = rva.checked_add(offset) else {
            break;
        };
        let (Some(page), Some(block_size)) =
            (image.u32_rva(block_rva), image.u32_rva(block_rva + 4))
        else {
            problems.push("relocation directory: block header could not be read".to_owned());
            break;
        };
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;
        for entry in 0..entries {
            let Some(value) = image.u16_rva(block_rva + 8 + entry * 2) else {
                break;
            };
            let kind = value >> 12;
            let at = page.wrapping_add(u32::from(value & 0x0fff));
            match kind {
                0 => {}
                3 | 10 => {
                    if list.len() >= image.limits.relocations {
                        return (list, other, true);
                    }
                    list.push(Relocation {
                        rva: at,
                        width: if kind == 3 { 4 } else { 8 },
                    });
                }
                _ => other = other.saturating_add(1),
            }
        }
        offset = offset.saturating_add(block_size);
    }
    (list, other, false)
}

/// The resource directory entry at `entry_rva`: `(name_or_id, offset_to_data, is_directory)`.
fn resource_entry(image: &Image<'_>, entry_rva: u32) -> Option<(u32, u32, bool)> {
    let name = image.u32_rva(entry_rva)?;
    let target = image.u32_rva(entry_rva + 4)?;
    Some((name, target & 0x7fff_ffff, target & 0x8000_0000 != 0))
}

/// The first data entry of the `RT_VERSION` (16) resource.
fn read_version(image: &Image<'_>, root: u32) -> Option<VersionInfo> {
    let entries_of = |dir_rva: u32| -> Vec<(u32, u32, bool)> {
        let named = image.u16_rva(dir_rva + 12).unwrap_or(0);
        let ids = image.u16_rva(dir_rva + 14).unwrap_or(0);
        let count = u32::from(named) + u32::from(ids);
        (0..count.min(256))
            .filter_map(|i| resource_entry(image, dir_rva + 16 + i * 8))
            .collect()
    };
    let (_, type_dir, is_dir) = entries_of(root)
        .into_iter()
        .find(|(name, _, _)| *name == 16)?;
    if !is_dir {
        return None;
    }
    let (_, name_dir, is_dir) = entries_of(root.checked_add(type_dir)?).into_iter().next()?;
    if !is_dir {
        return None;
    }
    let (_, data_entry, is_dir) = entries_of(root.checked_add(name_dir)?).into_iter().next()?;
    if is_dir {
        return None;
    }
    let entry = root.checked_add(data_entry)?;
    let data_rva = image.u32_rva(entry)?;
    let data_size = image.u32_rva(entry + 4)?;
    let start = image.offset(data_rva)?;
    let end = start.checked_add(usize::try_from(data_size).ok()?.min(64 * 1024))?;
    let data = image.bytes.get(start..end.min(image.bytes.len()))?;
    parse_version_resource(data)
}

/// One `VS_VERSIONINFO`-style block: `(key, value bytes, children bytes, total length)`.
fn version_block(data: &[u8]) -> Option<(String, &[u8], &[u8], usize)> {
    let length = usize::from(u16_at(data, 0)?);
    let value_length = usize::from(u16_at(data, 2)?);
    let text = u16_at(data, 4)? == 1;
    if length < 6 || length > data.len() {
        return None;
    }
    let block = &data[..length];
    let mut key = Vec::new();
    let mut at = 6;
    while let Some(unit) = u16_at(block, at) {
        at += 2;
        if unit == 0 {
            break;
        }
        key.push(unit);
        if key.len() > 64 {
            return None;
        }
    }
    let align = |n: usize| (n + 3) & !3;
    let value_start = align(at);
    let value_bytes = if text { value_length * 2 } else { value_length };
    let value_end = value_start.saturating_add(value_bytes).min(length);
    let value = block.get(value_start.min(length)..value_end).unwrap_or(&[]);
    let children_start = align(value_end).min(length);
    Some((
        String::from_utf16_lossy(&key),
        value,
        &block[children_start..],
        length,
    ))
}

fn utf16_value(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units).trim().to_owned()
}

/// Parses the bytes of a `VS_VERSIONINFO` resource.
pub fn parse_version_resource(data: &[u8]) -> Option<VersionInfo> {
    let (key, value, mut children, _) = version_block(data)?;
    if key != "VS_VERSION_INFO" {
        return None;
    }
    let mut info = VersionInfo::default();
    // VS_FIXEDFILEINFO: signature 0xFEEF04BD, then dwFileVersionMS/LS at 8 and 12.
    if u32_at(value, 0) == Some(0xfeef_04bd)
        && let (Some(ms), Some(ls)) = (u32_at(value, 8), u32_at(value, 12))
    {
        info.fixed_file_version = Some(format!(
            "{}.{}.{}.{}",
            ms >> 16,
            ms & 0xffff,
            ls >> 16,
            ls & 0xffff
        ));
    }
    let mut guard = 0;
    while !children.is_empty() && guard < 64 {
        guard += 1;
        let Some((child_key, _, grand, length)) = version_block(children) else {
            break;
        };
        if child_key == "StringFileInfo" {
            // The first string table is read: most files carry one.
            if let Some((_, _, mut strings, _)) = version_block(grand) {
                let mut count = 0;
                while !strings.is_empty() && count < 64 {
                    count += 1;
                    let Some((name, value, _, length)) = version_block(strings) else {
                        break;
                    };
                    let text = Some(utf16_value(value)).filter(|t| !t.is_empty());
                    match name.as_str() {
                        "CompanyName" => info.company_name = text,
                        "ProductName" => info.product_name = text,
                        "FileDescription" => info.file_description = text,
                        "FileVersion" => info.file_version = text,
                        "ProductVersion" => info.product_version = text,
                        "OriginalFilename" => info.original_filename = text,
                        "InternalName" => info.internal_name = text,
                        "LegalCopyright" => info.legal_copyright = text,
                        _ => {}
                    }
                    let next = (length + 3) & !3;
                    strings = strings.get(next..).unwrap_or(&[]);
                }
            }
        }
        let next = (length + 3) & !3;
        children = children.get(next..).unwrap_or(&[]);
    }
    Some(info)
}

/// `bytes` laid out as the loader maps them at `image_base`, before relocation: headers, then each
/// section's raw bytes at its virtual address, the rest zero. `None` when `SizeOfImage` exceeds
/// `max_image` — the caller's bound, so a crafted header cannot ask for gigabytes.
pub fn mapped_image(pe: &PeFile, bytes: &[u8], max_image: usize) -> Option<Vec<u8>> {
    let size = usize::try_from(pe.size_of_image).ok()?;
    if size > max_image {
        return None;
    }
    let mut image = vec![0_u8; size];
    let headers = usize::try_from(pe.size_of_headers)
        .ok()?
        .min(bytes.len())
        .min(size);
    image[..headers].copy_from_slice(&bytes[..headers]);
    for section in &pe.sections {
        let Ok(dest) = usize::try_from(section.virtual_address) else {
            continue;
        };
        let Ok(raw_start) = usize::try_from(section.raw_offset) else {
            continue;
        };
        let length = usize::try_from(section.raw_size.min(section.mapped_size())).unwrap_or(0);
        let Some(source) = bytes.get(raw_start..raw_start.saturating_add(length).min(bytes.len()))
        else {
            continue;
        };
        let end = dest.saturating_add(source.len()).min(size);
        if dest < end {
            image[dest..end].copy_from_slice(&source[..end - dest]);
        }
    }
    Some(image)
}

/// Applies `pe`'s base relocations to a [`mapped_image`] as the loader does when it maps the image at
/// `loaded_base` instead of the preferred `ImageBase`.
pub fn relocate(pe: &PeFile, image: &mut [u8], loaded_base: u64) {
    let delta = loaded_base.wrapping_sub(pe.image_base);
    if delta == 0 {
        return;
    }
    for fixup in &pe.relocations {
        let Ok(at) = usize::try_from(fixup.rva) else {
            continue;
        };
        match fixup.width {
            8 => {
                if let Some(slot) = image.get_mut(at..at + 8) {
                    let mut array = [0_u8; 8];
                    array.copy_from_slice(slot);
                    let value = u64::from_le_bytes(array).wrapping_add(delta);
                    slot.copy_from_slice(&value.to_le_bytes());
                }
            }
            4 => {
                if let Some(slot) = image.get_mut(at..at + 4) {
                    let value = u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]);
                    #[allow(clippy::cast_possible_truncation)]
                    let value = value.wrapping_add(delta as u32);
                    slot.copy_from_slice(&value.to_le_bytes());
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A small, valid PE32+ DLL built byte by byte: headers, a `.text` section with code, a `.rdata`
    /// section holding an import of `kernel32.dll!GetTickCount64`, an export `Run` and a version
    /// resource, and a `.reloc` section with two `DIR64` fixups.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn sample_dll() -> Vec<u8> {
        let file_alignment = 0x200_usize;
        let mut file = vec![0_u8; 0x200];
        file[0..2].copy_from_slice(b"MZ");
        file[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        file[0x40..0x44].copy_from_slice(b"PE\0\0");
        let fh = 0x44;
        file[fh..fh + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        file[fh + 2..fh + 4].copy_from_slice(&4_u16.to_le_bytes());
        file[fh + 4..fh + 8].copy_from_slice(&0x6000_0000_u32.to_le_bytes());
        file[fh + 16..fh + 18].copy_from_slice(&240_u16.to_le_bytes());
        file[fh + 18..fh + 20].copy_from_slice(&0x2022_u16.to_le_bytes()); // DLL | EXECUTABLE | LARGE_ADDRESS
        let oh = fh + 20;
        file[oh..oh + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        file[oh + 16..oh + 20].copy_from_slice(&0x1000_u32.to_le_bytes()); // entry
        file[oh + 24..oh + 32].copy_from_slice(&0x1_8000_0000_u64.to_le_bytes());
        file[oh + 32..oh + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        file[oh + 36..oh + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        file[oh + 56..oh + 60].copy_from_slice(&0x5000_u32.to_le_bytes()); // SizeOfImage
        file[oh + 60..oh + 64].copy_from_slice(&0x200_u32.to_le_bytes()); // SizeOfHeaders
        file[oh + 68..oh + 70].copy_from_slice(&2_u16.to_le_bytes());
        file[oh + 70..oh + 72].copy_from_slice(&0x0160_u16.to_le_bytes());
        file[oh + 108..oh + 112].copy_from_slice(&16_u32.to_le_bytes());
        let dirs = oh + 112;
        let set_dir = |file: &mut Vec<u8>, index: usize, rva: u32, size: u32| {
            let at = dirs + index * 8;
            file[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            file[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        };
        set_dir(&mut file, 0, 0x2100, 0x100); // export
        set_dir(&mut file, 1, 0x2000, 0x28); // import
        set_dir(&mut file, 2, 0x3000, 0x200); // resource
        set_dir(&mut file, 5, 0x4000, 0x0c); // reloc
        let st = oh + 240;
        let sections: [(&[u8], u32, u32, u32, u32); 4] = [
            (b".text", 0x1000, 0x200, 0x200, 0x6000_0020),
            (b".rdata", 0x2000, 0x400, 0x400, 0x4000_0040),
            (b".rsrc", 0x3000, 0x200, 0x800, 0x4000_0040),
            (b".reloc", 0x4000, 0x200, 0xa00, 0x4200_0040),
        ];
        for (index, (name, va, raw_size, raw_offset, flags)) in sections.iter().enumerate() {
            let at = st + index * 40;
            file[at..at + name.len()].copy_from_slice(name);
            file[at + 8..at + 12].copy_from_slice(&raw_size.to_le_bytes());
            file[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
            file[at + 16..at + 20].copy_from_slice(&raw_size.to_le_bytes());
            file[at + 20..at + 24].copy_from_slice(&raw_offset.to_le_bytes());
            file[at + 36..at + 40].copy_from_slice(&flags.to_le_bytes());
        }
        // .text at 0x200: a prologue and pointers to relocate at 0x1010 and 0x1018.
        let mut text = vec![0xcc_u8; file_alignment];
        text[..4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        text[0x10..0x18].copy_from_slice(&0x1_8000_2000_u64.to_le_bytes());
        text[0x18..0x20].copy_from_slice(&0x1_8000_1000_u64.to_le_bytes());
        file.extend_from_slice(&text);
        // .rdata at 0x400 (RVA 0x2000): import descriptor, ILT, name, dll name; export directory.
        let mut rdata = vec![0_u8; 0x400];
        let put32 = |buf: &mut Vec<u8>, at: usize, v: u32| {
            buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        put32(&mut rdata, 0x00, 0x2040); // OriginalFirstThunk
        put32(&mut rdata, 0x0c, 0x2080); // Name
        put32(&mut rdata, 0x10, 0x2040); // FirstThunk
        rdata[0x40..0x48].copy_from_slice(&0x2060_u64.to_le_bytes());
        rdata[0x62..0x62 + 15].copy_from_slice(b"GetTickCount64\0");
        rdata[0x80..0x80 + 13].copy_from_slice(b"kernel32.dll\0");
        // Export directory at RVA 0x2100.
        put32(&mut rdata, 0x10c, 0x2180); // Name
        put32(&mut rdata, 0x110, 1); // Base
        put32(&mut rdata, 0x114, 1); // NumberOfFunctions
        put32(&mut rdata, 0x118, 1); // NumberOfNames
        put32(&mut rdata, 0x11c, 0x2140); // AddressOfFunctions
        put32(&mut rdata, 0x120, 0x2150); // AddressOfNames
        put32(&mut rdata, 0x124, 0x2160); // AddressOfNameOrdinals
        put32(&mut rdata, 0x140, 0x1000);
        put32(&mut rdata, 0x150, 0x2170);
        rdata[0x170..0x174].copy_from_slice(b"Run\0");
        rdata[0x180..0x188].copy_from_slice(b"one.dll\0");
        file.extend_from_slice(&rdata);
        // .rsrc at 0x800 (RVA 0x3000): type 16 → id 1 → lang 0 → data entry → VS_VERSIONINFO.
        let mut rsrc = vec![0_u8; 0x200];
        let dir = |buf: &mut Vec<u8>, at: usize, id: u32, target: u32| {
            buf[at + 14..at + 16].copy_from_slice(&1_u16.to_le_bytes());
            buf[at + 16..at + 20].copy_from_slice(&id.to_le_bytes());
            buf[at + 20..at + 24].copy_from_slice(&target.to_le_bytes());
        };
        dir(&mut rsrc, 0x00, 16, 0x8000_0018);
        dir(&mut rsrc, 0x18, 1, 0x8000_0030);
        dir(&mut rsrc, 0x30, 0, 0x48);
        let version = version_resource();
        put32(&mut rsrc, 0x48, 0x3060);
        put32(&mut rsrc, 0x4c, u32::try_from(version.len()).unwrap());
        rsrc[0x60..0x60 + version.len()].copy_from_slice(&version);
        file.extend_from_slice(&rsrc);
        // .reloc at 0xa00 (RVA 0x4000): one block for page 0x1000 with two DIR64 entries.
        let mut reloc = vec![0_u8; 0x200];
        put32(&mut reloc, 0, 0x1000);
        put32(&mut reloc, 4, 0x0c);
        reloc[8..10].copy_from_slice(&((10_u16 << 12) | 0x010).to_le_bytes());
        reloc[10..12].copy_from_slice(&((10_u16 << 12) | 0x018).to_le_bytes());
        file.extend_from_slice(&reloc);
        let checksum = pe_checksum(&file, oh + 64);
        file[oh + 64..oh + 68].copy_from_slice(&checksum.to_le_bytes());
        file
    }

    fn block(key: &str, value: &[u8], text: bool, children: &[u8]) -> Vec<u8> {
        let mut out = vec![0_u8; 6];
        for unit in key.encode_utf16().chain([0]) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(value);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(children);
        let length = u16::try_from(out.len()).unwrap();
        let value_length = if text { value.len() / 2 } else { value.len() };
        out[0..2].copy_from_slice(&length.to_le_bytes());
        out[2..4].copy_from_slice(&u16::try_from(value_length).unwrap().to_le_bytes());
        out[4..6].copy_from_slice(&u16::from(text).to_le_bytes());
        out
    }

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn version_resource() -> Vec<u8> {
        let mut fixed = vec![0_u8; 52];
        fixed[0..4].copy_from_slice(&0xfeef_04bd_u32.to_le_bytes());
        fixed[8..12].copy_from_slice(&((1_u32 << 16) | 2).to_le_bytes());
        fixed[12..16].copy_from_slice(&((3_u32 << 16) | 4).to_le_bytes());
        let mut strings = block("CompanyName", &wide("Example Corp"), true, &[]);
        while !strings.len().is_multiple_of(4) {
            strings.push(0);
        }
        strings.extend(block("OriginalFilename", &wide("one.dll"), true, &[]));
        let table = block("040904b0", &[], true, &strings);
        let file_info = block("StringFileInfo", &[], true, &table);
        block("VS_VERSION_INFO", &fixed, false, &file_info)
    }

    #[test]
    fn a_built_dll_reads_back_whole() {
        let bytes = sample_dll();
        assert!(is_pe(&bytes));
        let pe = parse(&bytes).unwrap();
        assert_eq!(pe.machine, Machine::X64);
        assert!(pe.pe32_plus && pe.is_dll);
        assert_eq!(pe.image_base, 0x1_8000_0000);
        assert_eq!(pe.sections.len(), 4);
        assert_eq!(pe.sections[0].name, ".text");
        assert_eq!(pe.sections[0].permissions(), "r-x");
        assert_eq!(pe.imports.len(), 1);
        assert_eq!(pe.imports[0].name, "kernel32.dll");
        assert_eq!(pe.imports[0].functions, vec!["GetTickCount64".to_owned()]);
        let exports = pe.exports.as_ref().unwrap();
        assert_eq!(exports.dll_name.as_deref(), Some("one.dll"));
        assert_eq!(exports.functions[0].name.as_deref(), Some("Run"));
        assert_eq!(exports.functions[0].rva, 0x1000);
        assert_eq!(pe.relocations.len(), 2);
        assert_eq!(
            pe.relocations[0],
            Relocation {
                rva: 0x1010,
                width: 8
            }
        );
        let version = pe.version.as_ref().unwrap();
        assert_eq!(version.company_name.as_deref(), Some("Example Corp"));
        assert_eq!(version.original_filename.as_deref(), Some("one.dll"));
        assert_eq!(version.fixed_file_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(pe.header_checksum, pe.computed_checksum);
        assert!(pe.anomalies.is_empty(), "{:?}", pe.anomalies);
        assert!(pe.problems.is_empty(), "{:?}", pe.problems);
    }

    #[test]
    fn structural_anomalies_are_named() {
        let mut bytes = sample_dll();
        // Make .text writable, append an overlay and leave the checksum stale.
        let st = 0x44 + 20 + 240;
        bytes[st + 36..st + 40].copy_from_slice(&0xe000_0020_u32.to_le_bytes());
        bytes.extend_from_slice(&[0x55; 64]);
        let pe = parse(&bytes).unwrap();
        assert!(pe.anomalies.contains(&Anomaly::WritableExecutableSection));
        assert!(pe.anomalies.contains(&Anomaly::EntryPointInWritableSection));
        assert!(pe.anomalies.contains(&Anomaly::Overlay));
        assert!(pe.anomalies.contains(&Anomaly::ChecksumMismatch));
        assert_eq!(pe.overlay_bytes, 64);
    }

    #[test]
    fn the_mapped_image_is_relocated_like_the_loader_does() {
        let bytes = sample_dll();
        let pe = parse(&bytes).unwrap();
        let mut image = mapped_image(&pe, &bytes, 1 << 20).unwrap();
        assert_eq!(image.len(), 0x5000);
        assert_eq!(&image[0x1000..0x1004], &[0x48, 0x83, 0xec, 0x28]);
        relocate(&pe, &mut image, 0x7ff6_0000_0000);
        let fixed = u64::from_le_bytes(image[0x1010..0x1018].try_into().unwrap());
        assert_eq!(fixed, 0x7ff6_0000_2000);
        assert!(mapped_image(&pe, &bytes, 0x100).is_none());
    }

    #[test]
    fn entropy_is_zero_for_one_value_and_eight_for_all() {
        assert_eq!(entropy(&[7; 100]), Some(0.0));
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all).unwrap() - 8.0).abs() < 1e-9);
        assert_eq!(entropy(&[]), None);
    }

    #[test]
    fn garbage_is_an_error_or_a_partial_result_never_a_panic() {
        let base = sample_dll();
        for cut in [
            0, 1, 2, 0x3c, 0x40, 0x84, 0x90, 0x100, 0x180, 0x200, 0x300, 0x500,
        ] {
            let _ = parse(&base[..cut.min(base.len())]);
        }
        // Flip every byte of the headers in turn and parse each result.
        for at in 0..0x200 {
            let mut bytes = base.clone();
            bytes[at] ^= 0xff;
            let _ = parse(&bytes);
        }
        // Pseudo-random bytes behind a valid header.
        let mut state = 0x1234_5678_u32;
        let mut noise = base[..0x200].to_vec();
        for _ in 0..8192 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            noise.push(state.to_le_bytes()[0]);
        }
        let _ = parse(&noise);
        assert!(!is_pe(b"MZ"));
        assert!(parse(b"not a pe at all, but long enough to have a header field........").is_err());
    }
}
