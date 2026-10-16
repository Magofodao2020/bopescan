// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! One executable file's integrity, assessed the same way wherever it was found — on disk by
//! `file_inventory`, loaded in a process by `process_modules`, or in the Roblox player by
//! `roblox_memory` (B.O.P.E, ADR 0133).
//!
//! # What is read
//!
//! The file's SHA-256; its PE structure (`bope_parsers::pe`); what Windows says about its embedded
//! Authenticode signature, offline (ADR 0035), and when that signature was timestamped; and, when it
//! has no valid embedded signature, whether a Windows catalog lists its hash. A catalog listing is the
//! trusted reference for Windows' own files: it is the hash that build of Windows shipped.
//!
//! # The classes
//!
//! | Class | Means |
//! |---|---|
//! | `verified_reference` | a valid Windows catalog lists this exact hash |
//! | `valid_signature` | the embedded signature verifies offline |
//! | `integrity_compromised` | a signature or catalog entry is present and does not verify: the bytes changed after signing, or the certificate is distrusted |
//! | `malicious_corroborated` | the file's name is a known executor or injector **and**, independently, it is unsigned and imports the APIs that write into or start threads in another process |
//! | `suspicious` | unsigned or unverifiable **and** at least one structural or contextual fact an ordinary install does not produce — see [`Reason`] |
//! | `inconclusive` | the signature could not be checked offline, or the file is not a readable image, and nothing else was found |
//! | `unknown` | unsigned, not in a catalog, and nothing else found — most game mods, tools and older software |
//! | `not_verified` | the file could not be read |
//!
//! **No class is a verdict.** An unsigned DLL is not malicious, and a signed one is not safe: a stolen
//! certificate signs as well as a real one, and `allow` in a rule identifies software by hash or by the
//! certificate's hash, never by a name (ADR 0035). Revocation is never checked — that needs the network —
//! and every assessment says so in its limitations.

use std::collections::BTreeSet;

use bope_host::{
    CatalogCheck, Host, MAX_FILE_BYTES, MAX_READ_AT_BYTES, SignatureCheck, SourceError,
};
use bope_parsers::memory::INJECTION_APIS;
use bope_parsers::pe::{self, Anomaly, PeFile};

use crate::common::{Fields, signature_word};
use crate::location;

/// The integrity class of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntegrityClass {
    /// A valid Windows catalog lists the file's hash.
    VerifiedReference,
    /// The embedded signature verifies.
    ValidSignature,
    /// Unsigned, not in a catalog, nothing else found.
    Unknown,
    /// Unsigned or unverifiable with a fact an ordinary install does not produce.
    Suspicious,
    /// A signature or catalog entry that does not verify.
    IntegrityCompromised,
    /// A known cheat-capable name corroborated by independent technical facts.
    MaliciousCorroborated,
    /// The file could not be read.
    NotVerified,
    /// The check could not be completed offline, or the file is not a readable image.
    Inconclusive,
}

impl IntegrityClass {
    /// Stable identifier used in observations and rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedReference => "verified_reference",
            Self::ValidSignature => "valid_signature",
            Self::Unknown => "unknown",
            Self::Suspicious => "suspicious",
            Self::IntegrityCompromised => "integrity_compromised",
            Self::MaliciousCorroborated => "malicious_corroborated",
            Self::NotVerified => "not_verified",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Every class, in report order.
    pub const ALL: [Self; 8] = [
        Self::MaliciousCorroborated,
        Self::IntegrityCompromised,
        Self::Suspicious,
        Self::Inconclusive,
        Self::Unknown,
        Self::NotVerified,
        Self::ValidSignature,
        Self::VerifiedReference,
    ];
}

/// One fact that went into a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// A valid catalog lists the hash.
    InCatalog,
    /// The embedded signature verifies.
    SignatureValid,
    /// The embedded signature is present and does not verify.
    SignatureInvalid,
    /// The catalog entry is present and does not verify.
    CatalogInvalid,
    /// No embedded signature and no catalog entry.
    Unsigned,
    /// A signature or catalog check needed something this machine does not hold offline.
    UnverifiableOffline,
    /// A PE image whose extension is not one executable images use.
    DisguisedExtension,
    /// Named like a file in `System32`/`SysWOW64`, outside the Windows folder, and unsigned.
    SystemNameOutsideWindows,
    /// In the Windows folder, unsigned and not in a catalog.
    UnsignedInWindowsFolder,
    /// The version resource names another original file name.
    OriginalNameDiffers,
    /// A section is writable and executable.
    WritableExecutableSection,
    /// The entry point is outside every section, or in a writable one.
    UnusualEntryPoint,
    /// An executable section has no bytes in the file: it is filled at run time (packers).
    RuntimeFilledCode,
    /// An executable section's bytes are compressed or encrypted (entropy above 7.2).
    PackedCode,
    /// Imports at least two APIs that write into, or start threads in, another process.
    InjectionImports,
    /// The file name matches a known executor or injector in the tool catalog.
    CheatToolName,
    /// In a folder any program running as the user may write to.
    UserWritableLocation,
    /// The file is not a readable PE image.
    NotAnImage,
    /// The file could not be read.
    Unreadable,
}

impl Reason {
    /// Stable identifier used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InCatalog => "in_catalog",
            Self::SignatureValid => "signature_valid",
            Self::SignatureInvalid => "signature_invalid",
            Self::CatalogInvalid => "catalog_invalid",
            Self::Unsigned => "unsigned",
            Self::UnverifiableOffline => "unverifiable_offline",
            Self::DisguisedExtension => "disguised_extension",
            Self::SystemNameOutsideWindows => "system_name_outside_windows",
            Self::UnsignedInWindowsFolder => "unsigned_in_windows_folder",
            Self::OriginalNameDiffers => "original_name_differs",
            Self::WritableExecutableSection => "writable_executable_section",
            Self::UnusualEntryPoint => "unusual_entry_point",
            Self::RuntimeFilledCode => "runtime_filled_code",
            Self::PackedCode => "packed_code",
            Self::InjectionImports => "injection_imports",
            Self::CheatToolName => "cheat_tool_name",
            Self::UserWritableLocation => "user_writable_location",
            Self::NotAnImage => "not_an_image",
            Self::Unreadable => "unreadable",
        }
    }
}

/// Extensions executable images ordinarily carry.
pub const IMAGE_EXTENSIONS: [&str; 12] = [
    "exe", "dll", "sys", "ocx", "scr", "cpl", "drv", "efi", "mui", "ax", "tlb", "acm",
];

/// The extension of `name`, lower-cased, without the dot.
pub fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

/// What one assessment found, ready to become an observation's fields.
#[derive(Debug)]
pub struct Assessment {
    /// The class.
    pub class: IntegrityClass,
    /// What went into it, sorted.
    pub reasons: BTreeSet<Reason>,
    /// What the assessment could not establish.
    pub limitations: BTreeSet<&'static str>,
    /// The SHA-256, when read.
    pub sha256: Option<String>,
    /// The parsed image, when it parsed.
    pub image: Option<PeFile>,
    /// The fields to add to an observation.
    pub fields: Fields,
}

/// Assesses files with the context they share: where Windows is and which names its system folders
/// hold, gathered once.
pub struct Assessor<'h> {
    host: &'h dyn Host,
    windows: String,
    system_names: BTreeSet<String>,
}

impl<'h> Assessor<'h> {
    /// An assessor for `host`, listing `System32` and `SysWOW64` once for their file names.
    pub fn new(host: &'h dyn Host) -> Self {
        let windows = crate::common::env_folder(host, "SystemRoot")
            .or_else(|| crate::common::env_folder(host, "WinDir"))
            .unwrap_or_else(|| r"C:\Windows".to_owned());
        let mut system_names = BTreeSet::new();
        for folder in ["System32", "SysWOW64"] {
            let dir = crate::common::join(&windows, folder);
            for entry in host.list_dir(&dir).ok().flatten().unwrap_or_default() {
                if entry.is_file && matches!(extension(&entry.name).as_str(), "dll" | "exe" | "sys")
                {
                    system_names.insert(entry.name.to_ascii_lowercase());
                }
            }
        }
        Self {
            host,
            windows,
            system_names,
        }
    }

    /// The Windows folder this assessor uses.
    pub fn windows_folder(&self) -> &str {
        &self.windows
    }

    /// How many system file names it knows.
    pub fn system_names(&self) -> usize {
        self.system_names.len()
    }

    /// Whether `path` is under the Windows folder.
    pub fn under_windows(&self, path: &str) -> bool {
        let folder = &self.windows;
        path.len() > folder.len()
            && path.is_char_boundary(folder.len())
            && path[..folder.len()].eq_ignore_ascii_case(folder)
            && path[folder.len()..].starts_with('\\')
    }

    /// The bytes of `path` used for structure and hash: the whole file up to the host's read limit,
    /// else its first [`MAX_READ_AT_BYTES`] — the headers and directories of nearly every image.
    fn bytes(&self, path: &str) -> Result<(Vec<u8>, bool), SourceError> {
        match self.host.read_file(path) {
            Ok(Some(bytes)) => Ok((bytes, true)),
            Ok(None) => Err(SourceError::Failed("the file is gone".to_owned())),
            Err(SourceError::TooLarge { .. }) => self
                .host
                .read_file_at(path, 0, MAX_READ_AT_BYTES)
                .and_then(|bytes| {
                    bytes.ok_or_else(|| SourceError::Failed("the file is gone".to_owned()))
                })
                .map(|bytes| (bytes, false)),
            Err(error) => Err(error),
        }
    }

    /// Assesses the file at `path`.
    #[allow(clippy::too_many_lines)]
    pub fn assess(&self, path: &str) -> Assessment {
        let mut reasons = BTreeSet::new();
        let mut limitations: BTreeSet<&'static str> = BTreeSet::new();
        limitations.insert("revocation_not_checked");
        let name = location::last_segment(path).to_owned();
        let ext = extension(&name);
        let place = location::classify(path);
        let user_writable = place.is_user_writable();
        if user_writable {
            reasons.insert(Reason::UserWritableLocation);
        }
        let mut fields = Fields::new()
            .with("name", name.clone())
            .with("extension", ext.clone())
            .with(location::FIELD, place.as_str());

        let (bytes, whole) = match self.bytes(path) {
            Ok(read) => read,
            Err(error) => {
                reasons.insert(Reason::Unreadable);
                limitations.insert(if error == SourceError::AccessDenied {
                    "access_denied"
                } else {
                    "read_failed"
                });
                return finish(
                    IntegrityClass::NotVerified,
                    reasons,
                    limitations,
                    None,
                    None,
                    fields,
                );
            }
        };
        let sha256 = if whole {
            bope_host::sha256_reader(&bytes[..]).ok()
        } else {
            limitations.insert("larger_than_one_read");
            self.host.file_sha256(path).ok()
        };
        fields = fields.maybe("sha256", sha256.clone());
        if !whole {
            fields = fields.with("partial_structure", true);
        }

        let image = pe::parse(&bytes).ok();
        let Some(image) = image else {
            reasons.insert(Reason::NotAnImage);
            return finish(
                IntegrityClass::Inconclusive,
                reasons,
                limitations,
                sha256,
                None,
                fields,
            );
        };
        if !IMAGE_EXTENSIONS.contains(&ext.as_str()) {
            reasons.insert(Reason::DisguisedExtension);
        }
        fields = describe_image(fields, &image);
        if let Some(original) = image
            .version
            .as_ref()
            .and_then(|v| v.original_filename.as_deref())
        {
            let original = original.trim_end_matches(".mui").trim_end_matches(".MUI");
            if !original.is_empty() && !original.eq_ignore_ascii_case(&name) {
                reasons.insert(Reason::OriginalNameDiffers);
            }
        }
        for anomaly in &image.anomalies {
            match anomaly {
                Anomaly::WritableExecutableSection => {
                    reasons.insert(Reason::WritableExecutableSection);
                }
                Anomaly::EntryPointOutsideSections | Anomaly::EntryPointInWritableSection => {
                    reasons.insert(Reason::UnusualEntryPoint);
                }
                Anomaly::ExecutableSectionWithoutRawData => {
                    reasons.insert(Reason::RuntimeFilledCode);
                }
                Anomaly::HighEntropyExecutableSection => {
                    reasons.insert(Reason::PackedCode);
                }
                _ => {}
            }
        }
        let injection = injection_imports(&image);
        if injection.len() >= 2 {
            reasons.insert(Reason::InjectionImports);
            fields = fields.with("injection_imports", injection.join(","));
        }
        let cheat_name = crate::catalog::match_name(&name).iter().any(|m| {
            m.kind == crate::catalog::MatchKind::KnownTool && m.tool.kind.is_cheat_capable()
        });
        if cheat_name {
            reasons.insert(Reason::CheatToolName);
        }

        // Signatures: embedded first; the catalog when there is no valid embedded one.
        let mut signed = false;
        let mut unverifiable = false;
        let mut compromised = false;
        match self.host.file_signature(path) {
            Ok(check) => {
                fields = fields.with("signature", signature_word(&check));
                match check {
                    SignatureCheck::Valid {
                        signer,
                        signer_cert_sha256,
                    } => {
                        signed = true;
                        reasons.insert(Reason::SignatureValid);
                        fields = fields
                            .with("signer", signer)
                            .with("signer_cert_sha256", signer_cert_sha256);
                        if let Ok(Some(at)) = self.host.signing_time(path) {
                            fields = fields.time("signed_at", Some(at));
                        }
                    }
                    SignatureCheck::Invalid => {
                        compromised = true;
                        reasons.insert(Reason::SignatureInvalid);
                    }
                    SignatureCheck::UnverifiableOffline => unverifiable = true,
                    SignatureCheck::NoEmbeddedSignature => {}
                }
            }
            Err(_) => {
                limitations.insert("signature_not_checked");
            }
        }
        let mut in_catalog = false;
        if signed {
            limitations.insert("catalog_not_checked");
        } else {
            match self.host.catalog_signature(path) {
                Ok(CatalogCheck::Signed {
                    catalog,
                    signer,
                    signer_cert_sha256,
                }) => {
                    in_catalog = true;
                    reasons.insert(Reason::InCatalog);
                    fields = fields
                        .with("catalog", "signed")
                        .with("catalog_file", catalog)
                        .with("catalog_signer", signer)
                        .with("catalog_signer_cert_sha256", signer_cert_sha256);
                }
                Ok(CatalogCheck::NotInCatalog) => fields = fields.with("catalog", "not_in_catalog"),
                Ok(CatalogCheck::Invalid) => {
                    compromised = true;
                    reasons.insert(Reason::CatalogInvalid);
                    fields = fields.with("catalog", "invalid");
                }
                Ok(CatalogCheck::UnverifiableOffline) => {
                    unverifiable = true;
                    fields = fields.with("catalog", "unverifiable_offline");
                }
                Err(_) => {
                    limitations.insert("catalog_not_checked");
                }
            }
        }
        if unverifiable {
            reasons.insert(Reason::UnverifiableOffline);
            limitations.insert("needs_network_to_verify");
        }
        let unsigned = !signed && !in_catalog && !compromised;
        if unsigned && !unverifiable {
            reasons.insert(Reason::Unsigned);
        }
        let in_windows = self.under_windows(path);
        if unsigned && !unverifiable && in_windows {
            reasons.insert(Reason::UnsignedInWindowsFolder);
        }
        if unsigned && !in_windows && self.system_names.contains(&name.to_ascii_lowercase()) {
            reasons.insert(Reason::SystemNameOutsideWindows);
        }

        let class = if compromised {
            IntegrityClass::IntegrityCompromised
        } else if in_catalog {
            IntegrityClass::VerifiedReference
        } else if signed {
            IntegrityClass::ValidSignature
        } else if cheat_name && reasons.contains(&Reason::InjectionImports) && !unverifiable {
            IntegrityClass::MaliciousCorroborated
        } else if [
            Reason::DisguisedExtension,
            Reason::SystemNameOutsideWindows,
            Reason::UnsignedInWindowsFolder,
            Reason::WritableExecutableSection,
            Reason::UnusualEntryPoint,
            Reason::RuntimeFilledCode,
            Reason::CheatToolName,
        ]
        .iter()
        .any(|r| reasons.contains(r))
            || (user_writable
                && (reasons.contains(&Reason::InjectionImports)
                    || (reasons.contains(&Reason::PackedCode)
                        && reasons.contains(&Reason::OriginalNameDiffers))))
        {
            IntegrityClass::Suspicious
        } else if unverifiable {
            IntegrityClass::Inconclusive
        } else {
            IntegrityClass::Unknown
        };
        finish(class, reasons, limitations, sha256, Some(image), fields)
    }
}

fn finish(
    class: IntegrityClass,
    reasons: BTreeSet<Reason>,
    limitations: BTreeSet<&'static str>,
    sha256: Option<String>,
    image: Option<PeFile>,
    fields: Fields,
) -> Assessment {
    let fields = fields
        .with("integrity_class", class.as_str())
        .with(
            "integrity_reasons",
            reasons
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
        .with(
            "limitations",
            limitations.iter().copied().collect::<Vec<_>>().join(","),
        );
    Assessment {
        class,
        reasons,
        limitations,
        sha256,
        image,
        fields,
    }
}

/// The injection APIs an image imports, sorted, each once.
pub fn injection_imports(image: &PeFile) -> Vec<&'static str> {
    let mut found: BTreeSet<&'static str> = BTreeSet::new();
    for dll in &image.imports {
        for function in &dll.functions {
            if let Some(api) = INJECTION_APIS.iter().find(|api| **api == function.as_str()) {
                found.insert(api);
            }
        }
    }
    found.into_iter().collect()
}

/// The structural fields of an image.
pub fn describe_image(fields: Fields, image: &PeFile) -> Fields {
    let version = image.version.clone().unwrap_or_default();
    fields
        .with("machine", image.machine.as_str())
        .with("is_dll", image.is_dll)
        .with("subsystem", image.subsystem)
        .with("pe_timestamp", image.timestamp)
        .with("sections", image.sections.len())
        .with(
            "section_permissions",
            image
                .sections
                .iter()
                .map(|s| format!("{}:{}", s.name, s.permissions()))
                .collect::<Vec<_>>()
                .join(","),
        )
        .with("imported_dlls", image.imports.len())
        .with(
            "exports",
            image.exports.as_ref().map_or(0, |e| e.functions.len()),
        )
        .with("tls_callbacks", image.tls_callbacks.len())
        .with("clr", image.clr)
        .with("overlay_bytes", image.overlay_bytes)
        .with(
            "checksum_matches",
            image.header_checksum == 0 || image.header_checksum == image.computed_checksum,
        )
        .with(
            "pe_anomalies",
            image
                .anomalies
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
        .maybe("company", version.company_name)
        .maybe("product", version.product_name)
        .maybe(
            "file_version",
            version.file_version.or(version.fixed_file_version),
        )
        .maybe("original_filename", version.original_filename)
        .maybe("file_description", version.file_description)
}

/// Whether bytes at the start of a file make it a PE image: the check used for files whose extension
/// does not say so.
pub fn sniff(host: &dyn Host, path: &str) -> Result<bool, SourceError> {
    let head = host
        .read_file_at(path, 0, 4096)?
        .ok_or_else(|| SourceError::Failed("the file is gone".to_owned()))?;
    Ok(pe::is_pe(&head))
}

/// The most bytes [`Assessor`] reads in one piece, for documentation and tests.
pub const WHOLE_FILE_LIMIT: usize = MAX_FILE_BYTES;

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        crate::common::hex(bytes)
    }

    fn host_with(files: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nfilesystem:\n  'C:\\Windows\\System32':\n    - {{ name: version.dll, sha256: '{z}', signature: {{ state: no_embedded_signature }}, catalog: {{ state: signed, catalog: 'a.cat', signer: Microsoft Windows, signer_cert_sha256: '{z}' }} }}\n{files}",
                z = "0".repeat(64)
            ),
            "inline",
        )
        .unwrap()
    }

    #[test]
    fn a_catalog_listed_system_file_is_the_verified_reference() {
        let dll = hex(&bope_parsers_sample());
        let host = host_with(&format!(
            "  'C:\\Windows\\System32\\x':\n    - {{ name: a.dll, hex: '{dll}', signature: {{ state: no_embedded_signature }}, catalog: {{ state: signed, catalog: 'b.cat', signer: Microsoft Windows, signer_cert_sha256: '{}' }} }}\n",
            "1".repeat(64)
        ));
        let assessor = Assessor::new(&host);
        assert_eq!(assessor.system_names(), 1);
        let found = assessor.assess(r"C:\Windows\System32\x\a.dll");
        assert_eq!(
            found.class,
            IntegrityClass::VerifiedReference,
            "{:?}",
            found.reasons
        );
        assert!(found.sha256.is_some());
        assert_eq!(found.fields.0["machine"], "x64");
        assert_eq!(found.fields.0["catalog_file"], "b.cat");
    }

    #[test]
    fn a_system_name_outside_windows_unsigned_is_suspicious_and_a_bad_signature_is_compromised() {
        let dll = hex(&bope_parsers_sample());
        let host = host_with(&format!(
            "  'C:\\Users\\a\\Downloads':\n    - {{ name: version.dll, hex: '{dll}', signature: {{ state: no_embedded_signature }}, catalog: {{ state: not_in_catalog }} }}\n    - {{ name: tool.dll, hex: '{dll}', signature: {{ state: invalid }} }}\n    - {{ name: plain.dll, hex: '{dll}', signature: {{ state: no_embedded_signature }}, catalog: {{ state: not_in_catalog }} }}\n    - {{ name: picture.jpg, hex: '{dll}', signature: {{ state: no_embedded_signature }}, catalog: {{ state: not_in_catalog }} }}\n    - {{ name: notes.dll, content: 'hello', signature: {{ state: no_embedded_signature }}, catalog: {{ state: not_in_catalog }} }}\n"
        ));
        let assessor = Assessor::new(&host);
        let masquerade = assessor.assess(r"C:\Users\a\Downloads\version.dll");
        assert_eq!(masquerade.class, IntegrityClass::Suspicious);
        assert!(
            masquerade
                .reasons
                .contains(&Reason::SystemNameOutsideWindows)
        );
        let tampered = assessor.assess(r"C:\Users\a\Downloads\tool.dll");
        assert_eq!(tampered.class, IntegrityClass::IntegrityCompromised);
        let plain = assessor.assess(r"C:\Users\a\Downloads\plain.dll");
        assert_eq!(plain.class, IntegrityClass::Unknown, "{:?}", plain.reasons);
        assert!(plain.limitations.contains("revocation_not_checked"));
        let disguised = assessor.assess(r"C:\Users\a\Downloads\picture.jpg");
        assert_eq!(disguised.class, IntegrityClass::Suspicious);
        assert!(disguised.reasons.contains(&Reason::DisguisedExtension));
        let not_image = assessor.assess(r"C:\Users\a\Downloads\notes.dll");
        assert_eq!(not_image.class, IntegrityClass::Inconclusive);
        let gone = assessor.assess(r"C:\Users\a\Downloads\missing.dll");
        assert_eq!(gone.class, IntegrityClass::NotVerified);
    }

    /// The parser crate's own sample DLL, rebuilt here from its public API is not possible, so the
    /// bytes come from a minimal hand-written image with one `.text` section.
    fn bope_parsers_sample() -> Vec<u8> {
        let mut file = vec![0_u8; 0x400];
        file[0..2].copy_from_slice(b"MZ");
        file[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        file[0x40..0x44].copy_from_slice(b"PE\0\0");
        let fh = 0x44;
        file[fh..fh + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        file[fh + 2..fh + 4].copy_from_slice(&1_u16.to_le_bytes());
        file[fh + 16..fh + 18].copy_from_slice(&240_u16.to_le_bytes());
        file[fh + 18..fh + 20].copy_from_slice(&0x2022_u16.to_le_bytes());
        let oh = fh + 20;
        file[oh..oh + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        file[oh + 16..oh + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        file[oh + 24..oh + 32].copy_from_slice(&0x1_8000_0000_u64.to_le_bytes());
        file[oh + 56..oh + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
        file[oh + 60..oh + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        file[oh + 108..oh + 112].copy_from_slice(&16_u32.to_le_bytes());
        let st = oh + 240;
        file[st..st + 5].copy_from_slice(b".text");
        file[st + 8..st + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        file[st + 12..st + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        file[st + 16..st + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        file[st + 20..st + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        file[st + 36..st + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        file[0x200..0x204].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        file
    }
}
