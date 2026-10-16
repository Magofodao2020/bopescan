// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The Authenticode signature embedded in a file, as `WinVerifyTrust` sees it without the network
//! (ADR 0035).
//!
//! **This is the one read in the program that could reach the network on its own.** Chain building and
//! revocation checking fetch certificates and revocation lists from URLs a certificate names, inside
//! the operating system and outside anything `cargo deny` or a lint can see. [`OFFLINE`] is what stops
//! that: no revocation checking, and URL retrieval from the local cache only — the flag Microsoft's
//! `WINTRUST_DATA` documentation names as required "to ensure the `WinVerifyTrust` function does not
//! attempt any network retrieval". The Windows CI job proves it on a real machine by reading the CAPI2
//! log for network retrievals, next to a run that is allowed to fetch and does.

/// The result codes this module tells apart, written out rather than imported from `windows` so that
/// [`classify`] compiles and is tested on every operating system, as `tpm.rs` does. The values are
/// those `windows` 0.62.2 declares in `Win32::Foundation`; a Windows-only test compares them.
pub mod codes {
    /// The signature verified.
    pub const S_OK: u32 = 0;
    /// `TRUST_E_NOSIGNATURE`: no signature was found in the file.
    pub const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
    /// `TRUST_E_SUBJECT_FORM_UNKNOWN`: not a kind of file a signature can be embedded in.
    pub const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
    /// `TRUST_E_BAD_DIGEST`: the file changed after it was signed.
    pub const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
    /// `TRUST_E_EXPLICIT_DISTRUST`: the certificate is marked as distrusted on this machine.
    pub const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
    /// `TRUST_E_SUBJECT_NOT_TRUSTED`: the subject failed the policy.
    pub const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B_0004;
    /// `TRUST_E_CERT_SIGNATURE`: a certificate's own signature does not verify.
    pub const TRUST_E_CERT_SIGNATURE: u32 = 0x8009_6004;
    /// `TRUST_E_NO_SIGNER_CERT`: the signature names no signing certificate.
    pub const TRUST_E_NO_SIGNER_CERT: u32 = 0x8009_6002;
    /// `CERT_E_UNTRUSTEDROOT`: the chain ends in a self-signed root this machine does not trust. Measured
    /// both for a genuine signature that carries its own root on a machine whose stores lack it, and for
    /// a self-signed one (ADR 0035, amendment of 2026-09-14).
    pub const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
    /// `CERT_E_EXPIRED`: the certificate expired and the signature carries no timestamp from before.
    pub const CERT_E_EXPIRED: u32 = 0x800B_0101;
    /// `CERT_E_WRONG_USAGE`: the certificate is not valid for code signing.
    pub const CERT_E_WRONG_USAGE: u32 = 0x800B_0110;
    /// `CERT_E_REVOKED`: revoked, according to revocation data this machine already holds.
    pub const CERT_E_REVOKED: u32 = 0x800B_010C;
    /// `CERT_E_CHAINING`: a chain to a trusted root could not be built from what is held locally. Measured
    /// for a genuine signature that does not carry its root, on a machine whose stores lack it.
    pub const CERT_E_CHAINING: u32 = 0x800B_010A;
    /// `CRYPT_E_REVOCATION_OFFLINE`: revocation data was needed and not available.
    pub const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
    /// `CERT_E_REVOCATION_FAILURE`: revocation could not be determined.
    pub const CERT_E_REVOCATION_FAILURE: u32 = 0x800B_010E;
    /// `CRYPT_E_NO_REVOCATION_CHECK`: no revocation check could be made.
    pub const CRYPT_E_NO_REVOCATION_CHECK: u32 = 0x8009_2012;
    /// `E_ACCESSDENIED`, as `HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)`.
    pub const E_ACCESSDENIED: u32 = 0x8007_0005;
}

/// What one `WinVerifyTrust` result code says, before a signer has been read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Verified; the signer is read from the state data next.
    Verified,
    /// No embedded signature, or not a signable kind of file.
    NoEmbeddedSignature,
    /// A signature is there and is not trusted.
    Invalid,
    /// Needed something this machine does not hold locally, or ended at a root it does not hold as
    /// trusted — which offline cannot tell apart from a root nobody trusts.
    UnverifiableOffline,
    /// The file could not be opened.
    AccessDenied,
    /// Anything else: not an answer about the signature.
    Failed,
}

/// Classifies a `WinVerifyTrust` result code (ADR 0035).
///
/// A code this module does not name is [`Verdict::Failed`], never one of the three answers: saying a
/// file's signature is invalid on a code nobody read would be a guess about someone's software.
pub fn classify(result: u32) -> Verdict {
    use codes::{
        CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOCATION_FAILURE, CERT_E_REVOKED,
        CERT_E_UNTRUSTEDROOT, CERT_E_WRONG_USAGE, CRYPT_E_NO_REVOCATION_CHECK,
        CRYPT_E_REVOCATION_OFFLINE, E_ACCESSDENIED, S_OK, TRUST_E_BAD_DIGEST,
        TRUST_E_CERT_SIGNATURE, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NO_SIGNER_CERT,
        TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
    };
    match result {
        S_OK => Verdict::Verified,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN => Verdict::NoEmbeddedSignature,
        TRUST_E_BAD_DIGEST
        | TRUST_E_EXPLICIT_DISTRUST
        | TRUST_E_SUBJECT_NOT_TRUSTED
        | TRUST_E_CERT_SIGNATURE
        | TRUST_E_NO_SIGNER_CERT
        | CERT_E_EXPIRED
        | CERT_E_WRONG_USAGE
        | CERT_E_REVOKED => Verdict::Invalid,
        // A root this machine does not hold as trusted is `CERT_E_CHAINING` when the signature does not
        // carry the root and `CERT_E_UNTRUSTEDROOT` when it does; a self-signed signature is the second
        // too. Offline, the two cannot be told apart, and a genuine publisher's file must not read as
        // `invalid` on a PC that has not fetched its root yet (ADR 0035, amendment of 2026-09-14).
        CERT_E_CHAINING
        | CERT_E_UNTRUSTEDROOT
        | CRYPT_E_REVOCATION_OFFLINE
        | CERT_E_REVOCATION_FAILURE
        | CRYPT_E_NO_REVOCATION_CHECK => Verdict::UnverifiableOffline,
        E_ACCESSDENIED => Verdict::AccessDenied,
        _ => Verdict::Failed,
    }
}

/// `WINTRUST_DATA` values, written out for the same reason as [`codes`].
pub mod flags {
    /// `WTD_UI_NONE`.
    pub const WTD_UI_NONE: u32 = 2;
    /// `WTD_CHOICE_FILE`.
    pub const WTD_CHOICE_FILE: u32 = 1;
    /// `WTD_STATEACTION_VERIFY`.
    pub const WTD_STATEACTION_VERIFY: u32 = 1;
    /// `WTD_STATEACTION_CLOSE`.
    pub const WTD_STATEACTION_CLOSE: u32 = 2;
    /// `WTD_REVOKE_NONE`: no revocation checking added to the policy's own.
    pub const WTD_REVOKE_NONE: u32 = 0;
    /// `WTD_REVOKE_WHOLECHAIN`: revocation checking on the whole chain.
    pub const WTD_REVOKE_WHOLECHAIN: u32 = 1;
    /// `WTD_REVOCATION_CHECK_NONE`: the provider checks no revocation.
    pub const WTD_REVOCATION_CHECK_NONE: u32 = 0x10;
    /// `WTD_REVOCATION_CHECK_CHAIN`: the provider checks revocation on the whole chain.
    pub const WTD_REVOCATION_CHECK_CHAIN: u32 = 0x40;
    /// `WTD_CACHE_ONLY_URL_RETRIEVAL`: URL retrieval from the local cache only.
    pub const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;
}

/// How a check is allowed to go about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustSettings {
    /// `WINTRUST_DATA::fdwRevocationChecks`.
    pub revocation_checks: u32,
    /// `WINTRUST_DATA::dwProvFlags`.
    pub provider_flags: u32,
}

/// The only settings the product uses: nothing fetched, nothing revoked by lookup (ADR 0035).
pub const OFFLINE: TrustSettings = TrustSettings {
    revocation_checks: flags::WTD_REVOKE_NONE,
    provider_flags: flags::WTD_REVOCATION_CHECK_NONE | flags::WTD_CACHE_ONLY_URL_RETRIEVAL,
};

/// Settings that let Windows fetch: whole-chain revocation checking and no cache-only restriction.
/// Never used by the product. It exists so the Windows CI job can show that the CAPI2 log does record
/// a network retrieval when one happens — without it, an empty log would prove nothing.
#[cfg(all(windows, test))]
const ONLINE: TrustSettings = TrustSettings {
    revocation_checks: flags::WTD_REVOKE_WHOLECHAIN,
    provider_flags: flags::WTD_REVOCATION_CHECK_CHAIN,
};

#[cfg(windows)]
impl bope_host::SignatureSource for crate::LiveHost {
    fn file_signature(
        &self,
        path: &str,
    ) -> Result<bope_host::SignatureCheck, bope_host::SourceError> {
        verify(path, OFFLINE)
    }

    fn catalog_signature(
        &self,
        path: &str,
    ) -> Result<bope_host::CatalogCheck, bope_host::SourceError> {
        catalog::check(path)
    }

    fn signing_time(&self, path: &str) -> Result<Option<jiff::Timestamp>, bope_host::SourceError> {
        let (_, outcome, time) = verify_full(path, OFFLINE);
        outcome.map(|_| time)
    }
}

/// A `FILETIME` value as a timestamp in whole seconds.
#[cfg(windows)]
fn filetime_timestamp(filetime: windows::Win32::Foundation::FILETIME) -> Option<jiff::Timestamp> {
    let value = (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime);
    bope_host::process_started_at(value)
}

/// Runs `WinVerifyTrust` on the file at `path` with `settings`, reads the signer when it verified, and
/// always closes the state data it opened.
#[cfg(windows)]
fn verify(
    path: &str,
    settings: TrustSettings,
) -> Result<bope_host::SignatureCheck, bope_host::SourceError> {
    verify_with_code(path, settings).1
}

/// [`verify_with_code`], with the signature's timestamp.
#[cfg(windows)]
fn verify_full(
    path: &str,
    settings: TrustSettings,
) -> (
    Option<u32>,
    Result<bope_host::SignatureCheck, bope_host::SourceError>,
    Option<jiff::Timestamp>,
) {
    let mut time = None;
    let (code, outcome) = verify_inner(path, settings, &mut time);
    (code, outcome, time)
}

/// [`verify`], also returning the code `WinVerifyTrust` gave, or `None` when the call was not made. The
/// live tests print it: ADR 0035's table maps codes, and the mapped answer alone cannot say which code
/// produced it.
#[cfg(windows)]
fn verify_with_code(
    path: &str,
    settings: TrustSettings,
) -> (
    Option<u32>,
    Result<bope_host::SignatureCheck, bope_host::SourceError>,
) {
    verify_inner(path, settings, &mut None)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn verify_inner(
    path: &str,
    settings: TrustSettings,
    signed_at: &mut Option<jiff::Timestamp>,
) -> (
    Option<u32>,
    Result<bope_host::SignatureCheck, bope_host::SourceError>,
) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use bope_host::{SignatureCheck, SourceError};
    use windows::Win32::Foundation::{HANDLE, HWND, INVALID_HANDLE_VALUE};
    use windows::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_PROVIDER_FLAGS,
        WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_UICHOICE,
        WINTRUST_DATA_UNION_CHOICE, WINTRUST_FILE_INFO, WinVerifyTrust,
    };
    use windows::core::PCWSTR;

    let (Ok(data_size), Ok(file_size)) = (
        u32::try_from(size_of::<WINTRUST_DATA>()),
        u32::try_from(size_of::<WINTRUST_FILE_INFO>()),
    ) else {
        return (
            None,
            Err(SourceError::Failed(
                "WINTRUST structures do not fit in a u32".to_owned(),
            )),
        );
    };

    // Owned here and outliving both calls: `file` and `data` only hold pointers into these.
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: file_size,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: data_size,
        dwUIChoice: WINTRUST_DATA_UICHOICE(flags::WTD_UI_NONE),
        fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(settings.revocation_checks),
        dwUnionChoice: WINTRUST_DATA_UNION_CHOICE(flags::WTD_CHOICE_FILE),
        dwStateAction: WINTRUST_DATA_STATE_ACTION(flags::WTD_STATEACTION_VERIFY),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(settings.provider_flags),
        ..Default::default()
    };
    data.Anonymous.pFile = &raw mut file;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // No window: `INVALID_HANDLE_VALUE` together with `WTD_UI_NONE` means no dialog can appear.
    let no_window = HWND(INVALID_HANDLE_VALUE.0);

    // SAFETY: `action`, `data`, `file` and `wide` are initialised locals that outlive the call; `data`
    // is a `WINTRUST_DATA` whose `cbStruct` is its own size and whose union holds the `pFile` that
    // `dwUnionChoice` names. `WTD_STATEACTION_VERIFY` asks for state data, closed below on every path.
    let result = unsafe { WinVerifyTrust(no_window, &raw mut action, (&raw mut data).cast()) };
    // `WinVerifyTrust` returns a signed `LONG` holding an HRESULT; its bits are the code.
    let verdict = classify(result.cast_unsigned());

    let outcome = match verdict {
        Verdict::Verified => read_signer(data.hWVTStateData, signed_at),
        Verdict::NoEmbeddedSignature => Ok(SignatureCheck::NoEmbeddedSignature),
        Verdict::Invalid => Ok(SignatureCheck::Invalid),
        Verdict::UnverifiableOffline => Ok(SignatureCheck::UnverifiableOffline),
        Verdict::AccessDenied => Err(SourceError::AccessDenied),
        Verdict::Failed => Err(SourceError::Failed(format!(
            "WinVerifyTrust returned {:#010x}",
            result.cast_unsigned()
        ))),
    };

    data.dwStateAction = WINTRUST_DATA_STATE_ACTION(flags::WTD_STATEACTION_CLOSE);
    // SAFETY: the same `data`, still pointing at live `file` and `wide`, with `hWVTStateData` as the
    // verify call left it. `WTD_STATEACTION_CLOSE` is required after every `WTD_STATEACTION_VERIFY` and
    // releases that state; its result says nothing about the file and is not read.
    unsafe {
        WinVerifyTrust(no_window, &raw mut action, (&raw mut data).cast());
    }
    (Some(result.cast_unsigned()), outcome)
}

/// The signing certificate of a verified file: its subject's display name and the SHA-256 of its
/// encoded bytes. Must be called before the state data is closed.
#[cfg(windows)]
#[allow(unsafe_code)]
fn read_signer(
    state: windows::Win32::Foundation::HANDLE,
    signed_at: &mut Option<jiff::Timestamp>,
) -> Result<bope_host::SignatureCheck, bope_host::SourceError> {
    use bope_host::{SignatureCheck, SourceError};
    use windows::Win32::Security::Cryptography::{
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
    };
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    };

    let missing = |what: &str| SourceError::Failed(format!("a verified signature had no {what}"));

    // SAFETY: `state` is the live state data of a verify call that has not been closed yet.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() {
        return Err(missing("provider data"));
    }
    // SAFETY: `provider` is non-null and owned by that same state data; signer 0, not a countersigner.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    // SAFETY: a non-null signer is a `CRYPT_PROVIDER_SGNR` owned by the state data, read in place.
    let Some(signer) = (unsafe { signer.as_ref() }) else {
        return Err(missing("signer"));
    };
    // `sftVerifyAsOf` is the time the signature was verified as of: the countersigner's
    // (timestamping authority's) time when there is one, and the current time otherwise, which is not
    // a signing time and is not reported.
    if signer.csCounterSigners > 0 {
        *signed_at = filetime_timestamp(signer.sftVerifyAsOf);
    }
    if signer.csCertChain == 0 || signer.pasCertChain.is_null() {
        return Err(missing("certificate chain"));
    }
    // SAFETY: `pasCertChain` holds `csCertChain` (at least one) entries; entry 0 is the signing
    // certificate, and its `pCert` is a certificate context owned by the state data.
    let Some(cert) = (unsafe { (*signer.pasCertChain).pCert.as_ref() }) else {
        return Err(missing("signing certificate"));
    };
    if cert.pbCertEncoded.is_null() || cert.cbCertEncoded == 0 {
        return Err(missing("encoded certificate"));
    }
    let Ok(encoded_len) = usize::try_from(cert.cbCertEncoded) else {
        return Err(missing("addressable certificate"));
    };
    // SAFETY: `pbCertEncoded` points at `cbCertEncoded` bytes owned by the certificate context, which
    // lives as long as the state data; they are copied into the digest before anything is closed.
    let encoded = unsafe { std::slice::from_raw_parts(cert.pbCertEncoded, encoded_len) };
    let signer_cert_sha256 = bope_host::sha256_reader(encoded)
        .map_err(|error| SourceError::Failed(error.to_string()))?;

    // SAFETY: `cert` is a live certificate context; with no buffer the call returns the length needed,
    // counting the terminating NUL.
    let needed = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    let Ok(needed) = usize::try_from(needed) else {
        return Err(missing("subject name"));
    };
    let mut name = vec![0_u16; needed.max(1)];
    // SAFETY: `name` is a writable buffer of the length the previous call asked for.
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name),
        )
    };
    let written = usize::try_from(written).unwrap_or(0);
    let signer_name = String::from_utf16_lossy(&name[..written.saturating_sub(1).min(name.len())]);
    if signer_name.trim().is_empty() {
        return Err(missing("subject name"));
    }

    Ok(SignatureCheck::Valid {
        signer: signer_name,
        signer_cert_sha256,
    })
}

/// Windows catalog membership: whether a catalog under `CatRoot` lists the file's hash, and whether
/// that catalog's signature verifies offline (B.O.P.E, ADR 0133).
///
/// The file is opened with `std::fs::File::open` — read access, every share mode — so nothing is
/// locked and no banned call is needed.
#[cfg(windows)]
mod catalog {
    use std::os::windows::io::AsRawHandle;

    use bope_host::{CatalogCheck, SignatureCheck, SourceError};
    use windows::Win32::Foundation::HANDLE;

    use super::{OFFLINE, Verdict, classify, flags, read_signer};

    /// `WTD_CHOICE_CATALOG`.
    const WTD_CHOICE_CATALOG: u32 = 2;

    /// An admin context and the catalog context found with it, released in that order.
    struct Admin {
        admin: isize,
        catalog: isize,
    }

    impl Drop for Admin {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            use windows::Win32::Security::Cryptography::Catalog::{
                CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
            };
            if self.catalog != 0 {
                // SAFETY: a catalog context enumerated with `admin`, released once.
                let _ = unsafe { CryptCATAdminReleaseCatalogContext(self.admin, self.catalog, 0) };
            }
            if self.admin != 0 {
                // SAFETY: an admin context acquired here, released once.
                let _ = unsafe { CryptCATAdminReleaseContext(self.admin, 0) };
            }
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Hashes the file with a catalog admin context for `algorithm` (`SHA256`, or `None` for the
    /// legacy SHA-1 context older catalogs use) and finds a catalog listing that hash.
    #[allow(unsafe_code)]
    fn find(file: HANDLE, algorithm: Option<&str>) -> Result<(Admin, Vec<u8>), SourceError> {
        use windows::Win32::Security::Cryptography::Catalog::{
            CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
            CryptCATAdminEnumCatalogFromHash,
        };
        use windows::core::PCWSTR;

        let name = algorithm.map(wide);
        let mut admin = Admin {
            admin: 0,
            catalog: 0,
        };
        // SAFETY: `admin.admin` is a valid out-pointer; default subsystem, no strong-hash policy;
        // `name` outlives the call.
        unsafe {
            CryptCATAdminAcquireContext2(
                &raw mut admin.admin,
                None,
                name.as_ref().map_or(PCWSTR::null(), |n| PCWSTR(n.as_ptr())),
                None,
                None,
            )
        }
        .map_err(|error| SourceError::Failed(format!("CryptCATAdminAcquireContext2: {error}")))?;
        let mut size = 0_u32;
        // SAFETY: a size query with no buffer; `size` receives the length.
        let _ = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin.admin, file, &raw mut size, None, None)
        };
        if size == 0 || size > 64 {
            return Err(SourceError::Failed(
                "the catalog hash of the file could not be computed".to_owned(),
            ));
        }
        let mut hash = vec![0_u8; size as usize];
        // SAFETY: `hash` holds `size` writable bytes; the file handle is open for reading.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin.admin,
                file,
                &raw mut size,
                Some(hash.as_mut_ptr()),
                None,
            )
        }
        .map_err(|error| {
            SourceError::Failed(format!("CryptCATAdminCalcHashFromFileHandle2: {error}"))
        })?;
        // SAFETY: `hash` is the digest just computed; no previous catalog context.
        admin.catalog = unsafe { CryptCATAdminEnumCatalogFromHash(admin.admin, &hash, None, None) };
        Ok((admin, hash))
    }

    pub(super) fn check(path: &str) -> Result<CatalogCheck, SourceError> {
        let file = std::fs::File::open(path).map_err(|error| SourceError::from_io(&error))?;
        let handle = HANDLE(file.as_raw_handle());
        let (mut admin, mut hash) = find(handle, Some("SHA256"))?;
        if admin.catalog == 0 {
            drop(admin);
            (admin, hash) = find(handle, None)?;
        }
        if admin.catalog == 0 {
            return Ok(CatalogCheck::NotInCatalog);
        }
        let outcome = verify_member(path, handle, &admin, &mut hash);
        drop(admin);
        drop(file);
        outcome
    }

    /// Verifies the catalog membership `admin` found, offline.
    #[allow(unsafe_code)]
    fn verify_member(
        path: &str,
        file: HANDLE,
        admin: &Admin,
        hash: &mut [u8],
    ) -> Result<CatalogCheck, SourceError> {
        use std::fmt::Write as _;

        use windows::Win32::Foundation::{HWND, INVALID_HANDLE_VALUE};
        use windows::Win32::Security::Cryptography::Catalog::{
            CATALOG_INFO, CryptCATCatalogInfoFromContext,
        };
        use windows::Win32::Security::WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
            WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_REVOCATION_CHECKS,
            WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_UICHOICE, WINTRUST_DATA_UNION_CHOICE,
            WinVerifyTrust,
        };
        use windows::core::PCWSTR;

        let mut info = CATALOG_INFO {
            cbStruct: u32::try_from(size_of::<CATALOG_INFO>()).unwrap_or(0),
            ..Default::default()
        };
        // SAFETY: `info` is a `CATALOG_INFO` whose `cbStruct` is its size; the context is live.
        unsafe { CryptCATCatalogInfoFromContext(admin.catalog, &raw mut info, 0) }.map_err(
            |error| SourceError::Failed(format!("CryptCATCatalogInfoFromContext: {error}")),
        )?;
        let catalog_path = info.wszCatalogFile;
        let length = catalog_path
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(catalog_path.len());
        let catalog_file = String::from_utf16_lossy(&catalog_path[..length]);
        let tag = hash.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02X}");
            out
        });
        let tag_wide = wide(&tag);
        let path_wide = wide(path);
        let mut member = WINTRUST_CATALOG_INFO {
            cbStruct: u32::try_from(size_of::<WINTRUST_CATALOG_INFO>()).unwrap_or(0),
            dwCatalogVersion: 0,
            pcwszCatalogFilePath: PCWSTR(catalog_path.as_ptr()),
            pcwszMemberTag: PCWSTR(tag_wide.as_ptr()),
            pcwszMemberFilePath: PCWSTR(path_wide.as_ptr()),
            hMemberFile: file,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: u32::try_from(hash.len()).unwrap_or(0),
            pcCatalogContext: std::ptr::null_mut(),
            hCatAdmin: admin.admin,
        };
        let mut data = WINTRUST_DATA {
            cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(0),
            dwUIChoice: WINTRUST_DATA_UICHOICE(flags::WTD_UI_NONE),
            fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(OFFLINE.revocation_checks),
            dwUnionChoice: WINTRUST_DATA_UNION_CHOICE(WTD_CHOICE_CATALOG),
            dwStateAction: WINTRUST_DATA_STATE_ACTION(flags::WTD_STATEACTION_VERIFY),
            dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(OFFLINE.provider_flags),
            ..Default::default()
        };
        data.Anonymous.pCatalog = &raw mut member;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let no_window = HWND(INVALID_HANDLE_VALUE.0);
        // SAFETY: every structure is a live local; the union holds the `pCatalog` its choice names;
        // the state is closed below on every path.
        let result = unsafe { WinVerifyTrust(no_window, &raw mut action, (&raw mut data).cast()) };
        let outcome = match classify(result.cast_unsigned()) {
            Verdict::Verified => match read_signer(data.hWVTStateData, &mut None)? {
                SignatureCheck::Valid {
                    signer,
                    signer_cert_sha256,
                } => Ok(CatalogCheck::Signed {
                    catalog: catalog_file
                        .rsplit('\\')
                        .next()
                        .unwrap_or(&catalog_file)
                        .to_owned(),
                    signer,
                    signer_cert_sha256,
                }),
                _ => Ok(CatalogCheck::Invalid),
            },
            Verdict::NoEmbeddedSignature | Verdict::Invalid => Ok(CatalogCheck::Invalid),
            Verdict::UnverifiableOffline => Ok(CatalogCheck::UnverifiableOffline),
            Verdict::AccessDenied => Err(SourceError::AccessDenied),
            Verdict::Failed => Err(SourceError::Failed(format!(
                "WinVerifyTrust (catalog) returned {:#010x}",
                result.cast_unsigned()
            ))),
        };
        data.dwStateAction = WINTRUST_DATA_STATE_ACTION(flags::WTD_STATEACTION_CLOSE);
        // SAFETY: closes the state the verify call opened; the structures are still live.
        unsafe {
            WinVerifyTrust(no_window, &raw mut action, (&raw mut data).cast());
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::codes::{
        CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOCATION_FAILURE, CERT_E_REVOKED,
        CERT_E_UNTRUSTEDROOT, CERT_E_WRONG_USAGE, CRYPT_E_NO_REVOCATION_CHECK,
        CRYPT_E_REVOCATION_OFFLINE, E_ACCESSDENIED, S_OK, TRUST_E_BAD_DIGEST,
        TRUST_E_CERT_SIGNATURE, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NO_SIGNER_CERT,
        TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
    };
    use super::*;

    #[test]
    fn a_verified_signature_is_verified() {
        assert_eq!(classify(S_OK), Verdict::Verified);
    }

    #[test]
    fn no_signature_and_an_unsignable_file_both_mean_nothing_embedded() {
        assert_eq!(classify(TRUST_E_NOSIGNATURE), Verdict::NoEmbeddedSignature);
        assert_eq!(
            classify(TRUST_E_SUBJECT_FORM_UNKNOWN),
            Verdict::NoEmbeddedSignature
        );
    }

    #[test]
    fn a_signature_windows_does_not_trust_is_invalid() {
        for code in [
            TRUST_E_BAD_DIGEST,
            TRUST_E_EXPLICIT_DISTRUST,
            TRUST_E_SUBJECT_NOT_TRUSTED,
            TRUST_E_CERT_SIGNATURE,
            TRUST_E_NO_SIGNER_CERT,
            CERT_E_EXPIRED,
            CERT_E_WRONG_USAGE,
            CERT_E_REVOKED,
        ] {
            assert_eq!(classify(code), Verdict::Invalid, "{code:#x}");
        }
    }

    /// Something this machine does not hold is a fact about the offline check, never "invalid": a
    /// legitimate publisher whose intermediate certificate is not cached must not read as tampered, and
    /// neither must one whose root this machine has not fetched. `CERT_E_UNTRUSTEDROOT` is what the
    /// Windows CI job measured for a genuine signature carrying its own root on a runner whose stores
    /// had lost that root (ADR 0035, amendment of 2026-09-14).
    #[test]
    fn what_needs_the_network_is_unverifiable_offline_not_invalid() {
        for code in [
            CERT_E_CHAINING,
            CERT_E_UNTRUSTEDROOT,
            CRYPT_E_REVOCATION_OFFLINE,
            CERT_E_REVOCATION_FAILURE,
            CRYPT_E_NO_REVOCATION_CHECK,
        ] {
            assert_eq!(classify(code), Verdict::UnverifiableOffline, "{code:#x}");
        }
    }

    #[test]
    fn a_code_nobody_named_is_not_an_answer_about_the_signature() {
        assert_eq!(classify(E_ACCESSDENIED), Verdict::AccessDenied);
        // E_FAIL, ERROR_FILE_NOT_FOUND as an HRESULT, CRYPT_E_SECURITY_SETTINGS.
        for code in [0x8000_4005_u32, 0x8007_0002, 0x8009_2026] {
            assert_eq!(classify(code), Verdict::Failed, "{code:#x}");
        }
    }

    /// The flag that keeps the check off the network is set, and nothing asks for revocation.
    #[test]
    fn the_product_settings_retrieve_from_the_cache_only_and_check_no_revocation() {
        assert_eq!(OFFLINE.revocation_checks, flags::WTD_REVOKE_NONE);
        assert_ne!(
            OFFLINE.provider_flags & flags::WTD_CACHE_ONLY_URL_RETRIEVAL,
            0
        );
        assert_ne!(OFFLINE.provider_flags & flags::WTD_REVOCATION_CHECK_NONE, 0);
        assert_eq!(
            OFFLINE.provider_flags & flags::WTD_REVOCATION_CHECK_CHAIN,
            0
        );
    }

    /// The written-out values are the ones the `windows` crate declares.
    #[cfg(windows)]
    #[test]
    fn written_out_values_match_the_windows_crate() {
        use windows::Win32::Foundation as f;
        use windows::Win32::Security::WinTrust as t;
        let hr = |code: windows::core::HRESULT| code.0.cast_unsigned();
        assert_eq!(TRUST_E_NOSIGNATURE, hr(f::TRUST_E_NOSIGNATURE));
        assert_eq!(
            TRUST_E_SUBJECT_FORM_UNKNOWN,
            hr(f::TRUST_E_SUBJECT_FORM_UNKNOWN)
        );
        assert_eq!(TRUST_E_BAD_DIGEST, hr(f::TRUST_E_BAD_DIGEST));
        assert_eq!(TRUST_E_EXPLICIT_DISTRUST, hr(f::TRUST_E_EXPLICIT_DISTRUST));
        assert_eq!(
            TRUST_E_SUBJECT_NOT_TRUSTED,
            hr(f::TRUST_E_SUBJECT_NOT_TRUSTED)
        );
        assert_eq!(TRUST_E_CERT_SIGNATURE, hr(f::TRUST_E_CERT_SIGNATURE));
        assert_eq!(TRUST_E_NO_SIGNER_CERT, hr(f::TRUST_E_NO_SIGNER_CERT));
        assert_eq!(CERT_E_UNTRUSTEDROOT, hr(f::CERT_E_UNTRUSTEDROOT));
        assert_eq!(CERT_E_EXPIRED, hr(f::CERT_E_EXPIRED));
        assert_eq!(CERT_E_WRONG_USAGE, hr(f::CERT_E_WRONG_USAGE));
        assert_eq!(CERT_E_REVOKED, hr(f::CERT_E_REVOKED));
        assert_eq!(CERT_E_CHAINING, hr(f::CERT_E_CHAINING));
        assert_eq!(
            CRYPT_E_REVOCATION_OFFLINE,
            hr(f::CRYPT_E_REVOCATION_OFFLINE)
        );
        assert_eq!(CERT_E_REVOCATION_FAILURE, hr(f::CERT_E_REVOCATION_FAILURE));
        assert_eq!(
            CRYPT_E_NO_REVOCATION_CHECK,
            hr(f::CRYPT_E_NO_REVOCATION_CHECK)
        );
        assert_eq!(E_ACCESSDENIED, hr(f::E_ACCESSDENIED));
        assert_eq!(flags::WTD_UI_NONE, t::WTD_UI_NONE.0);
        assert_eq!(flags::WTD_CHOICE_FILE, t::WTD_CHOICE_FILE.0);
        assert_eq!(flags::WTD_STATEACTION_VERIFY, t::WTD_STATEACTION_VERIFY.0);
        assert_eq!(flags::WTD_STATEACTION_CLOSE, t::WTD_STATEACTION_CLOSE.0);
        assert_eq!(flags::WTD_REVOKE_NONE, t::WTD_REVOKE_NONE.0);
        assert_eq!(flags::WTD_REVOKE_WHOLECHAIN, t::WTD_REVOKE_WHOLECHAIN.0);
        assert_eq!(
            flags::WTD_REVOCATION_CHECK_NONE,
            t::WTD_REVOCATION_CHECK_NONE.0
        );
        assert_eq!(
            flags::WTD_REVOCATION_CHECK_CHAIN,
            t::WTD_REVOCATION_CHECK_CHAIN.0
        );
        assert_eq!(
            flags::WTD_CACHE_ONLY_URL_RETRIEVAL,
            t::WTD_CACHE_ONLY_URL_RETRIEVAL.0
        );
    }

    // ----------------------------------------------------------------------------------------------
    // Live checks on a real Windows machine (ADR 0035). Ignored by default: they need a file with an
    // embedded signature, named by the Windows CI job, which runs them between readings of the CAPI2
    // log. Every test whose name starts `live_offline_` uses only the product's settings; the job
    // fails if the log records a network retrieval while those run. `live_online_` is the positive
    // twin that shows the log records one when the check is allowed to fetch.
    // ----------------------------------------------------------------------------------------------

    /// The embedded-signed file and its signing certificate's SHA-256, as the CI job found them with
    /// PowerShell's own `Get-AuthenticodeSignature` — a second implementation to agree with.
    #[cfg(windows)]
    fn signed_file() -> (String, String) {
        let path = std::env::var("RONGROI_SIGNED_FILE")
            .expect("RONGROI_SIGNED_FILE names a file with an embedded Authenticode signature");
        let cert = std::env::var("RONGROI_SIGNED_FILE_CERT_SHA256")
            .expect("RONGROI_SIGNED_FILE_CERT_SHA256 is its signing certificate's SHA-256");
        (path, cert.to_ascii_lowercase())
    }

    /// A private copy of a file under the temporary folder, so a test can change it.
    #[cfg(windows)]
    fn scratch_copy(source: &str, name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rongroi-signature-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch folder");
        let copy = dir.join(name);
        std::fs::copy(source, &copy).expect("copy of the signed file");
        copy
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "needs RONGROI_SIGNED_FILE; the Windows CI job runs it"]
    fn live_offline_an_embedded_signature_is_valid_and_names_the_certificate_powershell_names() {
        let (path, expected_cert) = signed_file();
        match verify(&path, OFFLINE) {
            Ok(bope_host::SignatureCheck::Valid {
                signer,
                signer_cert_sha256,
            }) => {
                assert!(!signer.trim().is_empty());
                assert_eq!(signer_cert_sha256, expected_cert);
            }
            other => panic!("expected a valid signature, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "needs RONGROI_SIGNED_FILE; the Windows CI job runs it"]
    fn live_offline_a_signed_file_changed_after_signing_is_invalid() {
        let (path, _) = signed_file();
        let copy = scratch_copy(&path, "tampered.exe");
        let mut bytes = std::fs::read(&copy).expect("read the copy");
        // The middle of an executable is code, covered by the signature's digest; the signature block
        // itself sits at the end.
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xFF;
        std::fs::write(&copy, &bytes).expect("write the changed copy");
        let result = verify(&copy.display().to_string(), OFFLINE);
        std::fs::remove_file(&copy).ok();
        assert_eq!(result, Ok(bope_host::SignatureCheck::Invalid));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "the Windows CI job runs it"]
    fn live_offline_an_unsigned_executable_and_a_text_file_have_nothing_embedded() {
        // This test binary was built on the runner and never signed.
        let own = std::env::current_exe().expect("own path");
        assert_eq!(
            verify(&own.display().to_string(), OFFLINE),
            Ok(bope_host::SignatureCheck::NoEmbeddedSignature)
        );
        let dir = std::env::temp_dir().join(format!("rongroi-signature-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch folder");
        let text = dir.join("reshade.ini");
        std::fs::write(&text, "[GENERAL]\n").expect("write a text file");
        let result = verify(&text.display().to_string(), OFFLINE);
        std::fs::remove_file(&text).ok();
        assert_eq!(result, Ok(bope_host::SignatureCheck::NoEmbeddedSignature));
    }

    /// A Windows file signed **only** through a catalog — `Get-AuthenticodeSignature` reports it signed,
    /// and its PE security directory is empty — has nothing embedded, which is why the state is not
    /// called "unsigned".
    ///
    /// "Only" matters, and was learned the hard way: `explorer.exe` on Windows 11 is reported as
    /// `Catalog` by PowerShell and still carries an embedded signature, which this check reads as
    /// valid. The CI job picks a file whose security directory is empty.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs RONGROI_CATALOG_SIGNED_FILE; the Windows CI job runs it"]
    fn live_offline_a_catalog_signed_file_has_nothing_embedded() {
        let path = std::env::var("RONGROI_CATALOG_SIGNED_FILE")
            .expect("RONGROI_CATALOG_SIGNED_FILE names a file signed only through a catalog, with an empty PE security directory");
        assert_eq!(
            verify(&path, OFFLINE),
            Ok(bope_host::SignatureCheck::NoEmbeddedSignature)
        );
    }

    /// What the product's settings answer for a file whose certificate chain the machine's stores do not
    /// complete (ADR 0035, amendment of 2026-09-14). The Windows CI job sets each case up and names it in
    /// `RONGROI_CHAIN_CASE`; the file is `RONGROI_CHAIN_FILE`. It runs between readings of the CAPI2 log
    /// like the other offline tests, under its own prefix so that the CAPI2 step, which runs with every
    /// store intact, does not pick it up. The asserted codes are the ones the job measured:
    ///
    /// | Case | Set up | Code |
    /// |---|---|---|
    /// | `intact`, `restored` | nothing removed, or every removed certificate imported back | `S_OK` |
    /// | `root_removed_not_in_signature` | the root, which the signature does not carry, deleted from every registry store | `CERT_E_CHAINING` |
    /// | `root_removed_carried_in_signature` | the root, which the signature carries, deleted the same way | `CERT_E_UNTRUSTEDROOT` |
    /// | `self_signed` | a copy of an unsigned binary signed with a certificate made for it | `CERT_E_UNTRUSTEDROOT` |
    ///
    /// `intermediate_removed` is set up only when an intermediate sits in a store, which on the runner
    /// none did — each was carried in its signature — so no code for it has been measured and none is
    /// asserted.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs RONGROI_CHAIN_FILE, RONGROI_CHAIN_CASE and stores the Windows CI job changed"]
    fn live_chain_offline_what_an_incomplete_chain_answers() {
        use bope_host::SignatureCheck;
        let path = std::env::var("RONGROI_CHAIN_FILE")
            .expect("RONGROI_CHAIN_FILE names a file with an embedded signature");
        let case = std::env::var("RONGROI_CHAIN_CASE").expect("RONGROI_CHAIN_CASE names the case");
        // The CI job finds this process's CAPI2 events by its id, which only the process itself knows.
        if let Ok(pid_file) = std::env::var("RONGROI_CHAIN_PID_FILE") {
            std::fs::write(pid_file, std::process::id().to_string()).expect("write the process id");
        }
        let (code, check) = verify_with_code(&path, OFFLINE);
        let shown = code.map_or_else(|| "no call".to_owned(), |code| format!("{code:#010x}"));
        println!("chain case {case}: WinVerifyTrust {shown} -> {check:?}");
        let unverifiable = |expected: u32| {
            assert_eq!(code, Some(expected), "{case}: got {shown} {check:?}");
            assert_eq!(check, Ok(SignatureCheck::UnverifiableOffline), "{case}");
        };
        match case.as_str() {
            "intact" | "restored" => {
                assert_eq!(code, Some(codes::S_OK), "{case}: got {shown} {check:?}");
                assert!(matches!(check, Ok(SignatureCheck::Valid { .. })), "{case}");
            }
            "root_removed_not_in_signature" => unverifiable(codes::CERT_E_CHAINING),
            "root_removed_carried_in_signature" | "self_signed" => {
                unverifiable(codes::CERT_E_UNTRUSTEDROOT);
            }
            "intermediate_removed" => {}
            other => panic!("unknown RONGROI_CHAIN_CASE {other}"),
        }
    }

    /// Not a check of the product: the settings here are ones the product never uses. It exists so the
    /// CI job can show the CAPI2 log records a network retrieval when one happens.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs RONGROI_SIGNED_FILE and network access; the Windows CI job runs it"]
    fn live_online_a_check_allowed_to_fetch_runs() {
        let (path, _) = signed_file();
        assert!(verify(&path, ONLINE).is_ok());
    }
}
