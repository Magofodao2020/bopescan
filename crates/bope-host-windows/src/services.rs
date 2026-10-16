// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! What the Service Control Manager says about one service now (B.O.P.E, ADR 0130).
//!
//! `OpenSCManagerW(SC_MANAGER_CONNECT)`, `OpenServiceW(SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)`,
//! `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)` and `QueryServiceConfigW`. No other access right is
//! asked for, so the handles cannot start, stop, pause or reconfigure a service.

use bope_host::{SourceError, bound_text};

/// `ERROR_ACCESS_DENIED`.
pub const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_SERVICE_DOES_NOT_EXIST`.
pub const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
/// Largest `QUERY_SERVICE_CONFIGW` buffer read; Windows documents 8 KiB as the most it needs.
pub const MAX_CONFIG_BYTES: usize = 8 * 1024;

/// What a Win32 error from the Service Control Manager means to a caller: `None` for "not installed".
pub fn classify(code: u32, context: &str) -> Option<SourceError> {
    match code {
        ERROR_SERVICE_DOES_NOT_EXIST => None,
        ERROR_ACCESS_DENIED => Some(SourceError::AccessDenied),
        other => Some(SourceError::Failed(format!(
            "{context}: Win32 error {other}"
        ))),
    }
}

/// A service text, bounded, or `None` when empty.
pub fn kept(text: &str) -> Option<String> {
    let text = text.trim().to_owned();
    (!text.is_empty()).then(|| bound_text(text, bope_host::MAX_SERVICE_TEXT_BYTES).0)
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl bope_host::ServiceSource for crate::LiveHost {
    fn service_status(&self, name: &str) -> Result<Option<bope_host::ServiceStatus>, SourceError> {
        use bope_host::{ServiceConfig, ServiceRunState, ServiceStartType, ServiceStatus};
        use windows::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
            QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
            SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
            SERVICE_STATUS_PROCESS,
        };
        use windows::core::{PCWSTR, PWSTR};

        struct Handle(SC_HANDLE);
        impl Drop for Handle {
            fn drop(&mut self) {
                // SAFETY: the handle came from a successful open and is closed once.
                let _ = unsafe { CloseServiceHandle(self.0) };
            }
        }
        let code = |e: &windows::core::Error| e.code().0.cast_unsigned() & 0xFFFF;

        // SAFETY: null machine and database names select the local active database.
        let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map(Handle)
            .map_err(|e| {
                classify(code(&e), "OpenSCManagerW").unwrap_or(SourceError::AccessDenied)
            })?;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        let service = match unsafe {
            OpenServiceW(
                manager.0,
                PCWSTR(wide.as_ptr()),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        } {
            Ok(handle) => Handle(handle),
            Err(e) => {
                return match classify(code(&e), "OpenServiceW") {
                    None => Ok(None),
                    Some(error) => Err(error),
                };
            }
        };
        let queried_at = jiff::Timestamp::now();

        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        // SAFETY: the buffer is exactly one `SERVICE_STATUS_PROCESS`, which this level fills.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                std::ptr::from_mut(&mut status).cast::<u8>(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )
        };
        // SAFETY: `bytes` is valid for its length; `needed` is a valid out pointer.
        unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                Some(bytes),
                &raw mut needed,
            )
        }
        .map_err(|e| {
            classify(code(&e), "QueryServiceStatusEx")
                .unwrap_or_else(|| SourceError::Failed("service vanished".to_owned()))
        })?;

        let config = (|| {
            let mut needed = 0u32;
            // SAFETY: a null buffer of size 0 only asks for the size needed.
            let _ = unsafe { QueryServiceConfigW(service.0, None, 0, &raw mut needed) };
            let size = (needed as usize).clamp(
                std::mem::size_of::<QUERY_SERVICE_CONFIGW>(),
                MAX_CONFIG_BYTES,
            );
            let mut buffer = vec![0u64; size.div_ceil(8)];
            let pointer = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
            let size_u32 = u32::try_from(size).unwrap_or(u32::MAX);
            // SAFETY: `buffer` is 8-aligned and at least `size` bytes, as passed.
            unsafe { QueryServiceConfigW(service.0, Some(pointer), size_u32, &raw mut needed) }
                .map_err(|e| {
                    classify(code(&e), "QueryServiceConfigW")
                        .unwrap_or_else(|| SourceError::Failed("service vanished".to_owned()))
                })?;
            let read = |p: PWSTR| -> Option<String> {
                if p.is_null() {
                    None
                } else {
                    // SAFETY: the call succeeded, so a non-null string pointer points to a
                    // NUL-terminated string inside `buffer`, which outlives this closure.
                    unsafe { p.to_string() }.ok().as_deref().and_then(kept)
                }
            };
            // SAFETY: the call succeeded, so the start of `buffer` holds an initialised struct.
            let raw = unsafe { &*pointer };
            Ok(ServiceConfig {
                start_type: ServiceStartType::from_win32(raw.dwStartType.0),
                display_name: read(raw.lpDisplayName),
                account: read(raw.lpServiceStartName),
                binary_path: read(raw.lpBinaryPathName),
            })
        })();

        Ok(Some(ServiceStatus {
            state: ServiceRunState::from_win32(status.dwCurrentState.0),
            pid: Some(status.dwProcessId).filter(|p| *p != 0),
            config,
            queried_at,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_classified() {
        assert_eq!(classify(ERROR_SERVICE_DOES_NOT_EXIST, "x"), None);
        assert_eq!(
            classify(ERROR_ACCESS_DENIED, "x"),
            Some(SourceError::AccessDenied)
        );
        assert!(matches!(classify(2, "x"), Some(SourceError::Failed(_))));
        assert_eq!(kept("  "), None);
        assert_eq!(kept(" LocalSystem ").as_deref(), Some("LocalSystem"));
    }
}
