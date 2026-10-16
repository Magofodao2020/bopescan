// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The program's one network call: an HTTPS `GET` through `WinHTTP`, used only to download the
//! `FastFlag` reference file from GitHub when the person asks for it or the desktop's automatic check
//! is on (B.O.P.E, ADR 0136). Nothing a scan reads is ever sent: the request carries the address, a
//! fixed `User-Agent`, and at most an `If-None-Match` tag the same server gave earlier.
//!
//! Only the two hosts in [`ALLOWED_HOSTS`] are accepted, only over HTTPS on port 443 with TLS 1.2 or
//! 1.3, with no redirect followed and no cookie kept. The `WinHttp*` functions are banned in
//! `clippy.toml` everywhere else; [`get`] carries the one `#[allow]`.

/// The only hosts a request may go to.
pub const ALLOWED_HOSTS: [&str; 2] = ["api.github.com", "raw.githubusercontent.com"];

/// One answer.
#[derive(Debug, Clone, Default)]
pub struct HttpsResponse {
    /// The status code.
    pub status: u16,
    /// The `ETag` header, when there was one.
    pub etag: Option<String>,
    /// The `Content-Type` header, when there was one.
    pub content_type: Option<String>,
    /// The body.
    pub body: Vec<u8>,
}

/// `GET https://{host}{path}`. Errors are returned as a sentence for the sync record.
pub fn get(
    host: &str,
    path: &str,
    if_none_match: Option<&str>,
    user_agent: &str,
    max_body: usize,
) -> Result<HttpsResponse, String> {
    if !ALLOWED_HOSTS.contains(&host) {
        return Err(format!("{host} is not an allowed host"));
    }
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err("invalid path".to_owned());
    }
    if if_none_match.is_some_and(|t| t.contains(['\r', '\n'])) {
        return Err("invalid tag".to_owned());
    }
    #[cfg(windows)]
    {
        live::get(host, path, if_none_match, user_agent, max_body)
    }
    #[cfg(not(windows))]
    {
        let _ = (user_agent, max_body);
        Err("downloading the reference needs Windows; import a copy instead".to_owned())
    }
}

#[cfg(windows)]
mod live {
    use windows::Win32::Networking::WinHttp::{
        INTERNET_DEFAULT_HTTPS_PORT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_DISABLE_COOKIES,
        WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3, WINHTTP_OPTION_DISABLE_FEATURE,
        WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
        WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_QUERY_ETAG,
        WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
        WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable, WinHttpQueryHeaders,
        WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
        WinHttpSetTimeouts,
    };
    use windows::core::{HSTRING, PCWSTR};

    use super::HttpsResponse;

    /// Closes a `WinHTTP` handle when dropped.
    struct Handle(*mut core::ffi::c_void);

    impl Drop for Handle {
        #[allow(unsafe_code, clippy::disallowed_methods)]
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle came from a WinHTTP open call, is non-null and is closed once.
                let _ = unsafe { WinHttpCloseHandle(self.0) };
            }
        }
    }

    fn checked(handle: *mut core::ffi::c_void, what: &str) -> Result<Handle, String> {
        if handle.is_null() {
            Err(format!("{what}: {}", windows::core::Error::from_thread()))
        } else {
            Ok(Handle(handle))
        }
    }

    #[allow(unsafe_code, clippy::disallowed_methods)]
    fn header_text(request: &Handle, level: u32) -> Option<String> {
        let mut buffer = [0_u16; 512];
        let mut length = u32::try_from(std::mem::size_of_val(&buffer)).ok()?;
        let mut index = 0_u32;
        // SAFETY: `buffer` is valid for `length` bytes; WinHTTP writes at most that and updates
        // `length` to the bytes written, without the terminator.
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        unsafe {
            WinHttpQueryHeaders(
                request.0,
                level,
                PCWSTR::null(),
                Some(buffer.as_mut_ptr().cast()),
                &raw mut length,
                &raw mut index,
            )
        }
        .ok()?;
        let chars = (length as usize / 2).min(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..chars]))
    }

    #[allow(unsafe_code, clippy::disallowed_methods, clippy::too_many_lines)]
    pub(super) fn get(
        host: &str,
        path: &str,
        if_none_match: Option<&str>,
        user_agent: &str,
        max_body: usize,
    ) -> Result<HttpsResponse, String> {
        let session = checked(
            // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
            unsafe {
                WinHttpOpen(
                    &HSTRING::from(user_agent),
                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    0,
                )
            },
            "WinHttpOpen",
        )?;
        let protocols = (WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
            .to_ne_bytes();
        // TLS 1.3 is not known to older Windows 10 builds; then TLS 1.2 alone.
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        if unsafe {
            WinHttpSetOption(
                Some(session.0),
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                Some(&protocols),
            )
        }
        .is_err()
        {
            let tls12 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2.to_ne_bytes();
            // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
            unsafe {
                WinHttpSetOption(
                    Some(session.0),
                    WINHTTP_OPTION_SECURE_PROTOCOLS,
                    Some(&tls12),
                )
            }
            .map_err(|e| format!("TLS settings: {e}"))?;
        }
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        unsafe { WinHttpSetTimeouts(session.0, 10_000, 10_000, 15_000, 30_000) }
            .map_err(|e| format!("timeouts: {e}"))?;
        let connection = checked(
            // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
            unsafe {
                WinHttpConnect(
                    session.0,
                    &HSTRING::from(host),
                    INTERNET_DEFAULT_HTTPS_PORT,
                    0,
                )
            },
            "WinHttpConnect",
        )?;
        let request = checked(
            // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
            unsafe {
                WinHttpOpenRequest(
                    connection.0,
                    &HSTRING::from("GET"),
                    &HSTRING::from(path),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    std::ptr::null(),
                    WINHTTP_FLAG_SECURE,
                )
            },
            "WinHttpOpenRequest",
        )?;
        let never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_ne_bytes();
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        unsafe {
            WinHttpSetOption(
                Some(request.0),
                WINHTTP_OPTION_REDIRECT_POLICY,
                Some(&never),
            )
        }
        .map_err(|e| format!("redirect policy: {e}"))?;
        let no_cookies = WINHTTP_DISABLE_COOKIES.to_ne_bytes();
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        unsafe {
            WinHttpSetOption(
                Some(request.0),
                WINHTTP_OPTION_DISABLE_FEATURE,
                Some(&no_cookies),
            )
        }
        .map_err(|e| format!("cookies: {e}"))?;
        let mut headers = String::from("Accept: application/json, text/plain\r\n");
        if host == "api.github.com" {
            headers.push_str(
                "Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n",
            );
        }
        if let Some(tag) = if_none_match {
            headers.push_str("If-None-Match: ");
            headers.push_str(tag);
            headers.push_str("\r\n");
        }
        let wide: Vec<u16> = headers.encode_utf16().collect();
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        unsafe { WinHttpSendRequest(request.0, Some(&wide), None, 0, 0, 0) }
            .map_err(|e| format!("sending the request: {e}"))?;
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        unsafe { WinHttpReceiveResponse(request.0, std::ptr::null_mut()) }
            .map_err(|e| format!("receiving the answer: {e}"))?;
        let mut status = 0_u32;
        let mut length = 4_u32;
        let mut index = 0_u32;
        // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
        unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                PCWSTR::null(),
                Some((&raw mut status).cast()),
                &raw mut length,
                &raw mut index,
            )
        }
        .map_err(|e| format!("status: {e}"))?;
        let mut response = HttpsResponse {
            status: u16::try_from(status).unwrap_or(0),
            etag: header_text(&request, WINHTTP_QUERY_ETAG),
            content_type: header_text(&request, WINHTTP_QUERY_CONTENT_TYPE),
            body: Vec::new(),
        };
        loop {
            let mut available = 0_u32;
            // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
            unsafe { WinHttpQueryDataAvailable(request.0, &raw mut available) }
                .map_err(|e| format!("reading the answer: {e}"))?;
            if available == 0 {
                break;
            }
            let start = response.body.len();
            if start + available as usize > max_body {
                return Err("the answer is larger than the limit".to_owned());
            }
            response.body.resize(start + available as usize, 0);
            let mut read = 0_u32;
            // SAFETY: the arguments are live locals or handles owned by a `Handle`; lengths are their own.
            unsafe {
                WinHttpReadData(
                    request.0,
                    response.body[start..].as_mut_ptr().cast(),
                    available,
                    &raw mut read,
                )
            }
            .map_err(|e| format!("reading the answer: {e}"))?;
            response.body.truncate(start + read as usize);
            if read == 0 {
                break;
            }
        }
        Ok(response)
    }
}
