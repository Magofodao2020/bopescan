// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A yes-or-no question in a window that belongs to Windows, not to a `WebView` (ADR 0052).
//!
//! The desktop app asks for a full scan here, before any collector runs and before any `WebView` exists,
//! so that what the scan reads is decided by a person and measured before a window of this program can
//! do anything (ADR 0001, ADR 0012).

/// Shows `text` under `title` with Yes and No, No the default, and returns whether Yes was chosen.
/// Closing the window is No. On anything but Windows there is no dialog and the answer is No.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn ask_yes_no(title: &str, text: &str) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MessageBoxW,
    };
    use windows::core::HSTRING;

    let title = HSTRING::from(title);
    let text = HSTRING::from(text);
    // SAFETY: both strings are NUL-terminated `HSTRING`s owned by this function and outlive the call,
    // which returns only after the window closes; there is no owner window.
    let answer = unsafe {
        MessageBoxW(
            None,
            &text,
            &title,
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    answer == IDYES
}

/// Anything but Windows: no dialog, and so no agreement.
#[cfg(not(windows))]
pub fn ask_yes_no(_title: &str, _text: &str) -> bool {
    false
}

/// Asks the person to choose a folder in the Windows folder picker, and returns its path, or `None`
/// when they cancelled or no picker could be shown (B.O.P.E, ADR 0116). Used only to choose where a
/// report is saved; nothing on the machine is read or changed by asking.
///
/// The picker runs on a thread of its own, initialised as a single-threaded COM apartment as the
/// Shell requires, so it never depends on how the calling thread was set up.
#[cfg(windows)]
pub fn pick_folder(title: &str) -> Option<String> {
    let title = title.to_owned();
    std::thread::spawn(move || pick_folder_on_this_thread(&title))
        .join()
        .ok()
        .flatten()
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn pick_folder_on_this_thread(title: &str) -> Option<String> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
        CoInitializeEx, CoTaskMemFree, CoUninitialize,
    };
    use windows::Win32::UI::Shell::{
        FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS, FileOpenDialog, IFileOpenDialog, SIGDN_FILESYSPATH,
    };
    use windows::core::HSTRING;

    // SAFETY: initialises COM for this new thread only; balanced by `CoUninitialize` below when it
    // succeeded.
    let initialised =
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }.is_ok();
    // SAFETY: every call is on a COM object created here, on the apartment initialised above; the
    // returned path is a `CoTaskMemAlloc` string freed with `CoTaskMemFree` after it is copied.
    let picked = unsafe {
        (|| -> windows::core::Result<Option<String>> {
            let dialog: IFileOpenDialog =
                CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)?;
            let options = dialog.GetOptions()?;
            dialog.SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM)?;
            dialog.SetTitle(&HSTRING::from(title))?;
            if dialog.Show(None).is_err() {
                // Cancelled, or closed: no folder.
                return Ok(None);
            }
            let item = dialog.GetResult()?;
            let path = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            let text = path.to_string().ok();
            CoTaskMemFree(Some(path.0 as *const core::ffi::c_void));
            Ok(text)
        })()
    };
    if initialised {
        // SAFETY: balances the successful `CoInitializeEx` above on the same thread.
        unsafe { CoUninitialize() };
    }
    picked.ok().flatten()
}

/// Anything but Windows: no picker.
#[cfg(not(windows))]
pub fn pick_folder(_title: &str) -> Option<String> {
    None
}
