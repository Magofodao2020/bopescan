// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The modules loaded in one process and what its address space holds that is executable
//! (B.O.P.E, ADR 0102).
//!
//! The process is opened with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`, the access
//! `EnumProcessModulesEx` documents, and the handle is closed on every path. `VirtualQueryEx` reads
//! region descriptors only; no byte of the process's memory is copied. A process that refuses the
//! access — a protected process, or one whose anti-cheat strips the rights from handles — is
//! [`bope_host::SourceError::AccessDenied`], which is the answer.

/// Most modules one process is asked for. A process with more is read up to this count and the rest
/// is reported as a failure rather than dropped silently.
#[cfg(windows)]
const MAX_MODULES: usize = 8_192;

/// Most regions one walk visits before it stops and says it stopped.
#[cfg(windows)]
const MAX_REGIONS: u32 = 1_000_000;

/// Whether a `PAGE_*` protection value allows execution.
///
/// Outside the `unsafe` code so it is tested on every operating system. `PAGE_GUARD` and
/// `PAGE_NOCACHE`-style modifiers live in the high bits and are masked off first.
pub fn is_executable_protection(protect: u32) -> bool {
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    let base = protect & 0xFF;
    matches!(
        base,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

#[cfg(windows)]
fn open_for_reading(
    pid: u32,
) -> Result<windows::Win32::Foundation::HANDLE, bope_host::SourceError> {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, WIN32_ERROR};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    #[allow(unsafe_code)]
    // SAFETY: the two rights only allow querying the process and reading its memory, neither of which
    // this module does beyond module names and region descriptors. The handle is not inherited and
    // every caller closes it.
    let opened = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) };
    opened.map_err(|error| {
        if WIN32_ERROR::from_error(&error) == Some(ERROR_ACCESS_DENIED) {
            bope_host::SourceError::AccessDenied
        } else {
            bope_host::SourceError::Failed(format!("OpenProcess({pid}) failed: {error}"))
        }
    })
}

#[cfg(windows)]
fn close(handle: windows::Win32::Foundation::HANDLE) {
    #[allow(unsafe_code)]
    // SAFETY: `handle` came from a successful `OpenProcess` and is not used after this call.
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
}

#[cfg(windows)]
impl bope_host::ModuleSource for crate::LiveHost {
    fn process_modules(&self, pid: u32) -> Result<Vec<String>, bope_host::SourceError> {
        let handle = open_for_reading(pid)?;
        let listed = list_modules(handle, pid);
        close(handle);
        listed
    }

    fn executable_memory(
        &self,
        pid: u32,
    ) -> Result<bope_host::ExecutableMemory, bope_host::SourceError> {
        let handle = open_for_reading(pid)?;
        let walked = walk_regions(handle);
        close(handle);
        Ok(walked)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn list_modules(
    handle: windows::Win32::Foundation::HANDLE,
    pid: u32,
) -> Result<Vec<String>, bope_host::SourceError> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
    };

    let mut modules = vec![HMODULE::default(); 1024];
    loop {
        let Ok(capacity) = u32::try_from(modules.len() * size_of::<HMODULE>()) else {
            return Err(bope_host::SourceError::Failed(
                "module buffer does not fit in a u32".to_owned(),
            ));
        };
        let mut needed = 0_u32;
        // SAFETY: `modules` holds `capacity` bytes of `HMODULE`s and outlives the call; `needed` is a
        // valid out-pointer. The call only reads the target process's module list.
        unsafe {
            EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                capacity,
                &raw mut needed,
                LIST_MODULES_ALL,
            )
        }
        .map_err(|error| {
            bope_host::SourceError::Failed(format!("EnumProcessModulesEx({pid}) failed: {error}"))
        })?;
        let count = needed as usize / size_of::<HMODULE>();
        if count <= modules.len() {
            modules.truncate(count);
            break;
        }
        if count > MAX_MODULES {
            return Err(bope_host::SourceError::Failed(format!(
                "process {pid} lists {count} modules, more than the {MAX_MODULES} this program reads"
            )));
        }
        modules.resize(count, HMODULE::default());
    }

    let mut paths = Vec::with_capacity(modules.len());
    let mut buffer = vec![0_u16; 32_768];
    for module in modules {
        // SAFETY: `buffer` is a writable UTF-16 buffer that outlives the call; the module handle came
        // from the list above. A module unloaded since then answers 0 and is skipped.
        let written = unsafe { GetModuleFileNameExW(Some(handle), Some(module), &mut buffer) };
        let written = written as usize;
        if written == 0 || written > buffer.len() {
            continue;
        }
        paths.push(String::from_utf16_lossy(&buffer[..written]));
    }
    Ok(paths)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn walk_regions(handle: windows::Win32::Foundation::HANDLE) -> bope_host::ExecutableMemory {
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, VirtualQueryEx,
    };

    let mut summary = bope_host::ExecutableMemory {
        complete: true,
        ..Default::default()
    };
    let mut address: usize = 0;
    loop {
        if summary.regions_walked >= MAX_REGIONS {
            summary.complete = false;
            break;
        }
        let mut info = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `info` is a valid out-structure of the size passed; the address is only a value the
        // call describes, never dereferenced here. The call reads region descriptors, not memory.
        let size = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const core::ffi::c_void),
                &raw mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if size == 0 {
            // The end of the address space, or a process that exited: either way the walk is over.
            break;
        }
        summary.regions_walked += 1;
        let region = info.RegionSize;
        if info.State == MEM_COMMIT && is_executable_protection(info.Protect.0) {
            let bytes = region as u64;
            if info.Type == MEM_PRIVATE {
                summary.private_regions += 1;
                summary.private_bytes = summary.private_bytes.saturating_add(bytes);
            } else if info.Type == MEM_MAPPED {
                summary.mapped_regions += 1;
                summary.mapped_bytes = summary.mapped_bytes.saturating_add(bytes);
            } else if info.Type == MEM_IMAGE {
                summary.image_regions += 1;
            }
        }
        let Some(next) = (info.BaseAddress as usize).checked_add(region) else {
            break;
        };
        if next <= address {
            break;
        }
        address = next;
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_protections_are_recognised_and_modifiers_ignored() {
        assert!(is_executable_protection(0x20));
        assert!(is_executable_protection(0x40));
        assert!(is_executable_protection(0x40 | 0x100)); // PAGE_GUARD
        assert!(is_executable_protection(0x10));
        assert!(!is_executable_protection(0x04)); // PAGE_READWRITE
        assert!(!is_executable_protection(0x02 | 0x200)); // PAGE_READONLY | PAGE_NOCACHE
        assert!(!is_executable_protection(0x01)); // PAGE_NOACCESS
    }
}
