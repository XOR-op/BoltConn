//! Bounded reads of Windows process parameters. The SDK exposes image/command-line
//! fields but reserves the cwd/environment fields used by the existing Windows backend.
//! Layouts: https://github.com/wine-mirror/wine/blob/master/include/winternl.h
//! Both native and WOW64 layouts must be handled by a 64-bit BoltConn.
use std::{ffi::c_void, mem};
use windows::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessWow64Information},
    Win32::{
        Foundation::HANDLE,
        System::{Diagnostics::Debug::ReadProcessMemory, Threading::PEB},
    },
};

#[derive(Clone, Copy)]
pub(super) struct RemoteString {
    length: usize,
    address: usize,
}

pub(super) struct Parameters {
    pub image: RemoteString,
    pub command_line: RemoteString,
    pub cwd: RemoteString,
    environment: usize,
}

pub(super) fn read_parameters(handle: HANDLE, peb: *const PEB) -> Option<Parameters> {
    let mut is_32_bit = cfg!(target_pointer_width = "32");
    let mut peb_address = peb as usize;
    #[cfg(target_pointer_width = "64")]
    {
        let mut wow64_peb = 0usize;
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                ProcessWow64Information,
                &mut wow64_peb as *mut _ as *mut c_void,
                mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status.is_err() {
            return None;
        }
        if wow64_peb != 0 {
            is_32_bit = true;
            peb_address = wow64_peb;
        }
    }
    let width = if is_32_bit { 4 } else { 8 };
    let parameter_offset = if is_32_bit { 0x10 } else { 0x20 };
    let pointer = read_bytes(handle, peb_address.checked_add(parameter_offset)?, width)?;
    let parameters = read_pointer(&pointer, 0, width)?;
    let (cwd, image, command_line, environment) = if is_32_bit {
        (0x24, 0x38, 0x40, 0x48)
    } else {
        (0x38, 0x60, 0x70, 0x80)
    };
    let bytes = read_bytes(handle, parameters, environment + width)?;
    let string = |offset: usize| {
        let length = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?) as usize;
        let maximum =
            u16::from_le_bytes(bytes.get(offset + 2..offset + 4)?.try_into().ok()?) as usize;
        if length > maximum || length % 2 != 0 {
            return None;
        }
        Some(RemoteString {
            length,
            address: read_pointer(&bytes, offset + width, width)?,
        })
    };
    Some(Parameters {
        image: string(image)?,
        command_line: string(command_line)?,
        cwd: string(cwd)?,
        environment: read_pointer(&bytes, environment, width)?,
    })
}

fn read_pointer(bytes: &[u8], offset: usize, width: usize) -> Option<usize> {
    let bytes = bytes.get(offset..offset.checked_add(width)?)?;
    match width {
        4 => Some(u32::from_le_bytes(bytes.try_into().ok()?) as usize),
        8 => usize::try_from(u64::from_le_bytes(bytes.try_into().ok()?)).ok(),
        _ => None,
    }
}

fn read_bytes(handle: HANDLE, address: usize, length: usize) -> Option<Vec<u8>> {
    if address == 0 || length > 1024 * 1024 {
        return None;
    }
    address.checked_add(length)?;
    let mut bytes = vec![0u8; length];
    let mut read = 0usize;
    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            length,
            Some(&mut read),
        )
        .ok()?;
    }
    (read == length).then_some(bytes)
}

pub(super) fn read_string(handle: HANDLE, string: RemoteString) -> Option<String> {
    if string.length == 0 {
        return Some(String::new());
    }
    let bytes = read_bytes(handle, string.address, string.length)?;
    let utf16: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    Some(String::from_utf16_lossy(&utf16))
}

impl Parameters {
    pub fn tag(&self, handle: HANDLE) -> Option<String> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let mut address = self.environment;
        let mut entry = Vec::new();
        // A process may change its environment during a read. Bound both allocation
        // and work, and never read beyond a page while looking for the terminator.
        let mut remaining = 1024 * 1024;
        while remaining > 0 {
            let length = (4096 - address % 4096).min(remaining);
            let bytes = read_bytes(handle, address, length)?;
            for pair in bytes.chunks_exact(2) {
                let ch = u16::from_le_bytes([pair[0], pair[1]]);
                if ch != 0 {
                    entry.push(ch);
                    continue;
                }
                if entry.is_empty() {
                    return None;
                }
                let text = String::from_utf16_lossy(&entry);
                if let Some((name, value)) = text.split_once('=')
                    && name.eq_ignore_ascii_case("BOLTCONN_TAG")
                {
                    return String::from_utf8(URL_SAFE_NO_PAD.decode(value).ok()?).ok();
                }
                entry.clear();
            }
            address = address.checked_add(length)?;
            remaining -= length;
        }
        None
    }
}
