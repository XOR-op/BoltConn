use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Reserved fd number for the bolt tag on Unix.
pub const BOLT_TAG_FD: libc::c_int = 1021;

const BOLT_TAG_PREFIX: &str = "/bolt-tag:";
/// macOS PSHMNAMLEN = 31 is the most restrictive limit across all three platforms.
const MAX_SHM_NAME_LEN: usize = 31;

/// Validate and base64-encode a tag string.
///
/// Returns the URL-safe no-pad base64 encoding on success, or an error message if the tag is
/// empty or the resulting shm name would exceed the OS limit.
pub fn validate_and_encode_tag(tag: &str) -> Result<String, String> {
    if tag.is_empty() {
        return Err("tag must not be empty".to_string());
    }
    let encoded = URL_SAFE_NO_PAD.encode(tag);
    let shm_name_len = BOLT_TAG_PREFIX.len() + encoded.len();
    if shm_name_len > MAX_SHM_NAME_LEN {
        let max_encoded_len = MAX_SHM_NAME_LEN - BOLT_TAG_PREFIX.len();
        return Err(format!(
            "tag is too long: base64-encoded value is {} chars but max is {} \
             (shm name must fit within {} chars on macOS)",
            encoded.len(),
            max_encoded_len,
            MAX_SHM_NAME_LEN,
        ));
    }
    Ok(encoded)
}

/// Set up fd `1021` with an anonymous shm object whose name encodes the tag.
///
/// Steps:
/// 1. `shm_open("/bolt-tag:<encoded>", O_RDWR|O_CREAT, 0o600)`
/// 2. Clear `O_CLOEXEC` so the fd survives `exec`
/// 3. `dup2` the shm fd to slot `BOLT_TAG_FD` (closing any prior occupant)
/// 4. `shm_unlink` the name immediately to make it anonymous
#[cfg(unix)]
pub fn setup_tag_fd(encoded_tag: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::io;

    let shm_name = format!("{}{}", BOLT_TAG_PREFIX, encoded_tag);
    let cname = CString::new(shm_name).map_err(io::Error::other)?;

    unsafe {
        let fd = libc::shm_open(cname.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600u32);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Clear O_CLOEXEC so the fd is inherited across exec().
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }

        // Free the target slot in case it's already occupied.
        if fd != BOLT_TAG_FD {
            libc::close(BOLT_TAG_FD);
            if libc::dup2(fd, BOLT_TAG_FD) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                libc::shm_unlink(cname.as_ptr());
                return Err(err);
            }
            libc::close(fd);
        }

        // Unlink immediately — the fd remains valid but the name disappears.
        libc::shm_unlink(cname.as_ptr());
    }
    Ok(())
}

/// Query the bolt tag for a running process by reading its fd `1021` metadata.
///
/// Returns `None` if the process was not launched by `boltconn run`, or if the fd does not exist
/// or does not carry a recognisable tag name.
#[cfg(target_os = "linux")]
pub fn get_tag_for_pid(pid: i32) -> Option<String> {
    let link_path = format!("/proc/{}/fd/{}", pid, BOLT_TAG_FD);
    let target = std::fs::read_link(&link_path).ok()?;
    let mut name = target.to_string_lossy().into_owned();

    // After shm_unlink the kernel appends " (deleted)" to the path.
    if let Some(base) = name.strip_suffix(" (deleted)") {
        name = base.to_owned();
    }

    // On Linux, shm_open("/bolt-tag:<v>") creates /dev/shm/bolt-tag:<v>.
    const LINUX_PREFIX: &str = "/dev/shm/bolt-tag:";
    let encoded = name.strip_prefix(LINUX_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    String::from_utf8(bytes).ok()
}

/// Query the bolt tag for a running process by reading its fd `1021` metadata.
#[cfg(target_os = "macos")]
pub fn get_tag_for_pid(pid: i32) -> Option<String> {
    use std::ffi::CStr;

    // PROC_PIDFDPSHMINFO (flavor 5) is the correct call for POSIX shared-memory fds
    // created via shm_open(). It returns pshm_fdinfo = proc_fileinfo + pshm_info.
    // (PROC_PIDFDVNODEPATHINFO = 2 is for regular file/vnode fds — wrong here.)
    const PROC_PIDFDPSHMINFO: libc::c_int = 5;

    // Mirror of struct proc_fileinfo from <sys/proc_info.h>.
    // Not exposed by the libc crate; defined here using libc primitive types.
    #[repr(C)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: libc::off_t,
        fi_type: i32,
        fi_guardflags: u32,
    }

    // Mirror of struct pshm_info from <sys/proc_info.h>.
    // pshm_stat is struct vinfo_stat (available as libc::vinfo_stat).
    // pshm_name[MAXPATHLEN] (1024) lives directly in pshm_info, not in a sub-struct.
    #[repr(C)]
    struct PshmInfo {
        pshm_stat: libc::vinfo_stat,
        pshm_mappaddr: u64,
        pshm_name: [libc::c_char; libc::PATH_MAX as usize],
    }

    // Mirror of struct pshm_fdinfo from <sys/proc_info.h>.
    #[repr(C)]
    struct PshmFdInfo {
        pfi: ProcFileInfo,
        pshminfo: PshmInfo,
    }

    let mut info: PshmFdInfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::proc_pidfdinfo(
            pid,
            BOLT_TAG_FD,
            PROC_PIDFDPSHMINFO,
            &mut info as *mut PshmFdInfo as *mut libc::c_void,
            std::mem::size_of::<PshmFdInfo>() as libc::c_int,
        )
    };
    if ret <= 0 {
        return None;
    }

    // The kernel stores the shm name as passed to shm_open(), including the leading '/'.
    let name = unsafe { CStr::from_ptr(info.pshminfo.pshm_name.as_ptr()) }.to_string_lossy();

    const MACOS_PREFIX: &str = "/bolt-tag:";
    let encoded = name.strip_prefix(MACOS_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    String::from_utf8(bytes).ok()
}

/// Query the bolt tag from the target process's environment block (Windows).
#[cfg(target_os = "windows")]
pub fn get_tag_for_pid(pid: i32) -> Option<String> {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            OpenProcess, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_READ, RTL_USER_PROCESS_PARAMETERS,
        },
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .ok()?;

        let mut basic_info: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        if NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            &mut basic_info as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        )
        .is_err()
        {
            let _ = CloseHandle(handle);
            return None;
        }

        let peb: PEB = read_vm(handle, basic_info.PebBaseAddress)?;
        let params: RTL_USER_PROCESS_PARAMETERS = read_vm(handle, peb.ProcessParameters)?;

        // Environment block is a sequence of null-terminated UTF-16 "KEY=VALUE\0" strings,
        // terminated by an extra \0.
        let env_ptr = params.Environment as *const u16;
        let env_size = params.EnvironmentSize as usize / 2; // bytes → u16 count
        let mut env_buf = vec![0u16; env_size];
        ReadProcessMemory(
            handle,
            env_ptr as *const _,
            env_buf.as_mut_ptr() as *mut _,
            params.EnvironmentSize as usize,
            None,
        )
        .ok()?;

        let _ = CloseHandle(handle);

        const KEY: &str = "BOLTCONN_TAG=";
        // Scan the environment block for our key.
        let mut i = 0usize;
        while i < env_buf.len() {
            // Find the end of this entry.
            let end = env_buf[i..].iter().position(|&c| c == 0).map(|p| i + p)?;
            let entry = String::from_utf16_lossy(&env_buf[i..end]);
            if let Some(value) = entry.strip_prefix(KEY) {
                let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
                return String::from_utf8(bytes).ok();
            }
            i = end + 1;
            if i >= env_buf.len() || env_buf[i] == 0 {
                break;
            }
        }
        None
    }
}

#[cfg(target_os = "windows")]
unsafe fn read_vm<T: Sized>(
    handle: windows::Win32::Foundation::HANDLE,
    addr: *const T,
) -> Option<T> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut buf: T = unsafe { std::mem::zeroed() };
    unsafe {
        ReadProcessMemory(
            handle,
            addr as *const _,
            &mut buf as *mut _ as *mut _,
            std::mem::size_of::<T>(),
            None,
        )
        .ok()?;
    }
    Some(buf)
}

/// Set the `BOLTCONN_TAG` environment variable before spawning a child (Windows only).
#[cfg(target_os = "windows")]
pub fn setup_tag_env(encoded_tag: &str) {
    std::env::set_var("BOLTCONN_TAG", encoded_tag);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_tag_fails() {
        assert!(validate_and_encode_tag("").is_err());
    }

    #[test]
    fn test_validate_short_tag_ok() {
        // "python" → base64 "cHl0aG9u" (8 chars) → shm name 18 chars ≤ 31
        let result = validate_and_encode_tag("python");
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(result.unwrap(), "cHl0aG9u");
    }

    #[test]
    fn test_validate_tag_at_max_fit() {
        // The effective max encoded length is 21 chars (31 - "/bolt-tag:".len()).
        // URL_SAFE_NO_PAD for 15 bytes → ceil(15*4/3) = 20 chars, so total shm name is 10 + 20 = 30.
        // URL_SAFE_NO_PAD for 16 bytes → ceil(16*4/3) = 22 chars, so 10 + 22 = 32 > 31.
        let tag = "a".repeat(15); // 15 bytes
        let result = validate_and_encode_tag(&tag);
        assert!(result.is_ok(), "15-byte tag should fit: {:?}", result);
        let encoded = result.unwrap();
        assert_eq!(
            BOLT_TAG_PREFIX.len() + encoded.len(),
            30,
            "should fit under limit"
        );
    }

    #[test]
    fn test_validate_tag_too_long() {
        // 16 bytes → base64 is 22 chars → total 32 > 31
        let tag = "a".repeat(16);
        let err = validate_and_encode_tag(&tag).unwrap_err();
        assert!(err.contains("max is 21"), "unexpected error: {err}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_tag_for_pid_linux_path_parsing() {
        // Simulate what get_tag_for_pid does internally by testing the parsing logic.
        fn parse(raw: &str) -> Option<String> {
            let mut name = raw.to_owned();
            if let Some(base) = name.strip_suffix(" (deleted)") {
                name = base.to_owned();
            }
            const LINUX_PREFIX: &str = "/dev/shm/bolt-tag:";
            let encoded = name.strip_prefix(LINUX_PREFIX)?;
            let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
            String::from_utf8(bytes).ok()
        }

        // With "(deleted)" suffix
        assert_eq!(
            parse("/dev/shm/bolt-tag:cHl0aG9u (deleted)"),
            Some("python".to_string())
        );
        // Without "(deleted)" suffix (still linked)
        assert_eq!(
            parse("/dev/shm/bolt-tag:cHl0aG9u"),
            Some("python".to_string())
        );
        // Non-matching prefix → None
        assert_eq!(parse("/dev/shm/other:cHl0aG9u"), None);
        // Unrelated fd content → None
        assert_eq!(parse("/proc/1/fd/1021"), None);
    }
}
