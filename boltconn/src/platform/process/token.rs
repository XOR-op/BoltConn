use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Reserved fd number for the bolt token on Unix.
pub const BOLT_TOKEN_FD: libc::c_int = 1021;

const BOLT_TOKEN_PREFIX: &str = "/bolt-token:";
/// macOS PSHMNAMLEN = 31 is the most restrictive limit across all three platforms.
const MAX_SHM_NAME_LEN: usize = 31;

/// Validate and base64-encode a token string.
///
/// Returns the URL-safe no-pad base64 encoding on success, or an error message if the token is
/// empty or the resulting shm name would exceed the OS limit.
pub fn validate_and_encode_token(token: &str) -> Result<String, String> {
    if token.is_empty() {
        return Err("token must not be empty".to_string());
    }
    let encoded = URL_SAFE_NO_PAD.encode(token);
    let shm_name_len = BOLT_TOKEN_PREFIX.len() + encoded.len();
    if shm_name_len > MAX_SHM_NAME_LEN {
        let max_encoded_len = MAX_SHM_NAME_LEN - BOLT_TOKEN_PREFIX.len();
        return Err(format!(
            "token is too long: base64-encoded value is {} chars but max is {} \
             (shm name must fit within {} chars on macOS)",
            encoded.len(),
            max_encoded_len,
            MAX_SHM_NAME_LEN,
        ));
    }
    Ok(encoded)
}

/// Set up fd `1021` with an anonymous shm object whose name encodes the token.
///
/// Steps:
/// 1. `shm_open("/bolt-token:<encoded>", O_RDWR|O_CREAT, 0o600)`
/// 2. Clear `O_CLOEXEC` so the fd survives `exec`
/// 3. `dup2` the shm fd to slot `BOLT_TOKEN_FD` (closing any prior occupant)
/// 4. `shm_unlink` the name immediately to make it anonymous
#[cfg(unix)]
pub fn setup_token_fd(encoded_token: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::io;

    let shm_name = format!("{}{}", BOLT_TOKEN_PREFIX, encoded_token);
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
        if fd != BOLT_TOKEN_FD {
            libc::close(BOLT_TOKEN_FD);
            if libc::dup2(fd, BOLT_TOKEN_FD) < 0 {
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

/// Query the bolt token for a running process by reading its fd `1021` metadata.
///
/// Returns `None` if the process was not launched by `boltconn run`, or if the fd does not exist
/// or does not carry a recognisable token name.
#[cfg(target_os = "linux")]
pub fn get_token_for_pid(pid: i32) -> Option<String> {
    let link_path = format!("/proc/{}/fd/{}", pid, BOLT_TOKEN_FD);
    let target = std::fs::read_link(&link_path).ok()?;
    let mut name = target.to_string_lossy().into_owned();

    // After shm_unlink the kernel appends " (deleted)" to the path.
    if let Some(base) = name.strip_suffix(" (deleted)") {
        name = base.to_owned();
    }

    // On Linux, shm_open("/bolt-token:<v>") creates /dev/shm/bolt-token:<v>.
    const LINUX_PREFIX: &str = "/dev/shm/bolt-token:";
    let encoded = name.strip_prefix(LINUX_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    String::from_utf8(bytes).ok()
}

/// Query the bolt token for a running process by reading its fd `1021` metadata.
#[cfg(target_os = "macos")]
pub fn get_token_for_pid(pid: i32) -> Option<String> {
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
            BOLT_TOKEN_FD,
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

    const MACOS_PREFIX: &str = "/bolt-token:";
    let encoded = name.strip_prefix(MACOS_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    String::from_utf8(bytes).ok()
}

/// Query the bolt token from the target process's environment block (Windows).
#[cfg(target_os = "windows")]
pub fn get_token_for_pid(pid: i32) -> Option<String> {
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

        const KEY: &str = "BOLTCONN_TOKEN=";
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

/// Set the `BOLTCONN_TOKEN` environment variable before spawning a child (Windows only).
#[cfg(target_os = "windows")]
pub fn setup_token_env(encoded_token: &str) {
    std::env::set_var("BOLTCONN_TOKEN", encoded_token);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_token_fails() {
        assert!(validate_and_encode_token("").is_err());
    }

    #[test]
    fn test_validate_short_token_ok() {
        // "python" → base64 "cHl0aG9u" (8 chars) → shm name 20 chars ≤ 31
        let result = validate_and_encode_token("python");
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(result.unwrap(), "cHl0aG9u");
    }

    #[test]
    fn test_validate_token_at_exact_limit() {
        // Find the longest raw token whose base64 is exactly 19 chars.
        // 19-char base64 URL_SAFE_NO_PAD encodes 14 bytes (floor(19*6/8)=14, 14*8/6=18.67→padded to 19 would be 20 with pad...).
        // Actually URL_SAFE_NO_PAD for 14 bytes → ceil(14*4/3) = ceil(18.67) = 19 chars. ✓
        let token = "a".repeat(14); // 14 bytes
        let result = validate_and_encode_token(&token);
        assert!(result.is_ok(), "14-byte token should fit: {:?}", result);
        let encoded = result.unwrap();
        assert_eq!(
            BOLT_TOKEN_PREFIX.len() + encoded.len(),
            MAX_SHM_NAME_LEN,
            "should be exactly at limit"
        );
    }

    #[test]
    fn test_validate_token_too_long() {
        // 15 bytes → base64 is 20 chars → total 32 > 31
        let token = "a".repeat(15);
        assert!(validate_and_encode_token(&token).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_token_for_pid_linux_path_parsing() {
        // Simulate what get_token_for_pid does internally by testing the parsing logic.
        fn parse(raw: &str) -> Option<String> {
            let mut name = raw.to_owned();
            if let Some(base) = name.strip_suffix(" (deleted)") {
                name = base.to_owned();
            }
            const LINUX_PREFIX: &str = "/dev/shm/bolt-token:";
            let encoded = name.strip_prefix(LINUX_PREFIX)?;
            let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
            String::from_utf8(bytes).ok()
        }

        // With "(deleted)" suffix
        assert_eq!(
            parse("/dev/shm/bolt-token:cHl0aG9u (deleted)"),
            Some("python".to_string())
        );
        // Without "(deleted)" suffix (still linked)
        assert_eq!(
            parse("/dev/shm/bolt-token:cHl0aG9u"),
            Some("python".to_string())
        );
        // Non-matching prefix → None
        assert_eq!(parse("/dev/shm/other:cHl0aG9u"), None);
        // Unrelated fd content → None
        assert_eq!(parse("/proc/1/fd/1021"), None);
    }
}
