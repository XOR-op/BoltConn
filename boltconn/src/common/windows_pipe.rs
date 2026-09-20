use std::{
    fs::OpenOptions,
    io,
    os::windows::{fs::OpenOptionsExt, io::IntoRawHandle},
};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            FILE_APPEND_DATA, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::{PCWSTR, PWSTR},
};

// GENERIC_WRITE on pipes includes FILE_CREATE_PIPE_INSTANCE. Clients only
// need the data/attribute rights, not permission to create another server.
const CLIENT_ACCESS: u32 = (FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0) & !FILE_APPEND_DATA.0;

struct LocalMemory(HLOCAL);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
    }
    let result = token_user_sid(token);
    let _ = unsafe { CloseHandle(token) };
    result
}

fn token_user_sid(token: HANDLE) -> io::Result<String> {
    // TOKEN_USER plus the maximum SID fits comfortably in this aligned buffer.
    let mut buffer = [0usize; 128];
    let mut size = 0;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            std::mem::size_of_val(&buffer) as u32,
            &mut size,
        )
    };
    result?;
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(user.User.Sid, &mut text)?;
    }
    let _allocation = LocalMemory(HLOCAL(text.0.cast()));
    unsafe { text.to_string() }.map_err(io::Error::other)
}

pub(crate) struct PipeSecurity {
    descriptor: Vec<u16>,
}

impl PipeSecurity {
    pub(crate) fn new() -> io::Result<Self> {
        let sid = current_user_sid()?;
        // A rootless server needs instance creation rights under its own user
        // SID; an elevated server receives those rights through Administrators.
        let rights = if is_root::is_root() {
            format!("0x{CLIENT_ACCESS:x}")
        } else {
            "GA".to_owned()
        };
        let descriptor = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;{rights};;;{sid})S:(ML;;NW;;;ME)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        Ok(Self { descriptor })
    }

    pub(crate) fn create(&self, path: &str, first: bool) -> io::Result<NamedPipeServer> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(self.descriptor.as_ptr()),
                1,
                &mut descriptor,
                None,
            )?;
        }
        let _allocation = LocalMemory(HLOCAL(descriptor.0));
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        // Windows copies the descriptor during this call. Keep the allocation
        // alive until creation finishes, and never fall back to a default ACL.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    path,
                    (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
                )
        }
    }
}

pub(crate) fn open_client(path: &str) -> io::Result<NamedPipeClient> {
    let file = OpenOptions::new()
        .access_mode(CLIENT_ACCESS)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OVERLAPPED.0 | SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0)
        .open(path)?;
    // Tokio takes ownership even if IOCP registration fails. Identification-only
    // SQOS preserves Tokio's protection against server-side impersonation.
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::UnixListenerGuard;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn repeated_clients_and_exclusive_server() {
        let path = format!(r"\\.\pipe\boltconn-security-test-{}", std::process::id());
        let listener = UnixListenerGuard::new(&path).unwrap();
        assert!(UnixListenerGuard::new(&path).is_err());
        for _ in 0..3 {
            let mut client = open_client(&path).unwrap();
            let mut server = listener.accept().await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                client.write_all(b"request").await.unwrap();
                let mut request = [0; 7];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"request");
                server.write_all(b"reply").await.unwrap();
                let mut reply = [0; 5];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"reply");
            })
            .await
            .unwrap();
        }
        drop(listener);
        assert!(open_client(&path).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires elevation and a linked token or BOLTCONN_TEST_MEDIUM_PID of a same-account non-elevated process; uses only a temporary pipe"]
    async fn non_elevated_same_account_can_control_but_not_create_server() {
        use windows::Win32::Security::{
            ImpersonateLoggedOnUser, RevertToSelf, TOKEN_DUPLICATE, TOKEN_ELEVATION,
            TOKEN_LINKED_TOKEN, TokenElevation, TokenLinkedToken,
        };
        assert!(is_root::is_root());
        let path = format!(r"\\.\pipe\boltconn-medium-test-{}", std::process::id());
        let security = PipeSecurity::new().unwrap();
        let mut server = security.create(&path, true).unwrap();
        struct Token(HANDLE);
        impl Drop for Token {
            fn drop(&mut self) {
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
        let mut size = 0;
        let linked = if let Ok(pid) = std::env::var("BOLTCONN_TEST_MEDIUM_PID") {
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };
            let process = Token(unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    pid.parse().unwrap(),
                )
                .unwrap()
            });
            let mut token = HANDLE::default();
            unsafe {
                OpenProcessToken(process.0, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token).unwrap();
            }
            Token(token)
        } else {
            let mut process_token = HANDLE::default();
            unsafe {
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process_token).unwrap();
            }
            let mut linked = TOKEN_LINKED_TOKEN::default();
            let result = unsafe {
                GetTokenInformation(
                    process_token,
                    TokenLinkedToken,
                    Some((&mut linked as *mut TOKEN_LINKED_TOKEN).cast()),
                    std::mem::size_of_val(&linked) as u32,
                    &mut size,
                )
            };
            let _ = unsafe { CloseHandle(process_token) };
            result.expect("this test requires the elevated user's linked token");
            Token(linked.LinkedToken)
        };
        assert_eq!(
            token_user_sid(linked.0).unwrap(),
            current_user_sid().unwrap()
        );
        let mut elevation = TOKEN_ELEVATION::default();
        unsafe {
            GetTokenInformation(
                linked.0,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of_val(&elevation) as u32,
                &mut size,
            )
            .unwrap();
        }
        assert_eq!(elevation.TokenIsElevated, 0);
        // Check the effective integrity level, not just group membership.
        use windows::Win32::Security::{
            GetSidSubAuthority, GetSidSubAuthorityCount, TOKEN_MANDATORY_LABEL, TokenIntegrityLevel,
        };
        let mut integrity = [0usize; 128];
        unsafe {
            GetTokenInformation(
                linked.0,
                TokenIntegrityLevel,
                Some(integrity.as_mut_ptr().cast()),
                std::mem::size_of_val(&integrity) as u32,
                &mut size,
            )
            .unwrap();
            let label = &*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
            let count = *GetSidSubAuthorityCount(label.Label.Sid);
            assert_eq!(
                *GetSidSubAuthority(label.Label.Sid, u32::from(count - 1)),
                0x2000
            );
        }
        for _ in 0..3 {
            // Impersonation is confined to synchronous open calls, never across
            // an await or on a Tokio worker running unrelated tasks.
            let (client, extra_server) = {
                struct Revert;
                impl Drop for Revert {
                    fn drop(&mut self) {
                        unsafe {
                            RevertToSelf().expect("revert test impersonation");
                        }
                    }
                }
                unsafe {
                    ImpersonateLoggedOnUser(linked.0).unwrap();
                }
                let _revert = Revert;
                (open_client(&path), security.create(&path, false))
            };
            let mut client = client.unwrap();
            assert_eq!(
                extra_server.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            server.connect().await.unwrap();
            let next = security.create(&path, false).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                client.write_all(b"request").await.unwrap();
                let mut request = [0; 7];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"request");
                server.write_all(b"reply").await.unwrap();
                let mut reply = [0; 5];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"reply");
            })
            .await
            .unwrap();
            server = next;
        }
    }
}
