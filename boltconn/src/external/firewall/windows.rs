use super::{KILL_SWITCH_BYPASS_IPV4, KILL_SWITCH_BYPASS_IPV6};
use ipnet::IpNet;
use std::{
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, GetLastError,
            HANDLE,
        },
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::PSECURITY_DESCRIPTOR,
        System::{Rpc::RPC_C_AUTHN_WINNT, Threading::CreateEventW},
    },
    core::{GUID, PCWSTR, PWSTR},
};

// Product-owned identities, independent of adapter identity or executable location.
// Static WFP objects survive a process crash, but not a BFE restart or reboot.
// Do not use dynamic sessions or PERSISTENT/BOOTTIME flags here.
struct Keys {
    provider: GUID,
    sublayer: GUID,
    owner: &'static str,
}
const KEYS: Keys = Keys {
    provider: GUID::from_u128(0xfce8ff24_ae1c_40de_99a7_4288110e9e9b),
    sublayer: GUID::from_u128(0x38c8f289_0738_4c18_aacf_3e0186b03d3e),
    owner: "Global\\BoltConn.KillSwitch.Owner.v1",
};
const LAYERS: [GUID; 2] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
];

pub struct KillSwitchGuard {
    keys: &'static Keys,
    // A named event serves as a process-lifetime ownership lock. Unlike a mutex,
    // its handle may be closed on another thread when the async daemon shuts down.
    _owner: OwnedHandle,
    active: bool,
}

impl KillSwitchGuard {
    pub fn setup(tun_name: &str) -> io::Result<Self> {
        let luid = unsafe { crate::platform::get_iface_luid(tun_name)?.Value };
        Self::install(&KEYS, luid, &std::env::current_exe()?, None)
    }

    fn install(
        keys: &'static Keys,
        tun_luid: u64,
        executable: &Path,
        scope: Option<&Path>,
    ) -> io::Result<Self> {
        let owner = claim_owner(keys)?;
        let app = app_id(executable)?;
        let scope = scope.map(app_id).transpose()?;
        let engine = Engine::open()?;
        engine.transaction(|| {
            // Replacement is atomic: failed setup leaves the previous crash-time
            // policy intact; there is no unprotected remove-then-add interval.
            engine.remove(keys)?;
            engine.add_policy(keys, tun_luid, &app, scope.as_ref())
        })?;
        tracing::info!(
            backend = "wfp",
            "Kill switch has been enabled (IPv4 and IPv6)"
        );
        Ok(Self {
            keys,
            _owner: owner,
            active: true,
        })
    }

    pub fn teardown(&mut self) -> io::Result<()> {
        if self.active {
            remove_policy(self.keys)?;
            self.active = false;
            tracing::info!("Kill switch has been disabled");
        }
        Ok(())
    }
}

impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        if let Err(error) = self.teardown() {
            tracing::error!(%error, "failed to remove Windows kill switch; use boltconn clean");
        }
    }
}

pub fn cleanup_stale_kill_switch() -> io::Result<()> {
    let _owner = claim_owner(&KEYS)?;
    remove_policy(&KEYS)
}

fn claim_owner(keys: &Keys) -> io::Result<OwnedHandle> {
    let name: Vec<u16> = keys.owner.encode_utf16().chain(Some(0)).collect();
    let handle = unsafe { CreateEventW(None, false, false, PCWSTR(name.as_ptr()))? };
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let owner = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    if already_exists {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a BoltConn kill switch is active; stop its daemon before cleanup or starting another",
        ));
    }
    Ok(owner)
}

fn remove_policy(keys: &Keys) -> io::Result<()> {
    let engine = Engine::open()?;
    engine.transaction(|| engine.remove(keys))
}

fn check(code: u32, operation: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation}: {} (0x{code:08x})",
            io::Error::from_raw_os_error(code as i32)
        )))
    }
}

// WFP owns these allocations; every successful query releases them through the API.
struct WfpMemory<T>(*mut T);
impl<T> Drop for WfpMemory<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FwpmFreeMemory0((&mut self.0 as *mut *mut T).cast()) };
        }
    }
}

fn app_id(path: &Path) -> io::Result<WfpMemory<FWP_BYTE_BLOB>> {
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut app = WfpMemory(ptr::null_mut());
    check(
        unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path.as_ptr()), &mut app.0) },
        "identify BoltConn executable",
    )?;
    Ok(app)
}

struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
struct Transaction<'a>(&'a Engine, bool);
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.1 {
            unsafe {
                FwpmTransactionAbort0(self.0.0);
            }
        }
    }
}
struct Enumeration<'a>(&'a Engine, HANDLE);
impl Drop for Enumeration<'_> {
    fn drop(&mut self) {
        unsafe {
            FwpmFilterDestroyEnumHandle0(self.0.0, self.1);
        }
    }
}

impl Engine {
    fn open() -> io::Result<Self> {
        let mut handle = HANDLE::default();
        let session = FWPM_SESSION0 {
            txnWaitTimeoutInMSec: 5000,
            ..Default::default()
        };
        check(
            unsafe {
                FwpmEngineOpen0(
                    PCWSTR::null(),
                    RPC_C_AUTHN_WINNT,
                    None,
                    Some(&session),
                    &mut handle,
                )
            },
            "open WFP engine",
        )?;
        Ok(Self(handle))
    }

    fn transaction(&self, operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        check(
            unsafe { FwpmTransactionBegin0(self.0, 0) },
            "begin WFP transaction",
        )?;
        let mut transaction = Transaction(self, false);
        operation()?;
        check(
            unsafe { FwpmTransactionCommit0(self.0) },
            "commit WFP transaction",
        )?;
        transaction.1 = true;
        Ok(())
    }

    fn filter_ids(&self, keys: &Keys) -> io::Result<Vec<u64>> {
        let mut provider: WfpMemory<FWPM_PROVIDER0> = WfpMemory(ptr::null_mut());
        let result = unsafe { FwpmProviderGetByKey0(self.0, &keys.provider, &mut provider.0) };
        if result == FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            return Ok(Vec::new());
        }
        check(result, "find BoltConn WFP provider")?;
        let mut ids = Vec::new();
        for layer in LAYERS {
            let mut provider = keys.provider;
            let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                providerKey: &mut provider,
                layerKey: layer,
                enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
                flags: FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
                actionMask: u32::MAX,
                ..Default::default()
            };
            let mut handle = HANDLE::default();
            check(
                unsafe { FwpmFilterCreateEnumHandle0(self.0, Some(&template), &mut handle) },
                "enumerate BoltConn filters",
            )?;
            let enumeration = Enumeration(self, handle);
            loop {
                let mut entries: WfpMemory<*mut FWPM_FILTER0> = WfpMemory(ptr::null_mut());
                let mut count = 0;
                check(
                    unsafe {
                        FwpmFilterEnum0(self.0, enumeration.1, 128, &mut entries.0, &mut count)
                    },
                    "read BoltConn filters",
                )?;
                if count == 0 {
                    break;
                }
                for entry in unsafe { std::slice::from_raw_parts(entries.0, count as usize) } {
                    let filter = unsafe { &**entry };
                    if filter.subLayerKey == keys.sublayer
                        && !filter.providerKey.is_null()
                        && unsafe { *filter.providerKey } == keys.provider
                    {
                        ids.push(filter.filterId);
                    }
                }
            }
        }
        Ok(ids)
    }

    fn remove(&self, keys: &Keys) -> io::Result<()> {
        let mut provider: WfpMemory<FWPM_PROVIDER0> = WfpMemory(ptr::null_mut());
        let result = unsafe { FwpmProviderGetByKey0(self.0, &keys.provider, &mut provider.0) };
        if result == FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            return Ok(());
        }
        check(result, "find BoltConn WFP provider")?;
        for id in self.filter_ids(keys)? {
            check(
                unsafe { FwpmFilterDeleteById0(self.0, id) },
                "remove BoltConn filter",
            )?;
        }
        let result = unsafe { FwpmSubLayerDeleteByKey0(self.0, &keys.sublayer) };
        if result != FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            check(result, "remove BoltConn WFP sublayer")?;
        }
        check(
            unsafe { FwpmProviderDeleteByKey0(self.0, &keys.provider) },
            "remove BoltConn WFP provider",
        )
    }

    fn add_policy(
        &self,
        keys: &Keys,
        mut tun_luid: u64,
        app: &WfpMemory<FWP_BYTE_BLOB>,
        scope: Option<&WfpMemory<FWP_BYTE_BLOB>>,
    ) -> io::Result<()> {
        let mut name: Vec<u16> = "BoltConn kill switch"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let display = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            ..Default::default()
        };
        let provider = FWPM_PROVIDER0 {
            providerKey: keys.provider,
            displayData: display,
            ..Default::default()
        };
        check(
            unsafe { FwpmProviderAdd0(self.0, &provider, PSECURITY_DESCRIPTOR::default()) },
            "add BoltConn WFP provider",
        )?;
        let mut provider_key = keys.provider;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: keys.sublayer,
            providerKey: &mut provider_key,
            displayData: display,
            weight: 0x8000,
            ..Default::default()
        };
        check(
            unsafe { FwpmSubLayerAdd0(self.0, &sublayer, PSECURITY_DESCRIPTOR::default()) },
            "add BoltConn WFP sublayer",
        )?;
        for (family, layer) in LAYERS.into_iter().enumerate() {
            // Soft permits exempt traffic only from our own block. They do not
            // override Windows Firewall or another provider's blocking policy.
            self.add_filter(
                keys,
                layer,
                true,
                vec![condition(
                    FWPM_CONDITION_ALE_APP_ID,
                    FWP_BYTE_BLOB_TYPE,
                    FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
                )],
            )?;
            let mut loopback = condition(
                FWPM_CONDITION_FLAGS,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            );
            loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
            self.add_filter(keys, layer, true, vec![loopback])?;
            self.add_filter(
                keys,
                layer,
                true,
                vec![condition(
                    FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                    FWP_UINT64,
                    FWP_CONDITION_VALUE0_0 {
                        uint64: &mut tun_luid,
                    },
                )],
            )?;
            for subnet in bypass_networks(family == 1) {
                match subnet {
                    IpNet::V4(net) => {
                        let mut mask = FWP_V4_ADDR_AND_MASK {
                            addr: u32::from(net.network()),
                            mask: u32::from(net.netmask()),
                        };
                        self.add_filter(
                            keys,
                            layer,
                            true,
                            vec![condition(
                                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                FWP_V4_ADDR_MASK,
                                FWP_CONDITION_VALUE0_0 {
                                    v4AddrMask: &mut mask,
                                },
                            )],
                        )?;
                    }
                    IpNet::V6(net) => {
                        let mut mask = FWP_V6_ADDR_AND_MASK {
                            addr: net.network().octets(),
                            prefixLength: net.prefix_len(),
                        };
                        self.add_filter(
                            keys,
                            layer,
                            true,
                            vec![condition(
                                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                FWP_V6_ADDR_MASK,
                                FWP_CONDITION_VALUE0_0 {
                                    v6AddrMask: &mut mask,
                                },
                            )],
                        )?;
                    }
                }
            }
            for protocol in [6, 17] {
                let mut conditions = vec![condition(
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_UINT8,
                    FWP_CONDITION_VALUE0_0 { uint8: protocol },
                )];
                // Tests can restrict blocking to a disposable helper executable,
                // exercising real WFP behavior without filtering other applications.
                if let Some(scope) = scope {
                    conditions.push(condition(
                        FWPM_CONDITION_ALE_APP_ID,
                        FWP_BYTE_BLOB_TYPE,
                        FWP_CONDITION_VALUE0_0 { byteBlob: scope.0 },
                    ));
                }
                self.add_filter(keys, layer, false, conditions)?;
            }
        }
        Ok(())
    }

    // All pointed-to condition values are owned by the caller for this synchronous
    // API call. WFP copies them before returning; no borrowed pointer is retained.
    fn add_filter(
        &self,
        keys: &Keys,
        layer: GUID,
        permit: bool,
        mut conditions: Vec<FWPM_FILTER_CONDITION0>,
    ) -> io::Result<()> {
        let mut name: Vec<u16> = if permit {
            "BoltConn exception"
        } else {
            "BoltConn block bypass"
        }
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let mut provider = keys.provider;
        let mut weight = if permit { 100u64 } else { 10 };
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                ..Default::default()
            },
            providerKey: &mut provider,
            layerKey: layer,
            subLayerKey: keys.sublayer,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: if permit {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                },
                ..Default::default()
            },
            ..Default::default()
        };
        check(
            unsafe { FwpmFilterAdd0(self.0, &filter, PSECURITY_DESCRIPTOR::default(), None) },
            "add BoltConn WFP filter",
        )
    }
}

fn condition(
    key: GUID,
    kind: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}

fn bypass_networks(ipv6: bool) -> Vec<IpNet> {
    if !ipv6 {
        return KILL_SWITCH_BYPASS_IPV4
            .iter()
            .map(|net| net.parse().unwrap())
            .collect();
    }
    let mut networks: Vec<IpNet> = KILL_SWITCH_BYPASS_IPV6
        .iter()
        .map(|net| net.parse().unwrap())
        .collect();
    // Dual-stack sockets can appear at the IPv6 ALE layer with mapped IPv4
    // destinations. Apply the same LAN exceptions without exempting public IPv4.
    for subnet in KILL_SWITCH_BYPASS_IPV4 {
        let net: ipnet::Ipv4Net = subnet.parse().unwrap();
        networks.push(
            ipnet::Ipv6Net::new(net.network().to_ipv6_mapped(), 96 + net.prefix_len())
                .unwrap()
                .into(),
        );
    }
    networks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawSocket;
    use std::{
        net::{SocketAddr, TcpListener},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    const TEST_KEYS: Keys = Keys {
        provider: GUID::from_u128(0x293215f4_f5bd_4433_a15b_32ac5200f178),
        sublayer: GUID::from_u128(0x598fe687_42e7_49f3_ad28_65c38c6e7c8f),
        owner: "Global\\BoltConn.KillSwitch.Test.Owner.v1",
    };
    const CHILD: &str = "external::firewall::windows::tests::wfp_child";

    #[test]
    fn ipv6_exceptions_include_only_local_mapped_ipv4() {
        let networks = bypass_networks(true);
        for address in [
            "::1",
            "fc12::1",
            "fe80::1",
            "::ffff:192.168.64.15",
            "::ffff:127.0.0.1",
        ] {
            let address: std::net::IpAddr = address.parse().unwrap();
            assert!(
                networks.iter().any(|net| net.contains(&address)),
                "{address}"
            );
        }
        for address in ["2606:4700:4700::1111", "::ffff:1.1.1.1", "ff02::1"] {
            let address: std::net::IpAddr = address.parse().unwrap();
            assert!(
                !networks.iter().any(|net| net.contains(&address)),
                "{address}"
            );
        }
    }

    fn child(executable: &Path) -> Command {
        let mut command = Command::new(executable);
        command.args(["--ignored", "--exact", CHILD, "--nocapture"]);
        command
    }

    // Invoked only by the parent below. A separate executable identity limits
    // every block rule to this disposable test helper, including after a crash.
    #[test]
    #[ignore = "helper for scoped_wfp_lifecycle"]
    fn wfp_child() {
        let Ok(role) = std::env::var("BOLTCONN_WFP_ROLE") else {
            return;
        };
        if role == "watchdog" {
            std::fs::write(std::env::var_os("BOLTCONN_WFP_READY").unwrap(), "ready").unwrap();
            std::thread::sleep(Duration::from_secs(60));
            remove_policy(&TEST_KEYS).unwrap();
            return;
        }
        if role == "owner" {
            let helper = std::env::var_os("BOLTCONN_WFP_HELPER").unwrap();
            let tun = std::env::var("BOLTCONN_TEST_TUN").unwrap();
            let luid = unsafe { crate::platform::get_iface_luid(&tun).unwrap().Value };
            let _guard = KillSwitchGuard::install(
                &TEST_KEYS,
                luid,
                &std::env::current_exe().unwrap(),
                Some(Path::new(&helper)),
            )
            .unwrap();
            std::fs::write(std::env::var_os("BOLTCONN_WFP_READY").unwrap(), "ready").unwrap();
            // Bounded even if the parent fails before terminating us.
            std::thread::sleep(Duration::from_secs(45));
            return;
        }
        assert_eq!(role, "probe");
        let target: SocketAddr = std::env::var("BOLTCONN_WFP_TARGET")
            .unwrap()
            .parse()
            .unwrap();
        let udp = std::env::var("BOLTCONN_WFP_PROTOCOL").unwrap() == "udp";
        let socket = socket2::Socket::new(
            if target.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            if udp {
                socket2::Type::DGRAM
            } else {
                socket2::Type::STREAM
            },
            None,
        )
        .unwrap();
        if target.is_ipv6() && target.ip().to_canonical().is_ipv4() {
            socket.set_only_v6(false).unwrap();
        }
        if std::env::var("BOLTCONN_WFP_BIND").as_deref() == Ok("yes") {
            let iface = std::env::var("BOLTCONN_TEST_INTERFACE").unwrap();
            if target.is_ipv4() {
                crate::platform::bind_to_interface_v4(socket.as_raw_socket(), &iface).unwrap();
                socket
                    .bind(
                        &SocketAddr::new(crate::platform::get_iface_address(&iface).unwrap(), 0)
                            .into(),
                    )
                    .unwrap();
            } else {
                crate::platform::bind_to_interface_v6(socket.as_raw_socket(), &iface).unwrap();
                if target.ip().to_canonical().is_ipv4() {
                    crate::platform::bind_to_interface_v4(socket.as_raw_socket(), &iface).unwrap();
                    let std::net::IpAddr::V4(local) =
                        crate::platform::get_iface_address(&iface).unwrap()
                    else {
                        panic!()
                    };
                    socket
                        .bind(&SocketAddr::new(local.to_ipv6_mapped().into(), 0).into())
                        .unwrap();
                } else {
                    socket
                        .bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())
                        .unwrap();
                }
            }
        }
        let result = if udp {
            let socket: std::net::UdpSocket = socket.into();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let query: &[u8] = if target.ip().is_multicast() {
                b"boltconn-wfp-test"
            } else {
                b"\x42\x43\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
            };
            socket.send_to(query, target).and_then(|_| {
                let mut reply = [0u8; 2048];
                socket.recv_from(&mut reply).map(|(length, _)| {
                    if target.ip().is_multicast() {
                        assert_eq!(&reply[..length], query);
                    } else {
                        assert!(length >= 12 && reply[..2] == query[..2] && reply[2] & 0x80 != 0);
                    }
                })
            })
        } else {
            socket.connect_timeout(&target.into(), Duration::from_secs(4))
        };
        if std::env::var("BOLTCONN_WFP_EXPECT").as_deref() == Ok("blocked") {
            let error = result.unwrap_err();
            if udp {
                assert!(
                    matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::PermissionDenied
                    ),
                    "{target}: {error}"
                );
            } else {
                assert_eq!(
                    error.raw_os_error(),
                    Some(10013),
                    "expected WSAEACCES for {target}"
                );
            }
        } else {
            result.unwrap_or_else(|error| panic!("{target}: {error}"));
        }
        println!(
            "{target}: {}",
            std::env::var("BOLTCONN_WFP_EXPECT").unwrap()
        );
    }

    fn probe(executable: &Path, target: &str, protocol: &str, bind: bool, blocked: bool) {
        let status = child(executable)
            .env("BOLTCONN_WFP_ROLE", "probe")
            .env("BOLTCONN_WFP_TARGET", target)
            .env("BOLTCONN_WFP_PROTOCOL", protocol)
            .env("BOLTCONN_WFP_BIND", if bind { "yes" } else { "no" })
            .env(
                "BOLTCONN_WFP_EXPECT",
                if blocked { "blocked" } else { "allowed" },
            )
            .status()
            .unwrap();
        assert!(status.success(), "probe failed: {target}");
    }

    struct MulticastEcho {
        target: std::net::SocketAddrV6,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl MulticastEcho {
        fn new() -> Self {
            let SocketAddr::V6(mut target) = std::env::var("BOLTCONN_TEST_IPV6_UDP")
                .unwrap()
                .parse()
                .unwrap()
            else {
                panic!()
            };
            let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
            target.set_port(socket.local_addr().unwrap().port());
            socket
                .join_multicast_v6(target.ip(), target.scope_id())
                .unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stopped = stop.clone();
            let thread = std::thread::spawn(move || {
                let mut buffer = [0u8; 128];
                while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok((length, peer)) = socket.recv_from(&mut buffer) {
                        socket.send_to(&buffer[..length], peer).unwrap();
                    }
                }
            });
            Self {
                target,
                stop,
                thread: Some(thread),
            }
        }
    }
    impl Drop for MulticastEcho {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = self.thread.take().unwrap().join();
        }
    }

    #[test]
    #[ignore = "admin, existing TUN and reachable test endpoints; filters only the disposable helper executable"]
    fn scoped_wfp_lifecycle() {
        assert!(is_root::is_root());
        let executable = std::env::current_exe().unwrap();
        let directory = executable
            .parent()
            .unwrap()
            .join(format!("wfp-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let helper = directory.join("probe.exe");
        std::fs::copy(&executable, &helper).unwrap();
        let tun = std::env::var("BOLTCONN_TEST_TUN").unwrap();
        let luid = unsafe { crate::platform::get_iface_luid(&tun).unwrap().Value };
        let lan = std::env::var("BOLTCONN_TEST_LAN_TCP").unwrap();
        let echo = MulticastEcho::new();
        let multicast = echo.target.to_string();
        let loopback = TcpListener::bind("127.0.0.1:0").unwrap();
        let loopback_v6 = TcpListener::bind("[::1]:0").unwrap();
        // Cleanup only the dedicated test provider; production daemon state is untouched.
        let initial_owner = claim_owner(&TEST_KEYS).unwrap();
        remove_policy(&TEST_KEYS).unwrap();
        drop(initial_owner);
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = remove_policy(&TEST_KEYS);
            }
        }
        let _cleanup = Cleanup;
        probe(&helper, "1.1.1.1:443", "tcp", true, false);
        probe(&helper, "1.1.1.1:53", "udp", true, false);
        probe(&helper, &multicast, "udp", true, false);
        let mut guard =
            KillSwitchGuard::install(&TEST_KEYS, luid, &executable, Some(&helper)).unwrap();
        assert!(claim_owner(&TEST_KEYS).is_err());
        probe(&helper, "1.1.1.1:443", "tcp", true, true);
        probe(&helper, "1.1.1.1:53", "udp", true, true);
        probe(&helper, &multicast, "udp", true, true);
        probe(&helper, "[::ffff:1.1.1.1]:443", "tcp", true, true);
        probe(&helper, &lan, "tcp", true, false);
        let lan_socket: SocketAddr = lan.parse().unwrap();
        let std::net::IpAddr::V4(lan_ip) = lan_socket.ip() else {
            panic!()
        };
        probe(
            &helper,
            &format!("[{}]:{}", lan_ip.to_ipv6_mapped(), lan_socket.port()),
            "tcp",
            true,
            false,
        );
        probe(
            &helper,
            &loopback.local_addr().unwrap().to_string(),
            "tcp",
            false,
            false,
        );
        probe(
            &helper,
            &loopback_v6.local_addr().unwrap().to_string(),
            "tcp",
            false,
            false,
        );
        probe(&executable, "1.1.1.1:443", "tcp", true, false);
        probe(&helper, "1.1.1.1:443", "tcp", false, false); // Existing TUN next-hop exception.
        let engine = Engine::open().unwrap();
        let mut original = engine.filter_ids(&TEST_KEYS).unwrap();
        original.sort_unstable();
        assert!(!original.is_empty());
        // A failed atomic replacement must retain the old rules and blocking.
        assert!(
            engine
                .transaction(|| {
                    engine.remove(&TEST_KEYS)?;
                    Err(io::Error::other("injected setup failure"))
                })
                .is_err()
        );
        let mut after_failure = engine.filter_ids(&TEST_KEYS).unwrap();
        after_failure.sort_unstable();
        assert_eq!(original, after_failure);
        probe(&helper, "1.1.1.1:443", "tcp", true, true);
        guard.teardown().unwrap();
        guard.teardown().unwrap();
        drop(guard);
        probe(&helper, "1.1.1.1:443", "tcp", true, false);
        probe(&helper, &multicast, "udp", true, false);
        assert!(engine.filter_ids(&TEST_KEYS).unwrap().is_empty());

        let ready = directory.join("ready");
        let mut owner = child(&executable)
            .env("BOLTCONN_WFP_ROLE", "owner")
            .env("BOLTCONN_WFP_HELPER", &helper)
            .env("BOLTCONN_WFP_READY", &ready)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            if let Some(status) = owner.try_wait().unwrap() {
                panic!("owner exited early: {status}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Always terminate the helper we created, including the readiness failure case.
        owner.kill().unwrap();
        owner.wait().unwrap();
        assert!(ready.exists(), "owner never installed its filters");
        assert!(
            !engine.filter_ids(&TEST_KEYS).unwrap().is_empty(),
            "crash unexpectedly removed blocking"
        );
        probe(&helper, "1.1.1.1:443", "tcp", true, true);
        // Restart replaces stale policy, and graceful teardown removes it.
        let guard = KillSwitchGuard::install(&TEST_KEYS, luid, &executable, Some(&helper)).unwrap();
        drop(guard);
        probe(&helper, "1.1.1.1:443", "tcp", true, false);
        remove_policy(&TEST_KEYS).unwrap();
        assert!(engine.filter_ids(&TEST_KEYS).unwrap().is_empty());
        // Exercise the executable exemption with that same executable covered by
        // the blocking scope, so the permit is required for the connection to work.
        let guard = KillSwitchGuard::install(&TEST_KEYS, luid, &helper, Some(&helper)).unwrap();
        probe(&helper, "1.1.1.1:443", "tcp", true, false);
        drop(guard);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "global filtering: requires an independently launched 60-second watchdog and an existing TUN daemon"]
    fn system_wfp_existing_tun() {
        assert!(is_root::is_root());
        let ready = std::env::var_os("BOLTCONN_WFP_WATCHDOG_READY").unwrap();
        assert!(
            std::fs::metadata(ready)
                .unwrap()
                .modified()
                .unwrap()
                .elapsed()
                .unwrap()
                < Duration::from_secs(10)
        );
        let executable = std::env::current_exe().unwrap();
        let daemon = std::env::var_os("BOLTCONN_TEST_DAEMON_EXE").unwrap();
        let tun = std::env::var("BOLTCONN_TEST_TUN").unwrap();
        let luid = unsafe { crate::platform::get_iface_luid(&tun).unwrap().Value };
        let echo = MulticastEcho::new();
        probe(&executable, &echo.target.to_string(), "udp", true, false);
        let mut guard =
            KillSwitchGuard::install(&TEST_KEYS, luid, Path::new(&daemon), None).unwrap();
        probe(&executable, "1.1.1.1:443", "tcp", true, true);
        probe(&executable, "1.1.1.1:53", "udp", true, true);
        probe(&executable, &echo.target.to_string(), "udp", true, true);
        probe(
            &executable,
            &std::env::var("BOLTCONN_TEST_LAN_TCP").unwrap(),
            "tcp",
            true,
            false,
        );
        probe(&executable, "1.1.1.1:443", "tcp", false, false);
        guard.teardown().unwrap();
        probe(&executable, "1.1.1.1:443", "tcp", true, false);
        assert!(
            Engine::open()
                .unwrap()
                .filter_ids(&TEST_KEYS)
                .unwrap()
                .is_empty()
        );
    }
}
