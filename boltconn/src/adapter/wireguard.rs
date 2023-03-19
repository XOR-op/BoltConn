use crate::adapter::{AddrConnector, Connector, TcpOutBound, UdpOutBound};

use crate::common::{io_err, OutboundTrait, MAX_PKT_SIZE};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::smol::{SmolStack, VirtualIpDevice};
use crate::transport::wireguard::{WireguardConfig, WireguardTunnel};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex, Notify};
use tokio::task::JoinHandle;

// Shared Wireguard Tunnel between multiple client connections
pub struct Endpoint {
    wg: Arc<WireguardTunnel>,
    stack: Arc<Mutex<SmolStack>>,
    stop_sender: broadcast::Sender<()>,
    notify: Arc<Notify>,
    is_active: Arc<AtomicBool>,
}

impl Endpoint {
    pub async fn new(
        outbound: UdpSocket,
        config: &WireguardConfig,
        dns: Arc<Dns>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        let notify = Arc::new(Notify::new());
        // control conn
        let (stop_send, mut stop_recv) = broadcast::channel(1);

        let (mut wg_smol_tx, wg_smol_rx) = flume::unbounded();
        let (smol_wg_tx, mut smol_wg_rx) = flume::unbounded();
        let tunnel = Arc::new(WireguardTunnel::new(outbound, config, dns, notify.clone()).await?);
        let device = VirtualIpDevice::new(config.mtu, wg_smol_rx, smol_wg_tx);
        let smol_stack = Arc::new(Mutex::new(SmolStack::new(
            config.ip_addr,
            device,
            Duration::from_secs(120),
        )));

        let last_active = Arc::new(Mutex::new(Instant::now()));
        let indicator = Arc::new(AtomicBool::new(true));
        let indi_write = indicator.clone();

        // drive wg tunnel
        let wg_out = {
            let tunnel = tunnel.clone();
            let stop_send = stop_send.clone();
            let timer = last_active.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                loop {
                    if tunnel
                        .send_outgoing_packet(&mut smol_wg_rx, &mut buf)
                        .await
                        .is_err()
                    {
                        let _ = stop_send.send(());
                        return;
                    }
                    *timer.lock().await = Instant::now();
                }
            })
        };

        let wg_in = {
            let tunnel = tunnel.clone();
            let stop_send = stop_send.clone();
            let timer = last_active.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                let mut wg_buf = [0u8; MAX_PKT_SIZE];
                loop {
                    if let Ok(newer) = tunnel
                        .receive_incoming_packet(&mut wg_smol_tx, &mut buf, &mut wg_buf)
                        .await
                    {
                        if newer {
                            *timer.lock().await = Instant::now();
                        }
                    } else {
                        let _ = stop_send.send(());
                        return;
                    }
                }
            })
        };

        let wg_tick = {
            let tunnel = tunnel.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                loop {
                    tunnel.tick(&mut buf).await;
                    // <del>From boringtun, the recommended interval is 100ms.</del>
                    // Comments from Tunn::update_timers says one second interval is enough.
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
            })
        };

        // drive smol
        let smol_drive = {
            let smol_stack = smol_stack.clone();
            let notifier = notify.clone();

            tokio::spawn(async move {
                let mut immediate_next_loop = false;
                notifier.notified().await;
                loop {
                    let mut stack_handle = smol_stack.lock().await;
                    stack_handle.drive_iface();
                    immediate_next_loop |= stack_handle.poll_all_tcp().await;
                    immediate_next_loop |= stack_handle.poll_all_udp().await;
                    stack_handle.purge_closed_tcp();
                    stack_handle.purge_timeout_udp();
                    drop(stack_handle);
                    if !immediate_next_loop {
                        notifier.notified().await;
                    }
                    immediate_next_loop = false;
                }
            })
        };

        // timeout inactive tunnel
        {
            let stop_send = stop_send.clone();
            let indi_write = indi_write.clone();
            tokio::spawn(async move {
                loop {
                    if last_active.lock().await.elapsed() > timeout {
                        indi_write.store(false, Ordering::Relaxed);
                        let _ = stop_send.send(());
                        tracing::trace!(
                            "[Wireguard] Stop inactive tunnel after for {}s.",
                            timeout.as_secs()
                        );
                        break;
                    }
                    tokio::time::sleep(timeout / 2).await;
                }
            });
        }

        tokio::spawn(async move {
            // kill all coroutine
            let _ = stop_recv.recv().await;
            indi_write.store(false, Ordering::Relaxed);
            wg_out.abort();
            wg_in.abort();
            wg_tick.abort();
            smol_drive.abort();
        });

        Ok(Arc::new(Self {
            wg: tunnel,
            stack: smol_stack,
            stop_sender: stop_send,
            notify,
            is_active: indicator,
        }))
    }

    pub fn clone_notify(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

pub struct WireguardManager {
    iface: String,
    active_conn: DashMap<WireguardConfig, Arc<Endpoint>>,
    dns: Arc<Dns>,
    timeout: Duration,
}

impl WireguardManager {
    pub fn new(iface: &str, dns: Arc<Dns>, timeout: Duration) -> Self {
        Self {
            iface: iface.to_string(),
            active_conn: Default::default(),
            dns,
            timeout,
        }
    }

    pub async fn get_wg_conn(&self, config: &WireguardConfig) -> anyhow::Result<Arc<Endpoint>> {
        loop {
            // get an existing conn, or create
            return match self.active_conn.entry(config.clone()) {
                Entry::Occupied(conn) => {
                    if !conn.get().is_active.load(Ordering::Relaxed) {
                        conn.remove_entry();
                        continue;
                    }
                    Ok(conn.get().clone())
                }
                Entry::Vacant(entry) => {
                    let server_addr = get_dst(&self.dns, &config.endpoint).await?;
                    let outbound = match server_addr {
                        SocketAddr::V4(_) => {
                            let socket = Egress::new(&self.iface).udpv4_socket().await?;
                            socket.connect(server_addr).await?;
                            socket
                        }
                        SocketAddr::V6(_) => {
                            let socket = Egress::new(&self.iface).udpv6_socket().await?;
                            socket.connect(server_addr).await?;
                            socket
                        }
                    };
                    let ep =
                        Endpoint::new(outbound, config, self.dns.clone(), self.timeout).await?;
                    entry.insert(ep.clone());
                    Ok(ep)
                }
            };
        }
    }
}

#[derive(Clone)]
pub struct WireguardHandle {
    src_port: u16,
    dst: NetworkAddr,
    endpoint: Arc<Endpoint>,
    dns: Arc<Dns>,
}

impl WireguardHandle {
    pub fn new(src_port: u16, dst: NetworkAddr, endpoint: Arc<Endpoint>, dns: Arc<Dns>) -> Self {
        Self {
            src_port,
            dst,
            endpoint,
            dns,
        }
    }

    async fn attach_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> io::Result<()> {
        // todo: remote dns
        let dst = get_dst(&self.dns, &self.dst).await?;
        let notify = self.endpoint.clone_notify();
        self.endpoint
            .stack
            .lock()
            .await
            .open_tcp(self.src_port, dst, inbound, abort_handle, notify)
    }

    async fn attach_udp(
        self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()> {
        // todo: remote dns
        let dst = get_dst(&self.dns, &self.dst).await?;
        let notify = self.endpoint.clone_notify();
        self.endpoint
            .stack
            .lock()
            .await
            .open_udp(self.src_port, dst, inbound, abort_handle, notify)
    }
}

impl TcpOutBound for WireguardHandle {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().attach_tcp(inbound, abort_handle))
    }

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        _outbound: Box<dyn OutboundTrait>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tracing::warn!("spawn_tcp_with_outbound() should not be called with Wireguard");
        self.spawn_tcp(inbound, abort_handle)
    }
}

impl UdpOutBound for WireguardHandle {
    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().attach_udp(inbound, abort_handle))
    }
}

async fn get_dst(dns: &Dns, dst: &NetworkAddr) -> io::Result<SocketAddr> {
    Ok(match dst {
        NetworkAddr::DomainName { domain_name, port } => {
            // translate fake ip
            SocketAddr::new(
                dns.genuine_lookup(domain_name.as_str())
                    .await
                    .ok_or_else(|| io_err("DNS failed"))?,
                *port,
            )
        }
        NetworkAddr::Raw(s) => *s,
    })
}
