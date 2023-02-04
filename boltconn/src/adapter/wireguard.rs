use crate::adapter::{Connector, TcpOutBound, UdpOutBound};
use crate::common::buf_pool::{PktBufPool, MAX_PKT_SIZE};
use crate::common::duplex_chan::DuplexChan;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::smol::{SmolStack, VirtualIpDevice};
use crate::transport::wireguard::{WireguardConfig, WireguardTunnel};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

// Shared Wireguard Tunnel between multiple client connections
pub struct Endpoint {
    wg: Arc<WireguardTunnel>,
    stack: Arc<Mutex<SmolStack>>,
    stop_sender: broadcast::Sender<()>,
}

impl Endpoint {
    pub async fn new(
        outbound: UdpSocket,
        config: &WireguardConfig,
        dns: Arc<Dns>,
        allocator: PktBufPool,
        timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        // control conn
        let (stop_send, mut stop_recv) = broadcast::channel(1);

        let (mut wg_smol_tx, wg_smol_rx) = mpsc::channel(128);
        let (smol_wg_tx, mut smol_wg_rx) = mpsc::channel(128);
        let tunnel = Arc::new(WireguardTunnel::new(outbound, config, dns).await?);
        let device = VirtualIpDevice::new(config.mtu, wg_smol_rx, smol_wg_tx);
        let smol_stack = Arc::new(Mutex::new(SmolStack::new(
            config.ip_addr,
            device,
            allocator,
        )));

        let last_active = Arc::new(Mutex::new(Instant::now()));

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
                    if tunnel
                        .receive_incoming_packet(&mut wg_smol_tx, &mut buf, &mut wg_buf)
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
        // drive smol
        let smol_drive = {
            let smol_stack = smol_stack.clone();
            tokio::spawn(async move {
                loop {
                    let mut stack_handle = smol_stack.lock().await;
                    stack_handle.poll_all_tcp().await;
                }
            })
        };

        tokio::spawn(async move {
            // kill all coroutine when error or timeout
            loop {
                if let Ok(Ok(_)) = tokio::time::timeout(timeout, stop_recv.recv()).await {
                    // stop_recv got signal
                    wg_out.abort();
                    wg_in.abort();
                    smol_drive.abort();
                    return;
                } else if last_active.lock().await.elapsed() > timeout {
                    // timeout
                    wg_out.abort();
                    wg_in.abort();
                    smol_drive.abort();
                    return;
                }
            }
        });

        Ok(Arc::new(Self {
            wg: tunnel,
            stack: smol_stack,
            stop_sender: stop_send,
        }))
    }
}

pub struct WireguardManager {
    iface: String,
    active_conn: DashMap<WireguardConfig, Arc<Endpoint>>,
    dns: Arc<Dns>,
    allocator: PktBufPool,
    timeout: Duration,
}

impl WireguardManager {
    pub fn new(iface: &str, dns: Arc<Dns>, allocator: PktBufPool, timeout: Duration) -> Self {
        Self {
            iface: iface.to_string(),
            active_conn: Default::default(),
            dns,
            allocator,
            timeout,
        }
    }

    pub async fn get_wg_conn(&self, config: &WireguardConfig) -> anyhow::Result<Arc<Endpoint>> {
        // get an existing conn, or create
        match self.active_conn.entry(config.clone()) {
            Entry::Occupied(conn) => Ok(conn.get().clone()),
            Entry::Vacant(entry) => {
                let server_addr = get_dst(&self.dns, &config.endpoint).await?;
                let outbound = match server_addr {
                    SocketAddr::V4(_) => Egress::new(&self.iface).udpv4_socket().await?,
                    SocketAddr::V6(_) => unimplemented!(),
                };
                let ep = Endpoint::new(
                    outbound,
                    config,
                    self.dns.clone(),
                    self.allocator.clone(),
                    self.timeout,
                )
                .await?;
                entry.insert(ep.clone());
                Ok(ep)
            }
        }
    }
}

#[derive(Clone)]
pub struct WireguardHandle {
    src_port: u16,
    dst: NetworkAddr,
    endpoint: Arc<Endpoint>,
    dns: Arc<Dns>,
    allocator: PktBufPool,
}

impl WireguardHandle {
    pub fn new(
        src_port: u16,
        dst: NetworkAddr,
        endpoint: Arc<Endpoint>,
        dns: Arc<Dns>,
        allocator: PktBufPool,
    ) -> Self {
        Self {
            src_port,
            dst,
            endpoint,
            dns,
            allocator,
        }
    }

    async fn attach_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> io::Result<()> {
        let dst = get_dst(&self.dns, &self.dst).await?;
        self.endpoint
            .stack
            .lock()
            .await
            .open_tcp(self.src_port, dst, inbound, abort_handle)
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

    fn spawn_tcp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().attach_tcp(outer, abort_handle)),
        )
    }
}

impl UdpOutBound for WireguardHandle {
    fn spawn_udp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        todo!()
    }

    fn spawn_udp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<std::io::Result<()>>) {
        todo!()
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
