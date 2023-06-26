use crate::adapter::{AddrConnector, AddrConnectorWrapper, Connector, Outbound, OutboundType};
use std::future::Future;

use crate::common::duplex_chan::DuplexChan;
use crate::common::{io_err, StreamOutboundTrait, MAX_PKT_SIZE};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::smol::{SmolStack, VirtualIpDevice};
use crate::transport::wireguard::{WireguardConfig, WireguardTunnel};
use crate::transport::{AdapterOrSocket, UdpSocketAdapter};
use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tokio::select;
use tokio::sync::{broadcast, Mutex, Notify};
use tokio::task::JoinHandle;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::name_server::{GenericConnector, RuntimeProvider};
use trust_dns_resolver::proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_resolver::proto::udp::DnsUdpSocket;
use trust_dns_resolver::proto::TokioTime;
use trust_dns_resolver::{AsyncResolver, TokioHandle};

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
        outbound: AdapterOrSocket,
        config: &WireguardConfig,
        dns: Arc<Dns>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        let notify = Arc::new(Notify::new());
        // control conn
        let (stop_send, mut stop_recv) = broadcast::channel(1);

        let (mut wg_smol_tx, wg_smol_rx) = flume::unbounded();
        let (smol_wg_tx, mut smol_wg_rx) = flume::unbounded();
        let tunnel =
            Arc::new(WireguardTunnel::new(outbound, config, dns.clone(), notify.clone()).await?);
        let device = VirtualIpDevice::new(config.mtu, wg_smol_rx, smol_wg_tx);
        let smol_stack = Arc::new(Mutex::new(SmolStack::new(
            config.ip_addr,
            device,
            dns,
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
                        select! {
                            _ = tokio::time::sleep(Duration::from_secs(3)) =>{}
                            _ = notifier.notified() =>{}
                        }
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

    pub async fn get_wg_conn(
        &self,
        config: &WireguardConfig,
        adapter: Option<AdapterOrSocket>,
    ) -> anyhow::Result<Arc<Endpoint>> {
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
                    let outbound = adapter.unwrap_or(AdapterOrSocket::Socket(match server_addr {
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
                    }));
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
    config: Arc<WireguardConfig>,
    manager: Arc<WireguardManager>,
    dns_config: Arc<ResolverConfig>,
}

impl WireguardHandle {
    pub fn new(
        src_port: u16,
        dst: NetworkAddr,
        config: WireguardConfig,
        manager: Arc<WireguardManager>,
        dns_config: Arc<ResolverConfig>,
    ) -> Self {
        Self {
            src_port,
            dst,
            config: Arc::new(config),
            manager,
            dns_config,
        }
    }

    async fn attach_tcp(
        self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
        adapter: Option<AdapterOrSocket>,
    ) -> io::Result<()> {
        let endpoint = self.get_endpoint(adapter).await?;
        let dst = match self.dst {
            NetworkAddr::Raw(s) => s,
            NetworkAddr::DomainName { domain_name, port } => {
                let abort_h = ConnAbortHandle::new();
                abort_h.fulfill(vec![]).await;
                let resolver = AsyncResolver::new(
                    self.dns_config.as_ref().clone(),
                    ResolverOpts::default(),
                    GenericConnector::new(WireguardDnsProvider {
                        handle: Default::default(),
                        endpoint: endpoint.clone(),
                        abort_handle: abort_h,
                    }),
                );
                let r = resolver
                    .ipv4_lookup(domain_name)
                    .await
                    .map_err(|_| io_err("Failed to resolve"))?;
                match r.into_iter().next() {
                    None => return Err(io_err("Not found")),
                    Some(dst) => SocketAddr::new(dst.0.into(), port),
                }
            }
        };

        let notify = endpoint.clone_notify();
        let mut x = endpoint.stack.lock().await;
        x.open_tcp(self.src_port, dst, inbound, abort_handle, notify)
    }

    async fn get_endpoint(&self, adapter: Option<AdapterOrSocket>) -> io::Result<Arc<Endpoint>> {
        self.manager
            .get_wg_conn(&self.config, adapter)
            .await
            .map_err(|e| io_err(format!("{}", e).as_str()))
    }

    async fn attach_udp(
        self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        adapter: Option<AdapterOrSocket>,
    ) -> io::Result<()> {
        let endpoint = self.get_endpoint(adapter).await?;
        let notify = endpoint.clone_notify();
        let mut x = endpoint.stack.lock().await;
        x.open_udp(self.src_port, inbound, abort_handle, notify)
    }
}

impl Outbound for WireguardHandle {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Wireguard
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().attach_tcp(inbound, abort_handle, None))
    }

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        if tcp_outbound.is_some() || udp_outbound.is_none() {
            tracing::error!("Invalid Wireguard UDP outbound ancestor");
            return tokio::spawn(async move { Ok(()) });
        }
        let udp_outbound = udp_outbound.unwrap();
        tokio::spawn(self.clone().attach_tcp(
            inbound,
            abort_handle,
            Some(AdapterOrSocket::Adapter(Arc::from(udp_outbound))),
        ))
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().attach_udp(inbound, abort_handle, None))
    }

    fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>> {
        if tcp_outbound.is_some() || udp_outbound.is_none() {
            tracing::error!("Invalid Wireguard UDP outbound ancestor");
            return tokio::spawn(async move { Ok(()) });
        }
        let udp_outbound = udp_outbound.unwrap();
        tokio::spawn(self.clone().attach_udp(
            inbound,
            abort_handle,
            Some(AdapterOrSocket::Adapter(Arc::from(udp_outbound))),
        ))
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

#[derive(Clone)]
struct WireguardDnsProvider {
    handle: TokioHandle,
    endpoint: Arc<Endpoint>,
    abort_handle: ConnAbortHandle,
}

impl RuntimeProvider for WireguardDnsProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = AddrConnectorWrapper;
    type Tcp = AsyncIoTokioAsStd<DuplexChan>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let ep = self.endpoint.clone();
        let handle = self.abort_handle.clone();
        let (inbound, outbound) = Connector::new_pair(10);
        Box::pin(async move {
            let notify = ep.clone_notify();
            let mut x = ep.stack.lock().await;
            x.open_tcp(0, server_addr, inbound, handle, notify)?;
            Ok(AsyncIoTokioAsStd(DuplexChan::new(outbound)))
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let ep = self.endpoint.clone();
        let handle = self.abort_handle.clone();
        let (inbound, outbound) = AddrConnector::new_pair(10);
        Box::pin(async move {
            let notify = ep.clone_notify();
            let mut x = ep.stack.lock().await;
            x.open_udp(0, inbound, handle, notify)?;
            let outbound = AddrConnectorWrapper::from(outbound);
            Ok(outbound)
        })
    }
}

impl DnsUdpSocket for AddrConnectorWrapper {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        data: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        // By design, only one of AddrConnectorWrapper::rx should be used. So a blocking lock is ok.
        let mut guard = match self.rx.try_lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("Lock should not fail");
                return Poll::Pending;
            }
        };
        match ready!(guard.poll_recv(cx)) {
            None => Poll::Ready(Err(ErrorKind::ConnectionAborted.into())),
            Some((buf, addr)) => {
                let len = if data.len() < buf.len() {
                    let len = data.len();
                    data[..len].copy_from_slice(&buf[..len]);
                    len
                } else {
                    let len = buf.len();
                    data[..len].copy_from_slice(&buf[..len]);
                    len
                };
                let addr = match addr {
                    NetworkAddr::Raw(s) => s,
                    NetworkAddr::DomainName {
                        domain_name: _,
                        port,
                    } => {
                        tracing::warn!("AddrConnector: should be unreachable");
                        SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port)
                    }
                };
                Poll::Ready(Ok((len, addr)))
            }
        }
    }

    fn poll_send_to(
        &self,
        _cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let len = buf.len();
        match self
            .tx
            .try_send((Bytes::copy_from_slice(buf), NetworkAddr::Raw(target)))
        {
            Ok(_) => Poll::Ready(Ok(len)),
            Err(_) => Poll::Pending,
        }
    }
}
