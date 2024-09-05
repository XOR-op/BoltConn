use crate::adapter::{AddrConnector, AddrConnectorWrapper, Connector, Outbound, OutboundType};
use std::collections::HashMap;

use crate::adapter;
use crate::adapter::udp_over_tcp::UdpOverTcpAdapter;
use crate::common::{io_err, local_async_run, AbortCanary, StreamOutboundTrait, MAX_PKT_SIZE};
use crate::network::dns::{Dns, GenericDns};
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::smol::{SmolDnsProvider, SmolStack, VirtualIpDevice};
use crate::transport::wireguard::{WireguardConfig, WireguardTunnel};
use crate::transport::{AdapterOrSocket, InterfaceAddress, UdpSocketAdapter};
use async_trait::async_trait;
use bytes::Bytes;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::proto::udp::DnsUdpSocket;
use hickory_resolver::proto::TokioTime;
use hickory_resolver::AsyncResolver;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tokio::select;
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
        outbound: AdapterOrSocket,
        config: &WireguardConfig,
        endpoint_resolver: Arc<Dns>,
        timeout: Duration,
    ) -> Result<Arc<Self>, TransportError> {
        let notify = Arc::new(Notify::new());

        // control conn
        let (stop_send, mut stop_recv) = broadcast::channel(1);

        let (mut wg_smol_tx, wg_smol_rx) = flume::bounded(4096);
        let (smol_wg_tx, mut smol_wg_rx) = flume::unbounded();
        let tunnel = Arc::new(
            WireguardTunnel::new(outbound, config, endpoint_resolver, notify.clone()).await?,
        );
        let device = VirtualIpDevice::new(config.mtu, wg_smol_rx, smol_wg_tx);
        let smol_stack = {
            let iface =
                InterfaceAddress::from_dual(config.ip_addr, config.ip_addr6).ok_or_else(|| {
                    TransportError::Internal(
                        "Unexpected behavior: no ip address configured for WireGuard; should be checked during configuration",
                    )
                })?;
            Arc::new_cyclic(|me| {
                // create dns
                let resolver = {
                    AsyncResolver::new(
                        config.dns.clone(),
                        ResolverOpts::default(),
                        GenericConnector::new(SmolDnsProvider::new(
                            me.clone(),
                            ConnAbortHandle::placeholder(),
                            notify.clone(),
                        )),
                    )
                };
                let dns = Arc::new(GenericDns::new_with_resolver(
                    resolver,
                    config.dns_preference,
                ));
                Mutex::new(SmolStack::new(iface, device, dns, Duration::from_secs(120)))
            })
        };

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
                    match tunnel
                        .receive_incoming_packet(&mut wg_smol_tx, &mut buf, &mut wg_buf)
                        .await
                    {
                        Ok(true) => *timer.lock().await = Instant::now(),
                        Ok(false) => {}
                        Err(_) => {
                            let _ = stop_send.send(());
                            return;
                        }
                    }
                }
            })
        };

        let wg_tick = {
            let tunnel = tunnel.clone();
            let stop_send = stop_send.clone();
            let name = config.name.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                let mut continuous_err_cnt = 0;
                loop {
                    match tunnel.tick(&mut buf).await {
                        Err(e) => {
                            continuous_err_cnt += 1;
                            if continuous_err_cnt >= 2 {
                                // Stop the current WireGuard connection
                                let _ = stop_send.send(());
                                tracing::warn!("[WireGuard] Close connection #{} for {}", name, e);
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        }
                        Ok(has_sent) => {
                            if has_sent {
                                continuous_err_cnt = 0;
                            }
                            // <del>From boringtun, the recommended interval is 100ms.</del>
                            // Comments from Tunn::update_timers says one second interval is enough.
                            tokio::time::sleep(Duration::from_millis(1000)).await;
                        }
                    }
                }
            })
        };

        // drive smol
        let smol_drive = {
            let smol_stack = smol_stack.clone();
            let notifier = notify.clone();
            let (abort_canary, canary_clone) = AbortCanary::pair();

            local_async_run(async move {
                let mut immediate_next_loop = false;
                notifier.notified().await;
                while abort_canary.alive() {
                    let mut stack_handle = smol_stack.lock().await;
                    stack_handle.drive_iface();
                    immediate_next_loop |= stack_handle.poll_all_tcp().await;
                    immediate_next_loop |= stack_handle.poll_all_udp().await;
                    stack_handle.purge_invalid_tcp();
                    stack_handle.purge_timeout_udp();
                    let wait_time = if immediate_next_loop {
                        Duration::from_secs(0)
                    } else {
                        stack_handle
                            .suggested_wait_time()
                            .unwrap_or(Duration::from_secs(3))
                    };
                    drop(stack_handle);
                    if !immediate_next_loop {
                        select! {
                            _ = tokio::time::sleep(wait_time) =>{}
                            _ = notifier.notified() =>{}
                        }
                    }
                    immediate_next_loop = false;
                }
            });
            canary_clone
        };

        // timeout inactive tunnel
        {
            let stop_send = stop_send.clone();
            let indi_write = indi_write.clone();
            let name = config.name.clone();
            tokio::spawn(async move {
                loop {
                    if last_active.lock().await.elapsed() > timeout {
                        indi_write.store(false, Ordering::Relaxed);
                        let _ = stop_send.send(());
                        tracing::debug!(
                            "[WireGuard] Stop inactive tunnel #{} after for {}s.",
                            name,
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
    // We use an async wrapper to avoid deadlock in DashMap
    active_conn: Mutex<HashMap<WireguardConfig, Arc<Endpoint>>>,
    endpoint_resolver: Arc<Dns>,
    timeout: Duration,
}

impl WireguardManager {
    pub fn new(iface: &str, dns: Arc<Dns>, timeout: Duration) -> Self {
        Self {
            iface: iface.to_string(),
            active_conn: Default::default(),
            endpoint_resolver: dns,
            timeout,
        }
    }

    pub async fn get_wg_conn(
        &self,
        config: &WireguardConfig,
        adapter: Option<AdapterOrSocket>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> Result<Arc<Endpoint>, TransportError> {
        for _ in 0..10 {
            // get an existing conn, or create
            let mut guard = self.active_conn.lock().await;
            if let Some(endpoint) = guard.get(config) {
                if endpoint.is_active.load(Ordering::Relaxed) {
                    let _ = ret_tx.send(false);
                    return Ok(endpoint.clone());
                } else {
                    guard.remove(config);
                    continue;
                }
            } else {
                let _ = ret_tx.send(true);
                let server_addr =
                    adapter::get_dst(&self.endpoint_resolver, &config.endpoint).await?;
                let outbound = match adapter {
                    Some(a) => a,
                    None => {
                        if config.over_tcp {
                            let stream = Egress::new(&self.iface).tcp_stream(server_addr).await?;
                            AdapterOrSocket::Adapter(Arc::new(UdpOverTcpAdapter::new(
                                stream,
                                server_addr,
                            )?))
                        } else {
                            AdapterOrSocket::Socket(match server_addr {
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
                            })
                        }
                    }
                };
                let ep = Endpoint::new(
                    outbound,
                    config,
                    self.endpoint_resolver.clone(),
                    self.timeout,
                )
                .await?;
                guard.insert(config.clone(), ep.clone());
                return Ok(ep);
            }
        }
        Err(TransportError::WireGuard(
            "get_wg_conn: unexpected loop time",
        ))
    }
}

#[derive(Clone)]
pub struct WireguardHandle {
    src: SocketAddr,
    dst: NetworkAddr,
    config: Arc<WireguardConfig>,
    manager: Arc<WireguardManager>,
    dns_config: Arc<ResolverConfig>,
}

impl WireguardHandle {
    pub fn new(
        src: SocketAddr,
        dst: NetworkAddr,
        config: WireguardConfig,
        manager: Arc<WireguardManager>,
        dns_config: Arc<ResolverConfig>,
    ) -> Self {
        Self {
            src,
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
        ret_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> io::Result<()> {
        let endpoint = self.get_endpoint(adapter, ret_tx).await?;
        let notify = endpoint.clone_notify();
        let smol_dns = endpoint.stack.lock().await.get_dns();
        let dst = match self.dst {
            NetworkAddr::Raw(s) => s,
            NetworkAddr::DomainName { domain_name, port } => SocketAddr::new(
                smol_dns
                    .genuine_lookup(domain_name.as_str())
                    .await
                    .ok_or::<io::Error>(ErrorKind::AddrNotAvailable.into())?,
                port,
            ),
        };
        let mut x = endpoint.stack.lock().await;
        x.open_tcp(self.src, dst, inbound, abort_handle, notify)
    }

    async fn get_endpoint(
        &self,
        adapter: Option<AdapterOrSocket>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> io::Result<Arc<Endpoint>> {
        self.manager
            .get_wg_conn(&self.config, adapter, ret_tx)
            .await
            .map_err(|e| io_err(format!("{}", e).as_str()))
    }

    async fn attach_udp(
        self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        adapter: Option<AdapterOrSocket>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> io::Result<()> {
        let endpoint = self.get_endpoint(adapter, ret_tx).await?;
        let notify = endpoint.clone_notify();
        let mut x = endpoint.stack.lock().await;
        x.open_udp(self.src, inbound, abort_handle, notify)
    }
}

#[async_trait]
impl Outbound for WireguardHandle {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Wireguard
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let (tx, _) = tokio::sync::oneshot::channel();
        tokio::spawn(adapter::connect_timeout(
            self.clone().attach_tcp(inbound, abort_handle, None, tx),
            "WireGuard TCP",
        ))
    }

    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<bool> {
        if tcp_outbound.is_some() || udp_outbound.is_none() {
            tracing::error!("Invalid Wireguard UDP outbound ancestor");
            return Err(ErrorKind::InvalidData.into());
        }
        let udp_outbound = udp_outbound.unwrap();
        let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(adapter::connect_timeout(
            self.clone().attach_tcp(
                inbound,
                abort_handle,
                Some(AdapterOrSocket::Adapter(Arc::from(udp_outbound))),
                ret_tx,
            ),
            "WireGuard TCP multi-hop",
        ));
        ret_rx
            .await
            .map_err(|_| ErrorKind::ConnectionAborted.into())
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>> {
        let (ret_tx, _) = tokio::sync::oneshot::channel();
        tokio::spawn(adapter::connect_timeout(
            self.clone().attach_udp(inbound, abort_handle, None, ret_tx),
            "WireGuard UDP",
        ))
    }

    async fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> io::Result<bool> {
        if tcp_outbound.is_some() || udp_outbound.is_none() {
            tracing::error!("Invalid Wireguard UDP outbound ancestor");
            return Err(ErrorKind::InvalidData.into());
        }
        let udp_outbound = udp_outbound.unwrap();
        let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(adapter::connect_timeout(
            self.clone().attach_udp(
                inbound,
                abort_handle,
                Some(AdapterOrSocket::Adapter(Arc::from(udp_outbound))),
                ret_tx,
            ),
            "WireGuard UDP multi-hop",
        ));
        ret_rx
            .await
            .map_err(|_| ErrorKind::ConnectionAborted.into())
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
