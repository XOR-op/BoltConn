use crate::adapter::{Connector, TcpOutBound, UdpOutBound};
use crate::common::buf_pool::{PktBufPool, MAX_PKT_SIZE};
use crate::common::duplex_chan::DuplexChan;
use crate::network::dns::Dns;
use crate::proxy::ConnAbortHandle;
use crate::transport::smol::{SmolStack, VirtualIpDevice};
use crate::transport::wireguard::{WireguardConfig, WireguardTunnel};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

// Shared Wireguard Tunnel between multiple client connections
struct Endpoint {
    wg: Arc<WireguardTunnel>,
    stack: Mutex<SmolStack>,
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
        let smol_stack = SmolStack::new(config.ip_addr, device, allocator);

        let last_active = Arc::new(Mutex::new(Instant::now()));

        // drive wg tunnel
        let wg_out = {
            let tunnel = tunnel.clone();
            let stop_send = stop_send.clone();
            let timer = last_active.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                loop {
                    if let Err(_) = tunnel.send_outgoing_packet(&mut smol_wg_rx, &mut buf).await {
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
                    if let Err(_) = tunnel
                        .receive_incoming_packet(&mut wg_smol_tx, &mut buf, &mut wg_buf)
                        .await
                    {
                        let _ = stop_send.send(());
                        return;
                    }
                    *timer.lock().await = Instant::now();
                }
            })
        };
        // drive smol
        let smol_drive = { tokio::spawn(async move {}) };

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
            stack: Mutex::new(smol_stack),
            stop_sender: stop_send,
        }))
    }
}

pub struct WireguardManager {
    active_conn: DashMap<WireguardConfig, Arc<Endpoint>>,
}

pub struct WireguardHandle {
    endpoint: Arc<Endpoint>,
    allocator: PktBufPool,
}

impl TcpOutBound for WireguardHandle {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        todo!()
    }

    fn spawn_tcp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<std::io::Result<()>>) {
        todo!()
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
