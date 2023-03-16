// Adapter to NAT

use crate::adapter::{AddrConnector, Connector, DuplexCloseGuard};
use crate::common::{mut_buf, MAX_PKT_SIZE};
use crate::proxy::{ConnAbortHandle, ConnAgent, NetworkAddr};
use bytes::{BufMut, Bytes, BytesMut};
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;

const UDP_ALIVE_PROBE_INTERVAL: Duration = Duration::from_secs(30);

pub struct TunUdpAdapter {
    info: Arc<RwLock<ConnAgent>>,
    send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
    recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    next: AddrConnector,
    available: Arc<AtomicBool>,
}

impl TunUdpAdapter {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        info: Arc<RwLock<ConnAgent>>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
        next: AddrConnector,
        available: Arc<AtomicBool>,
    ) -> Self {
        Self {
            info,
            send_rx,
            recv_tx,
            next,
            available,
        }
    }

    pub async fn run(mut self, abort_handle: ConnAbortHandle) -> Result<()> {
        let mut first_packet = true;
        let outgoing_info_arc = self.info.clone();
        let mut inbound_read = self.send_rx;
        let AddrConnector { tx, mut rx } = self.connector;
        let abort_handle2 = abort_handle.clone();
        let available2 = self.available.clone();
        // recv from inbound and send to outbound
        let mut duplex_guard = DuplexCloseGuard::new(tokio::spawn(async move {
            while available2.load(Ordering::Relaxed) {
                let Ok(result_with_ddl) = timeout(
                    UDP_ALIVE_PROBE_INTERVAL,
                    inbound_read.recv(),
                ).await else {
                    continue;
                };
                match result_with_ddl {
                    None => {
                        break;
                    }
                    Some((buf, addr)) => {
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc.write().await.update_proto(buf.as_ref());
                        }
                        outgoing_info_arc.write().await.more_upload(buf.len());
                        // todo: real ip to fake ip
                        todo!();
                        if tx.send((buf, addr)).await.is_err() {
                            tracing::warn!("TunUdpAdapter tx send err");
                            available2.store(false, Ordering::Relaxed);
                            abort_handle2.cancel().await;
                            break;
                        }
                    }
                }
            }
            outgoing_info_arc.write().await.mark_fin();
        }));
        duplex_guard.set_err_exit();
        // recv from outbound and send to inbound
        while let Some((data, addr)) = rx.recv().await {
            self.info.write().await.more_download(data.len());
            if let Err(err) = self.recv_tx.send((data, addr)).await {
                tracing::warn!("TunUdpAdapter write to inbound failed: {}", err);
                abort_handle.cancel().await;
                break;
            }
        }
        self.info.write().await.mark_fin();
        Ok(())
    }
}

pub struct StandardUdpAdapter {
    info: Arc<RwLock<ConnAgent>>,
    inbound: UdpSocket,
    src: SocketAddr,
    available: Arc<AtomicBool>,
    connector: Connector,
}

impl StandardUdpAdapter {
    pub fn new(
        info: Arc<RwLock<ConnAgent>>,
        inbound: UdpSocket,
        src: SocketAddr,
        available: Arc<AtomicBool>,
        connector: Connector,
    ) -> Self {
        Self {
            info,
            inbound,
            src,
            available,
            connector,
        }
    }

    // todo: may be buggy, because of no SOCKS decapsulation is performed
    pub async fn run(self, abort_handle: ConnAbortHandle) -> Result<()> {
        let mut first_packet = true;
        let outgoing_info_arc = self.info.clone();
        let inbound_read = Arc::new(self.inbound);
        let inbound_write = inbound_read.clone();
        let src_addr = self.src;
        let Connector { tx, mut rx } = self.connector;
        let abort_handle2 = abort_handle.clone();
        let available2 = self.available.clone();
        // recv from inbound and send to outbound
        let mut duplex_guard = DuplexCloseGuard::new(tokio::spawn(async move {
            while available2.load(Ordering::Relaxed) {
                let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
                let result_with_ddl = timeout(
                    UDP_ALIVE_PROBE_INTERVAL,
                    inbound_read.recv_from(unsafe { mut_buf(&mut buf) }),
                )
                .await;
                let Ok(result) = result_with_ddl else {
                    continue;
                };
                if let Ok((len, pkt_src)) = result {
                    // check if packet is from the valid socks client
                    if src_addr == pkt_src {
                        unsafe { buf.advance_mut(len) }
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc.write().await.update_proto(buf.as_ref());
                        }
                        outgoing_info_arc.write().await.more_upload(buf.len());
                        if tx.send(buf.freeze()).await.is_err() {
                            available2.store(false, Ordering::Relaxed);
                            abort_handle2.cancel().await;
                            break;
                        }
                    } else {
                        // drop silently
                    }
                } else {
                    // udp socket err
                    break;
                }
            }
            outgoing_info_arc.write().await.mark_fin();
        }));
        duplex_guard.set_err_exit();

        // recv from outbound and send to inbound
        while let Some((buf, src)) = rx.recv().await {
            self.info.write().await.more_download(buf.len());
            if let Err(err) = inbound_write.send_to(buf.as_ref(), self.src).await {
                tracing::warn!("StandardUdpAdapter write to inbound failed: {}", err);
                abort_handle.cancel().await;
                break;
            }
        }
        self.info.write().await.mark_fin();
        todo!();
        Ok(())
    }
}
