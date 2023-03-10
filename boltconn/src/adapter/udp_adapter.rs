// Adapter to NAT

use crate::adapter::{Connector, DuplexCloseGuard};
use crate::common::{mut_buf, MAX_PKT_SIZE};
use crate::proxy::{ConnAbortHandle, ConnAgent, SessionManager};
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
    inbound_read: mpsc::Receiver<Bytes>,
    inbound_write: Arc<UdpSocket>,
    src: SocketAddr,
    dst: SocketAddr,
    available: Arc<AtomicBool>,
    connector: Connector,
    session_mgr: Arc<SessionManager>,
}

impl TunUdpAdapter {
    const BUF_SIZE: usize = 65536;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        info: Arc<RwLock<ConnAgent>>,
        inbound_read: mpsc::Receiver<Bytes>,
        inbound_write: Arc<UdpSocket>,
        src: SocketAddr,
        dst: SocketAddr,
        available: Arc<AtomicBool>,
        connector: Connector,
        session_mgr: Arc<SessionManager>,
    ) -> Self {
        Self {
            info,
            inbound_read,
            inbound_write,
            src,
            dst,
            available,
            connector,
            session_mgr,
        }
    }

    pub async fn run(self, abort_handle: ConnAbortHandle) -> Result<()> {
        let mut first_packet = true;
        let outgoing_info_arc = self.info.clone();
        let mut inbound_read = self.inbound_read;
        let Connector { tx, mut rx } = self.connector;
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
                    Some(buf) => {
                        // tracing::trace!("[NatAdapter] outgoing {} bytes", buf.len);
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc.write().await.update_proto(buf.as_ref());
                        }
                        outgoing_info_arc.write().await.more_upload(buf.len());
                        if tx.send(buf).await.is_err() {
                            tracing::warn!("NatAdapter tx send err");
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
        while let Some(buf) = rx.recv().await {
            let Some(token_ip) = self.session_mgr.lookup_udp_token(self.src, self.dst).await else {
                // no mapping, drop and return
                break;
            };
            // tracing::trace!("[NatAdapter] incoming {} bytes", buf.len);
            self.info.write().await.more_download(buf.len());
            if let Err(err) = self
                .inbound_write
                .send_to(buf.as_ref(), SocketAddr::new(token_ip, self.src.port()))
                .await
            {
                tracing::warn!("NatAdapter write to inbound failed: {}", err);
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
        while let Some(buf) = rx.recv().await {
            self.info.write().await.more_download(buf.len());
            if let Err(err) = inbound_write.send_to(buf.as_ref(), self.src).await {
                tracing::warn!("StandardUdpAdapter write to inbound failed: {}", err);
                abort_handle.cancel().await;
                break;
            }
        }
        self.info.write().await.mark_fin();
        Ok(())
    }
}
