// Adapter to NAT

use crate::adapter::{AddrConnector, DuplexCloseGuard};
use crate::common::{mut_buf, MAX_PKT_SIZE};
use crate::network::dns::Dns;
use crate::proxy::{ConnAbortHandle, ConnContext, NetworkAddr};
use bytes::{BufMut, Bytes, BytesMut};
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

const UDP_ALIVE_PROBE_INTERVAL: Duration = Duration::from_secs(30);

pub struct TunUdpAdapter {
    info: Arc<ConnContext>,
    send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
    recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    next: AddrConnector,
    dns: Arc<Dns>,
    available: Arc<AtomicBool>,
}

impl TunUdpAdapter {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        info: Arc<ConnContext>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
        next: AddrConnector,
        dns: Arc<Dns>,
        available: Arc<AtomicBool>,
    ) -> Self {
        Self {
            info,
            send_rx,
            recv_tx,
            next,
            dns,
            available,
        }
    }

    pub async fn run(self, abort_handle: ConnAbortHandle) -> Result<()> {
        let mut first_packet = true;
        let outgoing_info_arc = self.info.clone();
        let mut inbound_read = self.send_rx;
        let AddrConnector { tx, mut rx } = self.next;
        let abort_handle2 = abort_handle.clone();
        let available2 = self.available.clone();
        // recv from inbound and send to outbound
        let mut duplex_guard = DuplexCloseGuard::new(tokio::spawn(async move {
            while available2.load(Ordering::Relaxed) {
                let Ok(result_with_ddl) =
                    timeout(UDP_ALIVE_PROBE_INTERVAL, inbound_read.recv()).await
                else {
                    continue;
                };
                match result_with_ddl {
                    None => {
                        break;
                    }
                    Some((buf, addr)) => {
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc.update_proto(buf.as_ref());
                        }
                        outgoing_info_arc.more_upload(buf.len());
                        if tx.send((buf, addr)).await.is_err() {
                            tracing::warn!("TunUdpAdapter tx send err");
                            available2.store(false, Ordering::Relaxed);
                            abort_handle2.cancel().await;
                            break;
                        }
                    }
                }
            }
            outgoing_info_arc.mark_fin();
        }));
        duplex_guard.set_err_exit();
        // recv from outbound and send to inbound
        while let Some((data, addr)) = rx.recv().await {
            self.info.more_download(data.len());
            let src_addr = match addr {
                NetworkAddr::Raw(s) => s,
                NetworkAddr::DomainName { domain_name, port } => {
                    SocketAddr::new(self.dns.domain_to_fake_ip(domain_name.as_str()), port)
                }
            };
            if let Err(err) = self.recv_tx.send((data, src_addr)).await {
                tracing::warn!("TunUdpAdapter write to inbound failed: {}", err);
                abort_handle.cancel().await;
                break;
            }
        }
        self.info.mark_fin();
        Ok(())
    }
}

pub struct StandardUdpAdapter {
    info: Arc<ConnContext>,
    inbound: UdpSocket,
    src: SocketAddr,
    available: Arc<AtomicBool>,
    connector: AddrConnector,
}

impl StandardUdpAdapter {
    pub fn new(
        info: Arc<ConnContext>,
        inbound: UdpSocket,
        src: SocketAddr,
        available: Arc<AtomicBool>,
        connector: AddrConnector,
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
        let AddrConnector { tx, mut rx } = self.connector;
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
                        let buf = buf.freeze();

                        // decapsule udp header
                        let Ok((frag, addr, payload)) =
                            fast_socks5::parse_udp_request(buf.as_ref()).await
                        else {
                            continue;
                        };
                        if frag != 0 {
                            // cannot handle, drop
                            continue;
                        }

                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc.update_proto(payload);
                        }
                        outgoing_info_arc.more_upload(buf.len());
                        if tx
                            .send((buf.slice_ref(payload), addr.into()))
                            .await
                            .is_err()
                        {
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
            outgoing_info_arc.mark_fin();
        }));
        duplex_guard.set_err_exit();

        // recv from outbound and send to inbound
        while let Some((buf, src)) = rx.recv().await {
            self.info.more_download(buf.len());
            // encapsule
            let Ok(data) = (match src {
                NetworkAddr::Raw(s) => fast_socks5::new_udp_header(s),
                NetworkAddr::DomainName { domain_name, port } => {
                    fast_socks5::new_udp_header((domain_name.as_str(), port))
                }
            }) else {
                continue;
            };

            if let Err(err) = inbound_write.send_to(data.as_slice(), self.src).await {
                tracing::warn!("StandardUdpAdapter write to inbound failed: {}", err);
                abort_handle.cancel().await;
                break;
            }
        }
        self.info.mark_fin();
        Ok(())
    }
}
