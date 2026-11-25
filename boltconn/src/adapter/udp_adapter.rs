// Adapter to NAT

use crate::adapter::{AddrConnector, DuplexCloseGuard, RelayAbortGuard, finish_unreported};
use crate::network::dns::Dns;
use crate::proxy::{ConnAbortHandle, ConnHandle, NetworkAddr};
use boltapi::{ConnResultCode, ConnStage, ConnState, ConnTermination};
use bytes::Bytes;
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

const UDP_ALIVE_PROBE_INTERVAL: Duration = Duration::from_secs(30);

async fn finish_udp(
    info: &ConnHandle,
    abort_handle: &ConnAbortHandle,
    code: ConnResultCode,
    stage: ConnStage,
    detail: Option<String>,
) {
    if info.snapshot().state.established_at_ms.is_some() {
        info.set_state(ConnState::Closing);
        info.finish(code, Some(stage), detail.clone());
    } else if code == ConnResultCode::ClientClosed {
        // UDP clients may disappear while their outbound is still connecting.
        // This is still a meaningful terminal cause without an establishment
        // timestamp.
        info.finish(code, Some(stage), detail.clone());
    } else {
        finish_unreported(
            info,
            abort_handle,
            ConnTermination::new(code, stage, detail.clone()),
        )
        .await;
    }
    abort_handle.cancel(ConnTermination::new(code, stage, detail));
}

pub struct TunUdpAdapter {
    info: ConnHandle,
    send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
    recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    next: AddrConnector,
    dns: Arc<Dns>,
    available: Arc<AtomicBool>,
}

impl TunUdpAdapter {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        info: ConnHandle,
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
        let mut abort_guard = RelayAbortGuard::new(self.info.clone(), abort_handle.clone());
        let mut first_packet = true;
        let outgoing_info_arc = self.info.clone();
        let mut inbound_read = self.send_rx;
        let AddrConnector { tx, mut rx } = self.next;
        let abort_handle2 = abort_handle.clone();
        let available2 = self.available.clone();
        // recv from inbound and send to outbound
        let mut duplex_guard = DuplexCloseGuard::new(
            tokio::spawn(async move {
                let mut transfer_error = None;
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
                                transfer_error = Some("outbound channel closed".to_string());
                                available2.store(false, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                }
                match transfer_error {
                    Some(detail) => {
                        finish_udp(
                            &outgoing_info_arc,
                            &abort_handle2,
                            ConnResultCode::TransferError,
                            ConnStage::Transferring,
                            Some(detail),
                        )
                        .await
                    }
                    None => {
                        finish_udp(
                            &outgoing_info_arc,
                            &abort_handle2,
                            ConnResultCode::ClientClosed,
                            ConnStage::Closing,
                            None,
                        )
                        .await
                    }
                }
            }),
            abort_handle.clone(),
        );
        duplex_guard.set_err_exit();
        // recv from outbound and send to inbound
        let mut client_closed = None;
        while let Some((data, addr)) = rx.recv().await {
            self.info.more_download(data.len());
            let src_addr = match addr {
                NetworkAddr::Socket { address: s } => s,
                NetworkAddr::Domain {
                    name: domain_name,
                    port,
                } => SocketAddr::new(self.dns.domain_to_fake_ip(domain_name.as_str()), port),
            };
            if let Err(err) = self.recv_tx.send((data, src_addr)).await {
                tracing::warn!("TunUdpAdapter write to inbound failed: {}", err);
                client_closed = Some(crate::proxy::bounded_error_detail(&err.to_string()));
                break;
            }
        }
        match client_closed {
            Some(detail) => {
                finish_udp(
                    &self.info,
                    &abort_handle,
                    ConnResultCode::ClientClosed,
                    ConnStage::Closing,
                    Some(detail),
                )
                .await
            }
            None => {
                finish_udp(
                    &self.info,
                    &abort_handle,
                    ConnResultCode::RemoteClosed,
                    ConnStage::Closing,
                    None,
                )
                .await
            }
        }
        abort_guard.disarm();
        Ok(())
    }
}

pub struct SocksUdpAdapter {
    info: ConnHandle,
    send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
    recv_tx: Arc<UdpSocket>,
    src: SocketAddr,
    available: Arc<AtomicBool>,
    connector: AddrConnector,
}

impl SocksUdpAdapter {
    pub fn new(
        info: ConnHandle,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: Arc<UdpSocket>,
        src: SocketAddr,
        available: Arc<AtomicBool>,
        connector: AddrConnector,
    ) -> Self {
        Self {
            info,
            send_rx,
            recv_tx,
            src,
            available,
            connector,
        }
    }

    pub async fn run(self, abort_handle: ConnAbortHandle) -> Result<()> {
        let mut abort_guard = RelayAbortGuard::new(self.info.clone(), abort_handle.clone());
        let mut first_packet = true;
        let outgoing_info_arc = self.info.clone();
        let mut inbound_read = self.send_rx;
        let AddrConnector { tx, mut rx } = self.connector;
        let abort_handle2 = abort_handle.clone();
        let available2 = self.available.clone();
        // recv from inbound and send to outbound
        let mut duplex_guard = DuplexCloseGuard::new(
            tokio::spawn(async move {
                let mut transfer_error = None;
                while available2.load(Ordering::Relaxed) {
                    let Ok(result_with_ddl) =
                        timeout(UDP_ALIVE_PROBE_INTERVAL, inbound_read.recv()).await
                    else {
                        continue;
                    };

                    if let Some((buf, pkt_dst)) = result_with_ddl {
                        // check if packet is from the valid socks client

                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc.update_proto(&buf);
                        }
                        outgoing_info_arc.more_upload(buf.len());
                        if tx.send((buf, pkt_dst)).await.is_err() {
                            transfer_error = Some("outbound channel closed".to_string());
                            available2.store(false, Ordering::Relaxed);
                            break;
                        }
                    } else {
                        // udp socket err
                        break;
                    }
                }
                match transfer_error {
                    Some(detail) => {
                        finish_udp(
                            &outgoing_info_arc,
                            &abort_handle2,
                            ConnResultCode::TransferError,
                            ConnStage::Transferring,
                            Some(detail),
                        )
                        .await
                    }
                    None => {
                        finish_udp(
                            &outgoing_info_arc,
                            &abort_handle2,
                            ConnResultCode::ClientClosed,
                            ConnStage::Closing,
                            None,
                        )
                        .await
                    }
                }
            }),
            abort_handle.clone(),
        );
        duplex_guard.set_err_exit();

        // recv from outbound and send to inbound
        let mut client_closed = None;
        while let Some((buf, src)) = rx.recv().await {
            self.info.more_download(buf.len());
            // encapsule
            let Ok(data) = (match src {
                NetworkAddr::Socket { address: s } => fast_socks5::new_udp_header(s),
                NetworkAddr::Domain {
                    name: domain_name,
                    port,
                } => fast_socks5::new_udp_header((domain_name.as_str(), port)),
            }) else {
                continue;
            };
            let mut res = Vec::with_capacity(data.len() + buf.len());
            res.extend_from_slice(&data);
            res.extend_from_slice(buf.as_ref());

            if let Err(err) = self.recv_tx.send_to(&res, self.src).await {
                tracing::warn!("SocksUdpAdapter write to inbound failed: {}", err);
                client_closed = Some(crate::proxy::bounded_error_detail(&err.to_string()));
                break;
            }
        }
        match client_closed {
            Some(detail) => {
                finish_udp(
                    &self.info,
                    &abort_handle,
                    ConnResultCode::ClientClosed,
                    ConnStage::Closing,
                    Some(detail),
                )
                .await
            }
            None => {
                finish_udp(
                    &self.info,
                    &abort_handle,
                    ConnResultCode::RemoteClosed,
                    ConnStage::Closing,
                    None,
                )
                .await
            }
        }
        abort_guard.disarm();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsPreference;
    use crate::dispatch::{ConnInfo, InboundInfo};
    use crate::network::dns::NameserverPolicies;
    use crate::platform::process::NetworkType;
    use crate::proxy::ContextManager;
    use crate::proxy::error::{DnsError, TransportError};
    use std::collections::HashMap;

    #[tokio::test(start_paused = true)]
    async fn failed_chained_hop_finishes_a_connecting_connection() {
        let dst: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let abort_handle = ConnAbortHandle::new();
        let info = ContextManager::new(10).begin(
            ConnInfo {
                src: "127.0.0.1:12345".parse().unwrap(),
                dst: NetworkAddr::Socket { address: dst },
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Udp,
                process_info: None,
            },
            NetworkAddr::Socket { address: dst },
            None,
            abort_handle.clone(),
        );
        let dns = Dns::with_config(
            "test",
            "unused",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            Vec::new(),
        );
        let (_send_tx, send_rx) = mpsc::channel(4);
        let (recv_tx, _recv_rx) = mpsc::channel(4);
        let (adapter_connector, outbound_connector) = AddrConnector::new_pair(4);
        let adapter = TunUdpAdapter::new(
            info.clone(),
            send_rx,
            recv_tx,
            adapter_connector,
            Arc::new(dns),
            Arc::new(AtomicBool::new(true)),
        );
        let adapter_abort = abort_handle.clone();
        let adapter_task = tokio::spawn(async move {
            let _ = adapter.run(adapter_abort).await;
        });
        abort_handle.fulfill(vec![("udp".to_string(), adapter_task)]);

        // The hop drops the relay before it reports, so the adapter sees the close first.
        crate::adapter::spawn_hop("hop".to_string(), abort_handle.clone(), async move {
            drop(outbound_connector);
            Err(TransportError::Dns(DnsError::ResolveDomain(
                "example.com".to_string(),
            )))
        });

        tokio::time::timeout(Duration::from_secs(60), async {
            while !info.done() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("failed hop left the connection connecting");
        assert_eq!(
            info.snapshot().state.termination.unwrap().code,
            ConnResultCode::DnsError
        );
    }
}
