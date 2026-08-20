use crate::adapter::{
    AddrConnector, AddrConnectorWrapper, Connector, Outbound, OutboundType, TcpTransferType,
    UdpTransferType,
};
use async_trait::async_trait;
use std::sync::Arc;

use crate::common::StreamOutboundTrait;
use crate::common::duplex_chan::DuplexChan;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, ConnHandle};
use crate::transport::UdpSocketAdapter;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct ChainOutbound {
    name: String,
    chains: Vec<Arc<dyn Outbound>>,
}

impl ChainOutbound {
    pub fn new(name: &str, chains: Vec<Box<dyn Outbound>>) -> Self {
        Self {
            name: name.to_string(),
            chains: chains.into_iter().map(Arc::from).collect(),
        }
    }

    fn spawn(
        self,
        mut use_tcp: bool,
        mut inbound_tcp_container: Option<Connector>,
        mut inbound_udp_container: Option<AddrConnector>,
        abort_handle: ConnAbortHandle,
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        tokio::spawn(async move {
            if let (Some(first), Some(conn)) = (self.chains.first(), &conn) {
                conn.set_activation_owner(first.id());
            }
            let mut not_first_jump = false;
            let mut need_next_jump = true;
            let (first_part, last_one) = self.chains.split_at(self.chains.len() - 1);

            // connect proxies
            for (index, tunnel) in first_part.iter().enumerate() {
                if !need_next_jump {
                    return Ok(());
                }
                // The first hop owns the final activation transition. Shared
                // hops also receive the handle so they can contribute their
                // concrete generation path while the connection is pre-active.
                let tracked_conn = (index == 0 || is_shared_link(tunnel.outbound_type()))
                    .then(|| conn.clone())
                    .flatten();
                if use_tcp {
                    let inbound = inbound_tcp_container.take().unwrap();
                    if tunnel.outbound_type().tcp_transfer_type() == TcpTransferType::TcpOverUdp {
                        use_tcp = false;
                        let (inner, outer) = AddrConnector::new_pair(10);
                        inbound_udp_container = Some(outer);
                        need_next_jump = tunnel
                            .spawn_tcp_with_outbound(
                                inbound,
                                None,
                                Some(Box::new(AddrConnectorWrapper::from(inner))),
                                abort_handle.clone(),
                                tracked_conn,
                            )
                            .await?;
                    } else {
                        let (inner, outer) = Connector::new_pair(10);
                        let chan = Box::new(DuplexChan::new(inner));
                        inbound_tcp_container = Some(outer);
                        need_next_jump = tunnel
                            .spawn_tcp_with_outbound(
                                inbound,
                                Some(chan),
                                None,
                                abort_handle.clone(),
                                tracked_conn,
                            )
                            .await?;
                    }
                } else {
                    let inbound = inbound_udp_container.take().unwrap();
                    if tunnel.outbound_type().udp_transfer_type() == UdpTransferType::UdpOverTcp {
                        // UoT, then next jump will use TCP
                        use_tcp = true;
                        let (inner, outer) = Connector::new_pair(10);
                        let chan = Box::new(DuplexChan::new(inner));
                        inbound_tcp_container = Some(outer);
                        need_next_jump = tunnel
                            .spawn_udp_with_outbound(
                                inbound,
                                Some(chan),
                                None,
                                abort_handle.clone(),
                                not_first_jump,
                                tracked_conn,
                            )
                            .await?;
                    } else {
                        let (inner, outer) = AddrConnector::new_pair(10);
                        inbound_udp_container = Some(outer);
                        need_next_jump = tunnel
                            .spawn_udp_with_outbound(
                                inbound,
                                None,
                                Some(Box::new(AddrConnectorWrapper::from(inner))),
                                abort_handle.clone(),
                                not_first_jump,
                                tracked_conn,
                            )
                            .await?;
                    };
                }
                not_first_jump = true;
            }

            if !need_next_jump {
                return Ok(());
            }

            // connect last one
            let last_index = self.chains.len() - 1;
            let last_conn = (last_index == 0 || is_shared_link(last_one[0].outbound_type()))
                .then_some(conn)
                .flatten();
            if use_tcp {
                let inbound = inbound_tcp_container.unwrap();
                last_one[0].spawn_tcp(inbound, abort_handle, last_conn);
            } else {
                let inbound = inbound_udp_container.unwrap();
                last_one[0].spawn_udp(inbound, abort_handle, true, last_conn);
            }

            Ok(())
        })
    }
}

fn is_shared_link(outbound_type: OutboundType) -> bool {
    matches!(
        outbound_type,
        OutboundType::Wireguard | OutboundType::Ssh | OutboundType::Anytls
    )
}

#[async_trait]
impl Outbound for ChainOutbound {
    fn id(&self) -> String {
        self.name.clone()
    }

    fn outbound_type(&self) -> OutboundType {
        OutboundType::Chain
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        self.clone()
            .spawn(true, Some(inbound), None, abort_handle, conn)
    }

    async fn spawn_tcp_with_outbound(
        &self,
        _inbound: Connector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
        _conn: Option<ConnHandle>,
    ) -> Result<bool, TransportError> {
        tracing::error!("spawn_tcp_with_outbound() should not be called with ChainOutbound");
        Err(TransportError::Internal("Invalid outbound"))
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        self.clone()
            .spawn(false, None, Some(inbound), abort_handle, conn)
    }

    async fn spawn_udp_with_outbound(
        &self,
        _inbound: AddrConnector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
        _conn: Option<ConnHandle>,
    ) -> Result<bool, TransportError> {
        tracing::error!("spawn_udp_with_outbound() should not be called with ChainUdpOutbound");
        Err(TransportError::Internal("Invalod outbound"))
    }
}
