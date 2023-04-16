use crate::adapter::{
    empty_handle, AddrConnector, AddrConnectorWrapper, Connector, Outbound, OutboundType,
    TcpTransferType, UdpTransferType,
};
use std::io;

use crate::common::duplex_chan::DuplexChan;
use crate::common::StreamOutboundTrait;
use crate::proxy::ConnAbortHandle;
use crate::transport::UdpSocketAdapter;
use tokio::task::JoinHandle;

pub struct ChainOutbound {
    chains: Vec<Box<dyn Outbound>>,
}

impl ChainOutbound {
    pub fn new(chains: Vec<Box<dyn Outbound>>) -> Self {
        Self { chains }
    }

    fn spawn(
        &self,
        mut use_tcp: bool,
        mut inbound_tcp_container: Option<Connector>,
        mut inbound_udp_container: Option<AddrConnector>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let mut handles = vec![];
        let mut not_first_jump = false;
        let (first_part, last_one) = self.chains.split_at(self.chains.len() - 1);

        // connect proxies
        for tunnel in first_part {
            if use_tcp {
                let inbound = inbound_tcp_container.take().unwrap();
                if tunnel.outbound_type().tcp_transfer_type() == TcpTransferType::TcpOverUdp {
                    use_tcp = false;
                    let (inner, outer) = AddrConnector::new_pair(10);
                    inbound_udp_container = Some(outer);
                    handles.push(tunnel.spawn_tcp_with_outbound(
                        inbound,
                        None,
                        Some(Box::new(AddrConnectorWrapper::from(inner))),
                        abort_handle.clone(),
                    ));
                } else {
                    let (inner, outer) = Connector::new_pair(10);
                    let chan = Box::new(DuplexChan::new(inner));
                    inbound_tcp_container = Some(outer);
                    handles.push(tunnel.spawn_tcp_with_outbound(
                        inbound,
                        Some(chan),
                        None,
                        abort_handle.clone(),
                    ));
                }
            } else {
                let inbound = inbound_udp_container.take().unwrap();
                if tunnel.outbound_type().udp_transfer_type() == UdpTransferType::UdpOverTcp {
                    // UoT, then next jump will use TCP
                    use_tcp = true;
                    let (inner, outer) = Connector::new_pair(10);
                    let chan = Box::new(DuplexChan::new(inner));
                    inbound_tcp_container = Some(outer);
                    handles.push(tunnel.spawn_udp_with_outbound(
                        inbound,
                        Some(chan),
                        None,
                        abort_handle.clone(),
                        not_first_jump,
                    ));
                } else {
                    let (inner, outer) = AddrConnector::new_pair(10);
                    inbound_udp_container = Some(outer);
                    handles.push(tunnel.spawn_udp_with_outbound(
                        inbound,
                        None,
                        Some(Box::new(AddrConnectorWrapper::from(inner))),
                        abort_handle.clone(),
                        not_first_jump,
                    ));
                };
            }
            not_first_jump = true;
        }

        // connect last one
        if use_tcp {
            let inbound = inbound_tcp_container.unwrap();
            handles.push(last_one[0].spawn_tcp(inbound, abort_handle));
        } else {
            let inbound = inbound_udp_container.unwrap();
            handles.push(last_one[0].spawn_udp(inbound, abort_handle, true));
        }

        tokio::spawn(async move {
            for i in handles {
                if let Ok(Err(e)) = i.await {
                    return Err(e);
                }
            }
            Ok(())
        })
    }
}

impl Outbound for ChainOutbound {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Chain
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        self.spawn(true, Some(inbound), None, abort_handle)
    }

    fn spawn_tcp_with_outbound(
        &self,
        _inbound: Connector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tracing::error!("spawn_tcp_with_outbound() should not be called with ChainOutbound");
        empty_handle()
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>> {
        self.spawn(false, None, Some(inbound), abort_handle)
    }

    fn spawn_udp_with_outbound(
        &self,
        _inbound: AddrConnector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>> {
        tracing::error!("spawn_udp_with_outbound() should not be called with ChainUdpOutbound");
        empty_handle()
    }
}
