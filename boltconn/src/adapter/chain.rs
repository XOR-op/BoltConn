use crate::adapter::{
    AddrConnector, BothOutBound, Connector, TcpOutBound, UdpOutBound, UdpSocketAdapter,
    UdpTransferType,
};

use crate::common::duplex_chan::DuplexChan;
use crate::common::OutboundTrait;
use crate::proxy::ConnAbortHandle;
use tokio::task::JoinHandle;

pub struct ChainOutbound {
    chains: Vec<Box<dyn TcpOutBound>>,
}

impl ChainOutbound {
    pub fn new(chains: Vec<Box<dyn TcpOutBound>>) -> Self {
        Self { chains }
    }
}

impl TcpOutBound for ChainOutbound {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        let mut handles = vec![];
        let mut inbound_container = Some(inbound);
        let (first_part, last_one) = self.chains.split_at(self.chains.len() - 1);

        // connect proxies
        for tunnel in first_part {
            let inbound = inbound_container.take().unwrap();
            let (inner, outer) = Connector::new_pair(10);
            let chan = Box::new(DuplexChan::new(inner));
            let handle = tunnel.spawn_tcp_with_outbound(inbound, chan, abort_handle.clone());
            handles.push(handle);
            inbound_container = Some(outer)
        }

        // connect last one
        let inbound = inbound_container.unwrap();
        handles.push(last_one[0].spawn_tcp(inbound, abort_handle));

        tokio::spawn(async move {
            for i in handles {
                if let Ok(Err(e)) = i.await {
                    return Err(e);
                }
            }
            Ok(())
        })
    }

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        _outbound: Box<dyn OutboundTrait>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        tracing::error!("spawn_tcp_with_outbound() should not be called with ChainOutbound");
        self.spawn_tcp(inbound, abort_handle)
    }
}

pub struct ChainUdpOutbound {
    chains: Vec<Box<dyn BothOutBound>>,
}

impl ChainUdpOutbound {
    pub fn new(chains: Vec<Box<dyn BothOutBound>>) -> Self {
        Self { chains }
    }
}

impl UdpOutBound for ChainUdpOutbound {
    fn transfer_type(&self) -> UdpTransferType {
        UdpTransferType::NotApplicable
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        let mut use_tcp = false;
        let mut handles = vec![];
        let mut inbound_container = Some(inbound);
        let mut inbound_tcp_container = None;
        let (first_part, last_one) = self.chains.split_at(self.chains.len() - 1);

        // connect proxies
        for tunnel in first_part {
            if use_tcp {
                let inbound = inbound_tcp_container.take().unwrap();
                let (inner, outer) = Connector::new_pair(10);
                let chan = Box::new(DuplexChan::new(inner));
                let handle = tunnel.spawn_tcp_with_outbound(inbound, chan, abort_handle.clone());
                handles.push(handle);
                inbound_tcp_container = Some(outer)
            } else {
                let inbound = inbound_container.take().unwrap();
                let (inner, outer) = AddrConnector::new_pair(10);
                let handle = if tunnel.transfer_type() == UdpTransferType::UdpOverTcp {
                    // UoT, then next jump will use TCP
                    use_tcp = true;
                    let (inner, outer) = Connector::new_pair(10);
                    let chan = Box::new(DuplexChan::new(inner));
                    inbound_tcp_container = Some(outer);
                    tunnel.spawn_udp_with_outbound(inbound, chan, abort_handle.clone())
                } else {
                    inbound_container = Some(outer);
                    tunnel.spawn_udp_with_outbound(inbound, inner, abort_handle.clone())
                };
                handles.push(handle);
            }
        }

        // connect last one
        if use_tcp {
            let inbound = inbound_tcp_container.unwrap();
            handles.push(last_one[0].spawn_tcp(inbound, abort_handle));
        } else {
            let inbound = inbound_container.unwrap();
            handles.push(last_one[0].spawn_udp(inbound, abort_handle));
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

    fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        _outbound: Box<dyn UdpSocketAdapter>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        tracing::error!("spawn_udp_with_outbound() should not be called with ChainUdpOutbound");
        self.spawn_udp(inbound, abort_handle)
    }
}
