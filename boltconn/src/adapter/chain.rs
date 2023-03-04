use crate::adapter::{Connector, TcpOutBound};
use crate::common::duplex_chan::DuplexChan;
use crate::common::OutboundTrait;
use crate::dispatch::GeneralProxy;
use crate::proxy::ConnAbortHandle;
use tokio::task::JoinHandle;

pub struct ChainOutbound {
    chains: Vec<Box<dyn TcpOutBound>>,
}

impl ChainOutbound {
    pub fn new(chains: Vec<Box<dyn TcpOutBound>>) -> Self {
        todo!()
    }
}

impl TcpOutBound for ChainOutbound {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        todo!()
    }

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        _outbound: Box<dyn OutboundTrait>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        tracing::warn!("spawn_tcp_with_outbound() should not be called with DirectOutbound");
        self.spawn_tcp(inbound, abort_handle)
    }

    fn spawn_tcp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<std::io::Result<()>>) {
        todo!()
    }
}
