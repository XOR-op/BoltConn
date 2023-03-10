use crate::adapter::{Connector, TcpOutBound};

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
        tracing::warn!("spawn_tcp_with_outbound() should not be called with DirectOutbound");
        self.spawn_tcp(inbound, abort_handle)
    }
}
