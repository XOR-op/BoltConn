use crate::adapter::Connector;
use bytes::BytesMut;
use concurrent_queue::ConcurrentQueue;
use dashmap::DashMap;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::{broadcast, mpsc};

pub struct SmolStack {
    tcp_conn: DashMap<u16, Arc<Connector>>,
    udp_conn: DashMap<u16, Arc<Connector>>,
}

impl SmolStack {
    pub fn new(iface_ip: IpAddr) -> Self {
        // let iface = InterfaceBuilder::new().ip_addrs(iface_ip).finalize();
        todo!()
    }

    pub fn open_tcp(&self, port: u16, connector: Connector) {
        self.tcp_conn.insert(port, Arc::new(connector));
    }
}

// -----------------------------------------------------------------------------------

/// Virtual IP device
pub(crate) struct VirtualDevice {
    mtu: usize,
    outbound: mpsc::Sender<BytesMut>,
    packet_queue: Arc<ConcurrentQueue<BytesMut>>,
}

impl VirtualDevice {
    pub fn new(
        mtu: usize,
        mut inbound: mpsc::Receiver<BytesMut>,
        outbound: mpsc::Sender<BytesMut>,
        mut stop_signal: broadcast::Receiver<()>,
    ) -> Self {
        let queue = Arc::new(ConcurrentQueue::unbounded());
        let queue_clone = queue.clone();
        tokio::spawn(async move {
            // move data from inbound to internal buffer
            loop {
                select! {
                    _ = stop_signal.recv() =>return,
                    res = inbound.recv() => {
                        match res {
                            None=>return,
                            Some(item)=> {
                                let _ = queue.push(item);
                            }
                        }
                    }
                }
            }
        });
        Self {
            mtu,
            outbound,
            packet_queue: queue_clone,
        }
    }
}

impl<'a> Device<'a> for VirtualDevice {
    type RxToken = VirtualRxToken;
    type TxToken = VirtualTxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match self.packet_queue.pop() {
            Ok(item) => Some((
                VirtualRxToken { buf: item },
                VirtualTxToken {
                    sender: self.outbound.clone(),
                },
            )),
            Err(_) => None,
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(VirtualTxToken {
            sender: self.outbound.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.medium = Medium::Ip;
        cap.max_transmission_unit = self.mtu;
        cap
    }
}

pub(crate) struct VirtualRxToken {
    buf: BytesMut,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buf)
    }
}

pub(crate) struct VirtualTxToken {
    sender: mpsc::Sender<BytesMut>,
}

impl TxToken for VirtualTxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buf = BytesMut::with_capacity(len);
        let result = f(&mut buf);
        if result.is_ok() {
            let _ = self.sender.send(buf);
        }
        result
    }
}
