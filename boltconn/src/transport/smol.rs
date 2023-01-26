use crate::adapter::Connector;
use crate::common::buf_pool::{PktBufHandle, PktBufPool, MAX_PKT_SIZE};
use bytes::BytesMut;
use concurrent_queue::ConcurrentQueue;
use dashmap::mapref::entry::Entry;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use smoltcp::iface::{Interface, InterfaceBuilder, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::TcpSocket as SmolTcpSocket;
use smoltcp::socket::{TcpSocketBuffer, TcpState};
use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{broadcast, mpsc};

struct ConnTask {
    connector: Connector,
    handle: SocketHandle,
    remain_to_send: Option<(PktBufHandle, usize)>, // buffer, start_offset
}

impl ConnTask {
    pub fn new(connector: Connector, handle: SocketHandle) -> Self {
        Self {
            connector,
            handle,
            remain_to_send: None,
        }
    }
}

//          Program -- TCP/UDP -> SmolStack -> IP -- Internet
//                   \ TCP/UDP <- SmolStack <- IP /
pub struct SmolStack {
    tcp_conn: DashMap<u16, ConnTask>,
    udp_conn: DashMap<u16, ConnTask>,
    allocator: PktBufPool,
    ip_addr: IpAddr,
    iface: Interface<'static, VirtualIpDevice>,
}

impl SmolStack {
    pub fn new(iface_ip: IpAddr, ip_device: VirtualIpDevice, allocator: PktBufPool) -> Self {
        let iface = InterfaceBuilder::new(ip_device, vec![])
            .ip_addrs(iface_ip)
            .finalize();
        Self {
            tcp_conn: Default::default(),
            udp_conn: Default::default(),
            allocator,
            ip_addr: iface_ip,
            iface,
        }
    }

    pub fn open_tcp(
        &mut self,
        local_port: u16,
        remote_addr: SocketAddr,
        connector: Connector,
    ) -> io::Result<()> {
        match self.tcp_conn.entry(local_port) {
            Entry::Occupied(_) => Err(ErrorKind::AddrInUse.into()),
            Entry::Vacant(e) => {
                // create socket resource
                let tx_buf = TcpSocketBuffer::new(vec![0u8; MAX_PKT_SIZE]);
                let rx_buf = TcpSocketBuffer::new(vec![0u8; MAX_PKT_SIZE]);
                let mut client_socket = SmolTcpSocket::new(rx_buf, tx_buf);
                let handle = self.iface.add_socket(client_socket);

                // connect to remote
                let (client_socket, ctx) =
                    self.iface.get_socket_and_context::<SmolTcpSocket>(handle);
                client_socket
                    .connect(ctx, remote_addr, SocketAddr::new(self.ip_addr, local_port))
                    .map_err(|| Err(ErrorKind::ConnectionRefused.into()))?;

                e.insert(ConnTask::new(connector, handle));
                Ok(())
            }
        }
    }

    async fn poll_tcp_socket(&mut self, task: &mut ConnTask) -> io::Result<()> {
        let socket = self
            .iface
            .get_socket::<smoltcp::socket::TcpSocket>(*task.handle);
        // Send data
        if socket.can_send() {
            if let Some((buf, start)) = task.remain_to_send.take() {
                if let Ok(sent) = socket.send_slice(&buf.as_ready()[start..]) {
                    // successfully sent
                    if start + sent < buf.len {
                        task.remain_to_send = Some((buf, sent + start));
                    } else {
                        self.allocator.release(buf)
                    }
                } else {
                    return Err(ErrorKind::ConnectionAborted.into());
                }
            } else {
                // fetch new data
                match task.connector.rx.try_recv() {
                    Ok(buf) => {
                        if let Ok(sent) = socket.send_slice(buf.as_ready()) {
                            // successfully sent
                            if sent < buf.len {
                                task.remain_to_send = Some((buf, sent));
                            } else {
                                self.allocator.release(buf);
                            }
                        } else {
                            return Err(ErrorKind::ConnectionAborted.into());
                        }
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(_) => return Err(ErrorKind::ConnectionAborted.into()),
                }
            }
        }

        // Receive data
        if socket.can_recv() && task.connector.tx.capacity() < task.connector.tx.max_capacity() {
            let mut buf = self.allocator.obtain().await;
            if let Ok(size) = socket.recv_slice(buf.as_uninited()) {
                buf.len = size;
                // must not fail because there is only 1 sender
                let _ = task.connector.tx.send(buf).await;
            }
        }
        Ok(())
    }

    fn purge_closed_tcp(&mut self) {
        self.tcp_conn.retain(|port, task| {
            let socket = self
                .iface
                .get_socket::<smoltcp::socket::TcpSocket>(*task.handle);
            if socket.state() == TcpState::Closed {
                self.iface.remove_socket(*task.handle);
                false
            } else {
                true
            }
        });
    }
}

// -----------------------------------------------------------------------------------

/// Virtual IP device
pub(crate) struct VirtualIpDevice {
    mtu: usize,
    outbound: mpsc::Sender<BytesMut>,
    packet_queue: Arc<ConcurrentQueue<BytesMut>>,
}

impl VirtualIpDevice {
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

impl<'a> Device<'a> for VirtualIpDevice {
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
