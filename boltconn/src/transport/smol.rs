use crate::adapter::Connector;
use crate::common::buf_pool::{PktBufHandle, PktBufPool, MAX_PKT_SIZE};
use crate::proxy::ConnAbortHandle;
use bytes::BytesMut;
use concurrent_queue::ConcurrentQueue;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use smoltcp::iface::{Interface, InterfaceBuilder, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::TcpSocket as SmolTcpSocket;
use smoltcp::socket::{TcpSocketBuffer, TcpState};
use smoltcp::time::Instant;
use smoltcp::wire::IpCidr;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::ops::DerefMut;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

struct ConnTask {
    connector: Connector,
    handle: SocketHandle,
    abort_handle: ConnAbortHandle,
    remain_to_send: Option<(PktBufHandle, usize)>, // buffer, start_offset
}

impl ConnTask {
    pub fn new(connector: Connector, handle: SocketHandle, abort_handle: ConnAbortHandle) -> Self {
        Self {
            connector,
            handle,
            abort_handle,
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
            .ip_addrs(vec![IpCidr::new(iface_ip.into(), 32)])
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
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()> {
        match self.tcp_conn.entry(local_port) {
            Entry::Occupied(_) => Err(ErrorKind::AddrInUse.into()),
            Entry::Vacant(e) => {
                // create socket resource
                let tx_buf = TcpSocketBuffer::new(vec![0u8; MAX_PKT_SIZE]);
                let rx_buf = TcpSocketBuffer::new(vec![0u8; MAX_PKT_SIZE]);
                let client_socket = SmolTcpSocket::new(rx_buf, tx_buf);
                let handle = self.iface.add_socket(client_socket);

                // connect to remote
                let (client_socket, ctx) =
                    self.iface.get_socket_and_context::<SmolTcpSocket>(handle);
                client_socket
                    .connect(ctx, remote_addr, SocketAddr::new(self.ip_addr, local_port))
                    .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?;

                e.insert(ConnTask::new(connector, handle, abort_handle));
                Ok(())
            }
        }
    }

    pub async fn poll_all_tcp(&mut self) {
        for mut item in self.tcp_conn.iter_mut() {
            let socket = self
                .iface
                .get_socket::<smoltcp::socket::TcpSocket>(item.handle);
            #[allow(clippy::collapsible_if)]
            if socket.state() != TcpState::Closed {
                if Self::poll_tcp_socket(socket, item.deref_mut(), &mut self.allocator)
                    .await
                    .is_err()
                {
                    socket.close();
                    item.abort_handle.cancel().await;
                }
            }
        }
    }

    async fn poll_tcp_socket<'a>(
        socket: &mut smoltcp::socket::TcpSocket<'a>,
        task: &mut ConnTask,
        allocator: &mut PktBufPool,
    ) -> io::Result<()> {
        // Send data
        if socket.can_send() {
            if let Some((buf, start)) = task.remain_to_send.take() {
                if let Ok(sent) = socket.send_slice(&buf.as_ready()[start..]) {
                    // successfully sent
                    if start + sent < buf.len {
                        task.remain_to_send = Some((buf, sent + start));
                    } else {
                        allocator.release(buf)
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
                                allocator.release(buf);
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
            let mut buf = allocator.obtain().await;
            if let Ok(size) = socket.recv_slice(buf.as_uninited()) {
                buf.len = size;
                // must not fail because there is only 1 sender
                let _ = task.connector.tx.send(buf).await;
            }
        }
        Ok(())
    }

    fn purge_closed_tcp(&mut self) {
        self.tcp_conn.retain(|_port, task| {
            let socket = self
                .iface
                .get_socket::<smoltcp::socket::TcpSocket>(task.handle);
            if socket.state() == TcpState::Closed {
                self.iface.remove_socket(task.handle);
                false
            } else {
                true
            }
        });
    }
}

// -----------------------------------------------------------------------------------

/// Virtual IP device
pub struct VirtualIpDevice {
    mtu: usize,
    outbound: mpsc::Sender<BytesMut>,
    packet_queue: Arc<ConcurrentQueue<BytesMut>>,
}

impl VirtualIpDevice {
    pub fn new(
        mtu: usize,
        mut inbound: mpsc::Receiver<BytesMut>,
        outbound: mpsc::Sender<BytesMut>,
    ) -> Self {
        let queue = Arc::new(ConcurrentQueue::unbounded());
        let queue_clone = queue.clone();
        tokio::spawn(async move {
            // move data from inbound to internal buffer
            loop {
                match inbound.recv().await {
                    None => return,
                    Some(item) => {
                        let _ = queue.push(item);
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

pub struct VirtualRxToken {
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

pub struct VirtualTxToken {
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
