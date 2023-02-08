use crate::adapter::Connector;
use crate::common::buf_pool::{PktBufHandle, PktBufPool, MAX_PKT_SIZE};
use crate::proxy::ConnAbortHandle;
use bytes::BytesMut;
use concurrent_queue::ConcurrentQueue;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{
    tcp::Socket as SmolTcpSocket, udp::PacketBuffer as UdpSocketBuffer,
    udp::PacketMetadata as UdpPacketMetadata, udp::Socket as SmolUdpSocket,
};
use smoltcp::socket::{tcp::SocketBuffer as TcpSocketBuffer, tcp::State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpCidr, IpEndpoint};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

struct TcpConnTask {
    connector: Connector,
    handle: SocketHandle,
    abort_handle: ConnAbortHandle,
    remain_to_send: Option<(PktBufHandle, usize)>, // buffer, start_offset
}

impl TcpConnTask {
    pub fn new(connector: Connector, handle: SocketHandle, abort_handle: ConnAbortHandle) -> Self {
        Self {
            connector,
            handle,
            abort_handle,
            remain_to_send: None,
        }
    }
}

struct UdpConnTask {
    connector: Connector,
    handle: SocketHandle,
    abort_handle: ConnAbortHandle,
    dest: IpEndpoint,
    last_active: Instant,
}

impl UdpConnTask {
    pub fn new(
        connector: Connector,
        dest: IpEndpoint,
        handle: SocketHandle,
        abort_handle: ConnAbortHandle,
    ) -> Self {
        Self {
            connector,
            handle,
            abort_handle,
            dest,
            last_active: Instant::now(),
        }
    }
}

//          Program -- TCP/UDP -> SmolStack -> IP -- Internet
//                   \ TCP/UDP <- SmolStack <- IP /
pub struct SmolStack {
    tcp_conn: DashMap<u16, TcpConnTask>,
    udp_conn: DashMap<u16, UdpConnTask>,
    allocator: PktBufPool,
    ip_addr: IpAddr,
    iface: Interface,
    socket_set: SocketSet<'static>,
    udp_timeout: Duration,
}

impl SmolStack {
    pub fn new(
        iface_ip: IpAddr,
        mut ip_device: VirtualIpDevice,
        allocator: PktBufPool,
        udp_timeout: Duration,
    ) -> Self {
        let config = smoltcp::iface::Config::default();
        let mut iface = Interface::new(config, &mut ip_device);
        iface.update_ip_addrs(|v| {
            let _ = v.insert(0, IpCidr::new(iface_ip.into(), 32));
        });
        Self {
            tcp_conn: Default::default(),
            udp_conn: Default::default(),
            allocator,
            ip_addr: iface_ip,
            iface,
            socket_set: SocketSet::new(vec![]),
            udp_timeout,
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
                let mut client_socket = SmolTcpSocket::new(rx_buf, tx_buf);

                // connect to remote
                client_socket
                    .connect(
                        self.iface.context(),
                        remote_addr,
                        SocketAddr::new(self.ip_addr, local_port),
                    )
                    .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?;

                let handle = self.socket_set.add(client_socket);
                e.insert(TcpConnTask::new(connector, handle, abort_handle));
                tracing::debug!("Open tcp at port {local_port} to {remote_addr}");
                Ok(())
            }
        }
    }

    pub fn open_udp(
        &mut self,
        local_port: u16,
        remote_addr: SocketAddr,
        connector: Connector,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()> {
        match self.udp_conn.entry(local_port) {
            Entry::Occupied(_) => Err(ErrorKind::AddrInUse.into()),
            Entry::Vacant(e) => {
                let remote_addr = IpEndpoint::from(remote_addr);
                // create socket resource
                let tx_buf = UdpSocketBuffer::new(
                    vec![UdpPacketMetadata::EMPTY; 16],
                    vec![0u8; MAX_PKT_SIZE],
                );
                let rx_buf = UdpSocketBuffer::new(
                    vec![UdpPacketMetadata::EMPTY; 16],
                    vec![0u8; MAX_PKT_SIZE],
                );
                let mut client_socket = SmolUdpSocket::new(rx_buf, tx_buf);

                client_socket
                    .bind(remote_addr)
                    .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?;
                let handle = self.socket_set.add(client_socket);

                e.insert(UdpConnTask::new(
                    connector,
                    remote_addr,
                    handle,
                    abort_handle,
                ));
                tracing::debug!("Open udp at port {local_port} to {remote_addr}");
                Ok(())
            }
        }
    }

    pub async fn poll_all_tcp(&mut self) -> bool {
        let mut has_activity = false;
        for mut item in self.tcp_conn.iter_mut() {
            let socket = self.socket_set.get_mut::<SmolTcpSocket>(item.handle);
            tracing::debug!(
                "POLL tcp {}({:?}): {:?}",
                *item.key(),
                socket.local_endpoint(),
                socket.state()
            );
            if socket.state() != TcpState::Closed {
                match Self::poll_tcp_socket(socket, item.deref_mut(), &mut self.allocator).await {
                    Ok(v) => has_activity |= v,
                    Err(_) => {
                        socket.close();
                        item.abort_handle.cancel().await;
                    }
                }
            }
        }
        has_activity
    }

    async fn poll_tcp_socket<'a>(
        socket: &mut SmolTcpSocket<'a>,
        task: &mut TcpConnTask,
        allocator: &mut PktBufPool,
    ) -> io::Result<bool> {
        let mut has_activity = false;
        // Send data
        if socket.can_send() {
            tracing::debug!("CAN SEND!");
            if let Some((buf, start)) = task.remain_to_send.take() {
                if let Ok(sent) = socket.send_slice(&buf.as_ready()[start..]) {
                    // successfully sent
                    has_activity = true;
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
                            has_activity = true;
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
                has_activity = true;
                buf.len = size;
                // must not fail because there is only 1 sender
                let _ = task.connector.tx.send(buf).await;
            }
        }
        Ok(has_activity)
    }

    pub async fn poll_all_udp(&mut self) -> bool {
        let mut has_activity = false;
        for mut item in self.udp_conn.iter_mut() {
            let socket = self.socket_set.get_mut::<SmolUdpSocket>(item.handle);
            if socket.is_open() {
                match Self::poll_udp_socket(socket, item.deref_mut(), &mut self.allocator).await {
                    Ok(v) => has_activity |= v,
                    Err(_) => {
                        socket.close();
                        item.abort_handle.cancel().await;
                    }
                }
            }
        }
        has_activity
    }

    async fn poll_udp_socket<'a>(
        socket: &mut SmolUdpSocket<'a>,
        task: &mut UdpConnTask,
        allocator: &mut PktBufPool,
    ) -> io::Result<bool> {
        let mut has_activity = false;
        // Send data
        if socket.can_send() {
            // fetch new data
            match task.connector.rx.try_recv() {
                Ok(buf) => {
                    has_activity = true;
                    if socket.send_slice(buf.as_ready(), task.dest).is_ok() {
                        allocator.release(buf);
                        task.last_active = Instant::now();
                    } else {
                        return Err(ErrorKind::ConnectionAborted.into());
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(_) => return Err(ErrorKind::ConnectionAborted.into()),
            }
        }

        // Receive data
        if socket.can_recv() && task.connector.tx.capacity() < task.connector.tx.max_capacity() {
            let mut buf = allocator.obtain().await;
            if let Ok((size, ep)) = socket.recv_slice(buf.as_uninited()) {
                has_activity = true;
                if ep == task.dest {
                    buf.len = size;
                    task.last_active = Instant::now();
                    // must not fail because there is only 1 sender
                    let _ = task.connector.tx.send(buf).await;
                }
                // discard mismatched packet
            }
        }
        Ok(has_activity)
    }

    pub fn purge_closed_tcp(&mut self) {
        self.tcp_conn.retain(|_port, task| {
            let socket = self.socket_set.get_mut::<SmolTcpSocket>(task.handle);
            if socket.state() == TcpState::Closed {
                self.socket_set.remove(task.handle);
                // Here we only abort normally closed sockets. Maybe unnecessary?
                let c = task.abort_handle.clone();
                tokio::spawn(async move { c.cancel().await });
                false
            } else {
                true
            }
        });
    }

    pub fn purge_timeout_udp(&mut self) {
        self.udp_conn.retain(|_port, task| {
            if task.last_active.elapsed() > self.udp_timeout {
                self.socket_set.remove(task.handle);
                let c = task.abort_handle.clone();
                tokio::spawn(async move { c.cancel().await });
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

impl Device for VirtualIpDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        tracing::debug!("Allocate RxToken");
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

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        tracing::debug!("Allocate TxToken");
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
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        tracing::trace!("RxToken: Receive");
        f(&mut self.buf)
    }
}

pub struct VirtualTxToken {
    sender: mpsc::Sender<BytesMut>,
}

impl TxToken for VirtualTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = BytesMut::with_capacity(len);
        tracing::trace!("TxToken: Transmit {len} size");
        let r = f(&mut buf);
        let _ = self.sender.send(buf);
        r
    }
}
