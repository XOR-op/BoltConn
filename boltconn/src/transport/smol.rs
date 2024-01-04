use crate::adapter::{AddrConnector, AddrConnectorWrapper, Connector};

use crate::common::duplex_chan::DuplexChan;
use crate::common::{mut_buf, MAX_PKT_SIZE};
use crate::network::dns::GenericDns;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::InterfaceAddress;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use flume::TryRecvError;
use hickory_proto::iocompat::AsyncIoTokioAsStd;
use hickory_proto::TokioTime;
use hickory_resolver::name_server::RuntimeProvider;
use hickory_resolver::TokioHandle;
use rand::Rng;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{
    tcp::Socket as SmolTcpSocket, udp::PacketBuffer as UdpSocketBuffer,
    udp::PacketMetadata as UdpPacketMetadata, udp::Socket as SmolUdpSocket,
};
use smoltcp::socket::{tcp::SocketBuffer as TcpSocketBuffer, tcp::State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint};
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, Notify};

#[derive(Debug, Copy, Clone)]
enum SmolError {
    Disconnected,
    Aborted,
}

struct TcpConnTask {
    back_tx: mpsc::Sender<Bytes>,
    rx: flume::Receiver<Bytes>,
    handle: SocketHandle,
    abort_handle: ConnAbortHandle,
    remain_to_send: Option<(Bytes, usize)>, // buffer, start_offset
}

impl TcpConnTask {
    pub fn new(
        connector: Connector,
        handle: SocketHandle,
        abort_handle: ConnAbortHandle,
        notify: Arc<Notify>,
    ) -> Self {
        let Connector {
            tx: back_tx,
            rx: mut back_rx,
        } = connector;
        let (tx, rx) = flume::unbounded();
        // notify smol when new message comes
        tokio::spawn(async move {
            while let Some(buf) = back_rx.recv().await {
                let _ = tx.send(buf);
                notify.notify_one();
            }
        });
        Self {
            back_tx,
            rx,
            handle,
            abort_handle,
            remain_to_send: None,
        }
    }

    pub fn try_send(&mut self, socket: &mut SmolTcpSocket<'_>) -> io::Result<bool> {
        let mut has_activity = false;
        // Send data
        if socket.can_send() {
            if let Some((buf, start)) = self.remain_to_send.take() {
                if let Ok(sent) = socket.send_slice(&buf.as_ref()[start..]) {
                    // successfully sent
                    has_activity = true;
                    if start + sent < buf.len() {
                        self.remain_to_send = Some((buf, sent + start));
                    }
                } else {
                    return Err(ErrorKind::ConnectionAborted.into());
                }
            } else {
                // fetch new data
                match self.rx.try_recv() {
                    Ok(buf) => {
                        if let Ok(sent) = socket.send_slice(buf.as_ref()) {
                            // successfully sent
                            has_activity = true;
                            if sent < buf.len() {
                                self.remain_to_send = Some((buf, sent));
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
        if socket.state() == TcpState::CloseWait {
            socket.close();
        }
        Ok(has_activity)
    }

    pub async fn try_recv(&self, socket: &mut SmolTcpSocket<'_>) -> bool {
        // Receive data
        if socket.can_recv() && self.back_tx.capacity() > 0 {
            let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
            if let Ok(size) = socket.recv_slice(unsafe { mut_buf(&mut buf) }) {
                unsafe { buf.advance_mut(size) };
                // must not fail because there is only 1 sender
                let _ = self.back_tx.send(buf.freeze()).await;
                return true;
            }
        }
        false
    }
}

struct UdpConnTask {
    back_tx: mpsc::Sender<(Bytes, NetworkAddr)>,
    rx: flume::Receiver<(Bytes, SocketAddr)>,
    handle: SocketHandle,
    abort_handle: ConnAbortHandle,
    last_active: Instant,
}

impl UdpConnTask {
    pub fn new(
        connector: AddrConnector,
        handle: SocketHandle,
        abort_handle: ConnAbortHandle,
        dns: Arc<GenericDns<SmolDnsProvider>>,
        notify: Arc<Notify>,
    ) -> Self {
        let AddrConnector {
            tx: back_tx,
            rx: mut back_rx,
        } = connector;
        let (tx, rx) = flume::unbounded();
        tokio::spawn(async move {
            while let Some((buf, dst)) = back_rx.recv().await {
                if let Some(dst) = match dst {
                    NetworkAddr::Raw(s) => Some(s),
                    NetworkAddr::DomainName { domain_name, port } => dns
                        .genuine_lookup(domain_name.as_str())
                        .await
                        .map(|ip| SocketAddr::new(ip, port)),
                } {
                    let _ = tx.send((buf, dst));
                    notify.notify_one();
                }
            }
        });
        Self {
            back_tx,
            rx,
            handle,
            abort_handle,
            last_active: Instant::now(),
        }
    }

    pub fn try_send(&mut self, socket: &mut SmolUdpSocket<'_>) -> Result<bool, SmolError> {
        let mut has_activity = false;
        // Send data
        if socket.can_send() {
            // fetch new data
            match self.rx.try_recv() {
                // todo: full-cone NAT
                Ok((buf, addr)) => {
                    has_activity = true;
                    if socket
                        .send_slice(buf.as_ref(), IpEndpoint::from(addr))
                        .is_ok()
                    {
                        self.last_active = Instant::now();
                    } else {
                        return Err(SmolError::Aborted);
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(SmolError::Disconnected),
            }
        }
        Ok(has_activity)
    }

    pub async fn try_recv(&mut self, socket: &mut SmolUdpSocket<'_>) -> bool {
        // Receive data
        if socket.can_recv() && self.back_tx.capacity() > 0 {
            let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
            if let Ok((size, ep)) = socket.recv_slice(unsafe { mut_buf(&mut buf) }) {
                unsafe { buf.advance_mut(size) };
                self.last_active = Instant::now();
                let src_addr =
                    NetworkAddr::Raw(SocketAddr::new(ep.endpoint.addr.into(), ep.endpoint.port));
                // must not fail because there is only 1 sender
                let _ = self.back_tx.send((buf.freeze(), src_addr)).await;
                return true;
                // discard mismatched packet
            }
        }
        false
    }
}

//          Program -- TCP/UDP -> SmolStack -> IP -- Internet
//                   \ TCP/UDP <- SmolStack <- IP /
pub struct SmolStack {
    tcp_conn: DashMap<u16, TcpConnTask>,
    udp_conn: DashMap<u16, UdpConnTask>,
    ip_addr: InterfaceAddress,
    ip_device: VirtualIpDevice,
    iface: Interface,
    dns: Arc<GenericDns<SmolDnsProvider>>,
    socket_set: SocketSet<'static>,
    udp_timeout: Duration,
}

impl SmolStack {
    pub fn new(
        iface_ip: InterfaceAddress,
        mut ip_device: VirtualIpDevice,
        dns: Arc<GenericDns<SmolDnsProvider>>,
        udp_timeout: Duration,
    ) -> Self {
        let config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut ip_device, smoltcp::time::Instant::now());
        iface.update_ip_addrs(|v| match iface_ip {
            InterfaceAddress::Ipv4(addr) => {
                let _ = v.insert(0, IpCidr::new(addr.into(), 32));
            }
            InterfaceAddress::Ipv6(addr) => {
                let _ = v.insert(0, IpCidr::new(addr.into(), 128));
            }
            InterfaceAddress::DualStack(v4, v6) => {
                let _ = v.insert(0, IpCidr::new(v4.into(), 32));
                let _ = v.insert(1, IpCidr::new(v6.into(), 128));
            }
        });
        Self {
            tcp_conn: Default::default(),
            udp_conn: Default::default(),
            ip_addr: iface_ip,
            ip_device,
            iface,
            dns,
            socket_set: SocketSet::new(vec![]),
            udp_timeout,
        }
    }

    pub fn drive_iface(&mut self) -> bool {
        self.iface.poll(
            SmolInstant::now(),
            &mut self.ip_device,
            &mut self.socket_set,
        )
    }

    pub fn get_dns(&self) -> Arc<GenericDns<SmolDnsProvider>> {
        self.dns.clone()
    }

    pub fn open_tcp(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        connector: Connector,
        abort_handle: ConnAbortHandle,
        notify: Arc<Notify>,
    ) -> io::Result<()> {
        if local_addr.port() == 0 {
            for _ in 0..10 {
                let port = rand::thread_rng().gen_range(32768..65534);
                match self.tcp_conn.entry(port) {
                    Entry::Occupied(_) => continue,
                    Entry::Vacant(e) => {
                        let handle = Self::open_tcp_inner(
                            &mut self.iface,
                            &mut self.socket_set,
                            self.ip_addr
                                .matched_if_addr(remote_addr.ip())
                                .ok_or::<io::Error>(ErrorKind::AddrNotAvailable.into())?,
                            port,
                            remote_addr,
                        )?;
                        e.insert(TcpConnTask::new(connector, handle, abort_handle, notify));
                        return Ok(());
                    }
                }
            }
            Err(ErrorKind::AddrNotAvailable.into())
        } else {
            match self.tcp_conn.entry(local_addr.port()) {
                Entry::Occupied(_) => Err(ErrorKind::AddrInUse.into()),
                Entry::Vacant(e) => {
                    let handle = Self::open_tcp_inner(
                        &mut self.iface,
                        &mut self.socket_set,
                        self.ip_addr
                            .matched_if_addr(remote_addr.ip())
                            .ok_or::<io::Error>(ErrorKind::AddrNotAvailable.into())?,
                        local_addr.port(),
                        remote_addr,
                    )?;
                    e.insert(TcpConnTask::new(connector, handle, abort_handle, notify));
                    Ok(())
                }
            }
        }
    }

    fn open_tcp_inner(
        iface: &mut Interface,
        socket_set: &mut SocketSet<'static>,
        ip_addr: IpAddr,
        local_port: u16,
        remote_addr: SocketAddr,
    ) -> io::Result<SocketHandle> {
        // create socket resource
        let tx_buf = TcpSocketBuffer::new(vec![0u8; MAX_PKT_SIZE]);
        let rx_buf = TcpSocketBuffer::new(vec![0u8; MAX_PKT_SIZE]);
        let mut client_socket = SmolTcpSocket::new(rx_buf, tx_buf);
        // Since we are behind kernel's TCP/IP stack, no second Nagle is needed.
        client_socket.set_nagle_enabled(false);

        // connect to remote
        client_socket
            .connect(
                iface.context(),
                remote_addr,
                SocketAddr::new(ip_addr, local_port),
            )
            .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?;

        Ok(socket_set.add(client_socket))
    }

    pub fn open_udp(
        &mut self,
        local_addr: SocketAddr,
        connector: AddrConnector,
        abort_handle: ConnAbortHandle,
        notify: Arc<Notify>,
    ) -> io::Result<()> {
        // todo: IPv6 support when local_addr is a V4 address
        if local_addr.port() == 0 {
            for _ in 0..10 {
                let port = rand::thread_rng().gen_range(32768..65534);
                match self.udp_conn.entry(port) {
                    Entry::Occupied(_) => continue,
                    Entry::Vacant(e) => {
                        let handle = Self::open_udp_inner(
                            &mut self.socket_set,
                            self.ip_addr
                                .matched_if_addr(local_addr.ip())
                                .ok_or::<io::Error>(ErrorKind::AddrNotAvailable.into())?,
                            port,
                        )?;
                        e.insert(UdpConnTask::new(
                            connector,
                            handle,
                            abort_handle,
                            self.dns.clone(),
                            notify,
                        ));
                        return Ok(());
                    }
                }
            }
            Err(ErrorKind::AddrNotAvailable.into())
        } else {
            match self.udp_conn.entry(local_addr.port()) {
                Entry::Occupied(_) => Err(ErrorKind::AddrInUse.into()),
                Entry::Vacant(e) => {
                    let handle = Self::open_udp_inner(
                        &mut self.socket_set,
                        self.ip_addr
                            .matched_if_addr(local_addr.ip())
                            .ok_or::<io::Error>(ErrorKind::AddrNotAvailable.into())?,
                        local_addr.port(),
                    )?;
                    e.insert(UdpConnTask::new(
                        connector,
                        handle,
                        abort_handle,
                        self.dns.clone(),
                        notify,
                    ));
                    Ok(())
                }
            }
        }
    }

    fn open_udp_inner(
        socket_set: &mut SocketSet<'static>,
        ip_addr: IpAddr,
        local_port: u16,
    ) -> io::Result<SocketHandle> {
        // create socket resource
        let tx_buf =
            UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 16], vec![0u8; MAX_PKT_SIZE]);
        let rx_buf =
            UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 16], vec![0u8; MAX_PKT_SIZE]);
        let mut client_socket = SmolUdpSocket::new(rx_buf, tx_buf);

        client_socket
            .bind(IpEndpoint::new(ip_addr.into(), local_port))
            .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?;
        Ok(socket_set.add(client_socket))
    }

    pub async fn poll_all_tcp(&mut self) -> bool {
        let mut has_activity = false;
        // no double entry here, so theoretically there is no deadlock related to DashMap
        for mut item in self.tcp_conn.iter_mut() {
            let socket = self.socket_set.get_mut::<SmolTcpSocket>(item.handle);
            if socket.state() != TcpState::Closed {
                match item.try_send(socket) {
                    Ok(v) => has_activity |= v,
                    Err(_) => {
                        socket.close();
                        item.abort_handle.cancel();
                    }
                }
                // this async is a channel operation
                has_activity |= item.try_recv(socket).await;
            }
        }
        has_activity
    }

    pub async fn poll_all_udp(&mut self) -> bool {
        let mut has_activity = false;
        for mut item in self.udp_conn.iter_mut() {
            let socket = self.socket_set.get_mut::<SmolUdpSocket>(item.handle);
            if socket.is_open() {
                match item.try_send(socket) {
                    Ok(v) => has_activity |= v,
                    Err(SmolError::Aborted) => {
                        socket.close();
                        item.abort_handle.cancel();
                    }
                    Err(SmolError::Disconnected) => {
                        // send side has closed
                        // if don't received any data in 30s, close the socket
                        if item.last_active.elapsed() > Duration::from_secs(30) {
                            socket.close();
                            item.abort_handle.cancel();
                        }
                    }
                }
                // this async is a channel operation
                has_activity |= item.try_recv(socket).await;
            }
        }
        has_activity
    }

    pub fn purge_closed_tcp(&mut self) {
        self.tcp_conn.retain(|_port, task| {
            let socket = self.socket_set.get_mut::<SmolTcpSocket>(task.handle);
            if socket.state() == TcpState::Closed {
                self.socket_set.remove(task.handle);
                // Here we only abort normally closed sockets. Maybe unnecessary?
                task.abort_handle.cancel();
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
                task.abort_handle.cancel();
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
    outbound: flume::Sender<BytesMut>,
    packet_queue: flume::Receiver<BytesMut>,
}

impl VirtualIpDevice {
    pub fn new(
        mtu: usize,
        inbound: flume::Receiver<BytesMut>,
        outbound: flume::Sender<BytesMut>,
    ) -> Self {
        Self {
            mtu,
            outbound,
            packet_queue: inbound,
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
        match self.packet_queue.try_recv() {
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
        f(&mut self.buf)
    }
}

pub struct VirtualTxToken {
    sender: flume::Sender<BytesMut>,
}

impl TxToken for VirtualTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = BytesMut::with_capacity(len);
        // Safety: f exactly writes _len_ bytes, so all bytes are initialized.
        unsafe {
            buf.set_len(len);
        }
        let r = f(&mut buf);
        let _ = self.sender.send(buf);
        r
    }
}

#[derive(Clone)]
pub struct SmolDnsProvider {
    handle: TokioHandle,
    smol: std::sync::Weak<Mutex<SmolStack>>,
    abort_handle: ConnAbortHandle,
    notify: Arc<Notify>,
}

impl SmolDnsProvider {
    pub fn new(
        smol: std::sync::Weak<Mutex<SmolStack>>,
        abort_handle: ConnAbortHandle,
        notify: Arc<Notify>,
    ) -> Self {
        Self {
            handle: Default::default(),
            smol,
            abort_handle,
            notify,
        }
    }
}

impl RuntimeProvider for SmolDnsProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = AddrConnectorWrapper;
    type Tcp = AsyncIoTokioAsStd<DuplexChan>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let smol = self.smol.upgrade();
        let handle = self.abort_handle.clone();
        let notify = self.notify.clone();
        let (inbound, outbound) = Connector::new_pair(10);
        Box::pin(async move {
            let smol = smol.ok_or_else(|| io::Error::from(ErrorKind::ConnectionReset))?;
            let mut x = smol.lock().await;
            x.open_tcp(
                SocketAddr::new(
                    match &server_addr {
                        SocketAddr::V4(_) => Ipv4Addr::new(0, 0, 0, 0).into(),
                        SocketAddr::V6(_) => Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
                    },
                    0,
                ),
                server_addr,
                inbound,
                handle,
                notify,
            )?;
            Ok(AsyncIoTokioAsStd(DuplexChan::new(outbound)))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let smol = self.smol.upgrade();
        let notify = self.notify.clone();
        let handle = self.abort_handle.clone();
        let (inbound, outbound) = AddrConnector::new_pair(10);
        Box::pin(async move {
            let smol = smol.ok_or_else(|| io::Error::from(ErrorKind::ConnectionReset))?;
            let mut x = smol.lock().await;
            x.open_udp(local_addr, inbound, handle, notify)?;
            let outbound = AddrConnectorWrapper::from(outbound);
            Ok(outbound)
        })
    }
}
