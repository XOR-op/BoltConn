use ipnet::Ipv4Net;

use crate::common::{async_session::AsyncSession, io_err};

use std::{io, sync::Arc};

pub(super) struct TunInstance {
    session: Option<AsyncSession>,
    adapter: Arc<wintun::Adapter>,
}

impl TunInstance {
    pub fn new() -> io::Result<(Self, String)> {
        let name = "utun13";
        let module = match unsafe { wintun::load() } {
            Ok(module) => module,
            Err(_) => {
                tracing::error!("Failed to load wintun. Check if wintun.dll exists");
                return Err(io_err("Failed to load wintun.dll"));
            }
        };
        let device = wintun::Adapter::create(&module, name, "utun", None)
            .map_err(|e| io_err(format!("Failed to create wintun adapter: {}", e).as_str()))?;
        let session = device
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|_| io_err("Failed to initialize WinTun session"))?;
        Ok((
            Self {
                session: Some(AsyncSession::new(session)),
                adapter: device,
            },
            name.to_string(),
        ))
    }

    pub fn take_fd(&mut self) -> Option<AsyncSession> {
        self.session.take()
    }

    pub fn interface_up(&self, _name: &str) -> io::Result<()> {
        Ok(())
    }

    pub fn set_address(&self, _name: &str, addr: Ipv4Net) -> io::Result<()> {
        self.adapter.set_address(addr.addr()).map_err(|e| match e {
            wintun::Error::Io(e) => e,
            _ => io_err("Failed to set address"),
        })
    }

    // pub async fn send_outbound(pkt: &IPPkt, gw_name: &str, ipv6_enabled: bool) -> io::Result<()> {
    //     let addr = get_iface_address(gw_name)?;
    //     match pkt {
    //         IPPkt::V4(_) => {
    //             let sock = socket2::Socket::new(
    //                 socket2::Domain::IPV4,
    //                 socket2::Type::RAW,
    //                 Some(socket2::Protocol::from(IPPROTO_IP.0)),
    //             )?;
    //             sock.bind(&SocketAddr::new(addr, 0).into())?;
    //             todo!()
    //         }
    //         IPPkt::V6(_) => {
    //             if ipv6_enabled {
    //                 todo!()
    //             } else {
    //                 tracing::trace!("Drop IPv6 packets: IPv6 disabled");
    //             }
    //         }
    //     }
    //     Ok(())
    // }
}
