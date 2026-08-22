use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum SessionCtl {
    Tcp(TcpSessionCtl),
    Udp(UdpSessionCtl),
}

#[derive(Debug, Clone)]
pub struct TcpSessionCtl {
    pub source_addr: SocketAddr,
    pub dest_addr: SocketAddr,
    pub available: Arc<AtomicU8>,
    pub last_time: Instant,
}

impl TcpSessionCtl {
    pub fn new(source_addr: SocketAddr, dest_addr: SocketAddr) -> Self {
        Self {
            source_addr,
            dest_addr,
            available: Arc::new(AtomicU8::new(2)), // inbound and outbound
            last_time: Instant::now(),
        }
    }
}

/// Last-activity stamp, shared with the packet path so a live session can report progress
/// without going back through the session map.
#[derive(Debug, Clone)]
pub struct UdpSessionActivity(Arc<UdpSessionActivityInner>);

#[derive(Debug)]
struct UdpSessionActivityInner {
    // Instant itself is not atomic, so activity is stored as a millisecond offset from a
    // monotonic epoch fixed when the session is created.
    epoch: Instant,
    last_active_millis: AtomicU64,
}

impl UdpSessionActivity {
    fn new() -> Self {
        Self(Arc::new(UdpSessionActivityInner {
            epoch: Instant::now(),
            last_active_millis: AtomicU64::new(0),
        }))
    }

    /// Report that the session just carried a packet. This runs once per packet, so it has
    /// to stay a single relaxed atomic.
    pub fn touch(&self) {
        // fetch_max keeps an older reading from replacing a newer stamp when the inbound
        // loop and the staleness sweep observe concurrently.
        self.0
            .last_active_millis
            .fetch_max(self.elapsed_millis(), Ordering::Relaxed);
    }

    pub fn idle_duration(&self) -> time::Duration {
        let last_active = self.0.last_active_millis.load(Ordering::Relaxed);
        time::Duration::from_millis(self.elapsed_millis().saturating_sub(last_active))
    }

    fn elapsed_millis(&self) -> u64 {
        u64::try_from(self.0.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct UdpSessionCtl {
    pub source_addr: SocketAddr,
    pub available: Arc<AtomicBool>,
    pub activity: UdpSessionActivity,
}

impl UdpSessionCtl {
    pub fn new(source_addr: SocketAddr) -> Self {
        Self {
            source_addr,
            available: Arc::new(AtomicBool::new(true)),
            activity: UdpSessionActivity::new(),
        }
    }

    pub fn is_expired(&self, threshold: time::Duration) -> bool {
        self.activity.idle_duration() > threshold
    }

    pub fn invalidate(&self) {
        self.available.store(false, Ordering::Relaxed);
    }
}
