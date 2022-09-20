use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;
use tokio::sync::Notify;

pub const MAX_PKT_SIZE: usize = 65576;

pub type PktBuffer = [u8; MAX_PKT_SIZE];

fn get_default_pkt_buffer() -> PktBuffer {
    [0; MAX_PKT_SIZE]
}

#[derive(Clone)]
pub struct PktBufHandle {
    pub data: Arc<PktBuffer>,
    pub len: usize,
}

type PktBufPoolInner = Arc<Mutex<Vec<PktBufHandle>>>;

/// thread-safe
#[derive(Clone)]
pub struct PktBufPool {
    free: PktBufPoolInner,
    fixed_capacity: usize,
    extra_capacity: usize,
    extra_len: usize,
    notify: Arc<Notify>,
}

pub struct PktBufFuture {
    src: PktBufPoolInner,
    waker: Option<Arc<Mutex<Waker>>>,
}

impl Future for PktBufFuture {
    type Output = PktBufHandle;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut src = self.src.lock().unwrap();
        if src.len() > 0 {
            return Poll::Ready(src.pop().unwrap());
        }
        drop(src);
        // make sure only one thread will be created during sleep
        if let Some(waker) = &self.waker {
            let mut waker = waker.lock().unwrap();
            if !waker.will_wake(cx.waker()) {
                *waker = cx.waker().clone();
            }
        } else {
            let waker = Arc::new(Mutex::new(cx.waker().clone()));
            self.waker = Some(waker.clone());
            thread::spawn(move || {
                thread::sleep(Duration::from_micros(100));
                waker.lock().unwrap().wake_by_ref();
            });
        }
        Poll::Pending
    }
}

impl PktBufPool {
    pub fn new(lower_bound: usize, upper_bound: usize) -> Self {
        let mut free = Vec::with_capacity(lower_bound);
        for _ in 0..lower_bound {
            free.push(PktBufHandle {
                data: Arc::new(get_default_pkt_buffer()),
                len: 0,
            });
        }
        Self {
            free: Arc::new(Mutex::new(free)),
            fixed_capacity: lower_bound,
            extra_capacity: upper_bound,
            extra_len: 0,
            notify: Arc::new(Notify::new()),
        }
    }

    pub async fn obtain(&mut self) -> PktBufHandle {
        loop {
            let mut vec = self.free.lock().unwrap();
            if !vec.is_empty() {
                let mut handle = vec.pop().unwrap();
                handle.len = 0;
                return handle;
            } else if self.extra_len < self.extra_capacity {
                self.extra_len += 1;
                return PktBufHandle {
                    data: Arc::new(get_default_pkt_buffer()),
                    len: 0,
                };
            }
            drop(vec);
            self.notify.notified().await;
        }
    }

    pub fn release(&mut self, handle: PktBufHandle) {
        let mut vec = self.free.lock().unwrap();
        if vec.len() < self.fixed_capacity {
            vec.push(handle);
        } else {
            assert!(self.extra_len > 0);
            self.extra_len -= 1;
        }
        self.notify.notify_one();
    }
}
