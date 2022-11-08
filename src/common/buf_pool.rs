use std::future::Future;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use std::{io, thread};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::Notify;

pub const MAX_PKT_SIZE: usize = 65576;

pub type PktBuffer = [u8; MAX_PKT_SIZE];

fn get_default_pkt_buffer() -> PktBuffer {
    unsafe { MaybeUninit::uninit().assume_init() }
}

pub struct PktBufHandle {
    // pub data: Arc<PktBuffer>,
    pub data: Box<PktBuffer>,
    pub len: usize,
}

impl PktBufHandle {
    pub fn as_ready(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn as_uninited(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub async fn read(&mut self, read: &mut OwnedReadHalf) -> io::Result<usize> {
        assert_eq!(self.len, 0);
        match read.read(self.as_uninited()).await {
            Ok(s) => {
                self.len = s;
                Ok(s)
            }
            Err(e) => Err(e),
        }
    }
}

type PktBufPoolInner = Arc<Mutex<Vec<PktBufHandle>>>;

/// Fixed capacity for performace; extra capacity for burst traffic but not exhaust system resources
#[derive(Clone)]
pub struct PktBufPool {
    free: PktBufPoolInner,
    fixed_capacity: usize,
    extra_capacity: usize,
    extra_len: Arc<AtomicUsize>,
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
                // data: Arc::new(get_default_pkt_buffer()),
                data: Box::new(get_default_pkt_buffer()),
                len: 0,
            });
        }
        Self {
            free: Arc::new(Mutex::new(free)),
            fixed_capacity: lower_bound,
            extra_capacity: upper_bound,
            extra_len: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub async fn obtain(&self) -> PktBufHandle {
        loop {
            match self.try_obtain() {
                Some(v) => return v,
                None => {}
            }
            self.notify.notified().await;
        }
    }

    pub fn try_obtain(&self) -> Option<PktBufHandle> {
        let mut vec = self.free.lock().unwrap();
        if !vec.is_empty() {
            return Some(vec.pop().unwrap());
        } else if self.extra_len.load(Ordering::Relaxed) < self.extra_capacity {
            // no need for strict constraint
            self.extra_len.fetch_add(1, Ordering::Relaxed);
            return Some(PktBufHandle {
                // data: Arc::new(get_default_pkt_buffer()),
                data: Box::new(get_default_pkt_buffer()),
                len: 0,
            });
        }
        None
    }

    pub fn release(&self, mut handle: PktBufHandle) {
        let mut vec = self.free.lock().unwrap();
        if vec.len() < self.fixed_capacity {
            handle.len = 0;
            vec.push(handle);
        } else {
            self.extra_len.fetch_sub(1, Ordering::Relaxed);
        }
        self.notify.notify_one();
    }
}
