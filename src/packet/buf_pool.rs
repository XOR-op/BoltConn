use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;
use bytes::Bytes;

pub struct PktBuffer([u8; 65576]);

pub struct PktBufHandle(Arc<PktBuffer>);

type PktBufPoolInner = Arc<Mutex<Vec<PktBufHandle>>>;

/// thread-safe
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PktBufPool {
    free: PktBufPoolInner,
}

pub struct PktBufFuture {
    src: PktBufPoolInner,
    waker: Option<Arc<Mutex<Waker>>>,
}

impl Future for PktBufFuture {
    type Output = PktBufHandle;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut src = self.src.lock().unwrap();
        if src.len() > 0 {
            Poll::Ready(src.pop().unwrap())
        } else {
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
                })
            }
            Poll::Pending
        }
    }
}

impl PktBufPool {
    pub fn new(size: usize) -> Self {
        let mut free = Vec::with_capacity(size);
        for idx in 0..size {
            free.push(PktBufHandle {
                0: Arc::new(Default::default()),
            });
        }
        Self {
            free: Arc::new(Mutex::new(free)),
        }
    }

    pub async fn obtain(&mut self) -> PktBufFuture {
        PktBufFuture { src: self.free.clone() }
    }
    pub fn release(&mut self, handle: PktBufHandle) {
        self.free.lock().unwrap().push(handle)
    }
}
