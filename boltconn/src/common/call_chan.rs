use std::future::Future;

use tokio::sync::mpsc;

pub struct CallFuture<R> {
    rx: mpsc::Receiver<R>,
}

impl<R> Future for CallFuture<R> {
    type Output = Option<R>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<R>> {
        self.rx.poll_recv(cx)
    }
}

impl<R> CallFuture<R> {
    pub fn wait_blocking(mut self) -> Option<R> {
        self.rx.blocking_recv()
    }
}

pub struct CallParameter<P, R> {
    pub param: P,
    ret_tx: mpsc::Sender<R>,
}

impl<P: std::fmt::Debug, R> std::fmt::Debug for CallParameter<P, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallParameter")
            .field("param", &self.param)
            .finish()
    }
}

impl<P, R> CallParameter<P, R> {
    pub fn new(param: P) -> (Self, CallFuture<R>) {
        let (tx, rx) = mpsc::channel(1);
        let param = Self { param, ret_tx: tx };
        let future = CallFuture { rx };
        (param, future)
    }

    pub fn ret(self, ret: R) {
        // should not panic
        self.ret_tx.try_send(ret).unwrap()
    }

    pub fn into_parts(self) -> (P, CallReturnChannel<R>) {
        let ret_channel = CallReturnChannel { tx: self.ret_tx };
        (self.param, ret_channel)
    }

    pub fn from_parts(param: P, ret_channel: CallReturnChannel<R>) -> Self {
        Self {
            param,
            ret_tx: ret_channel.tx,
        }
    }
}

pub struct CallReturnChannel<R> {
    tx: mpsc::Sender<R>,
}
impl<R> CallReturnChannel<R> {
    pub fn ret(self, ret: R) -> Result<(), mpsc::error::TrySendError<R>> {
        // should not panic
        self.tx.try_send(ret)
    }
}
