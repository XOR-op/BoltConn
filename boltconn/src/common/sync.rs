use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn local_async_run<F>(
    name: Option<String>,
    future: F,
) -> Option<std::thread::JoinHandle<Option<F::Output>>>
where
    F: Future + Send + 'static,
    <F as Future>::Output: Send,
{
    let mut builder = std::thread::Builder::new();
    if let Some(name) = name.clone() {
        builder = builder.name(format!("bc-{}", name));
    }
    builder
        .spawn(|| {
            let Ok(local_rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                tracing::error!("Failed to start single thread runtime");
                return None;
            };
            Some(local_rt.block_on(future))
        })
        .inspect_err(|e| {
            tracing::error!("Failed to spawn thread: {} for {:?}", e, name);
        })
        .ok()
}

#[derive(Clone, Debug)]
pub struct AbortCanary(Arc<AtomicBool>);

impl Default for AbortCanary {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl AbortCanary {
    pub fn pair() -> (Self, Self) {
        let one = Self::default();
        let two = one.clone();
        (one, two)
    }

    pub fn alive(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub fn abort(&self) {
        self.0.store(false, Ordering::Relaxed)
    }
}
