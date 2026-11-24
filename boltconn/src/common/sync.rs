use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::runtime::Runtime;

/// Runs `future` on a dedicated thread with its own current-thread runtime.
///
/// The runtime is built before the thread starts, so failures such as fd exhaustion are
/// returned to the caller instead of silently dropping `future`.
pub fn local_async_run<F>(
    name: Option<String>,
    future: F,
) -> io::Result<std::thread::JoinHandle<F::Output>>
where
    F: Future + Send + 'static,
    <F as Future>::Output: Send,
{
    let local_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .inspect_err(|e| {
            tracing::error!(
                "Failed to start single thread runtime: {} for {:?}",
                e,
                name
            );
        })?;
    let local_rt = LocalRuntime(Some(local_rt));
    let mut builder = std::thread::Builder::new();
    if let Some(name) = name.clone() {
        builder = builder.name(format!("bc-{}", name));
    }
    builder
        .spawn(move || local_rt.block_on(future))
        .inspect_err(|e| {
            tracing::error!("Failed to spawn thread: {} for {:?}", e, name);
        })
}

/// Dropping a runtime inside an async context panics. If the thread fails to spawn, the
/// closure owning this runtime is dropped on the caller, so shut it down in the background.
struct LocalRuntime(Option<Runtime>);

impl LocalRuntime {
    fn block_on<F: Future>(mut self, future: F) -> F::Output {
        let runtime = self.0.take().expect("runtime is present until block_on");
        runtime.block_on(future)
    }
}

impl Drop for LocalRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unspawned_local_runtime_can_be_dropped_in_async_context() {
        // Mirrors a failed thread spawn, which drops the runtime on the async caller.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        drop(LocalRuntime(Some(runtime)));
    }
}
