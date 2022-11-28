use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default, Debug)]
pub struct IdGenerator(AtomicU64);

impl IdGenerator {
    pub fn get(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}
