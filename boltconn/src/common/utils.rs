use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Default, Debug)]
pub struct IdGenerator(AtomicU64);

impl IdGenerator {
    pub fn get(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

pub struct TputMeasurement {
    pub inner: std::sync::Mutex<TputMeasurementInner>,
}

pub struct TputMeasurementInner {
    pub accum_bytes: u64,
    pub last_time: Instant,
    pub interval: Duration,
}

impl TputMeasurement {
    pub fn new(interval: Duration) -> Self {
        Self {
            inner: std::sync::Mutex::new(TputMeasurementInner {
                accum_bytes: 0,
                last_time: Instant::now(),
                interval,
            }),
        }
    }

    pub fn update(&self, bytes: usize) -> Option<f64> {
        let mut inner = self.inner.lock().unwrap();
        inner.accum_bytes += bytes as u64;
        let now = Instant::now();
        let elapsed = now - inner.last_time;
        if elapsed >= inner.interval {
            let tput = inner.accum_bytes as f64 / elapsed.as_secs_f64();
            inner.accum_bytes = 0;
            inner.last_time = now;
            Some(tput)
        } else {
            None
        }
    }

    pub fn update_to_mbps(&self, bytes: usize) -> Option<f64> {
        self.update(bytes).map(|tput| tput * 8.0 / 1_000_000.0)
    }
}
