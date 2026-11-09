//! Process-wide request-rate limiting.

use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    requests_per_second: f64,
    capacity: f64,
    bucket: Mutex<Bucket>,
}

impl RateLimiter {
    pub fn new(requests_per_second: u64, burst: u64) -> Self {
        Self {
            requests_per_second: requests_per_second as f64,
            capacity: burst as f64,
            bucket: Mutex::new(Bucket {
                tokens: burst as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    pub fn try_acquire(&self) -> bool {
        let now = Instant::now();
        let Ok(mut bucket) = self.bucket.lock() else {
            tracing::error!("rate limiter state is poisoned; rejecting request");
            return false;
        };

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.requests_per_second).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn limits_burst_then_refills() {
        let limiter = RateLimiter::new(100, 2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
        thread::sleep(Duration::from_millis(20));
        assert!(limiter.try_acquire());
    }
}
