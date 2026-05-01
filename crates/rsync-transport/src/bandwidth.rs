use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthLimit {
    pub bytes_per_second: u64,
}

impl BandwidthLimit {
    pub fn new(bytes_per_second: u64) -> Self {
        Self { bytes_per_second }
    }
}

#[derive(Debug)]
pub struct BandwidthLimiter {
    limit: BandwidthLimit,
    started: Instant,
    transferred: u64,
}

impl BandwidthLimiter {
    pub fn new(limit: BandwidthLimit, started: Instant) -> Self {
        Self {
            limit,
            started,
            transferred: 0,
        }
    }

    fn delay_after_transfer(&mut self, bytes: u64, now: Instant) -> Duration {
        self.transferred = self.transferred.saturating_add(bytes);
        let target = Duration::from_secs_f64(
            self.transferred as f64 / self.limit.bytes_per_second.max(1) as f64,
        );
        target.saturating_sub(now.saturating_duration_since(self.started))
    }

    pub fn delay_after_write(&mut self, bytes: u64, now: Instant) -> Duration {
        self.delay_after_transfer(bytes, now)
    }

    pub fn delay_after_read(&mut self, bytes: u64, now: Instant) -> Duration {
        self.delay_after_transfer(bytes, now)
    }

    pub fn throttle(&mut self, bytes: u64) {
        let delay = self.delay_after_transfer(bytes, Instant::now());
        if delay > Duration::ZERO {
            std::thread::sleep(delay);
        }
    }
}

#[derive(Debug)]
pub struct BandwidthLimitedStream<S> {
    inner: S,
    limiter: BandwidthLimiter,
}

impl<S> BandwidthLimitedStream<S> {
    pub fn new(inner: S, limit: BandwidthLimit) -> Self {
        Self {
            inner,
            limiter: BandwidthLimiter::new(limit, Instant::now()),
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Read> Read for BandwidthLimitedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.limiter.throttle(read as u64);
        Ok(read)
    }
}

impl<S: Write> Write for BandwidthLimitedStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.limiter.throttle(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_limit_parses_default_kb() {
        let limit = BandwidthLimit::new(128 * 1024);
        assert_eq!(limit.bytes_per_second, 128 * 1024);
    }

    #[test]
    fn bandwidth_limit_parses_mb() {
        let limit = BandwidthLimit::new(2 * 1024 * 1024);
        assert_eq!(limit.bytes_per_second, 2 * 1024 * 1024);
    }

    #[test]
    fn limiter_computes_delay() {
        let limit = BandwidthLimit::new(1024);
        let started = Instant::now();
        let mut limiter = BandwidthLimiter::new(limit, started);

        // Write 1024 bytes: should take 1 second
        let delay = limiter.delay_after_write(1024, started + Duration::from_millis(0));
        assert!(delay >= Duration::from_millis(900));
    }

    #[test]
    fn limiter_no_delay_when_idle() {
        let limit = BandwidthLimit::new(1024);
        let started = Instant::now();
        let mut limiter = BandwidthLimiter::new(limit, started);

        // Write 512 bytes over 1 second: no delay needed
        let delay = limiter.delay_after_write(512, started + Duration::from_secs(1));
        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn limiter_computes_read_delay() {
        let limit = BandwidthLimit::new(1024);
        let started = Instant::now();
        let mut limiter = BandwidthLimiter::new(limit, started);

        let delay = limiter.delay_after_read(1024, started);

        assert!(delay >= Duration::from_millis(900));
    }
}
