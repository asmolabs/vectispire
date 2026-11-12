//! Token buckets with Bucket4j's semantics, which the chain's three limiters and the per-key budget share.
//!
//! **Why not `governor`.** The plan names it, and it does the arithmetic: a greedy refill of `capacity` tokens over
//! `window`. What it cannot do is what the bearer limiter needs — *read* a bucket without consuming and *not create
//! one* for an address that never failed — nor give the nanoseconds until one token is back, which the 429's
//! `Retry-After` is computed from. A bucket here is a few lines of integer arithmetic, and a test pins it
//! against the figures Bucket4j gives.
//!
//! Tokens are counted in units of `window / capacity` nanoseconds, so the refill is exact in integers: no
//! floating point, no drift. The map is bounded: past `max_entries` the least recently used bucket is dropped, the
//! `LinkedHashMap(accessOrder)` the Java filters use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Where "now" comes from — a clock a test moves by hand.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn nanos(&self) -> u128;
}

#[derive(Debug)]
pub struct SystemClock(Instant);

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> SystemClock {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn nanos(&self) -> u128 {
        self.0.elapsed().as_nanos()
    }
}

/// What a bucket said about one attempt to take a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consumption {
    pub consumed: bool,
    pub remaining_tokens: u64,
    /// How long until one token is back; zero when this one was taken.
    pub wait: Duration,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    /// Tokens × `window` nanoseconds: one token is `window` units, a nanosecond adds `capacity` units.
    units: u128,
    refilled_at: u128,
    used_at: u64,
}

/// A bounded map of buckets, one per key, each `capacity` tokens refilled greedily over `window`.
#[derive(Debug)]
pub struct Buckets {
    capacity: u64,
    window_nanos: u128,
    max_entries: usize,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    map: HashMap<String, Bucket>,
    tick: u64,
}

impl Buckets {
    pub fn new(capacity: u64, window: Duration, max_entries: usize, clock: Arc<dyn Clock>) -> Buckets {
        Buckets {
            capacity: capacity.max(1),
            window_nanos: window.as_nanos().max(1),
            max_entries,
            clock,
            state: Mutex::new(State::default()),
        }
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    fn full(&self) -> u128 {
        u128::from(self.capacity).saturating_mul(self.window_nanos)
    }

    fn refill(&self, bucket: &mut Bucket, now: u128) {
        let elapsed = now.saturating_sub(bucket.refilled_at);
        bucket.units = bucket.units.saturating_add(elapsed.saturating_mul(u128::from(self.capacity))).min(self.full());
        bucket.refilled_at = now;
    }

    fn wait_for_one(&self, bucket: &Bucket) -> Duration {
        if bucket.units >= self.window_nanos {
            return Duration::ZERO;
        }
        let missing = self.window_nanos.saturating_sub(bucket.units);
        let nanos = missing.div_ceil(u128::from(self.capacity));
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    fn tokens(&self, bucket: &Bucket) -> u64 {
        u64::try_from(bucket.units.checked_div(self.window_nanos).unwrap_or(0)).unwrap_or(u64::MAX)
    }

    /// `computeIfAbsent(key).tryConsumeAndReturnRemaining(1)`: creates the bucket full, takes a token if one is there.
    pub fn consume(&self, key: &str) -> Consumption {
        let now = self.clock.nanos();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.tick = state.tick.saturating_add(1);
        let tick = state.tick;
        let full = self.full();
        let bucket = state.map.entry(key.to_owned()).or_insert(Bucket { units: full, refilled_at: now, used_at: tick });
        bucket.used_at = tick;
        let mut copy = *bucket;
        self.refill(&mut copy, now);
        let consumed = copy.units >= self.window_nanos;
        if consumed {
            copy.units = copy.units.saturating_sub(self.window_nanos);
        }
        *bucket = copy;
        let result = Consumption {
            consumed,
            remaining_tokens: self.tokens(&copy),
            wait: if consumed { Duration::ZERO } else { self.wait_for_one(&copy) },
        };
        self.evict(&mut state);
        result
    }

    /// Whole tokens left in the bucket of `key`, **without creating it**; `None` when the key has never been seen.
    pub fn available(&self, key: &str) -> Option<u64> {
        let now = self.clock.nanos();
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut bucket = *state.map.get(key)?;
        self.refill(&mut bucket, now);
        Some(self.tokens(&bucket))
    }

    /// How long until a token is back in the bucket of `key`; zero for a key never seen or a bucket with one.
    pub fn wait(&self, key: &str) -> Duration {
        let now = self.clock.nanos();
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match state.map.get(key) {
            Some(bucket) => {
                let mut bucket = *bucket;
                self.refill(&mut bucket, now);
                self.wait_for_one(&bucket)
            }
            None => Duration::ZERO,
        }
    }

    /// Forgets every bucket — the `reset()` the Java filters give their tests.
    pub fn clear(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).map.clear();
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn evict(&self, state: &mut State) {
        while state.map.len() > self.max_entries {
            let oldest = state.map.iter().min_by_key(|(_, bucket)| bucket.used_at).map(|(key, _)| key.clone());
            match oldest {
                Some(key) => {
                    state.map.remove(&key);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock that moves only when told to.
    #[derive(Debug, Default)]
    pub struct ManualClock(AtomicU64);

    impl ManualClock {
        pub fn advance(&self, by: Duration) {
            self.0.fetch_add(u64::try_from(by.as_nanos()).unwrap_or(u64::MAX), Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn nanos(&self) -> u128 {
            u128::from(self.0.load(Ordering::SeqCst))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::ManualClock;
    use super::*;

    fn buckets(capacity: u64, window: Duration, max: usize) -> (Buckets, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        (Buckets::new(capacity, window, max, clock.clone()), clock)
    }

    #[test]
    fn a_bucket_starts_full_and_refuses_the_attempt_after_its_capacity() {
        let (limit, _) = buckets(10, Duration::from_secs(60), 100);
        for spent in 1..=10 {
            let taken = limit.consume("a");
            assert!(taken.consumed, "attempt {spent}");
            assert_eq!(taken.remaining_tokens, 10 - spent);
        }
        let refused = limit.consume("a");
        assert!(!refused.consumed);
        // One token is back after window / capacity: six seconds.
        assert_eq!(refused.wait, Duration::from_secs(6));
    }

    #[test]
    fn the_refill_is_greedy_not_in_one_step() {
        let (limit, clock) = buckets(10, Duration::from_secs(60), 100);
        for _ in 0..10 {
            limit.consume("a");
        }
        clock.advance(Duration::from_secs(6));
        assert!(limit.consume("a").consumed);
        assert!(!limit.consume("a").consumed);
        clock.advance(Duration::from_secs(60));
        assert_eq!(limit.available("a"), Some(10), "never above capacity");
    }

    #[test]
    fn reading_never_creates_a_bucket() {
        let (limit, _) = buckets(60, Duration::from_secs(300), 100);
        assert_eq!(limit.available("x"), None);
        assert_eq!(limit.wait("x"), Duration::ZERO);
        assert!(limit.is_empty());
    }

    #[test]
    fn the_wait_is_the_time_until_one_token_is_back() {
        let (limit, clock) = buckets(60, Duration::from_secs(300), 100);
        for _ in 0..60 {
            limit.consume("x");
        }
        assert_eq!(limit.available("x"), Some(0));
        assert_eq!(limit.wait("x"), Duration::from_secs(5));
        clock.advance(Duration::from_secs(2));
        assert_eq!(limit.wait("x"), Duration::from_secs(3));
    }

    #[test]
    fn the_least_recently_used_bucket_is_the_one_dropped() {
        let (limit, _) = buckets(2, Duration::from_secs(60), 2);
        limit.consume("a");
        limit.consume("b");
        limit.consume("a"); // a is now the more recent
        limit.consume("c"); // b is dropped
        assert_eq!(limit.len(), 2);
        assert_eq!(limit.available("b"), None);
        assert!(limit.available("a").is_some() && limit.available("c").is_some());
    }

    #[test]
    fn clearing_forgets_every_key() {
        let (limit, _) = buckets(1, Duration::from_secs(60), 10);
        limit.consume("a");
        limit.clear();
        assert!(limit.is_empty());
        assert!(limit.consume("a").consumed);
    }
}
