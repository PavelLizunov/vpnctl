use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_BUCKET_CAPACITY: f64 = 5.0;

pub const DEFAULT_REFILL_PER_SEC: f64 = 1.0 / 30.0;

pub const DEFAULT_BUCKET_IDLE_TTL: Duration = Duration::from_secs(3600);

pub const K_DENIALS_TO_BAN: u32 = 10;

pub const DEFAULT_BAN_TTL_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, capacity: f64, refill_per_sec: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last_refill = now;
    }

    fn try_consume(&mut self, capacity: f64, refill_per_sec: f64) -> bool {
        self.refill(capacity, refill_per_sec);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn seconds_until_one_token(&self, refill_per_sec: f64) -> u64 {
        if self.tokens >= 1.0 {
            return 1;
        }
        let deficit = 1.0 - self.tokens;
        let secs = (deficit / refill_per_sec).ceil();
        let secs_u64 = secs.max(1.0) as u64;
        secs_u64.max(1)
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    by_ip: Mutex<HashMap<IpAddr, TokenBucket>>,
    by_token: Mutex<HashMap<String, TokenBucket>>,
    denials_by_ip: Mutex<HashMap<IpAddr, u32>>,
    denials_by_token: Mutex<HashMap<String, u32>>,
    capacity: f64,
    refill_per_sec: f64,
    idle_ttl: Duration,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(
            DEFAULT_BUCKET_CAPACITY,
            DEFAULT_REFILL_PER_SEC,
            DEFAULT_BUCKET_IDLE_TTL,
        )
    }
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64, idle_ttl: Duration) -> Self {
        Self {
            by_ip: Mutex::new(HashMap::new()),
            by_token: Mutex::new(HashMap::new()),
            denials_by_ip: Mutex::new(HashMap::new()),
            denials_by_token: Mutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
            idle_ttl,
        }
    }

    pub fn try_acquire_ip(&self, ip: IpAddr) -> Result<(), (u64, u32)> {
        let mut map = self
            .by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = map
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.capacity));
        if bucket.try_consume(self.capacity, self.refill_per_sec) {
            drop(map);
            self.denials_by_ip
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&ip);
            Ok(())
        } else {
            let retry = bucket.seconds_until_one_token(self.refill_per_sec);
            drop(map);
            let mut denials = self
                .denials_by_ip
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = denials.entry(ip).or_insert(0);
            *count = count.saturating_add(1);
            Err((retry, *count))
        }
    }

    pub fn try_acquire_token(&self, token: &str) -> Result<(), (u64, u32)> {
        let mut map = self
            .by_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = map
            .entry(token.to_owned())
            .or_insert_with(|| TokenBucket::new(self.capacity));
        if bucket.try_consume(self.capacity, self.refill_per_sec) {
            drop(map);
            self.denials_by_token
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(token);
            Ok(())
        } else {
            let retry = bucket.seconds_until_one_token(self.refill_per_sec);
            drop(map);
            let mut denials = self
                .denials_by_token
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = denials.entry(token.to_owned()).or_insert(0);
            *count = count.saturating_add(1);
            Err((retry, *count))
        }
    }

    pub fn reset_denials_ip(&self, ip: IpAddr) {
        self.denials_by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ip);
    }

    pub fn reset_denials_token(&self, token: &str) {
        self.denials_by_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(token);
    }

    pub fn clamp_denials_ip(&self, ip: IpAddr) {
        if let Some(count) = self
            .denials_by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&ip)
        {
            *count = K_DENIALS_TO_BAN.saturating_sub(1);
        }
    }

    pub fn clamp_denials_token(&self, token: &str) {
        if let Some(count) = self
            .denials_by_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(token)
        {
            *count = K_DENIALS_TO_BAN.saturating_sub(1);
        }
    }

    pub fn cleanup(&self) -> (usize, usize) {
        let now = Instant::now();
        let cutoff = now - self.idle_ttl;

        let mut ip_map = self
            .by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before_ip = ip_map.len();
        ip_map.retain(|_, b| b.last_refill > cutoff);
        let after_ip = ip_map.len();
        let live_ips: HashSet<IpAddr> = ip_map.keys().copied().collect();
        drop(ip_map);
        self.denials_by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|k, _| live_ips.contains(k));

        let mut token_map = self
            .by_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before_token = token_map.len();
        token_map.retain(|_, b| b.last_refill > cutoff);
        let after_token = token_map.len();
        let live_tokens: HashSet<String> = token_map.keys().cloned().collect();
        drop(token_map);
        self.denials_by_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|k, _| live_tokens.contains(k));

        (before_ip - after_ip, before_token - after_token)
    }

    pub fn sizes(&self) -> (usize, usize) {
        let ip_n = self
            .by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        let token_n = self
            .by_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        (ip_n, token_n)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bucket_new_starts_full() {
        let b = TokenBucket::new(5.0);
        assert!(b.tokens >= 5.0 - 1e-9);
    }

    #[test]
    fn try_consume_drains_then_denies() {
        let mut b = TokenBucket::new(3.0);
        assert!(b.try_consume(3.0, 0.0));
        assert!(b.try_consume(3.0, 0.0));
        assert!(b.try_consume(3.0, 0.0));
        assert!(
            !b.try_consume(3.0, 0.0),
            "4th consume must fail when capacity=3 and no refill"
        );
    }

    #[test]
    fn refill_caps_at_capacity() {
        let mut b = TokenBucket::new(2.0);
        assert!(b.try_consume(2.0, 0.0));
        assert!(b.try_consume(2.0, 0.0));
        b.last_refill = Instant::now() - Duration::from_secs(3600);
        b.refill(2.0, 1.0);
        assert!((b.tokens - 2.0).abs() < 1e-6);
    }

    #[test]
    fn seconds_until_one_token_is_at_least_one() {
        let mut b = TokenBucket::new(1.0);
        b.try_consume(1.0, 1.0);
        let s = b.seconds_until_one_token(1.0);
        assert!((1..=2).contains(&s), "expected 1-2 sec, got {s}");
    }

    #[test]
    fn limiter_separate_ips_dont_share_quota() {
        let lim = RateLimiter::new(2.0, 0.0, Duration::from_secs(60));
        let ip_a: IpAddr = "1.1.1.1".parse().unwrap();
        let ip_b: IpAddr = "2.2.2.2".parse().unwrap();
        assert!(lim.try_acquire_ip(ip_a).is_ok());
        assert!(lim.try_acquire_ip(ip_a).is_ok());
        assert!(lim.try_acquire_ip(ip_a).is_err(), "A's third must throttle");
        assert!(lim.try_acquire_ip(ip_b).is_ok());
        assert!(lim.try_acquire_ip(ip_b).is_ok());
        assert!(lim.try_acquire_ip(ip_b).is_err());
    }

    #[test]
    fn limiter_per_ip_and_per_token_are_independent_axes() {
        let lim = RateLimiter::new(2.0, 0.0, Duration::from_secs(60));
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(lim.try_acquire_ip(ip).is_ok());
        assert!(lim.try_acquire_ip(ip).is_ok());
        assert!(lim.try_acquire_ip(ip).is_err());
        assert!(lim.try_acquire_token("tok-A").is_ok());
        assert!(lim.try_acquire_token("tok-A").is_ok());
        assert!(lim.try_acquire_token("tok-A").is_err());
        assert!(lim.try_acquire_token("tok-B").is_ok());
    }

    #[test]
    fn cleanup_drops_idle_buckets() {
        let lim = RateLimiter::new(5.0, 0.1, Duration::from_millis(50));
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(lim.try_acquire_ip(ip).is_ok());
        assert_eq!(lim.sizes(), (1, 0), "one IP bucket created");
        std::thread::sleep(Duration::from_millis(60));
        let (dropped_ip, dropped_token) = lim.cleanup();
        assert_eq!(dropped_ip, 1, "idle IP bucket must be dropped");
        assert_eq!(dropped_token, 0, "no token buckets to drop");
        assert_eq!(lim.sizes(), (0, 0));
    }

    #[test]
    fn cleanup_keeps_recent_buckets() {
        let lim = RateLimiter::new(5.0, 0.1, Duration::from_secs(60));
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(lim.try_acquire_ip(ip).is_ok());
        let (dropped_ip, _) = lim.cleanup();
        assert_eq!(dropped_ip, 0, "fresh bucket inside TTL must not be dropped");
        assert_eq!(lim.sizes().0, 1);
    }

    #[test]
    fn clamp_denials_token_makes_next_denial_rehit_k() {
        let lim = RateLimiter::new(1.0, 0.0, Duration::from_secs(60));
        let tok = "leaked-url";
        assert!(lim.try_acquire_token(tok).is_ok());
        let mut last = 0;
        for _ in 0..K_DENIALS_TO_BAN {
            match lim.try_acquire_token(tok) {
                Err((_, count)) => last = count,
                Ok(()) => panic!("token bucket should be empty"),
            }
        }
        assert_eq!(
            last, K_DENIALS_TO_BAN,
            "counter should be K after K denials"
        );
        lim.clamp_denials_token(tok);
        match lim.try_acquire_token(tok) {
            Err((_, count)) => assert_eq!(
                count, K_DENIALS_TO_BAN,
                "after clamp, the next denial must land on == K to retry the ban, got {count}"
            ),
            Ok(()) => panic!("token bucket should still be empty"),
        }
    }

    #[test]
    fn clamp_denials_ip_makes_next_denial_rehit_k() {
        let lim = RateLimiter::new(1.0, 0.0, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(lim.try_acquire_ip(ip).is_ok());
        let mut last = 0;
        for _ in 0..K_DENIALS_TO_BAN {
            match lim.try_acquire_ip(ip) {
                Err((_, count)) => last = count,
                Ok(()) => panic!("ip bucket should be empty"),
            }
        }
        assert_eq!(last, K_DENIALS_TO_BAN);
        lim.clamp_denials_ip(ip);
        match lim.try_acquire_ip(ip) {
            Err((_, count)) => assert_eq!(
                count, K_DENIALS_TO_BAN,
                "after clamp, the next IP denial must re-hit == K, got {count}"
            ),
            Ok(()) => panic!("ip bucket should still be empty"),
        }
    }

    #[test]
    fn clamp_denials_on_absent_key_is_noop() {
        let lim = RateLimiter::new(1.0, 0.0, Duration::from_secs(60));
        lim.clamp_denials_token("never-seen");
        assert!(lim.try_acquire_token("never-seen").is_ok());
        match lim.try_acquire_token("never-seen") {
            Err((_, count)) => assert_eq!(
                count, 1,
                "absent-key clamp must not seed the counter; first denial should be 1, got {count}"
            ),
            Ok(()) => panic!("second acquire should deny"),
        }
    }

    #[tokio::test]
    async fn refill_is_time_based() {
        let lim = RateLimiter::new(1.0, 100.0, Duration::from_secs(60));
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        assert!(lim.try_acquire_ip(ip).is_ok());
        assert!(
            lim.try_acquire_ip(ip).is_err(),
            "second consume immediately fails"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            lim.try_acquire_ip(ip).is_ok(),
            "after 50ms with 100/sec refill, capacity caps at 1 but >= 1 token is available"
        );
    }
}
