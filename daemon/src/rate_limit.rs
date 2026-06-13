//! Token-bucket rate limiter for `/sub/<token>` (Phase Track-2).
//!
//! Why this exists
//! ---------------
//! Phase Track-1 + Plan B back-pressure already protect the daemon
//! from OOM under flood: the bounded mpsc channel drops access-log
//! rows when full. But the HTTP handler still does the work — token
//! resolution, sing-box config rendering, response serialization —
//! for every request, regardless of how many. An attacker holding
//! one valid token can still saturate CPU and bandwidth.
//!
//! This module rejects abusive traffic at the door with HTTP 429 +
//! `Retry-After`, BEFORE the daemon spends meaningful work on the
//! request. Two independent buckets per request:
//!
//!   * **per-IP**: protects against one attacker hitting many tokens
//!     (or unknown-token probing).
//!   * **per-token**: protects against many attackers hitting one
//!     leaked subscription URL (the URL-shared scenario Track-1 was
//!     built to detect — Track-2 actively throttles it).
//!
//! Both buckets must allow the request for it to proceed. The first
//! one to deny chooses the `Retry-After` value.
//!
//! Capacities
//! ----------
//! Defaults are conservative for a homelab Hiddify deployment: a
//! legitimate client refetches `/sub` once per day at most. The
//! defaults give a 5-request burst then 1 token every 30 seconds —
//! roughly 120 requests/hour absolute max per (IP, token). Way more
//! than legit, way less than DoS-useful.
//!
//! Lifecycle
//! ---------
//! `RateLimiter` owns two `Mutex<HashMap>`s. `Arc<RateLimiter>`
//! sits in `AppState` so handlers can `try_acquire_ip` /
//! `try_acquire_token`. A periodic cleanup task in `app::build()`
//! drops bucket entries that haven't been touched in over an hour
//! (otherwise the per-IP map grows unbounded over time).
//!
//! Storage trade-offs
//! ------------------
//! In-memory only — restart resets every bucket. Persistent
//! auto-bans (after K consecutive 429s, ban for 24h, stored in
//! inventory) is Track-2 chunk 2; this chunk is the foundation.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default capacity (max burst). 5 requests in immediate succession
/// before throttling kicks in. A Hiddify client doing two refetches
/// in a profile-reload click won't trip this; a tight curl loop will.
pub const DEFAULT_BUCKET_CAPACITY: f64 = 5.0;

/// Default refill rate in tokens-per-second. 1/30 = one token every
/// 30 seconds. Combined with capacity 5 → 120 req/hour absolute max.
pub const DEFAULT_REFILL_PER_SEC: f64 = 1.0 / 30.0;

/// How long an idle bucket survives in the map before cleanup drops
/// it. 1 hour is a balance: long enough that a returning client
/// doesn't get a fresh full bucket every time, short enough that
/// the per-IP map can't grow without bound from one-shot probes.
pub const DEFAULT_BUCKET_IDLE_TTL: Duration = Duration::from_secs(3600);

/// Phase Track-2 chunk 2: how many consecutive 429s for the same
/// (axis, key) trip a persistent ban. 10 is conservative — a normal
/// client trying to refresh past the bucket cap would have to be
/// hammering the URL deliberately to reach this. The ban TTL is
/// `DEFAULT_BAN_TTL_SECS`.
pub const K_DENIALS_TO_BAN: u32 = 10;

/// 24 hours in seconds. Default ban TTL when the handler escalates
/// after `K_DENIALS_TO_BAN` consecutive 429s. Long enough to be a
/// real penalty; short enough that a misconfigured legit client
/// recovers within a day without admin intervention.
pub const DEFAULT_BAN_TTL_SECS: u64 = 24 * 3600;

/// Single token bucket. Refills lazily on each `try_consume` based
/// on wall-clock time elapsed since the last refill.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    /// Current token count. Floating-point so partial refill is
    /// continuous rather than quantised — a 0.5-second elapsed
    /// adds 0.5/30 = 0.0166 tokens, accumulated correctly across
    /// many small intervals.
    tokens: f64,
    /// Wall-clock time of the most recent `tokens` update — refill
    /// math is `(now - last_refill) * refill_rate`.
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Catch up tokens based on time elapsed since `last_refill`,
    /// capped at `capacity`. Always updates `last_refill` to now.
    fn refill(&mut self, capacity: f64, refill_per_sec: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last_refill = now;
    }

    /// Try to consume 1 token. Returns `true` on success, `false`
    /// if the bucket is empty (caller should produce a 429).
    fn try_consume(&mut self, capacity: f64, refill_per_sec: f64) -> bool {
        self.refill(capacity, refill_per_sec);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Seconds the caller should wait before retrying — the deficit
    /// (1.0 minus current tokens) divided by the refill rate, ceiled
    /// to whole seconds. Always at least 1 (we never tell a client
    /// "retry in 0 seconds" — that just produces a tight loop).
    fn seconds_until_one_token(&self, refill_per_sec: f64) -> u64 {
        if self.tokens >= 1.0 {
            return 1;
        }
        let deficit = 1.0 - self.tokens;
        let secs = (deficit / refill_per_sec).ceil();
        // Clamp into u64 conservatively (can't be negative, but the
        // f64 → u64 cast saturates on overflow which is fine).
        let secs_u64 = secs.max(1.0) as u64;
        secs_u64.max(1)
    }
}

/// Two-axis rate limiter: one bucket per source IP, one per token.
/// Both buckets must allow the request for it to proceed; the first
/// to deny picks the `Retry-After`.
///
/// Tracks consecutive denials per axis (Phase Track-2 chunk 2) so the
/// `/sub` handler can escalate to a persistent ban after `K` 429s in
/// a row. The counter resets on a successful acquire — a single legit
/// request clears the escalation. Counters live alongside the buckets
/// in their own `Mutex<HashMap>` (cheap, same shape).
#[derive(Debug)]
pub struct RateLimiter {
    by_ip: Mutex<HashMap<IpAddr, TokenBucket>>,
    by_token: Mutex<HashMap<String, TokenBucket>>,
    /// Consecutive-denial counters — number of `try_acquire_ip` calls
    /// in a row that returned `Err` since the last `Ok`. Reset to 0
    /// when a request succeeds.
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

    /// Try to acquire one token from the per-IP bucket. Returns
    /// `Ok(())` on success (and resets the consecutive-denial
    /// counter for this IP) or `Err((retry_after_seconds,
    /// consecutive_denial_count))` on throttle. The handler uses the
    /// denial count to decide whether to escalate to a persistent
    /// ban after K consecutive 429s.
    pub fn try_acquire_ip(&self, ip: IpAddr) -> Result<(), (u64, u32)> {
        let mut map = self
            .by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = map
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.capacity));
        if bucket.try_consume(self.capacity, self.refill_per_sec) {
            // Success path: drop the lock first so the counter map
            // doesn't need both held simultaneously.
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

    /// Try to acquire one token from the per-token bucket. Same
    /// semantics as `try_acquire_ip` — see that method's doc.
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

    /// Reset the consecutive-denial counter for a key after the
    /// handler escalates to a persistent ban. Without this, the
    /// counter would keep climbing past K and the handler would keep
    /// trying to (re-)write a ban row each subsequent 429.
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

    /// Clamp the consecutive-denial counter for `ip` down to
    /// `K_DENIALS_TO_BAN - 1`. Called by the `/sub` handler when a ban
    /// escalation at the `== K` crossing FAILED to write (`add_ban`
    /// errored transiently). Without this the counter would already be
    /// at `K` (the failing `try_acquire_ip` set it there), so the next
    /// denial increments to `K + 1`, `K + 1 == K` is false, and the ban
    /// is never retried until the counter happens to reset on a
    /// successful acquire. Clamping back to `K - 1` makes the NEXT
    /// denial land on `== K` again and re-attempt the escalation.
    ///
    /// Why `K - 1` and not `K`: the escalation gate is `== K` (a
    /// deliberate choice — see the `sub.rs` comment — to avoid a
    /// parallel-request duplicate-ban race). Leaving the counter at `K`
    /// would make the next denial overshoot to `K + 1`. Setting it to
    /// `K - 1` reproduces the exact pre-crossing state so the retry hits
    /// `== K` cleanly without weakening the race-fix. If the key is
    /// absent (counter already reset by a concurrent success), this is a
    /// no-op — we never resurrect a counter that isn't there.
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

    /// Per-token mirror of [`clamp_denials_ip`]. See that method's doc
    /// for the full rationale (transient `add_ban` failure recovery
    /// without breaking the `== K` race-fix).
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

    /// Drop bucket entries that haven't been touched in `idle_ttl`.
    /// Called periodically by the cleanup task in `app::build()`.
    /// Returns `(ip_dropped, token_dropped)` for telemetry.
    ///
    /// Also drops the corresponding denial-counter entries — they
    /// piggyback on the bucket's idle TTL because both indicate
    /// "this key hasn't been seen in a while". An orphaned denial
    /// counter without its bucket would never reset the next time
    /// the key reappeared.
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
        // Snapshot live keys before releasing the bucket map's lock.
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

    /// Test-only helper: count of live buckets in each map.
    /// `pub` so tests in other crates can sanity-check sizing, but
    /// production code shouldn't depend on internal cardinality.
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
        // Refill rate of 0 so no time-based replenishment can rescue us.
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
        // Drain to 0.
        assert!(b.try_consume(2.0, 0.0));
        assert!(b.try_consume(2.0, 0.0));
        // Backdate last_refill by an hour and refill at 1/sec —
        // would naively add 3600 tokens, but capacity=2 caps it.
        b.last_refill = Instant::now() - Duration::from_secs(3600);
        b.refill(2.0, 1.0);
        assert!((b.tokens - 2.0).abs() < 1e-6);
    }

    #[test]
    fn seconds_until_one_token_is_at_least_one() {
        let mut b = TokenBucket::new(1.0);
        b.try_consume(1.0, 1.0); // drain
        // Empty bucket, 1 token/sec refill → ~1 second to recover.
        let s = b.seconds_until_one_token(1.0);
        assert!((1..=2).contains(&s), "expected 1-2 sec, got {s}");
    }

    #[test]
    fn limiter_separate_ips_dont_share_quota() {
        let lim = RateLimiter::new(2.0, 0.0, Duration::from_secs(60));
        let ip_a: IpAddr = "1.1.1.1".parse().unwrap();
        let ip_b: IpAddr = "2.2.2.2".parse().unwrap();
        // A drains its quota (2 requests).
        assert!(lim.try_acquire_ip(ip_a).is_ok());
        assert!(lim.try_acquire_ip(ip_a).is_ok());
        assert!(lim.try_acquire_ip(ip_a).is_err(), "A's third must throttle");
        // B has its own quota — independent.
        assert!(lim.try_acquire_ip(ip_b).is_ok());
        assert!(lim.try_acquire_ip(ip_b).is_ok());
        assert!(lim.try_acquire_ip(ip_b).is_err());
    }

    #[test]
    fn limiter_per_ip_and_per_token_are_independent_axes() {
        let lim = RateLimiter::new(2.0, 0.0, Duration::from_secs(60));
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        // Drain per-IP quota.
        assert!(lim.try_acquire_ip(ip).is_ok());
        assert!(lim.try_acquire_ip(ip).is_ok());
        assert!(lim.try_acquire_ip(ip).is_err());
        // Per-token bucket is fresh — independent axis.
        assert!(lim.try_acquire_token("tok-A").is_ok());
        assert!(lim.try_acquire_token("tok-A").is_ok());
        assert!(lim.try_acquire_token("tok-A").is_err());
        // Different token starts at full capacity.
        assert!(lim.try_acquire_token("tok-B").is_ok());
    }

    #[test]
    fn cleanup_drops_idle_buckets() {
        let lim = RateLimiter::new(5.0, 0.1, Duration::from_millis(50));
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        // Touch the bucket.
        assert!(lim.try_acquire_ip(ip).is_ok());
        assert_eq!(lim.sizes(), (1, 0), "one IP bucket created");
        // Wait past the TTL.
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

    /// C3 regression guard. Drive the per-token denial counter up to
    /// exactly `K`, then simulate a transient `add_ban` failure by
    /// clamping the counter (what the handler now does on `add_ban`
    /// error instead of leaving it at `K`). The NEXT denial must land
    /// back on `== K` so the handler re-attempts the escalation —
    /// rather than overshooting to `K + 1` and skipping the ban
    /// forever until the counter resets.
    #[test]
    fn clamp_denials_token_makes_next_denial_rehit_k() {
        // capacity=1, refill=0 → first acquire succeeds, every later
        // acquire denies and bumps the counter by 1.
        let lim = RateLimiter::new(1.0, 0.0, Duration::from_secs(60));
        let tok = "leaked-url";
        // Burn the single token.
        assert!(lim.try_acquire_token(tok).is_ok());
        // Deny K times → counter reaches exactly K on the K-th denial.
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
        // Simulate add_ban failure: handler clamps to K-1 instead of
        // leaving the counter at K.
        lim.clamp_denials_token(tok);
        // The very next denial must re-hit == K (NOT K+1) so the
        // escalation is retried.
        match lim.try_acquire_token(tok) {
            Err((_, count)) => assert_eq!(
                count, K_DENIALS_TO_BAN,
                "after clamp, the next denial must land on == K to retry the ban, got {count}"
            ),
            Ok(()) => panic!("token bucket should still be empty"),
        }
    }

    /// Symmetric guard for the IP axis — same C3 recovery contract.
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

    /// Clamping a key that has no counter entry (already reset by a
    /// concurrent successful acquire) is a no-op — it must not create
    /// a phantom counter that would later mis-trigger an escalation.
    #[test]
    fn clamp_denials_on_absent_key_is_noop() {
        let lim = RateLimiter::new(1.0, 0.0, Duration::from_secs(60));
        lim.clamp_denials_token("never-seen");
        // A fresh acquire on a full bucket succeeds and would have
        // removed any counter; assert no spurious denial state leaked
        // in by acquiring twice — first ok, second denies at count 1
        // (not K-1+1).
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
        // Capacity 1, refill 100/sec → after 50ms, ~5 tokens fill.
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
