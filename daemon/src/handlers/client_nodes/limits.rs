use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::rate_limit::RateLimiter;

const MAX_IP_BUCKETS: usize = 4096;
const MAX_CREDENTIAL_BUCKETS: usize = 4096;
const WINDOW: Duration = Duration::from_secs(60);
const IDLE_TTL: Duration = Duration::from_secs(3600);

struct Bucket {
    owner: Weak<RateLimiter>,
    used: u32,
    started: Instant,
    touched: Instant,
}

#[derive(Default)]
struct PollLimits {
    anonymous_ips: HashMap<(usize, [u8; 32]), Bucket>,
    credentials: HashMap<(usize, [u8; 32]), Bucket>,
}

impl PollLimits {
    fn acquire(
        &mut self,
        owner: &Arc<RateLimiter>,
        namespace: &[u8],
        key: [u8; 32],
        capacity: u32,
    ) -> Result<(), u64> {
        let now = Instant::now();
        let anonymous = namespace == b"nodes:ip";
        let (buckets, max_buckets) = if anonymous {
            (&mut self.anonymous_ips, MAX_IP_BUCKETS)
        } else {
            (&mut self.credentials, MAX_CREDENTIAL_BUCKETS)
        };
        buckets.retain(|_, bucket| {
            bucket.owner.strong_count() > 0
                && if anonymous {
                    now.duration_since(bucket.started) < WINDOW
                } else {
                    now.duration_since(bucket.touched) < IDLE_TTL
                }
        });
        let key = (Arc::as_ptr(owner) as usize, key);
        if buckets.len() >= max_buckets && !buckets.contains_key(&key) {
            if !anonymous {
                return Err(WINDOW.as_secs());
            }
            // Anonymous churn cannot reserve credential capacity or deny a new
            // legitimate source IP. Expired windows were removed above; if all
            // remaining windows are active, replace the least recently used IP.
            if let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.touched)
                .map(|(key, _)| *key)
            {
                buckets.remove(&oldest);
            }
        }
        let bucket = buckets.entry(key).or_insert_with(|| Bucket {
            owner: Arc::downgrade(owner),
            used: 0,
            started: now,
            touched: now,
        });
        if now.duration_since(bucket.started) >= WINDOW {
            bucket.used = 0;
            bucket.started = now;
        }
        bucket.touched = now;
        if bucket.used < capacity {
            bucket.used += 1;
            Ok(())
        } else {
            Err(WINDOW
                .as_secs()
                .saturating_sub(now.duration_since(bucket.started).as_secs())
                .max(1))
        }
    }
}

pub(super) fn acquire(
    owner: &Arc<RateLimiter>,
    namespace: &[u8],
    identity: &str,
    capacity: u32,
) -> Result<(), u64> {
    static LIMITS: OnceLock<Mutex<PollLimits>> = OnceLock::new();
    let mut digest = Sha256::new();
    digest.update(namespace);
    digest.update([0]);
    digest.update(identity.as_bytes());
    LIMITS
        .get_or_init(|| Mutex::new(PollLimits::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .acquire(owner, namespace, digest.finalize().into(), capacity)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn polling_is_bounded_and_dead_app_buckets_are_reclaimed() {
        let owner = Arc::new(RateLimiter::default());
        let mut limits = PollLimits::default();
        for i in 0..MAX_CREDENTIAL_BUCKETS {
            let key = Sha256::digest(i.to_le_bytes()).into();
            assert!(limits.acquire(&owner, b"nodes:device", key, 60).is_ok());
        }
        assert!(
            limits
                .acquire(&owner, b"nodes:device", Sha256::digest(b"new").into(), 60)
                .is_err()
        );
        assert_eq!(limits.credentials.len(), MAX_CREDENTIAL_BUCKETS);
        drop(owner);
        let next = Arc::new(RateLimiter::default());
        assert!(limits.acquire(&next, b"nodes:device", [0; 32], 60).is_ok());
        assert_eq!(limits.credentials.len(), 1);
    }

    #[test]
    fn polling_throttles_without_consuming_render_quota() {
        let owner = Arc::new(RateLimiter::default());
        let mut limits = PollLimits::default();
        for _ in 0..60 {
            assert!(limits.acquire(&owner, b"nodes:device", [1; 32], 60).is_ok());
        }
        assert!(matches!(
            limits.acquire(&owner, b"nodes:device", [1; 32], 60),
            Err(1..=60)
        ));
        assert!(limits.acquire(&owner, b"nodes:device", [2; 32], 60).is_ok());
        assert_eq!(owner.sizes(), (0, 0));
        assert!(owner.try_acquire_token("synthetic-render-token").is_ok());
    }

    #[test]
    fn a_completed_window_restores_the_identity_budget() {
        let owner = Arc::new(RateLimiter::default());
        let mut limits = PollLimits::default();
        assert!(limits.acquire(&owner, b"nodes:device", [1; 32], 1).is_ok());
        assert!(limits.acquire(&owner, b"nodes:device", [1; 32], 1).is_err());
        for bucket in limits.credentials.values_mut() {
            bucket.started = Instant::now() - WINDOW;
        }
        assert!(limits.acquire(&owner, b"nodes:device", [1; 32], 1).is_ok());
    }

    #[test]
    fn anonymous_ip_saturation_preserves_new_authenticated_polling() {
        let owner = Arc::new(RateLimiter::default());
        let mut limits = PollLimits::default();
        for i in 0..MAX_IP_BUCKETS {
            let key = Sha256::digest(i.to_le_bytes()).into();
            assert!(limits.acquire(&owner, b"nodes:ip", key, 600).is_ok());
        }
        assert_eq!(limits.anonymous_ips.len(), MAX_IP_BUCKETS);
        assert!(limits.credentials.is_empty());
        let legitimate_ip = Sha256::digest(b"legitimate-source").into();
        assert!(
            limits
                .acquire(&owner, b"nodes:ip", legitimate_ip, 600)
                .is_ok()
        );
        for _ in 0..60 {
            assert!(limits.acquire(&owner, b"nodes:device", [7; 32], 60).is_ok());
        }
        assert!(
            limits
                .acquire(&owner, b"nodes:device", [7; 32], 60)
                .is_err()
        );
        assert_eq!(limits.anonymous_ips.len(), MAX_IP_BUCKETS);
        assert_eq!(limits.credentials.len(), 1);
    }

    #[test]
    fn anonymous_ip_windows_are_reclaimed_when_their_budget_resets() {
        let owner = Arc::new(RateLimiter::default());
        let mut limits = PollLimits::default();
        assert!(limits.acquire(&owner, b"nodes:ip", [1; 32], 600).is_ok());
        for bucket in limits.anonymous_ips.values_mut() {
            bucket.started = Instant::now() - WINDOW;
        }
        assert!(limits.acquire(&owner, b"nodes:ip", [2; 32], 600).is_ok());
        assert_eq!(limits.anonymous_ips.len(), 1);
        assert!(
            limits
                .anonymous_ips
                .contains_key(&(Arc::as_ptr(&owner) as usize, [2; 32]))
        );
    }

    #[test]
    fn a_tracked_ip_keeps_its_six_hundred_request_budget() {
        let owner = Arc::new(RateLimiter::default());
        let mut limits = PollLimits::default();
        for _ in 0..600 {
            assert!(limits.acquire(&owner, b"nodes:ip", [3; 32], 600).is_ok());
        }
        assert!(matches!(
            limits.acquire(&owner, b"nodes:ip", [3; 32], 600),
            Err(1..=60)
        ));
    }
}
