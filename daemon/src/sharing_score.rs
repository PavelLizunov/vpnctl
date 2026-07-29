//! Composite account-sharing risk scorer (2026-06-17, v2).
//!
//! Replaces the old single-threshold heuristic («`distinct_asns >= 3` over
//! the 30-day window») which fired on any traveller.
//!
//! v2 lesson (the multiviruss false positive): fetch-side and raw-IP signals
//! are NOISE. A single mobile phone rotates across a dozen carrier IPs in a
//! day (looked like "16 IPs"); a power user fetches `/sub` through proxies /
//! CDNs from several countries (looked like "impossible travel"); a tester
//! uses six client apps. None of that is sharing. So v2:
//!   - counts ISP-scale **NETWORKS**, not raw IPs (IPv4 `/16`, IPv6 `/64`),
//!   - makes **typical simultaneity** (P75 of daily connection-snapshot peaks)
//!     the dominant term — one stale connection cannot own a 30-day score,
//!   - keeps "distinct ISP-scale networks per day" as a secondary signal,
//!   - de-rates impossible-travel to a weak corroborator (only MANY hops),
//!   - DROPS fetch-side diversity (ASNs / countries / client-apps) from the
//!     score entirely — it lives on the user page as context, not as a
//!     risk driver.
//!
//! Two typical networks score below the flag on their own (one person with a
//! phone + a laptop online together is legitimate); 3+ typical simultaneous
//! networks, or 2 corroborated by many daily networks, is what flags.
//!
//! Pure (no I/O, no i18n) so it unit-tests trivially; the render translates
//! [`SharingReason`] labels.

use vpnctl_inventory::SharingSignals;

/// One contributing signal + the points it added. The render maps the
/// variant to a localized label and shows the carried value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingReason {
    /// 75th percentile of daily peak simultaneous ISP-scale networks.
    /// The dominant signal, robust to a few carrier hand-over outliers.
    TypicalConcurrentNets(u32),
    /// Most distinct ISP-scale networks connected from in any single day.
    DailyNets(u32),
    /// `/sub` country changes faster than physically possible (weak — only
    /// many hops score, since a few are proxy/CDN-fetch + geoip artefacts).
    ImpossibleTravel(u64),
}

impl SharingReason {
    /// Points this reason contributes to the 0-100 score.
    pub fn points(self) -> u8 {
        match self {
            // STRONGEST — simultaneous distinct access networks. 2 alone is
            // sub-flag (one person, two devices); 3+ is the real signal.
            SharingReason::TypicalConcurrentNets(n) => match n {
                0 | 1 => 0,
                2 => 25,
                3 => 45,
                _ => 65,
            },
            // Distinct access networks in a single day (carrier rotation
            // already collapsed to ISP-scale buckets).
            SharingReason::DailyNets(n) => match n {
                0..=3 => 0,
                4..=6 => 8,
                7..=10 => 18,
                _ => 28,
            },
            // De-rated: a handful of country hops is usually proxy/CDN
            // fetching or geoip flap, not two people abroad.
            SharingReason::ImpossibleTravel(h) => match h {
                0..=2 => 0,
                3 | 4 => 8,
                _ => 15,
            },
        }
    }
}

/// Risk band for colour / sort / "is it worth showing" decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SharingLevel {
    /// < `FLAG_THRESHOLD` — not surfaced as likely-shared.
    None,
    Low,
    Medium,
    High,
}

/// Minimum score to surface a user in the "likely-shared" list.
pub const FLAG_THRESHOLD: u8 = 35;

/// Composite result: capped score, band, and the contributing reasons
/// (only signals that scored > 0, highest-points first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingScore {
    pub score: u8,
    pub level: SharingLevel,
    pub reasons: Vec<SharingReason>,
}

impl SharingScore {
    /// True once the score reaches [`FLAG_THRESHOLD`].
    pub fn is_flagged(&self) -> bool {
        self.score >= FLAG_THRESHOLD
    }
}

/// Score one user's raw [`SharingSignals`] into a 0-100 composite.
pub fn score(s: &SharingSignals) -> SharingScore {
    let candidates = [
        SharingReason::TypicalConcurrentNets(s.typical_concurrent_nets),
        SharingReason::DailyNets(s.max_daily_nets),
        SharingReason::ImpossibleTravel(s.impossible_travel_hops),
    ];
    let mut reasons: Vec<SharingReason> =
        candidates.into_iter().filter(|r| r.points() > 0).collect();
    // Highest-impact reason first so the UI leads with the smoking gun.
    reasons.sort_by_key(|b| std::cmp::Reverse(b.points()));

    let raw: u32 = reasons.iter().map(|r| u32::from(r.points())).sum();
    let score = raw.min(100) as u8;
    let level = if score >= 60 {
        SharingLevel::High
    } else if score >= FLAG_THRESHOLD {
        SharingLevel::Medium
    } else if score >= 15 {
        SharingLevel::Low
    } else {
        SharingLevel::None
    };
    SharingScore {
        score,
        level,
        reasons,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use vpnctl_core::UserId;

    fn sig(typical_nets: u32, daily_nets: u32, travel: u64) -> SharingSignals {
        SharingSignals {
            user_id: UserId("u".into()),
            // Fetch-side diversity is intentionally non-zero but MUST NOT
            // affect the score (dropped in v2).
            distinct_ips: 99,
            distinct_asns: 9,
            distinct_countries: 9,
            distinct_device_classes: 9,
            typical_concurrent_nets: typical_nets,
            max_daily_nets: daily_nets,
            impossible_travel_hops: travel,
        }
    }

    #[test]
    fn mobile_rotation_single_user_does_not_flag() {
        // The multiviruss shape: one device, never two networks at once
        // (concurrency 1), ~5 networks in its busiest day (mobile + home + work),
        // a couple of proxy-fetch country hops. Must stay below the flag —
        // and the huge fetch-side diversity must contribute NOTHING.
        let r = score(&sig(1, 5, 2));
        assert_eq!(r.score, 8, "only DailyNets(5)=8; diversity ignored");
        assert!(!r.is_flagged());
        assert_eq!(r.level, SharingLevel::None);
    }

    #[test]
    fn one_person_two_devices_stays_under_flag() {
        // Phone on mobile + laptop on Wi-Fi online together = 2 nets at once.
        // Legitimate; 25 alone must not flag.
        let r = score(&sig(2, 4, 0));
        assert_eq!(r.score, 33); // 25 + 8
        assert!(!r.is_flagged());
    }

    #[test]
    fn normal_mobile_user_with_one_off_network_spikes_does_not_flag() {
        // demonnot-3 production shape after robust aggregation: typical
        // concurrency 2, max 3 ISP-scale networks/day, no impossible travel.
        let r = score(&sig(2, 3, 0));
        assert_eq!(r.score, 25);
        assert!(!r.is_flagged());
    }

    #[test]
    fn three_simultaneous_networks_flags() {
        // 3 distinct access networks in ONE snapshot ⇒ clearly multiple
        // clients at once. Flags on the concurrency term alone.
        let r = score(&sig(3, 0, 0));
        assert_eq!(r.score, 45);
        assert_eq!(r.level, SharingLevel::Medium);
        assert!(r.is_flagged());
        assert_eq!(r.reasons[0], SharingReason::TypicalConcurrentNets(3));
    }

    #[test]
    fn two_nets_plus_many_daily_nets_flags() {
        // 2 at once + 8 distinct daily networks (corroboration) ⇒ shared.
        let r = score(&sig(2, 8, 0));
        assert_eq!(r.score, 43); // 25 + 18
        assert!(r.is_flagged());
    }

    #[test]
    fn score_caps_at_100() {
        let r = score(&sig(9, 99, 9));
        assert_eq!(r.score, 100);
        assert_eq!(r.level, SharingLevel::High);
    }
}
