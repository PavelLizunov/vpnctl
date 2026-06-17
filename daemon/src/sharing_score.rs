//! Composite account-sharing risk scorer (2026-06-17).
//!
//! Replaces the old single-threshold heuristic («`distinct_asns >= 3` over
//! the 30-day retention window») which fired on any traveller (home Wi-Fi +
//! mobile + work = 3 ASNs) and only ever looked at `/sub` URL fetches, never
//! at the actual VPN connections.
//!
//! Industry practice (Fingerprint, Netflix household, impossible-travel
//! detection) weights SIMULTANEITY far above cumulative diversity. So does
//! this scorer: the dominant term is `peak_concurrent_ips` — the most
//! distinct client IPs seen in ONE clash snapshot (two IPs at the same
//! instant ⇒ two clients online together), recorded by the poller into
//! `vpn_user_ip_concurrency`. The remaining terms add corroboration:
//! country-level impossible travel, distinct connect-from IPs per day,
//! client-app diversity, and the legacy ASN/country spread (down-weighted).
//!
//! The score is the sum of each signal's points, capped at 100, and carries
//! the list of contributing reasons so the UI can SHOW WHY a user is flagged
//! rather than emit an opaque number. Pure (no I/O, no i18n) so it unit-tests
//! trivially; the render translates [`SharingReason`] labels.

use vpnctl_inventory::SharingSignals;

/// One contributing signal + the points it added. The render maps the
/// variant to a localized label and shows the carried value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingReason {
    /// Most distinct client IPs in a single clash snapshot (true concurrency).
    ConcurrentIps(u32),
    /// `/sub` fetches whose country changed faster than is physically possible.
    ImpossibleTravel(u64),
    /// Most distinct connect-from IPs in any single day.
    DailyIps(u32),
    /// Distinct client-app classes (Shadowrocket / v2rayTun / browser / …).
    DeviceClasses(u64),
    /// Distinct ASNs the `/sub` URL was fetched from (legacy signal).
    Asns(u64),
    /// Distinct countries the `/sub` URL was fetched from.
    Countries(u64),
}

impl SharingReason {
    /// Points this reason contributes to the 0-100 score.
    pub fn points(self) -> u8 {
        match self {
            // STRONGEST — simultaneous distinct client IPs.
            SharingReason::ConcurrentIps(n) => match n {
                0 | 1 => 0,
                2 => 25,
                3 => 40,
                _ => 55,
            },
            // Physically-impossible country hops between consecutive fetches.
            SharingReason::ImpossibleTravel(h) => match h {
                0 => 0,
                1 => 20,
                _ => 35,
            },
            // Many distinct connect-from IPs within a single day.
            SharingReason::DailyIps(n) => match n {
                0..=2 => 0,
                3 => 10,
                4 | 5 => 20,
                _ => 30,
            },
            // Many distinct client apps.
            SharingReason::DeviceClasses(n) => match n {
                0..=2 => 0,
                3 => 5,
                _ => 15,
            },
            // Legacy ASN spread — down-weighted (travellers trip it).
            SharingReason::Asns(n) => match n {
                0..=2 => 0,
                3 | 4 => 5,
                _ => 12,
            },
            // Country spread.
            SharingReason::Countries(n) => match n {
                0 | 1 => 0,
                2 => 5,
                _ => 12,
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
        SharingReason::ConcurrentIps(s.peak_concurrent_ips),
        SharingReason::ImpossibleTravel(s.impossible_travel_hops),
        SharingReason::DailyIps(s.max_daily_source_ips),
        SharingReason::DeviceClasses(s.distinct_device_classes),
        SharingReason::Asns(s.distinct_asns),
        SharingReason::Countries(s.distinct_countries),
    ];
    let mut reasons: Vec<SharingReason> = candidates
        .into_iter()
        .filter(|r| r.points() > 0)
        .collect();
    // Highest-impact reason first so the UI leads with the smoking gun.
    reasons.sort_by(|a, b| b.points().cmp(&a.points()));

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

    fn sig(
        peak: u32,
        travel: u64,
        daily: u32,
        devcls: u64,
        asns: u64,
        countries: u64,
    ) -> SharingSignals {
        SharingSignals {
            user_id: UserId("u".into()),
            distinct_ips: 0,
            distinct_asns: asns,
            distinct_countries: countries,
            distinct_device_classes: devcls,
            peak_concurrent_ips: peak,
            max_daily_source_ips: daily,
            impossible_travel_hops: travel,
        }
    }

    #[test]
    fn single_user_one_ip_never_flags() {
        // One client, one IP at a time, a couple of ASNs (home + mobile),
        // one client app. The old method flagged ≥3 ASNs; this must stay calm.
        let r = score(&sig(1, 0, 2, 1, 2, 1));
        assert_eq!(r.score, 0);
        assert_eq!(r.level, SharingLevel::None);
        assert!(!r.is_flagged());
        assert!(r.reasons.is_empty());
    }

    #[test]
    fn traveller_three_asns_three_countries_stays_below_flag() {
        // The classic false positive: 3 ASNs + 3 countries over a month,
        // but never two IPs at once. Legacy heuristic fired; composite must
        // stay under the flag threshold (5 + 12 = 17 → Low, not flagged).
        let r = score(&sig(1, 0, 1, 1, 3, 3));
        assert!(r.score < FLAG_THRESHOLD, "score {} should be < flag", r.score);
        assert_eq!(r.level, SharingLevel::Low);
    }

    #[test]
    fn concurrent_ips_dominate_and_flag() {
        // Two distinct client IPs in one snapshot ⇒ real simultaneity.
        let r = score(&sig(2, 0, 0, 0, 0, 0));
        assert_eq!(r.score, 25);
        assert!(!r.is_flagged(), "a single soft signal alone shouldn't flag");
        // Concurrency + one impossible-travel hop ⇒ clearly shared.
        let r2 = score(&sig(3, 1, 0, 0, 0, 0));
        assert_eq!(r2.score, 60);
        assert_eq!(r2.level, SharingLevel::High);
        assert!(r2.is_flagged());
        assert_eq!(r2.reasons[0], SharingReason::ConcurrentIps(3)); // smoking gun first
    }

    #[test]
    fn score_caps_at_100() {
        let r = score(&sig(9, 5, 9, 9, 9, 9));
        assert_eq!(r.score, 100);
        assert_eq!(r.level, SharingLevel::High);
    }
}
