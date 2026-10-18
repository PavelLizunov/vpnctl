use vpnctl_inventory::SharingSignals;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingReason {
    TypicalConcurrentNets(u32),
    DailyNets(u32),
    ImpossibleTravel(u64),
}

impl SharingReason {
    pub fn points(self) -> u8 {
        match self {
            SharingReason::TypicalConcurrentNets(n) => match n {
                0 | 1 => 0,
                2 => 25,
                3 => 45,
                _ => 65,
            },
            SharingReason::DailyNets(n) => match n {
                0..=3 => 0,
                4..=6 => 8,
                7..=10 => 18,
                _ => 28,
            },
            SharingReason::ImpossibleTravel(h) => match h {
                0..=2 => 0,
                3 | 4 => 8,
                _ => 15,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SharingLevel {
    None,
    Low,
    Medium,
    High,
}

pub const FLAG_THRESHOLD: u8 = 35;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingScore {
    pub score: u8,
    pub level: SharingLevel,
    pub reasons: Vec<SharingReason>,
}

impl SharingScore {
    pub fn is_flagged(&self) -> bool {
        self.score >= FLAG_THRESHOLD
    }
}

pub fn score(s: &SharingSignals) -> SharingScore {
    let candidates = [
        SharingReason::TypicalConcurrentNets(s.typical_concurrent_nets),
        SharingReason::DailyNets(s.max_daily_nets),
        SharingReason::ImpossibleTravel(s.impossible_travel_hops),
    ];
    let mut reasons: Vec<SharingReason> =
        candidates.into_iter().filter(|r| r.points() > 0).collect();
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
        let r = score(&sig(1, 5, 2));
        assert_eq!(r.score, 8, "only DailyNets(5)=8; diversity ignored");
        assert!(!r.is_flagged());
        assert_eq!(r.level, SharingLevel::None);
    }

    #[test]
    fn one_person_two_devices_stays_under_flag() {
        let r = score(&sig(2, 4, 0));
        assert_eq!(r.score, 33);
        assert!(!r.is_flagged());
    }

    #[test]
    fn normal_mobile_user_with_one_off_network_spikes_does_not_flag() {
        let r = score(&sig(2, 3, 0));
        assert_eq!(r.score, 25);
        assert!(!r.is_flagged());
    }

    #[test]
    fn three_simultaneous_networks_flags() {
        let r = score(&sig(3, 0, 0));
        assert_eq!(r.score, 45);
        assert_eq!(r.level, SharingLevel::Medium);
        assert!(r.is_flagged());
        assert_eq!(r.reasons[0], SharingReason::TypicalConcurrentNets(3));
    }

    #[test]
    fn two_nets_plus_many_daily_nets_flags() {
        let r = score(&sig(2, 8, 0));
        assert_eq!(r.score, 43);
        assert!(r.is_flagged());
    }

    #[test]
    fn score_caps_at_100() {
        let r = score(&sig(9, 99, 9));
        assert_eq!(r.score, 100);
        assert_eq!(r.level, SharingLevel::High);
    }
}
