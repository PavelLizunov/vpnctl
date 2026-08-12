use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vpnctl_core::ServerId;

pub const QUALITY_MIN_SAMPLES: u64 = 12;

/// One low-load service-path poll tick from one measurement point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceQualitySample {
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub vantage: String,
    pub target_count: u32,
    pub available_targets: u32,
    pub attempts: u32,
    pub successes: u32,
    pub tcp_rtt_ms: Vec<u32>,
    /// SSH-port reachability from the same vantage, kept out of the
    /// service score so a healthy control channel cannot inflate VPN quality.
    pub control_attempts: u32,
    pub control_successes: u32,
    pub control_rtt_ms: Vec<u32>,
    /// Secondary signal only. `None` means ICMP was disabled or unavailable.
    pub icmp_attempts: Option<u32>,
    pub icmp_successes: Option<u32>,
    pub icmp_rtt_ms: Option<Vec<u32>>,
}

/// Rolling-window service-path score. `score=None` until `min_samples`
/// batches exist; the component metrics may still be shown as provisional.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceQualityScore {
    pub window_hours: u32,
    pub sample_count: u64,
    pub min_samples: u64,
    pub vantage: Option<String>,
    pub availability_pct: Option<f64>,
    pub packet_loss_pct: Option<f64>,
    pub median_rtt_ms: Option<u32>,
    pub p95_rtt_ms: Option<u32>,
    pub jitter_ms: Option<f64>,
    pub score: Option<u8>,
    pub control_availability_pct: Option<f64>,
    pub control_p95_rtt_ms: Option<u32>,
    pub control_score: Option<u8>,
    pub last_sample_at: Option<DateTime<Utc>>,
}

fn percentile(sorted: &[u32], pct: usize) -> Option<u32> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (pct.saturating_mul(sorted.len()).saturating_add(99) / 100).max(1);
    sorted.get(rank.saturating_sub(1)).copied()
}

fn descending_quality(value: f64, full_at: f64, zero_at: f64) -> f64 {
    if value <= full_at {
        1.0
    } else if value >= zero_at {
        0.0
    } else {
        (zero_at - value) / (zero_at - full_at)
    }
}

/// Pure score function used by inventory queries and boundary tests.
/// Weights: availability 40%, loss 30%, p95 latency 20%, jitter 10%.
pub fn score_samples(
    samples: &[ServiceQualitySample],
    window_hours: u32,
    min_samples: u64,
) -> ServiceQualityScore {
    let mut ordered: Vec<&ServiceQualitySample> = samples.iter().collect();
    ordered.sort_by_key(|s| s.ts);

    let targets: u64 = ordered.iter().map(|s| u64::from(s.target_count)).sum();
    let available: u64 = ordered
        .iter()
        .map(|s| u64::from(s.available_targets.min(s.target_count)))
        .sum();
    let attempts: u64 = ordered.iter().map(|s| u64::from(s.attempts)).sum();
    let successes: u64 = ordered
        .iter()
        .map(|s| u64::from(s.successes.min(s.attempts)))
        .sum();
    let control_attempts: u64 = ordered.iter().map(|s| u64::from(s.control_attempts)).sum();
    let control_successes: u64 = ordered
        .iter()
        .map(|s| u64::from(s.control_successes.min(s.control_attempts)))
        .sum();

    let availability_pct = (targets > 0).then(|| available as f64 * 100.0 / targets as f64);
    let packet_loss_pct =
        (attempts > 0).then(|| (attempts - successes) as f64 * 100.0 / attempts as f64);
    let control_availability_pct =
        (control_attempts > 0).then(|| control_successes as f64 * 100.0 / control_attempts as f64);

    let mut all_rtts: Vec<u32> = ordered
        .iter()
        .flat_map(|sample| sample.tcp_rtt_ms.iter().copied())
        .collect();
    all_rtts.sort_unstable();
    let median_rtt_ms = percentile(&all_rtts, 50);
    let p95_rtt_ms = percentile(&all_rtts, 95);
    let mut control_rtts: Vec<u32> = ordered
        .iter()
        .flat_map(|sample| sample.control_rtt_ms.iter().copied())
        .collect();
    control_rtts.sort_unstable();
    let control_p95_rtt_ms = percentile(&control_rtts, 95);

    let sample_medians: Vec<u32> = ordered
        .iter()
        .filter_map(|sample| {
            let mut values = sample.tcp_rtt_ms.clone();
            values.sort_unstable();
            percentile(&values, 50)
        })
        .collect();
    let jitter_ms = (sample_medians.len() >= 2).then(|| {
        let total: u64 = sample_medians
            .windows(2)
            .map(|pair| u64::from(pair[0].abs_diff(pair[1])))
            .sum();
        total as f64 / (sample_medians.len() - 1) as f64
    });

    // A UDP-only/no-ingress batch is still useful for the separately
    // measured SSH control path, but it must not satisfy the service
    // score's minimum sample count. Likewise, only real control attempts
    // count toward control-path confidence.
    let sample_count = ordered
        .iter()
        .filter(|sample| sample.target_count > 0 && sample.attempts > 0)
        .count() as u64;
    let control_sample_count = ordered
        .iter()
        .filter(|sample| sample.control_attempts > 0)
        .count() as u64;
    let score = if sample_count < min_samples || availability_pct.is_none() {
        None
    } else {
        let availability = availability_pct.unwrap_or(0.0) / 100.0;
        let loss = 1.0 - packet_loss_pct.unwrap_or(100.0) / 100.0;
        // A fully unreachable service has no RTT. Once enough samples
        // exist that is a real zero-quality observation, not "unknown".
        let latency = p95_rtt_ms
            .map(|v| descending_quality(f64::from(v), 100.0, 500.0))
            .unwrap_or(0.0);
        let jitter = jitter_ms
            .map(|v| descending_quality(v, 10.0, 100.0))
            .unwrap_or(0.0);
        Some(
            (availability * 40.0 + loss * 30.0 + latency * 20.0 + jitter * 10.0)
                .round()
                .clamp(0.0, 100.0) as u8,
        )
    };
    let control_score = if control_sample_count < min_samples {
        None
    } else {
        control_availability_pct.map(|value| value.round().clamp(0.0, 100.0) as u8)
    };

    let vantage = ordered.first().map(|first| {
        if ordered.iter().all(|sample| sample.vantage == first.vantage) {
            first.vantage.clone()
        } else {
            "mixed measurement points".to_string()
        }
    });

    ServiceQualityScore {
        window_hours,
        sample_count,
        min_samples,
        vantage,
        availability_pct,
        packet_loss_pct,
        median_rtt_ms,
        p95_rtt_ms,
        jitter_ms,
        score,
        control_availability_pct,
        control_p95_rtt_ms,
        control_score,
        last_sample_at: ordered.last().map(|sample| sample.ts),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample(
        minute: i64,
        targets: u32,
        available: u32,
        attempts: u32,
        successes: u32,
        rtts: &[u32],
    ) -> ServiceQualitySample {
        ServiceQualitySample {
            ts: DateTime::from_timestamp(1_700_000_000 + minute * 60, 0).unwrap(),
            server_id: ServerId("de".into()),
            vantage: "control".into(),
            target_count: targets,
            available_targets: available,
            attempts,
            successes,
            tcp_rtt_ms: rtts.to_vec(),
            control_attempts: 1,
            control_successes: 1,
            control_rtt_ms: vec![5],
            icmp_attempts: None,
            icmp_successes: None,
            icmp_rtt_ms: None,
        }
    }

    #[test]
    fn no_data_and_too_few_samples_are_unknown_not_zero() {
        assert_eq!(score_samples(&[], 24, 12).score, None);
        assert_eq!(
            score_samples(&[sample(0, 1, 0, 3, 0, &[])], 24, 12).score,
            None
        );
    }

    #[test]
    fn perfect_service_scores_one_hundred() {
        let samples: Vec<_> = (0..12)
            .map(|n| sample(n, 2, 2, 6, 6, &[20, 21, 22]))
            .collect();
        let score = score_samples(&samples, 24, 12);
        assert_eq!(score.score, Some(100));
        assert_eq!(score.availability_pct, Some(100.0));
        assert_eq!(score.packet_loss_pct, Some(0.0));
    }

    #[test]
    fn fully_unreachable_service_scores_zero_after_minimum_samples() {
        let samples: Vec<_> = (0..12).map(|n| sample(n, 2, 0, 6, 0, &[])).collect();
        let score = score_samples(&samples, 24, 12);
        assert_eq!(score.score, Some(0));
        assert_eq!(score.availability_pct, Some(0.0));
        assert_eq!(score.packet_loss_pct, Some(100.0));
        assert_eq!(score.p95_rtt_ms, None);
        assert_eq!(score.control_score, Some(100));
    }

    #[test]
    fn control_only_batches_do_not_fake_service_sample_confidence() {
        let samples: Vec<_> = (0..12).map(|n| sample(n, 0, 0, 0, 0, &[])).collect();
        let score = score_samples(&samples, 24, 12);
        assert_eq!(score.sample_count, 0);
        assert_eq!(score.score, None);
        assert_eq!(score.control_score, Some(100));
    }

    #[test]
    fn latency_and_jitter_boundaries_follow_the_declared_weights() {
        let fast: Vec<_> = (0..12)
            .map(|n| sample(n, 1, 1, 1, 1, &[100 + (n % 2) as u32 * 10]))
            .collect();
        assert_eq!(score_samples(&fast, 24, 12).score, Some(100));

        let slow: Vec<_> = (0..12)
            .map(|n| sample(n, 1, 1, 1, 1, &[500 + (n % 2) as u32 * 100]))
            .collect();
        // Availability + loss remain perfect (70 points); latency and
        // jitter are both at their zero-quality boundaries.
        assert_eq!(score_samples(&slow, 24, 12).score, Some(70));
    }

    #[test]
    fn computes_nearest_rank_median_p95_and_temporal_jitter() {
        let samples = vec![
            sample(0, 1, 1, 3, 3, &[10, 20, 30]),
            sample(5, 1, 1, 3, 3, &[30, 40, 100]),
        ];
        let score = score_samples(&samples, 7 * 24, 2);
        assert_eq!(score.median_rtt_ms, Some(30));
        assert_eq!(score.p95_rtt_ms, Some(100));
        assert_eq!(score.jitter_ms, Some(20.0));
    }
}
