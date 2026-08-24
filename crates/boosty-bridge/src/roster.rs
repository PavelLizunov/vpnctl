//! Roster snapshot conversion, timeline event derivation, and eligibility helpers.

use std::collections::BTreeMap;

use crate::types::{SubscriberSnapshot, SyncReport};

const TOMBSTONE_RETENTION_SECS: i64 = 90 * 86_400;

pub(crate) type AuditEvent = (String, Option<String>, serde_json::Value);

/// Merge live observations with missing tombstones and derive one durable
/// audit event per changed subscriber. The first enriched report establishes
/// a baseline instead of pretending every existing subscriber joined today.
pub(crate) fn subscriber_events(
    previous: Option<&SyncReport>,
    report: &mut SyncReport,
) -> Vec<AuditEvent> {
    let Some(previous) = previous.filter(|r| r.observed_at > 0) else {
        report.subscribers.sort_by_key(|s| s.subscriber_id);
        return vec![(
            "boosty.baseline".into(),
            None,
            serde_json::json!({
                "kind": "baseline",
                "count": report.subscribers.len(),
                "observed_at": report.observed_at,
            }),
        )];
    };

    let mut old: BTreeMap<i64, SubscriberSnapshot> = previous
        .subscribers
        .iter()
        .filter(|s| {
            s.present
                || s.missing_since.is_none_or(|ts| {
                    ts >= report.observed_at.saturating_sub(TOMBSTONE_RETENTION_SECS)
                })
        })
        .cloned()
        .map(|s| (s.subscriber_id, s))
        .collect();
    let mut merged = Vec::with_capacity(report.subscribers.len() + old.len());
    let mut events = Vec::new();

    for current in report.subscribers.drain(..) {
        let target = Some(current.subscriber_id.to_string());
        match old.remove(&current.subscriber_id) {
            None => events.push(snapshot_event("joined", &current, target)),
            Some(previous) if !previous.present => {
                events.push(snapshot_event("reappeared", &current, target.clone()));
                if let Some(changes) = snapshot_changes(&previous, &current) {
                    events.push(changed_event(
                        &current,
                        report.observed_at,
                        &changes,
                        target,
                    ));
                }
            }
            Some(previous) => {
                if let Some(changes) = snapshot_changes(&previous, &current) {
                    events.push(changed_event(
                        &current,
                        report.observed_at,
                        &changes,
                        target,
                    ));
                }
            }
        }
        merged.push(current);
    }

    for (_, mut missing) in old {
        if missing.present {
            missing.present = false;
            missing.missing_since = Some(report.observed_at);
            events.push(snapshot_event(
                "missing",
                &missing,
                Some(missing.subscriber_id.to_string()),
            ));
        }
        merged.push(missing);
    }
    merged.sort_by_key(|s| s.subscriber_id);
    report.subscribers = merged;
    events
}

fn changed_event(
    snapshot: &SubscriberSnapshot,
    observed_at: i64,
    changes: &serde_json::Map<String, serde_json::Value>,
    target: Option<String>,
) -> AuditEvent {
    (
        "boosty.subscriber.changed".into(),
        target,
        serde_json::json!({
            "kind": "changed",
            "name": snapshot.name,
            "observed_at": observed_at,
            "changes": changes,
        }),
    )
}

fn snapshot_event(kind: &str, snapshot: &SubscriberSnapshot, target: Option<String>) -> AuditEvent {
    (
        format!("boosty.subscriber.{kind}"),
        target,
        serde_json::json!({
            "kind": kind,
            "name": snapshot.name,
            "status": snapshot.status,
            "level": snapshot.level_name,
            "payments": snapshot.payments,
            "off_time": snapshot.off_time,
            "missing_since": snapshot.missing_since,
        }),
    )
}

fn snapshot_changes(
    old: &SubscriberSnapshot,
    new: &SubscriberSnapshot,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let old = serde_json::to_value(old).ok()?.as_object()?.clone();
    let new = serde_json::to_value(new).ok()?.as_object()?.clone();
    let mut changes = serde_json::Map::new();
    for (key, new_value) in new {
        if matches!(key.as_str(), "subscriber_id" | "present" | "missing_since") {
            continue;
        }
        let old_value = old.get(&key).cloned().unwrap_or(serde_json::Value::Null);
        if old_value != new_value {
            changes.insert(
                key,
                serde_json::json!({ "old": old_value, "new": new_value }),
            );
        }
    }
    (!changes.is_empty()).then_some(changes)
}

/// Whether a Boosty subscriber should have VPN access: actively subscribed
/// to a PAID level. The free "Follower" pseudo-level reports `price == 0`
/// and is excluded (operator policy 2026-07-10). `NaN` price → excluded
/// (`NaN > 0.0` is false), the safe default.
pub(crate) fn is_vpn_eligible(s: &boosty_api::model::Subscriber) -> bool {
    s.is_active() && s.level.price > 0.0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn snapshot(id: i64, payments: &str) -> SubscriberSnapshot {
        SubscriberSnapshot {
            subscriber_id: id,
            name: format!("subscriber-{id}"),
            payments: payments.into(),
            status: "active".into(),
            subscribed: true,
            ..Default::default()
        }
    }

    #[test]
    fn subscriber_journal_baselines_then_records_changes_and_missing() {
        let mut first = SyncReport {
            observed_at: 10,
            subscribers: vec![snapshot(1, "100"), snapshot(2, "200")],
            ..Default::default()
        };
        let baseline = subscriber_events(None, &mut first);
        assert_eq!(baseline.len(), 1);
        assert_eq!(baseline[0].0, "boosty.baseline");

        let mut second = SyncReport {
            observed_at: 20,
            subscribers: vec![snapshot(1, "150")],
            ..Default::default()
        };
        let events = subscriber_events(Some(&first), &mut second);
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| {
            e.0 == "boosty.subscriber.changed"
                && e.2["changes"]["payments"]["old"] == "100"
                && e.2["changes"]["payments"]["new"] == "150"
        }));
        assert!(
            events
                .iter()
                .any(|e| e.0 == "boosty.subscriber.missing" && e.1.as_deref() == Some("2"))
        );
        assert_eq!(second.subscribers.len(), 2, "missing tombstone is retained");
        assert!(!second.subscribers[1].present);

        let mut third = SyncReport {
            observed_at: 30,
            subscribers: vec![SubscriberSnapshot {
                name: "renamed".into(),
                ..snapshot(2, "250")
            }],
            ..Default::default()
        };
        let reappeared = subscriber_events(Some(&second), &mut third);
        assert!(
            reappeared
                .iter()
                .any(|e| e.0 == "boosty.subscriber.reappeared")
        );
        assert!(reappeared.iter().any(|e| {
            e.0 == "boosty.subscriber.changed"
                && e.2["changes"]["name"]["old"] == "subscriber-2"
                && e.2["changes"]["payments"]["new"] == "250"
        }));

        let mut empty = SyncReport {
            observed_at: 40,
            ..Default::default()
        };
        assert_eq!(subscriber_events(None, &mut empty).len(), 1);
        let mut still_empty = SyncReport {
            observed_at: 50,
            ..Default::default()
        };
        assert!(subscriber_events(Some(&empty), &mut still_empty).is_empty());
    }
}
