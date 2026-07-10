//! Pure reconciliation logic: given the current Boosty subscription state
//! and the set of vpnctl users linked to Boosty subscribers, decide what
//! access changes are needed. No I/O — every branch is unit-tested.
//!
//! ## Safety invariant
//!
//! The reconciler ONLY ever emits actions for users that are LINKED to a
//! Boosty subscriber (`links`). A vpnctl user with no Boosty link
//! (`tester`, `claude-chat-proxy`, hand-created accounts) is never touched
//! — it can neither be disabled nor enabled by the bridge. This is what
//! makes it safe to run against a production inventory that mixes
//! Boosty-sourced and operator-managed users.

use std::collections::{HashMap, HashSet};

/// Current subscription state of one Boosty subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberState {
    /// Boosty's numeric subscriber id.
    pub subscriber_id: i64,
    /// Whether the subscription is currently active (paying).
    pub active: bool,
}

/// A vpnctl user that is linked to a Boosty subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedUser {
    /// vpnctl user id (username).
    pub user_id: String,
    /// The Boosty subscriber this user is linked to.
    pub subscriber_id: i64,
    /// Whether the user's VPN access is currently disabled (soft-muted).
    pub disabled: bool,
}

/// A reconciliation action the bridge should apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Linked user whose subscription is active but whose access is
    /// currently disabled → re-enable (set `disabled = false`).
    Enable { user_id: String },
    /// Linked user whose subscription has lapsed (inactive or removed) but
    /// whose access is currently enabled → disable (set `disabled = true`).
    Disable { user_id: String },
    /// Active subscriber with no linked vpnctl user → surface so the
    /// operator can link an existing user or provision a new one. Never
    /// applied automatically.
    NewSubscriber { subscriber_id: i64 },
}

/// Compute the set of actions that reconcile vpnctl access with Boosty
/// subscription state.
///
/// A linked user whose `subscriber_id` is absent from `subscribers` is
/// treated as **inactive** (the subscriber is no longer on the blog's
/// roster at all), which is the access-revoking safe default.
pub fn reconcile(subscribers: &[SubscriberState], links: &[LinkedUser]) -> Vec<Action> {
    let active_by_id: HashMap<i64, bool> = subscribers
        .iter()
        .map(|s| (s.subscriber_id, s.active))
        .collect();

    let linked_subscriber_ids: HashSet<i64> = links.iter().map(|l| l.subscriber_id).collect();

    let mut actions = Vec::new();

    // Linked users: enable/disable to match subscription state.
    for link in links {
        // Absent from the roster ⇒ no longer a subscriber ⇒ inactive.
        let active = active_by_id
            .get(&link.subscriber_id)
            .copied()
            .unwrap_or(false);

        match (active, link.disabled) {
            // Paying again but muted → turn access back on.
            (true, true) => actions.push(Action::Enable {
                user_id: link.user_id.clone(),
            }),
            // Lapsed but still enabled → cut access.
            (false, false) => actions.push(Action::Disable {
                user_id: link.user_id.clone(),
            }),
            // Already in the right state → no-op.
            (true, false) | (false, true) => {}
        }
    }

    // Active subscribers with no link at all → surface for the operator.
    for sub in subscribers {
        if sub.active && !linked_subscriber_ids.contains(&sub.subscriber_id) {
            actions.push(Action::NewSubscriber {
                subscriber_id: sub.subscriber_id,
            });
        }
    }

    actions
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sub(id: i64, active: bool) -> SubscriberState {
        SubscriberState {
            subscriber_id: id,
            active,
        }
    }

    fn link(user: &str, id: i64, disabled: bool) -> LinkedUser {
        LinkedUser {
            user_id: user.into(),
            subscriber_id: id,
            disabled,
        }
    }

    #[test]
    fn active_but_disabled_gets_enabled() {
        let actions = reconcile(&[sub(1, true)], &[link("alice", 1, true)]);
        assert_eq!(
            actions,
            vec![Action::Enable {
                user_id: "alice".into()
            }]
        );
    }

    #[test]
    fn lapsed_but_enabled_gets_disabled() {
        let actions = reconcile(&[sub(1, false)], &[link("bob", 1, false)]);
        assert_eq!(
            actions,
            vec![Action::Disable {
                user_id: "bob".into()
            }]
        );
    }

    #[test]
    fn active_and_enabled_is_noop() {
        assert!(reconcile(&[sub(1, true)], &[link("a", 1, false)]).is_empty());
    }

    #[test]
    fn lapsed_and_disabled_is_noop() {
        assert!(reconcile(&[sub(1, false)], &[link("a", 1, true)]).is_empty());
    }

    #[test]
    fn linked_user_absent_from_roster_is_disabled() {
        // Subscriber 1 is gone from the roster entirely; the linked, still-
        // enabled user must be disabled (access-revoking safe default).
        let actions = reconcile(&[], &[link("gone", 1, false)]);
        assert_eq!(
            actions,
            vec![Action::Disable {
                user_id: "gone".into()
            }]
        );
    }

    #[test]
    fn unlinked_active_subscriber_is_surfaced() {
        let actions = reconcile(&[sub(7, true)], &[]);
        assert_eq!(actions, vec![Action::NewSubscriber { subscriber_id: 7 }]);
    }

    #[test]
    fn unlinked_inactive_subscriber_is_ignored() {
        assert!(reconcile(&[sub(7, false)], &[]).is_empty());
    }

    #[test]
    fn unlinked_user_never_touched() {
        // The reconciler only knows about LINKED users. An operator-managed
        // user simply isn't in `links`, so no action can target it. This
        // test documents the invariant: with an empty link set and no
        // active subscribers, nothing happens regardless of roster.
        assert!(reconcile(&[sub(1, false), sub(2, false)], &[]).is_empty());
    }

    #[test]
    fn mixed_batch_is_handled_independently() {
        let subscribers = vec![
            sub(1, true),  // alice active
            sub(2, false), // bob lapsed
            sub(3, true),  // carol active
            sub(9, true),  // unlinked active → surfaced
        ];
        let links = vec![
            link("alice", 1, true),  // enable
            link("bob", 2, false),   // disable
            link("carol", 3, false), // noop
            link("dave", 4, false),  // subscriber 4 absent → disable
        ];
        let mut actions = reconcile(&subscribers, &links);
        actions.sort_by_key(|a| match a {
            Action::Enable { user_id } => (0, user_id.clone(), 0),
            Action::Disable { user_id } => (1, user_id.clone(), 0),
            Action::NewSubscriber { subscriber_id } => (2, String::new(), *subscriber_id),
        });
        assert_eq!(
            actions,
            vec![
                Action::Enable {
                    user_id: "alice".into()
                },
                Action::Disable {
                    user_id: "bob".into()
                },
                Action::Disable {
                    user_id: "dave".into()
                },
                Action::NewSubscriber { subscriber_id: 9 },
            ]
        );
    }
}
