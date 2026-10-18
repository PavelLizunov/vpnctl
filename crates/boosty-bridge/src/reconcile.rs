use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberState {
    pub subscriber_id: i64,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedUser {
    pub user_id: String,
    pub subscriber_id: i64,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Enable { user_id: String },
    Disable { user_id: String },
    NewSubscriber { subscriber_id: i64 },
}

pub fn reconcile(subscribers: &[SubscriberState], links: &[LinkedUser]) -> Vec<Action> {
    let active_by_id: HashMap<i64, bool> = subscribers
        .iter()
        .map(|s| (s.subscriber_id, s.active))
        .collect();

    let linked_subscriber_ids: HashSet<i64> = links.iter().map(|l| l.subscriber_id).collect();

    let mut actions = Vec::new();

    for link in links {
        let active = active_by_id
            .get(&link.subscriber_id)
            .copied()
            .unwrap_or(false);

        match (active, link.disabled) {
            (true, true) => actions.push(Action::Enable {
                user_id: link.user_id.clone(),
            }),
            (false, false) => actions.push(Action::Disable {
                user_id: link.user_id.clone(),
            }),
            (true, false) | (false, true) => {}
        }
    }

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
        assert!(reconcile(&[sub(1, false), sub(2, false)], &[]).is_empty());
    }

    #[test]
    fn mixed_batch_is_handled_independently() {
        let subscribers = vec![sub(1, true), sub(2, false), sub(3, true), sub(9, true)];
        let links = vec![
            link("alice", 1, true),
            link("bob", 2, false),
            link("carol", 3, false),
            link("dave", 4, false),
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

    #[test]
    fn many_users_share_one_subscriber() {
        let mut actions = reconcile(
            &[sub(11297041, true)],
            &[
                link("demonnot-1", 11297041, true),
                link("demonnot-2", 11297041, true),
                link("demonnot-3", 11297041, false),
            ],
        );
        actions.sort_by_key(|a| match a {
            Action::Enable { user_id } => user_id.clone(),
            _ => String::from("~"),
        });
        assert_eq!(
            actions,
            vec![
                Action::Enable {
                    user_id: "demonnot-1".into()
                },
                Action::Enable {
                    user_id: "demonnot-2".into()
                },
            ]
        );

        let mut lapsed = reconcile(
            &[sub(11297041, false)],
            &[
                link("demonnot-1", 11297041, false),
                link("demonnot-2", 11297041, false),
            ],
        );
        lapsed.sort_by_key(|a| match a {
            Action::Disable { user_id } => user_id.clone(),
            _ => String::from("~"),
        });
        assert_eq!(
            lapsed,
            vec![
                Action::Disable {
                    user_id: "demonnot-1".into()
                },
                Action::Disable {
                    user_id: "demonnot-2".into()
                },
            ]
        );
    }
}
