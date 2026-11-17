#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use vpnctld::ha::coordinator::{
        Action, Coordinator, FenceProof, HaConfig, Lease, PreviousLeader, ReplicaProof, Role,
    };

    const NOW: u64 = 1_000;
    const EXPIRES: u64 = 2_000;
    const STOP_BUDGET: u64 = 100;

    fn config() -> HaConfig {
        HaConfig {
            node_id: "controller-a".into(),
            stop_budget_ms: STOP_BUDGET,
            max_replica_age_ms: 500,
            schema_version: 7,
            build: "spec-build".into(),
        }
    }

    fn grant(holder: &str, epoch: u64, expires_at_ms: u64) -> Lease {
        Lease {
            holder: holder.into(),
            epoch,
            expires_at_ms,
            previous: Some(PreviousLeader {
                node_id: "controller-b".into(),
                epoch: 6,
            }),
        }
    }

    fn local_grant() -> Lease {
        grant("controller-a", 7, EXPIRES)
    }

    fn replica(verified_at_ms: u64) -> ReplicaProof {
        ReplicaProof {
            verified_at_ms,
            inventory_revision: 42,
            required_revision: 42,
            schema_version: 7,
            build: "spec-build".into(),
            integrity_verified: true,
            identities_verified: true,
        }
    }

    fn fence() -> FenceProof {
        FenceProof {
            previous_node_id: "controller-b".into(),
            previous_epoch: 6,
            successor_epoch: 7,
            external_actions_fenced: true,
        }
    }

    fn candidate() -> Coordinator {
        let mut coordinator = Coordinator::new(config()).unwrap();
        assert!(matches!(
            coordinator.observe(Some(local_grant()), NOW),
            Action::None
        ));
        assert!(matches!(coordinator.role(), Role::Candidate));
        assert!(!coordinator.may_serve(NOW));
        coordinator
    }

    fn leader() -> Coordinator {
        let mut coordinator = candidate();
        coordinator
            .activate(&replica(NOW), Some(&fence()), NOW)
            .unwrap();
        assert!(matches!(coordinator.role(), Role::Leader));
        assert!(coordinator.may_serve(NOW));
        coordinator
    }

    #[test]
    fn configuration_requires_identity_and_positive_time_budgets() {
        let mut empty_node = config();
        empty_node.node_id.clear();
        let mut empty_build = config();
        empty_build.build.clear();
        let mut zero_stop_budget = config();
        zero_stop_budget.stop_budget_ms = 0;
        let mut zero_replica_age = config();
        zero_replica_age.max_replica_age_ms = 0;

        for invalid in [empty_node, empty_build, zero_stop_budget, zero_replica_age] {
            assert!(Coordinator::new(invalid).is_err());
        }
        assert!(Coordinator::new(config()).is_ok());
    }

    #[test]
    fn new_controller_is_isolated_without_worker_or_admission() {
        let mut coordinator = Coordinator::new(config()).unwrap();
        assert!(matches!(coordinator.role(), Role::Isolated));
        assert!(!coordinator.may_serve(NOW));
        assert!(matches!(coordinator.tick(NOW), Action::None));
        assert!(
            coordinator
                .activate(&replica(NOW), Some(&fence()), NOW)
                .is_err()
        );
        coordinator.worker_stopped(NOW);
        assert!(matches!(coordinator.role(), Role::Isolated));
        assert!(!coordinator.may_serve(NOW));
    }

    #[test]
    fn remote_authority_only_creates_a_follower() {
        let mut coordinator = Coordinator::new(config()).unwrap();
        assert!(matches!(
            coordinator.observe(Some(grant("controller-c", 7, EXPIRES)), NOW),
            Action::None
        ));
        assert!(matches!(coordinator.role(), Role::Follower));
        assert!(!coordinator.may_serve(NOW));
        assert!(
            coordinator
                .activate(&replica(NOW), Some(&fence()), NOW)
                .is_err()
        );
        assert!(matches!(coordinator.tick(NOW + 1), Action::None));
    }

    #[test]
    fn verified_candidate_can_activate_once_with_matching_fence() {
        let mut coordinator = leader();
        assert!(
            coordinator
                .activate(&replica(NOW), Some(&fence()), NOW)
                .is_err()
        );
        assert!(matches!(coordinator.role(), Role::Leader));
        assert!(coordinator.may_serve(NOW));
    }

    #[test]
    fn initial_cluster_grant_bootstraps_without_fence() {
        let mut coordinator = Coordinator::new(config()).unwrap();
        let first = Lease {
            holder: "controller-a".into(),
            epoch: 1,
            expires_at_ms: EXPIRES,
            previous: None,
        };
        assert!(matches!(
            coordinator.observe(Some(first), NOW),
            Action::None
        ));
        assert!(matches!(coordinator.role(), Role::Candidate));
        coordinator.activate(&replica(NOW), None, NOW).unwrap();
        assert!(matches!(coordinator.role(), Role::Leader));
        assert!(coordinator.may_serve(NOW));
    }

    #[test]
    fn activation_rejects_build_schema_integrity_and_identity_mismatches() {
        let mut wrong_build = replica(NOW);
        wrong_build.build = "other-build".into();
        let mut wrong_schema = replica(NOW);
        wrong_schema.schema_version += 1;
        let mut unverified_integrity = replica(NOW);
        unverified_integrity.integrity_verified = false;
        let mut unverified_identities = replica(NOW);
        unverified_identities.identities_verified = false;

        for proof in [
            wrong_build,
            wrong_schema,
            unverified_integrity,
            unverified_identities,
        ] {
            let mut coordinator = candidate();
            assert!(coordinator.activate(&proof, Some(&fence()), NOW).is_err());
            assert!(!coordinator.may_serve(NOW));
            assert!(!matches!(coordinator.role(), Role::Leader));
        }
    }

    #[test]
    fn replication_must_include_every_required_revision() {
        let mut coordinator = candidate();
        let mut behind = replica(NOW);
        behind.inventory_revision = behind.required_revision - 1;
        assert!(coordinator.activate(&behind, Some(&fence()), NOW).is_err());
        assert!(!coordinator.may_serve(NOW));

        let mut coordinator = candidate();
        let mut ahead = replica(NOW);
        ahead.inventory_revision += 1;
        coordinator.activate(&ahead, Some(&fence()), NOW).unwrap();
        assert!(coordinator.may_serve(NOW));
    }

    #[test]
    fn replica_age_boundary_is_inclusive_and_future_proofs_are_rejected() {
        let mut coordinator = candidate();
        coordinator
            .activate(&replica(NOW - 500), Some(&fence()), NOW)
            .unwrap();
        assert!(coordinator.may_serve(NOW));

        for verified_at in [NOW - 501, NOW + 1] {
            let mut coordinator = candidate();
            assert!(
                coordinator
                    .activate(&replica(verified_at), Some(&fence()), NOW)
                    .is_err()
            );
            assert!(!coordinator.may_serve(NOW));
        }
    }

    #[test]
    fn predecessor_requires_complete_matching_external_fencing_evidence() {
        let mut coordinator = candidate();
        assert!(coordinator.activate(&replica(NOW), None, NOW).is_err());
        assert!(!coordinator.may_serve(NOW));

        let mut wrong_node = fence();
        wrong_node.previous_node_id = "controller-c".into();
        let mut wrong_previous_epoch = fence();
        wrong_previous_epoch.previous_epoch -= 1;
        let mut wrong_successor_epoch = fence();
        wrong_successor_epoch.successor_epoch += 1;
        let mut actions_not_fenced = fence();
        actions_not_fenced.external_actions_fenced = false;

        for evidence in [
            wrong_node,
            wrong_previous_epoch,
            wrong_successor_epoch,
            actions_not_fenced,
        ] {
            let mut coordinator = candidate();
            assert!(
                coordinator
                    .activate(&replica(NOW), Some(&evidence), NOW)
                    .is_err()
            );
            assert!(!coordinator.may_serve(NOW));
        }
    }

    #[test]
    fn activation_requires_strictly_more_than_stop_budget_remaining() {
        let deadline = EXPIRES - STOP_BUDGET;
        let mut coordinator = candidate();
        coordinator
            .activate(&replica(deadline - 1), Some(&fence()), deadline - 1)
            .unwrap();
        assert!(coordinator.may_serve(deadline - 1));

        for now in [deadline, deadline + 1, EXPIRES] {
            let mut coordinator = candidate();
            assert!(
                coordinator
                    .activate(&replica(now), Some(&fence()), now)
                    .is_err()
            );
            assert!(!coordinator.may_serve(now));
        }
    }

    #[test]
    fn deadline_closes_admission_without_waiting_for_tick_and_repeats_stop() {
        let mut coordinator = leader();
        let deadline = EXPIRES - STOP_BUDGET;
        assert!(coordinator.may_serve(deadline - 1));
        assert!(matches!(coordinator.tick(deadline - 1), Action::None));
        assert!(!coordinator.may_serve(deadline));
        assert!(matches!(coordinator.tick(deadline), Action::StopWorker));
        assert!(matches!(coordinator.role(), Role::Draining));
        assert!(!coordinator.may_serve(deadline));
        assert!(matches!(coordinator.tick(deadline + 1), Action::StopWorker));
        assert!(matches!(
            coordinator.observe(Some(local_grant()), deadline + 2),
            Action::StopWorker
        ));
        coordinator.worker_stopped(deadline + 3);
        assert!(!coordinator.may_serve(deadline + 3));
        assert!(!matches!(coordinator.role(), Role::Leader | Role::Draining));
        assert!(matches!(coordinator.tick(deadline + 4), Action::None));
    }

    #[test]
    fn invalid_or_missing_authority_stops_an_active_worker_immediately() {
        let mut zero_epoch = local_grant();
        zero_epoch.epoch = 0;
        let mut empty_holder = local_grant();
        empty_holder.holder.clear();
        let expired = grant("controller-a", 7, NOW + 1);
        let remote = grant("controller-c", 8, EXPIRES);

        for observation in [
            None,
            Some(zero_epoch),
            Some(empty_holder),
            Some(expired),
            Some(remote),
        ] {
            let mut coordinator = leader();
            assert!(matches!(
                coordinator.observe(observation, NOW + 1),
                Action::StopWorker
            ));
            assert!(matches!(coordinator.role(), Role::Draining));
            assert!(!coordinator.may_serve(NOW + 1));
            assert!(matches!(coordinator.tick(NOW + 2), Action::StopWorker));
        }
    }

    #[test]
    fn malformed_or_expired_grants_do_not_create_a_candidate() {
        let mut zero_epoch = local_grant();
        zero_epoch.epoch = 0;
        let mut empty_holder = local_grant();
        empty_holder.holder.clear();
        let mut previous_zero = local_grant();
        previous_zero.previous = Some(PreviousLeader {
            node_id: "controller-b".into(),
            epoch: 0,
        });
        let mut previous_same = local_grant();
        previous_same.previous = Some(PreviousLeader {
            node_id: "controller-b".into(),
            epoch: 7,
        });
        let mut previous_future = local_grant();
        previous_future.previous = Some(PreviousLeader {
            node_id: "controller-b".into(),
            epoch: 8,
        });

        for observation in [
            zero_epoch,
            empty_holder,
            previous_zero,
            previous_same,
            previous_future,
            grant("controller-a", 7, NOW),
            grant("controller-a", 7, NOW - 1),
        ] {
            let mut coordinator = Coordinator::new(config()).unwrap();
            assert!(matches!(
                coordinator.observe(Some(observation), NOW),
                Action::None
            ));
            assert!(!matches!(
                coordinator.role(),
                Role::Candidate | Role::Leader
            ));
            assert!(
                coordinator
                    .activate(&replica(NOW), Some(&fence()), NOW)
                    .is_err()
            );
            assert!(!coordinator.may_serve(NOW));
        }
    }

    #[test]
    fn identical_same_epoch_observation_is_idempotent_and_extension_keeps_leadership() {
        let mut coordinator = leader();
        assert!(matches!(
            coordinator.observe(Some(local_grant()), NOW + 1),
            Action::None
        ));
        assert!(matches!(coordinator.role(), Role::Leader));
        assert!(coordinator.may_serve(NOW + 1));

        assert!(matches!(
            coordinator.observe(Some(grant("controller-a", 7, 3_000)), NOW + 2),
            Action::None
        ));
        assert!(matches!(
            coordinator.tick(EXPIRES - STOP_BUDGET),
            Action::None
        ));
        assert!(coordinator.may_serve(EXPIRES - STOP_BUDGET));
        assert!(!coordinator.may_serve(3_000 - STOP_BUDGET));
        assert!(matches!(
            coordinator.tick(3_000 - STOP_BUDGET),
            Action::StopWorker
        ));
    }

    #[test]
    fn same_epoch_holder_previous_or_expiry_change_retires_the_epoch() {
        let changed_holder = grant("controller-c", 7, EXPIRES);
        let mut changed_previous_node = local_grant();
        changed_previous_node.previous = Some(PreviousLeader {
            node_id: "controller-c".into(),
            epoch: 6,
        });
        let mut changed_previous_epoch = local_grant();
        changed_previous_epoch.previous = Some(PreviousLeader {
            node_id: "controller-b".into(),
            epoch: 5,
        });
        let mut removed_previous = local_grant();
        removed_previous.previous = None;
        let shortened = grant("controller-a", 7, EXPIRES - 1);

        for changed in [
            changed_holder,
            changed_previous_node,
            changed_previous_epoch,
            removed_previous,
            shortened,
        ] {
            let mut coordinator = leader();
            assert!(matches!(
                coordinator.observe(Some(changed), NOW + 1),
                Action::StopWorker
            ));
            assert!(matches!(coordinator.role(), Role::Draining));
            assert!(!coordinator.may_serve(NOW + 1));
            coordinator.worker_stopped(NOW + 2);
            assert!(matches!(
                coordinator.observe(Some(grant("controller-a", 7, 3_000)), NOW + 3),
                Action::None
            ));
            assert!(
                coordinator
                    .activate(&replica(NOW + 3), Some(&fence()), NOW + 3)
                    .is_err()
            );
            assert!(!coordinator.may_serve(NOW + 3));
        }
    }

    #[test]
    fn newer_local_epoch_waits_for_stop_confirmation_then_can_activate() {
        let mut coordinator = leader();
        let successor = Lease {
            holder: "controller-a".into(),
            epoch: 8,
            expires_at_ms: 3_000,
            previous: Some(PreviousLeader {
                node_id: "controller-a".into(),
                epoch: 7,
            }),
        };
        let successor_fence = FenceProof {
            previous_node_id: "controller-a".into(),
            previous_epoch: 7,
            successor_epoch: 8,
            external_actions_fenced: true,
        };
        assert!(matches!(
            coordinator.observe(Some(successor), NOW + 1),
            Action::StopWorker
        ));
        assert!(matches!(coordinator.role(), Role::Draining));
        assert!(!coordinator.may_serve(NOW + 1));
        assert!(
            coordinator
                .activate(&replica(NOW + 2), Some(&successor_fence), NOW + 2)
                .is_err()
        );
        assert!(matches!(coordinator.tick(NOW + 2), Action::StopWorker));
        coordinator.worker_stopped(NOW + 3);
        assert!(matches!(coordinator.role(), Role::Candidate));
        assert!(!coordinator.may_serve(NOW + 3));
        coordinator
            .activate(&replica(NOW + 3), Some(&successor_fence), NOW + 3)
            .unwrap();
        assert!(matches!(coordinator.role(), Role::Leader));
        assert!(coordinator.may_serve(NOW + 3));
    }

    #[test]
    fn latest_remote_grant_during_draining_becomes_follower_after_stop() {
        let mut coordinator = leader();
        assert!(matches!(
            coordinator.observe(None, NOW + 1),
            Action::StopWorker
        ));
        assert!(matches!(
            coordinator.observe(Some(grant("controller-c", 8, 3_000)), NOW + 2),
            Action::StopWorker
        ));
        assert!(matches!(coordinator.role(), Role::Draining));
        assert!(!coordinator.may_serve(NOW + 2));
        coordinator.worker_stopped(NOW + 3);
        assert!(matches!(coordinator.role(), Role::Follower));
        assert!(!coordinator.may_serve(NOW + 3));
        assert!(matches!(coordinator.tick(NOW + 4), Action::None));
    }

    #[test]
    fn missing_latest_authority_during_draining_leaves_controller_isolated() {
        let mut coordinator = leader();
        assert!(matches!(
            coordinator.observe(Some(grant("controller-c", 8, 3_000)), NOW + 1),
            Action::StopWorker
        ));
        assert!(matches!(
            coordinator.observe(None, NOW + 2),
            Action::StopWorker
        ));
        coordinator.worker_stopped(NOW + 3);
        assert!(matches!(coordinator.role(), Role::Isolated));
        assert!(!coordinator.may_serve(NOW + 3));
        assert!(matches!(coordinator.tick(NOW + 4), Action::None));
    }

    #[test]
    fn expired_successor_cannot_become_candidate_when_worker_finally_stops() {
        let mut coordinator = leader();
        assert!(matches!(
            coordinator.observe(Some(grant("controller-a", 8, NOW + 200)), NOW + 1),
            Action::StopWorker
        ));
        coordinator.worker_stopped(NOW + 200);
        assert!(matches!(coordinator.role(), Role::Isolated));
        assert!(!coordinator.may_serve(NOW + 200));
        assert!(
            coordinator
                .activate(&replica(NOW + 200), Some(&fence()), NOW + 200)
                .is_err()
        );
    }

    #[test]
    fn partition_recovery_cannot_revive_the_fenced_epoch() {
        let mut coordinator = leader();
        assert!(matches!(
            coordinator.observe(None, NOW + 1),
            Action::StopWorker
        ));
        coordinator.worker_stopped(NOW + 2);
        assert!(matches!(coordinator.role(), Role::Isolated));
        assert!(matches!(
            coordinator.observe(Some(grant("controller-a", 7, 3_000)), NOW + 3),
            Action::None
        ));
        assert!(!matches!(
            coordinator.role(),
            Role::Candidate | Role::Leader
        ));
        assert!(
            coordinator
                .activate(&replica(NOW + 3), Some(&fence()), NOW + 3)
                .is_err()
        );
        assert!(!coordinator.may_serve(NOW + 3));
    }

    #[test]
    fn resumed_old_process_cannot_extend_a_lease_at_or_after_its_deadline() {
        for now in [EXPIRES - STOP_BUDGET, EXPIRES, EXPIRES + 1] {
            let mut coordinator = leader();
            assert!(!coordinator.may_serve(now));
            assert!(matches!(
                coordinator.observe(Some(grant("controller-a", 7, 5_000)), now),
                Action::StopWorker
            ));
            assert!(matches!(coordinator.role(), Role::Draining));
            assert!(!coordinator.may_serve(now));
            coordinator.worker_stopped(now + 1);
            assert!(matches!(
                coordinator.observe(Some(grant("controller-a", 7, 5_000)), now + 2),
                Action::None
            ));
            assert!(
                coordinator
                    .activate(&replica(now + 2), Some(&fence()), now + 2)
                    .is_err()
            );
            assert!(!coordinator.may_serve(now + 2));
        }
    }

    #[test]
    fn highest_epoch_survives_isolation_and_rejects_stale_local_grants() {
        let mut coordinator = Coordinator::new(config()).unwrap();
        assert!(matches!(
            coordinator.observe(Some(grant("controller-c", 9, 3_000)), NOW),
            Action::None
        ));
        assert!(matches!(coordinator.role(), Role::Follower));
        assert!(matches!(coordinator.observe(None, NOW + 1), Action::None));
        assert!(matches!(coordinator.role(), Role::Isolated));
        assert!(matches!(
            coordinator.observe(Some(local_grant()), NOW + 2),
            Action::None
        ));
        assert!(!matches!(
            coordinator.role(),
            Role::Candidate | Role::Leader
        ));
        assert!(
            coordinator
                .activate(&replica(NOW + 2), Some(&fence()), NOW + 2)
                .is_err()
        );
        assert!(!coordinator.may_serve(NOW + 2));
    }

    #[test]
    fn stale_grant_while_draining_cannot_replace_newer_authority() {
        let mut coordinator = leader();
        assert!(matches!(
            coordinator.observe(Some(grant("controller-c", 9, 3_000)), NOW + 1),
            Action::StopWorker
        ));
        assert!(matches!(
            coordinator.observe(Some(grant("controller-a", 8, 3_000)), NOW + 2),
            Action::StopWorker
        ));
        coordinator.worker_stopped(NOW + 3);
        assert!(!matches!(
            coordinator.role(),
            Role::Candidate | Role::Leader
        ));
        assert!(!coordinator.may_serve(NOW + 3));
        assert!(
            coordinator
                .activate(&replica(NOW + 3), Some(&fence()), NOW + 3)
                .is_err()
        );
    }

    #[test]
    fn very_short_lease_does_not_underflow_stop_deadline() {
        let mut coordinator = Coordinator::new(config()).unwrap();
        let short = Lease {
            holder: "controller-a".into(),
            epoch: 1,
            expires_at_ms: STOP_BUDGET - 1,
            previous: None,
        };
        assert!(matches!(coordinator.observe(Some(short), 0), Action::None));
        assert!(coordinator.activate(&replica(0), None, 0).is_err());
        assert!(!coordinator.may_serve(0));
    }

    #[test]
    fn large_monotonic_times_do_not_overflow_lease_budget_check() {
        let now = u64::MAX - STOP_BUDGET - 1;
        let mut coordinator = Coordinator::new(config()).unwrap();
        let far_future = Lease {
            holder: "controller-a".into(),
            epoch: 1,
            expires_at_ms: u64::MAX,
            previous: None,
        };
        assert!(matches!(
            coordinator.observe(Some(far_future), now),
            Action::None
        ));
        coordinator.activate(&replica(now), None, now).unwrap();
        assert!(coordinator.may_serve(now));
        assert!(!coordinator.may_serve(now + 1));
        assert!(matches!(coordinator.tick(now + 1), Action::StopWorker));
    }
}
