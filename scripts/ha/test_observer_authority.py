"""Regressions at the boundary between observer votes and Consul authorization."""

import threading
import unittest
from unittest.mock import Mock, patch

from controller_ha import ObservationChanged, Supervisor


class ObserverAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        fake_clock = patch("controller_ha.boottime", side_effect=lambda: self.now)
        self.addCleanup(fake_clock.stop)
        fake_clock.start()
        app = self.app = Supervisor.__new__(Supervisor)
        app.node = "home"
        app.config = {"witness": "witness", "peers": {"home": None, "aruba": None, "witness": None}}
        app.lock = threading.RLock()
        app.settings = {"observer_enforced": True, "observer_seed": "home", "observer_policy": "fixture-policy",
                        "paused": False, "target": None, "_index": 3}
        app.consul = Mock()
        app.stop = Mock()
        app.admit = Mock()
        app.active = True
        app.deadline = app.boottime_deadline = 115.0
        app.observer_heartbeat = 100.0
        app.observer_cache = self.report()
        app.observer_cache_generation = 0
        app.observer_read_lock = threading.Lock()
        app.read_observations = Mock(return_value=app.observer_cache)
        self.record = {"holder": "home", "epoch": 1, "session": "fixture-lease"}
        app.consul.authority.return_value = self.record
        app.consul.settings.return_value = app.settings
        app.consul.set_settings.return_value = 4
        app.executor = Mock()
        app.executor.status.return_value = {"ready": True}
        app.observer_book = Mock()
        app.observer_book.authorize.side_effect = lambda commit: commit(self.report(valid=6000)[1], self.now)
        app.witness_call = Mock(side_effect=lambda path, body: app.commit_observer_transition(app.node, body, yielding=path.endswith("yield")))

    def report(self, *, confirmed=True, valid=4000, revision=7):
        return (self.now, {"revision": revision, "directions": {"home": {
            "target": "aruba", "confirmed": confirmed, "valid_for_ms": valid}}}, True)

    def test_expiry_during_consul_io_does_not_stop_owner(self):
        def delay(*args, **kwargs):
            self.now += 5
        self.app.consul.set_settings.side_effect = delay

        self.assertFalse(self.app.observed_handover(self.record))
        self.app.consul.set_settings.assert_called_once()
        self.app.stop.assert_not_called()
        self.app.consul.release.assert_not_called()

    def test_corrective_report_during_consul_io_does_not_stop_owner(self):
        def correct(*args, **kwargs):
            self.app.read_observations.return_value = self.report(confirmed=False, valid=0, revision=8)
            self.app.observer_book.authorize.side_effect = lambda commit: commit(self.report(confirmed=False, revision=8)[1], self.now)
            return self.app.settings
        self.app.consul.settings.side_effect = correct

        self.assertFalse(self.app.observed_handover(self.record))
        self.app.stop.assert_not_called()
        self.app.consul.release.assert_not_called()

    def test_pause_during_the_witness_decision_prevents_owner_yield(self):
        def superseded(*args, **kwargs):
            raise RuntimeError("settings CAS lost to operator pause")
        self.app.consul.set_settings.side_effect = superseded

        self.assertFalse(self.app.observed_handover(self.record))
        self.app.consul.set_settings.assert_called_once()
        self.app.stop.assert_not_called()

    def test_rejected_permit_prevents_inflight_poll_reinstating_stale_tally(self):
        old = self.app.observer_cache
        def inflight(*args):
            self.app.invalidate_observations()
            return old
        self.app.read_observations.side_effect = inflight

        self.assertIsNone(self.app.refresh_observations())
        self.assertIsNone(self.app.current_observations())

    def test_failed_candidate_does_not_replace_the_incumbent(self):
        self.app.node = "aruba"
        self.assertTrue(self.app.observation_allows_acquisition(self.record))
        self.app.read_observations.return_value = self.report(confirmed=False, revision=8)
        with self.assertRaises(ObservationChanged):
            self.app.require_activation_observation(self.app.settings)
        failed_grant = {**self.record, "holder": "aruba", "epoch": 2}
        self.assertFalse(self.app.observation_allows_acquisition(failed_grant))
        self.app.node = "home"
        self.assertTrue(self.app.observation_allows_acquisition(failed_grant))

    def test_recovering_incumbent_rechecks_if_peer_won_during_acquisition(self):
        self.app.observer_cache = self.report(confirmed=False)
        self.assertTrue(self.app.observation_allows_acquisition(self.record))
        self.app.read_observations.return_value = self.report(revision=8)
        with self.assertRaises(ObservationChanged):
            self.app.require_activation_observation(self.app.settings)

    def test_witness_records_successor_under_its_lease_before_reply(self):
        self.app.consul.authority.return_value = {"holder": "aruba", "epoch": 2, "session": "candidate-lease"}
        result = self.app.commit_observer_transition("aruba", {"epoch": 2, "session": "candidate-lease"})
        reserve, publish = self.app.consul.set_settings.call_args_list
        self.assertEqual(result["epoch"], 2)
        admission = publish.args[0]["observer_admission"]
        self.assertEqual((admission["node"], admission["epoch"]), ("aruba", 2))
        self.assertNotIn("observer_admission", reserve.args[0])
        self.assertEqual(publish.args[0]["_index"], 4)
        self.assertEqual(publish.kwargs["owner_session"], "candidate-lease")

    def test_consul_delaying_candidate_past_expiry_keeps_previous_incumbent(self):
        self.app.consul.authority.return_value = {"holder": "aruba", "epoch": 2, "session": "candidate-lease"}
        def delay(*args, **kwargs):
            self.now += 6
        self.app.consul.set_settings.side_effect = delay

        with self.assertRaises(ObservationChanged):
            self.app.commit_observer_transition("aruba", {"epoch": 2, "session": "candidate-lease"})
        self.app.consul.set_settings.assert_called_once()
        self.assertEqual(self.app.observation_incumbent(self.app.consul.set_settings.call_args.args[0]), "home")

    def test_suspended_witness_cannot_renew_a_sample_deadline(self):
        self.app.observer_book.authorize.side_effect = lambda commit: commit(self.report()[1], self.now - 6)

        self.assertFalse(self.app.observed_handover(self.record))
        self.app.consul.set_settings.assert_not_called()
        self.app.stop.assert_not_called()

    def test_loss_of_exact_candidate_session_after_reservation_blocks_publication(self):
        candidate = {"holder": "aruba", "epoch": 2, "session": "candidate-lease"}
        self.app.consul.authority.return_value = candidate
        self.app.consul.set_settings.side_effect = [4, RuntimeError("Consul session lost")]

        with self.assertRaisesRegex(RuntimeError, "Consul session lost"):
            self.app.commit_observer_transition("aruba", {"epoch": 2, "session": "candidate-lease"})
        reserve, publish = self.app.consul.set_settings.call_args_list
        self.assertNotIn("observer_admission", reserve.args[0])
        self.assertEqual(publish.kwargs["owner_session"], candidate["session"])

    def test_late_planned_admission_preserves_requested_target(self):
        self.app.settings["target"] = "aruba"
        self.app.consul.authority.return_value = {"holder": "aruba", "epoch": 2, "session": "candidate-lease"}
        def delay(*args, **kwargs):
            self.now += 6
        self.app.consul.set_settings.side_effect = delay

        with self.assertRaises(ObservationChanged):
            self.app.commit_observer_transition("aruba", {"epoch": 2, "session": "candidate-lease"})
        self.assertEqual(self.app.consul.set_settings.call_args.args[0]["target"], "aruba")
        self.assertNotIn("observer_admission", self.app.consul.set_settings.call_args.args[0])

    def test_enforcement_rejects_a_grant_with_no_matching_admission(self):
        self.app.witness = False
        self.app.observer_enabled = True
        node_checks = {"home": "active", "aruba": "standby"}
        self.app.observer_cache[1].update(required_votes=2, observers={
            "a": {"domain": "one", "checks": node_checks}, "b": {"domain": "two", "checks": node_checks},
        })
        self.app.consul.settings.return_value = {"_index": 3}
        self.app.consul.get.return_value = {"Session": "fixture-lease", "record": self.record}
        self.app.remote = Mock(return_value={"observer_enabled": True})
        self.app.admitted_incumbent = Mock(return_value={"node": "home", "epoch": 0})

        with self.assertRaises(RuntimeError):
            self.app.action("enforce-observers", None)
        self.app.consul.set_settings.assert_not_called()

    def test_late_health_tick_is_inconclusive_on_an_admitted_worker(self):
        self.now += 6
        self.assertEqual(self.app.probe_status(), {"node": "home", "status": "unknown"})


if __name__ == "__main__":
    unittest.main()
