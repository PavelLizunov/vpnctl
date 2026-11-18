"""Black-box tests for the observer enrollment and reporting contract."""

import hashlib
import unittest

from observations import ObservationBook


CONTROLLERS = ("primary", "secondary")
DOMAINS = ("host-z", "host-a", "host-a")


def certificate(observer):
    return f"test certificate for {observer}".encode("ascii")


def enrollment(observer, domain):
    return {
        "domain": domain,
        "certificate_sha256": hashlib.sha256(certificate(observer)).hexdigest(),
    }


def roster(domains=DOMAINS):
    return {
        f"observer-{index}": enrollment(f"observer-{index}", domain)
        for index, domain in enumerate(domains)
    }


def checks(primary, secondary):
    return dict(zip(CONTROLLERS, (primary, secondary)))


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class ObservationBookTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.book = self.make_book()

    def make_book(self, domains=DOMAINS):
        return ObservationBook(roster(domains), CONTROLLERS, clock=self.clock)

    def sample(self, observer, primary, secondary):
        identity = f"observer-{observer}"
        challenge = self.book.challenge(identity)
        self.book.report(identity, {**challenge, "checks": checks(primary, secondary)})

    def direction(self, old="primary"):
        return self.book.summary()["directions"][old]

    def test_enrollment_requires_three_to_sixty_four_observers(self):
        for count, required in ((3, 2), (64, 33)):
            with self.subTest(count=count):
                domains = ("host-z",) * (count - 1) + ("host-a",)
                self.assertEqual(self.make_book(domains).summary()["required_votes"], required)
        for count in (2, 65):
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.make_book(("host-z",) * (count - 1) + ("host-a",))

    def test_enrollment_rejects_invalid_controller_ids(self):
        invalid = (
            ("primary",),
            ("primary", "secondary", "third"),
            ("primary", "primary"),
            ("primary", "Secondary"),
            ("primary", "2secondary"),
            ("primary", "s" * 42),
        )
        for controllers in invalid:
            with self.subTest(controllers=controllers), self.assertRaises(ValueError):
                ObservationBook(roster(), controllers, clock=self.clock)

    def test_enrollment_rejects_duplicate_pins_and_malformed_entries(self):
        valid = roster()
        pin = valid["observer-0"]["certificate_sha256"]
        malformed = (
            ("observer-0", {"domain": "host-z"}),
            ("observer-0", {**valid["observer-0"], "address": "example.invalid"}),
            ("observer-0", {"domain": "Host-Z", "certificate_sha256": pin}),
            ("observer-0", {"domain": "host_z", "certificate_sha256": pin}),
            ("observer-0", {"domain": "host-a", "certificate_sha256": pin}),
            ("observer-0", {"domain": "host-z", "certificate_sha256": pin.upper()}),
            ("observer-0", {"domain": "host-z", "certificate_sha256": pin[:-1]}),
            ("observer-0", {"domain": "host-z", "certificate_sha256": "g" * 64}),
            ("observer-0", valid["observer-1"] | {"domain": "host-z"}),
            ("Observer-0", valid["observer-0"]),
            ("observer_0", valid["observer-0"]),
            ("o" * 42, valid["observer-0"]),
        )
        for identity, entry in malformed:
            with self.subTest(identity=identity, entry=entry):
                candidate = valid.copy()
                del candidate["observer-0"]
                candidate[identity] = entry
                with self.assertRaises(ValueError):
                    ObservationBook(candidate, CONTROLLERS, clock=self.clock)

    def test_only_enrolled_certificates_and_identities_are_accepted(self):
        for identity in roster():
            self.assertEqual(self.book.identity(certificate(identity)), identity)
        with self.assertRaises(PermissionError):
            self.book.identity(certificate("unknown-observer"))
        with self.assertRaises(PermissionError):
            self.book.challenge("unknown-observer")
        challenge = self.book.challenge("observer-0")
        with self.assertRaises(PermissionError):
            self.book.report(
                "unknown-observer", {**challenge, "checks": checks("unreachable", "standby")}
            )

    def test_challenges_are_unique_identity_bound_and_single_use(self):
        first = self.book.challenge("observer-0")
        second = self.book.challenge("observer-1")
        for challenge in (first, second):
            self.assertEqual(set(challenge), {"nonce"})
            self.assertIsInstance(challenge["nonce"], str)
            self.assertTrue(challenge["nonce"])
        self.assertNotEqual(first["nonce"], second["nonce"])

        report = {**first, "checks": checks("unreachable", "standby")}
        with self.assertRaises(PermissionError):
            self.book.report("observer-1", report)
        self.book.report("observer-0", report)
        with self.assertRaises(PermissionError):
            self.book.report("observer-0", report)
        self.assertEqual(self.direction()["votes"], 0)

    def test_challenge_spacing_and_replacement(self):
        first = self.book.challenge("observer-0")
        self.clock.now = 1.875
        with self.assertRaises(RuntimeError):
            self.book.challenge("observer-0")
        self.clock.now = 2.0
        second = self.book.challenge("observer-0")
        self.assertNotEqual(first["nonce"], second["nonce"])
        result = checks("unavailable", "standby")
        with self.assertRaises(PermissionError):
            self.book.report("observer-0", {**first, "checks": result})
        self.book.report("observer-0", {**second, "checks": result})
        self.assertEqual(self.direction()["votes"], 0)

    def test_challenge_waits_two_seconds_after_delayed_report_receipt(self):
        first = self.book.challenge("observer-0")
        result = checks("unavailable", "standby")
        self.clock.now = 10.0
        self.book.report("observer-0", {**first, "checks": result})
        with self.assertRaises(RuntimeError):
            self.book.challenge("observer-0")
        self.book.challenge("observer-1")
        self.clock.now = 11.875
        with self.assertRaises(RuntimeError):
            self.book.challenge("observer-0")

        self.clock.now = 12.0
        second = self.book.challenge("observer-0")
        self.book.report("observer-0", {**second, "checks": result})
        self.assertEqual(self.direction()["votes"], 1)

    def test_challenge_has_a_twelve_second_lifetime(self):
        challenge = self.book.challenge("observer-0")
        self.clock.now = 11.875
        self.book.report("observer-0", {**challenge, "checks": checks("unavailable", "standby")})
        challenge = self.book.challenge("observer-1")
        self.clock.now += 12.125
        with self.assertRaises(PermissionError):
            self.book.report(
                "observer-1", {**challenge, "checks": checks("unavailable", "standby")}
            )

    def test_report_requires_exact_body_and_check_keys(self):
        invalid_checks = (
            None,
            [("primary", "unavailable"), ("secondary", "standby")],
            {"primary": "unavailable"},
            {**checks("unavailable", "standby"), "third": "standby"},
            checks("UNAVAILABLE", "standby"),
            checks("unavailable", True),
        )
        book = self.make_book()
        challenge = book.challenge("observer-0")
        result = checks("unavailable", "standby")
        invalid_bodies = (
            None,
            {"checks": result},
            challenge,
            {**challenge, "checks": result, "identity": "observer-0"},
            {"nonce": 7, "checks": result},
            *({**challenge, "checks": invalid} for invalid in invalid_checks),
        )
        for body in invalid_bodies:
            with self.subTest(body=body), self.assertRaises(ValueError):
                book.report("observer-0", body)
        self.assertIsNone(book.summary()["observers"]["observer-0"]["checks"])

    def test_initial_summary_includes_both_directions_and_every_enrolled_observer(self):
        self.assertEqual(
            self.book.summary(),
            {
                "required_votes": 2,
                "directions": {
                    old: {
                        "target": target,
                        "votes": 0,
                        "domains": [],
                        "confirmed": False,
                        "valid_for_ms": 0,
                    }
                    for old, target in (CONTROLLERS, CONTROLLERS[::-1])
                },
                "observers": {
                    identity: {"domain": entry["domain"], "age_ms": None, "checks": None}
                    for identity, entry in roster().items()
                },
            },
        )

    def test_summary_revision_tracks_only_accepted_reports(self):
        self.assertEqual(self.book.summary(include_revision=True)["revision"], 0)
        challenge = self.book.challenge("observer-0")
        self.assertEqual(self.book.summary(include_revision=True)["revision"], 0)
        result = checks("unavailable", "standby")
        report = {**challenge, "checks": result}
        self.book.report("observer-0", report)
        with self.assertRaises(PermissionError):
            self.book.report("observer-0", report)
        snapshot = self.book.summary(include_revision=True)
        self.assertEqual(snapshot["revision"], 1)
        self.assertEqual(snapshot["observers"]["observer-0"]["checks"], result)
        self.assertNotIn("revision", self.book.summary())

        self.sample(1, "unknown", "standby")
        snapshot = self.book.summary(include_revision=True)
        self.assertEqual(snapshot["revision"], 2)
        self.assertEqual(snapshot["observers"]["observer-1"]["checks"], checks("unknown", "standby"))
        self.clock.now = 20.0
        self.assertEqual(self.book.summary(include_revision=True)["revision"], 2)
        self.assertEqual(self.make_book().summary(include_revision=True)["revision"], 0)

    def test_direction_needs_two_reports_from_each_voting_observer(self):
        self.sample(0, "active", "standby")
        for observer in (1, 2):
            self.sample(observer, "unavailable", "standby")
        self.assertEqual(self.direction()["votes"], 0)

        self.clock.now = 2.0
        self.sample(1, "unreachable", "standby")
        self.assertEqual(self.direction()["votes"], 1)
        self.assertFalse(self.direction()["confirmed"])

        self.sample(0, "unavailable", "standby")
        self.assertEqual(self.direction()["votes"], 1)
        self.clock.now = 4.0
        self.sample(0, "unreachable", "standby")
        self.assertEqual(self.direction()["votes"], 2)
        self.assertEqual(self.direction()["domains"], ["host-a", "host-z"])
        self.assertTrue(self.direction()["confirmed"])
        self.assertEqual(self.direction("secondary")["votes"], 0)

    def test_reverse_direction_can_confirm_independently(self):
        for time in (0.0, 2.0):
            self.clock.now = time
            self.sample(0, "standby", "unreachable")
            self.sample(1, "standby", "unavailable")
        self.assertTrue(self.direction("secondary")["confirmed"])
        self.assertEqual(self.direction("secondary")["target"], "primary")
        self.assertFalse(self.direction()["confirmed"])

    def test_new_admission_needs_new_checks_for_the_next_handover(self):
        for instant in (0.0, 2.0):
            self.clock.now = instant
            for observer in (0, 1):
                self.sample(observer, "unreachable", "standby")
        self.assertTrue(self.direction()["confirmed"])

        self.clock.now = 3.0
        self.book.advance_admission()
        self.assertFalse(self.direction()["confirmed"])
        for instant, expected in ((4.0, False), (6.0, True)):
            self.clock.now = instant
            for observer in (0, 1):
                self.sample(observer, "unreachable", "standby")
            self.assertIs(self.direction()["confirmed"], expected)

    def test_tied_votes_with_silent_or_unknown_observers_do_not_confirm(self):
        self.book = self.make_book(("host-z", "host-a", "host-a", "host-z"))
        for time in (0.0, 2.0):
            self.clock.now = time
            self.sample(0, "unavailable", "standby")
            self.sample(1, "unavailable", "standby")
            self.sample(2, "unknown", "standby")
        self.assertEqual(self.book.summary()["required_votes"], 3)
        self.assertEqual(self.direction()["votes"], 2)
        self.assertEqual(self.direction()["domains"], ["host-a", "host-z"])
        self.assertFalse(self.direction()["confirmed"])
        self.assertEqual(self.direction()["valid_for_ms"], 0)

    def test_majority_from_one_hosting_domain_does_not_confirm(self):
        for time in (0.0, 2.0):
            self.clock.now = time
            self.sample(1, "unavailable", "standby")
            self.sample(2, "unreachable", "standby")
        self.assertEqual(self.direction()["votes"], 2)
        self.assertEqual(self.direction()["domains"], ["host-a"])
        self.assertFalse(self.direction()["confirmed"])
        self.assertEqual(self.direction()["valid_for_ms"], 0)

    def test_ambiguous_reports_reset_streak_and_cannot_supply_false_standby(self):
        ambiguous = (
            ("unknown", "standby"),
            ("active", "standby"),
            ("standby", "standby"),
            ("unreachable", "active"),
            ("unreachable", "unknown"),
            ("unreachable", "unavailable"),
            ("unavailable", "unreachable"),
        )
        for primary, secondary in ambiguous:
            with self.subTest(primary=primary, secondary=secondary):
                self.clock.now = 0.0
                self.book = self.make_book()
                self.sample(0, "unavailable", "standby")
                self.clock.now = 2.0
                self.sample(0, "unavailable", "standby")
                self.assertEqual(self.direction()["votes"], 1)
                for time in (4.0, 6.0):
                    self.clock.now = time
                    self.sample(0, primary, secondary)
                    self.assertEqual(self.direction()["votes"], 0)
                    self.assertEqual(self.direction("secondary")["votes"], 0)
                self.clock.now = 8.0
                self.sample(0, "unreachable", "standby")
                self.assertEqual(self.direction()["votes"], 0)
                self.clock.now = 10.0
                self.sample(0, "unavailable", "standby")
                self.assertEqual(self.direction()["votes"], 1)

    def test_opposite_direction_interrupts_a_matching_streak(self):
        self.sample(0, "unavailable", "standby")
        self.clock.now = 2.0
        self.sample(0, "standby", "unavailable")
        self.clock.now = 4.0
        self.sample(0, "unreachable", "standby")
        self.assertEqual(self.direction()["votes"], 0)
        self.assertEqual(self.direction("secondary")["votes"], 0)
        self.clock.now = 6.0
        self.sample(0, "unavailable", "standby")
        self.assertEqual(self.direction()["votes"], 1)

    def test_observations_exactly_twenty_seconds_apart_do_not_form_a_streak(self):
        challenge = self.book.challenge("observer-0")
        self.clock.now = 11.875
        self.book.report("observer-0", {**challenge, "checks": checks("unavailable", "standby")})
        self.clock.now = 20.0
        self.sample(0, "unreachable", "standby")
        self.assertEqual(self.direction()["votes"], 0)
        self.clock.now = 22.0
        self.sample(0, "unavailable", "standby")
        self.assertEqual(self.direction()["votes"], 1)

    def test_report_age_includes_time_between_challenge_and_slow_receipt(self):
        challenge = self.book.challenge("observer-0")
        result = checks("unreachable", "standby")
        self.clock.now = 11.875
        self.book.report("observer-0", {**challenge, "checks": result})
        observer = self.book.summary()["observers"]["observer-0"]
        self.assertEqual(observer["age_ms"], 11_875)
        self.assertEqual(observer["checks"], result)

        self.clock.now = 19.875
        self.assertEqual(self.book.summary()["observers"]["observer-0"]["checks"], result)
        self.clock.now = 20.0
        observer = self.book.summary()["observers"]["observer-0"]
        self.assertIsNone(observer["checks"])
        self.assertIn(observer["age_ms"], (None, 20_000))
        self.assertEqual(self.book.summary()["required_votes"], 2)

    def test_confirmed_freshness_includes_every_contributing_report(self):
        self.book = self.make_book(("host-z", "host-z", "host-a", "host-a"))
        for start in (0.0, 2.0):
            for observer in range(4):
                self.clock.now = start + observer * 0.25
                self.sample(observer, "unreachable", "standby")

        self.clock.now = 3.12525
        before_expiry = self.direction()
        self.assertTrue(before_expiry["confirmed"])
        self.assertEqual(before_expiry["votes"], 4)
        self.assertEqual(before_expiry["valid_for_ms"], 16_874)

        self.clock.now = 20.0
        self.assertEqual(self.direction()["votes"], 3)
        self.assertTrue(self.direction()["confirmed"])
        self.assertEqual(self.direction()["valid_for_ms"], 250)

        self.clock.now = 20.25
        self.assertEqual(self.direction()["votes"], 2)
        self.assertFalse(self.direction()["confirmed"])
        self.assertEqual(self.direction()["valid_for_ms"], 0)
        self.assertEqual(self.book.summary()["required_votes"], 3)


if __name__ == "__main__":
    unittest.main()
