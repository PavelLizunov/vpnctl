"""Short-lived reachability reports from enrolled HA observers."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from itertools import islice
import re
import secrets
from threading import RLock
import time


_ID = re.compile(r"[a-z][a-z0-9-]{0,40}")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_OUTAGE = {"unavailable", "unreachable"}
_STATUSES = _OUTAGE | {"active", "standby", "unknown"}
_ISSUE_INTERVAL = 2
_CHALLENGE_LIFETIME = 12
_FRESHNESS = 20


@dataclass(slots=True)
class _Sample:
    issued_at: float
    checks: dict[str, str]
    source: str | None


@dataclass(slots=True)
class _Observer:
    domain: str
    issued_at: float | None = None
    next_issue_at: float | None = None
    nonce: str | None = None
    previous: _Sample | None = None
    latest: _Sample | None = None


def _valid_id(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _boottime():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class ObservationBook:
    def __init__(self, roster, controllers, *, clock=None):
        if isinstance(controllers, (str, bytes)):
            raise ValueError("configure two distinct controller IDs")
        try:
            nodes = tuple(islice(controllers, 3))
        except TypeError as error:
            raise ValueError("configure two distinct controller IDs") from error
        if len(nodes) != 2 or not all(map(_valid_id, nodes)) or nodes[0] == nodes[1]:
            raise ValueError("configure two distinct controller IDs")
        self._targets = {nodes[0]: nodes[1], nodes[1]: nodes[0]}

        if not isinstance(roster, Mapping) or not 3 <= len(roster) <= 64:
            raise ValueError("enroll 3 to 64 observers")
        self._observers = {}
        self._pins = {}
        for identity, entry in roster.items():
            if (not _valid_id(identity) or not isinstance(entry, Mapping) or len(entry) != 2
                    or entry.keys() != {"domain", "certificate_sha256"}):
                raise ValueError("invalid observer enrollment")
            domain = entry["domain"]
            pin = entry["certificate_sha256"]
            if not _valid_id(domain) or not isinstance(pin, str) or not _FINGERPRINT.fullmatch(pin):
                raise ValueError("invalid observer domain or certificate fingerprint")
            if pin in self._pins:
                raise ValueError("observer certificate fingerprints must be unique")
            self._observers[identity] = _Observer(domain)
            self._pins[pin] = identity
        if len({observer.domain for observer in self._observers.values()}) < 2:
            raise ValueError("enroll observers from at least two domains")
        self._required_votes = len(self._observers) // 2 + 1
        self._revision = 0
        self._clock = _boottime if clock is None else clock
        self._lock = RLock()
        self._decision_after = None

    def authorize(self, commit):
        with self._lock:
            sampled_at = self._clock()
            return commit(self.summary(include_revision=True), sampled_at)

    def advance_admission(self):
        with self._lock:
            self._decision_after = self._clock()

    def identity(self, certificate_der: bytes) -> str:
        if isinstance(certificate_der, bytes):
            identity = self._pins.get(hashlib.sha256(certificate_der).hexdigest())
            if identity is not None:
                return identity
        raise PermissionError("observer certificate is not enrolled")

    def _observer(self, identity):
        if isinstance(identity, str) and identity in self._observers:
            return self._observers[identity]
        raise PermissionError("observer is not enrolled")

    def challenge(self, identity):
        observer = self._observer(identity)
        with self._lock:
            now = self._clock()
            if observer.next_issue_at is not None and now < observer.next_issue_at:
                raise RuntimeError("observer challenge issued too recently")
            observer.nonce = secrets.token_hex(32)
            observer.issued_at = now
            observer.next_issue_at = now + _ISSUE_INTERVAL
            return {"nonce": observer.nonce}

    def report(self, identity, body):
        observer = self._observer(identity)
        if (not isinstance(body, Mapping) or len(body) != 2
                or body.keys() != {"nonce", "checks"} or not isinstance(body["nonce"], str)):
            raise ValueError("invalid observation report")
        nonce = body["nonce"]
        checks = body["checks"]
        if (not isinstance(checks, Mapping) or len(checks) != 2
                or checks.keys() != self._targets.keys()):
            raise ValueError("report must check both controllers")
        checks = dict(checks)
        if any(not isinstance(status, str) or status not in _STATUSES for status in checks.values()):
            raise ValueError("invalid controller check status")
        source = next((source for source, target in self._targets.items()
                       if checks[source] in _OUTAGE and checks[target] == "standby"), None)
        with self._lock:
            now = self._clock()
            issued_at = observer.issued_at
            expected = observer.nonce
            if (expected is None or issued_at is None or now - issued_at > _CHALLENGE_LIFETIME
                    or len(nonce) != len(expected) or not nonce.isascii()
                    or not secrets.compare_digest(nonce, expected)):
                raise PermissionError("observer challenge is invalid or expired")
            observer.nonce = None
            # Separate the next probe from this completed sample, even after a slow report.
            observer.next_issue_at = now + _ISSUE_INTERVAL
            observer.previous = observer.latest
            observer.latest = _Sample(issued_at, checks, source)
            self._revision += 1

    def summary(self, *, include_revision=False):
        with self._lock:
            now = self._clock()
            votes = {source: [] for source in self._targets}
            observers = {}
            for identity, observer in self._observers.items():
                latest = observer.latest
                age = None if latest is None else now - latest.issued_at
                fresh = age is not None and age < _FRESHNESS
                observers[identity] = {
                    "domain": observer.domain,
                    "age_ms": None if age is None else int(age * 1000),
                    "checks": dict(latest.checks) if fresh else None,
                }
                previous = observer.previous
                if (fresh and latest.source is not None and previous is not None
                        and previous.source == latest.source and now - previous.issued_at < _FRESHNESS
                        and (self._decision_after is None or previous.issued_at >= self._decision_after)):
                    # The older member of the pair expires first.
                    votes[latest.source].append((observer.domain, previous.issued_at))

            directions = {}
            for source, target in self._targets.items():
                supporting = votes[source]
                domains = sorted({domain for domain, _ in supporting})
                confirmed = len(supporting) >= self._required_votes and len(domains) >= 2
                valid_for_ms = 0
                if confirmed:
                    oldest = min(issued_at for _, issued_at in supporting)
                    valid_for_ms = int((_FRESHNESS - (now - oldest)) * 1000)
                directions[source] = {
                    "target": target,
                    "votes": len(supporting),
                    "domains": domains,
                    "confirmed": confirmed,
                    "valid_for_ms": valid_for_ms,
                }
            summary = {"required_votes": self._required_votes, "directions": directions, "observers": observers}
            if include_revision:
                summary["revision"] = self._revision
            return summary
