# Controller observations from VPN servers

## Intent and invariants

Home and Aruba run the two controllers. Every enrolled VPN host can run a small
independent observer. Observations may request a handover; only Consul grants
authority. Promotion still requires fencing, the SSH barrier and a verified
replica. Standalone and opt-in HA without observations keep their current behavior.

## Interface and data contract

- A timer probes both distinct HTTPS origins concurrently. `GET /_vpnctl_ha/health`
  reports only local node identity and `active`, `standby`, `unavailable` or
  `unknown`. A stale health heartbeat on an admitted worker is `unknown`.
  It never queries or proxies to the other controller. The observer attributes
  pre-TLS connection refusal/timeout to that path and marks TLS, DNS and ambiguous
  failures `unknown`. The direct TLS ingress may explicitly attest local
  gateway loss with the same node-specific `unavailable` result. Standby means
  local readiness, not public traffic ownership.
- A separate witness listener authenticates a dedicated observer CA and an exact
  enrolled certificate fingerprint. It accepts only a short-lived challenge and a
  bounded report for that identity. A removed pin stops its reports being trusted;
  observers receive no HA control client credentials.
- An opinion requires two recent matching checks from the same observer, with
  the next probe challenge issued at least two seconds after its accepted report. A
  transition requires more than half the configured roster, representing at least
  two independent hosting networks, to report the old side unavailable and its
  peer ready as standby. Unknown, stale and missing checks never count or lower
  the threshold. Restart clears all reports and challenges.
- `/admin/ha` shows the roster, report age, both results and the confirmation
  threshold. Start with monitoring alone and enable enforcement via the existing
  HA operator surface. When enforced, cross-controller automatic acquisition needs
  a fresh confirmation. A reachable owner may request automatic handover under
  its current Consul grant before stopping and releasing it. Revalidate fresh
  evidence after Consul I/O. Before a candidate serves, the witness freezes the
  tally and reserves admission with a Consul transaction that checks the lease
  session and compares and swaps the settings. Consul must confirm the
  reservation before the proof expires. A second Consul transaction checks the
  same exact lease and compares and swaps settings at the reservation index to
  record the authoritative `observer_admission` (`policy`, `node`, `epoch`,
  `revision`). A late or ambiguous reservation leaves the recorded incumbent
  unchanged. Only probe pairs started after admission can vote on the next
  transfer. A recovered incumbent may reacquire when no fresh observation
  directs the peer to take over.
- Explicit initialization and planned handover retain their readiness and
  fencing checks. In both observer modes, the planned target remains selected
  until the admitted controller clears it during reconciliation with a settings
  compare-and-swap tied to its session.

## Verification checklist

- [ ] Authentication, replay, expiry, absent reports, ambiguity and correlated
  hosting domains cannot confirm an unsafe switch.
- [ ] Real HTTPS/mTLS probes verify the controller identity and create the
  expected observations. A TLS failure never reports the target as down.
- [ ] Real Consul/cgroup fixture verifies monitoring-only behavior, majority
  handover, admission matching the current Consul grant, and existing fencing
  and subscription invariants.
