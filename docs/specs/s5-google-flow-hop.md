# Spec: S5 Google Flow via Iceland Hop

**Status:** Historical workload-only deployment proposal, superseded for the
client VPN chain by [client-detour.md](client-detour.md). That contract owns
current role and grant requirements. A workload-only server remains excluded
from grants/subscriptions; enabling a client chain requires an explicit operator
transition to `vpn-exit` and grants. No role or grant is changed automatically.
The proposal below describes the former workload-only arrangement, not additional
requirements on the client chain.

## 1. Intent & Invariants
- What: route S5 management and Google Flow workload only through Iceland; S5 is not a user VPN exit.
- Invariants: pinned host keys on both SSH hops; grants/subscriptions exclude S5; Flow traffic has no direct fallback; DNS/QUIC/WebRTC/IPv4/IPv6 bypasses fail closed; no paid generation in automated verification.

## 2. Interface / Data Contract
```text
Inventory: S5.jump_via = ICELAND; S5.role = workload-only; grants(S5)=0
Management: vpnctld -> Iceland -> S5
Data: Flowpool profile google-flow-s5 -> Iceland -> S5 -> Google
Failure: missing hop/S5 or unexpected exit -> DENY + quarantine
```

## 3. Verification Checklist
- [ ] ProxyJump status/deploy/update work with both host keys pinned.
- [ ] S5 excluded from grants, subscriptions and fleet-wide actions.
- [ ] Flowpool dedicated profile uses remote DNS and blocks direct fallback.
- [ ] Observed egress is S5; proxy-down/direct-route probes fail.
- [ ] Free auth/status preflight passes; no paid generation occurs.
- [ ] Firewall accepts S5 management/tunnel ingress only from Iceland.
- [ ] Rollback and ordinary subscription byte stability verified.
