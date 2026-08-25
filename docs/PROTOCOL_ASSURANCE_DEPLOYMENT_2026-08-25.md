# Protocol Assurance production deployment — 2026-08-25

## Deployed state

- Control-plane build: `0.9.0+09dc0f1`.
- Inventory schema: migration 52.
- Assurance cadence: 600 seconds.
- External runner: root-owned executable, daemon-user-owned 0700/0600 template store.
- Engine binaries:
  - sing-box 1.13.19, SHA-256 `031042edfd30a215e4c69d83eb7d13c194e6ef50c782e2e1308d9d8fa128454a`;
  - Xray 26.3.27, SHA-256 `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.
- systemd sandbox keeps existing restrictions and adds only `AF_NETLINK`, required by the official sing-box client.

## Probe identity

A dedicated production probe identity was created through the normal CLI and granted exactly S1–S4. The accidental fifth grant was revoked before any deploy to that server. The probe was deployed through the canonical web/SSE deployment path. Existing user subscription output remained byte-stable by SHA-256.

Probe templates:

| Protocol | Templates | Client |
|---|---:|---|
| Hysteria2 | 4 | sing-box |
| VLESS Reality | 4 | sing-box |
| VLESS XHTTP | 4 | Xray |
| TUIC v5 | 1 | sing-box |
| VLESS-WS | 1 | sing-box |
| WireGuard/AmneziaWG | 0 | deliberately unknown until headless AWG support |

## Verification

- Manual external runner matrix: 14/14 protocol handshakes and HTTPS transfers verified.
- UI assurance matrix renders state/stage/failure/latency without probe secrets.
- Existing user subscriptions remained unchanged.
- No runner processes, temporary configs or temporary directories remained after probes.
- WireGuard reports `unknown / udp_path_unverified`, not a missing-template failure.

## Alert behavior

- Alert key is canonical per server×protocol.
- Three consecutive failures are required before an alert opens.
- The first and second controlled Hysteria2 template failures created no alert.
- The third failure created exactly one alert and persisted its Telegram message id.
- Restoring the template closed the alert automatically on the next successful transfer.
- Telegram direct egress from VM119 was unavailable; a stale proxy reference was removed, then S1 was selected as the verified notification egress. Canonical test-send returned HTTP 303/success.

## Rollback evidence

Operational rollback label: `pre-assurance-20260825T195805Z` (not a Git tag).

The following backup artifacts were verified present before migration/deploy:

- daemon and CLI binaries;
- offline inventory DB;
- environment file;
- assets;
- S1–S4 kernel configs;
- vpnctld systemd unit.

The production rollout did not alter ordinary user credentials or client artifacts. Automatic rollback paths were prepared and an earlier isolated inventory restore drill existed, but this exact assurance rollout set was not restored end-to-end after deployment.
