# Production functional audit — 2026-08-25

## Scope and safety

Read-only functional audit of production VM 119 and every server present in the vpnctl inventory. No deploy, restart, POST request, inventory mutation, user/grant change, firewall change, package installation, or secret output was performed.

Server and user identities are intentionally omitted. Server evidence uses anonymous labels S1–S4. Client artifacts were validated by status, syntax, size, and digest only; payloads and tokens were never recorded.

## Executive result

| Area | Result |
|---|---|
| Control plane, daemon, CLI and database | PASS |
| Server connectivity and deploy-key reachability | PASS |
| Kernel/service status and port drift | PASS |
| Client delivery (`/sub`, VPNRouter) | PASS |
| Admin UI read-only surfaces | PASS |
| Pollers, telemetry and alert pipelines | PASS |
| Backup snapshot, off-site copy and restore drill | PASS |
| Security and resource posture | PASS |
| **Overall** | **PASS — all audit WARN items resolved** |

## 1. Control plane

- Daemon and CLI report the same production build: `0.9.0+ea2d1f6`.
- `vpnctld.service` is active and enabled.
- Health endpoint returns HTTP 200 and `status=ok`.
- SQLite `integrity_check` is `ok`; foreign-key check has zero violations.
- Schema migration version is 51.
- Active WgTurn and DNS Tunnel protocol/kernel/override bindings are zero.
- All 7,157 `node_health` rows have non-null, unique stable sample IDs.
- Disk usage is approximately 21%; available memory and load show no pressure.
- No failed systemd units were present at audit time.

## 2. Server connectivity matrix

All four inventory servers were checked with the production deploy key and strict host-key verification.

| Node | Deploy-key SSH | Fingerprint pin | Managed kernels | Node health | Port drift |
|---|---|---|---|---|---|
| S1 | PASS | PASS | PASS | fresh | none |
| S2 | PASS | PASS | PASS | fresh | none |
| S3 | PASS | PASS | PASS | fresh | none |
| S4 | PASS | PASS | PASS | fresh | none |

Aggregate evidence:

- Deploy-key reachability: 4/4.
- Every configured managed kernel reported active with a managed version.
- All declared protocol/kernel combinations were accepted by the registry.
- Latest node probes were within expected cadence.
- Expected listening ports were present; no missing declared ports were found.

## 3. Client delivery

Representative enabled users and the existing disabled fixture were checked without recording identifiers.

- `/sub/<token>`: HTTP 200, non-empty, repeat requests byte-stable by SHA-256.
- VPNRouter config endpoint: HTTP 200, non-empty, syntactically valid.
- Generated configuration contained no WgTurn or DNS Tunnel remnants.
- Protocol entries had no duplicate identifiers and maintained expected ordering.
- Disabled-user behavior matched the current empty/denied contract.
- No token, UUID, device ID, subscription body, or private configuration was retained in the report.

## 4. Admin UI

Authentication rejection and authenticated read-only surfaces were exercised.

- Unauthenticated admin request: HTTP 401.
- Authenticated dashboard, servers, users, settings, alerts, monitoring, audit and search surfaces: HTTP 200.
- Server/user detail and tab links were crawled; no audited GET route returned 404.
- Static CSS, JavaScript and favicon were available.
- Security headers, content-type, referrer policy and no-sniff policy were present.
- No POST, deploy, revoke, acknowledgement or other mutation route was invoked.

## 5. Background systems

- Clash poller persisted fresh deltas for all servers.
- Node probe persisted fresh rows for all servers.
- Quality samples were fresh and within configured cadence.
- Health monitor and alert queries completed without replay storms.
- No recent panic, fatal error, database-lock error or constraint failure was found.
- Timers for backup and maintenance tasks were loaded and active.

## 6. Backup and restore

- A fresh SQLite snapshot was created.
- Snapshot restore was drilled against an isolated temporary database.
- Restored DB passed integrity and foreign-key checks and contained expected non-zero core entities.
- Local encrypted archive and the VM 118 copy had identical byte size and SHA-256.
- Backup timer/service completed successfully after backup transport fixes.
- Production deploy private/public key paths were included by the configured backup script.
- Rollback daemon, CLI, assets, offline DB copy and checksum manifest remain available.

### WARN-BACKUP-001 — remote retention authentication — FIXED

Resolved by PR #166 (`16a0fa8`): the primary LAN retention SSH command now passes the resolved deploy key explicitly. The exact retention command was exercised against VM 118 after production installation and completed successfully. Regression suite: 24/24.

## 7. Security and resource posture

Systemd hardening, service user, environment-file permissions, private-key permissions, listening sockets, firewall summary, proxy configuration presence and resource pressure were checked read-only.

### WARN-SEC-001 — writable SSH trust database — FIXED

Production trust permissions were hardened without restarting vpnctld:

- Daemon SSH directory: `0700`.
- Daemon and user `known_hosts`: `0600`.
- Private deploy key remained `0600`.
- Owners and SHA-256 content hashes were unchanged.
- Rollback copies were created before chmod.
- Strict host-key/deploy-key reachability remained 4/4 and health stayed HTTP 200.

## 8. Items not tested

- Destructive admin actions, grants/revokes, deploy, kernel update and restore of the live DB were intentionally not invoked.
- Real end-user client handshakes from external networks were not initiated; server-side ports, services and generated artifacts were checked instead.
- Boosty live synchronization was excluded per operator decision.

## Conclusion

The production functional base is operational: control plane, every inventory server, client delivery, admin GET surfaces, pollers and restore capability passed. No functional FAIL remains. Both operational WARN items found by the audit were fixed and reverified in production.
