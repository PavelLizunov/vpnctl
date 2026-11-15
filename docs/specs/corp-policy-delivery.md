# Corp portal delivery runbook

This is a source-backed procedure for a later explicitly authorized delivery.
It does not deploy, enable Corp, issue employee installers or authorize a merge.
The client private-installer procedure is in VPNRouter's
[delivery runbook](https://github.com/PavelLizunov/VPNRouter/blob/dsh/business-policy-health-plan-20261114/docs/business-policy-delivery.md).
Pin the accepted client/backend SHAs and applicable CI before executing it.

## Prepare ingress and runtime

1. Use the existing consistent inventory backup/restore procedure in
   [backup-restore](backup-restore.md). Preserve Corp credentials, policy ID,
   revision/history, signed bytes and audit; record the highest delivered
   revision outside a backup that can be rewound. Retain complete credentials
   privately before replacement or use. Do not copy them into task reports.
2. Deploy the accepted daemon, CLI, assets and managed sing-box from one revision
   using [deployment](deployment.md). The probe executable is fixed at
   `/opt/vpnctl/node-artifacts/sing-box`; verify the pinned XHTTP-capable artifact.
   The daemon owns private `/var/lib/vpnctl/corp-probes` (0700). It needs its
   own child's proc TCP/fd view and loopback sockets; unavailable runtime leaves
   enable/probe unavailable. No root capability or arbitrary executable setting
   is required. Check service resource limits and process cleanup after a probe.
3. Publish the canonical IPv4 DNS A address and valid public TLS chain for
   `admin.corp.ninitux.com`. The current observer admits IPv4 and mapped IPv4
   only. Defer AAAA/public IPv6 until its acceptance/denial behavior is separately
   verified; do not infer IPv6 proof from an IPv4 observation.
4. Preserve the canonical Host through the HTTPS proxy, strip caller-supplied
   address/forwarding headers, and set one authoritative X-Real-IP plus the actual
   external X-Forwarded-Proto. Set `VPNCTLD_TRUSTED_PROXIES` to the exact intended
   proxy peers. Prevent public direct access to the backend listener. Untrusted
   peers cannot supply client-IP evidence, and a trusted proxy must not pass a
   caller's chosen IP. Do not log Authorization, cookies, request bodies or probe
   echo headers; keep the observer access path out of verbose access logs.
5. Keep the operator host separate from the Corp host. Configure nonempty
   `VPNCTLD_ADMIN_USER`, `VPNCTLD_ADMIN_PASSWORD` and one canonical HTTPS
   `VPNCTLD_CORP_OPERATOR_ORIGIN`. The private operator UI is `/admin/corp` on
   that origin; it must not be exposed by the public Corp virtual host.

Ingress has three different authentication paths:

| Path | Required evidence |
|---|---|
| Browser login/editor and its protected APIs | Enabled binding/user, fresh matching verified VPN exit, separate password/session and appropriate Origin/CSRF |
| GET `/api/v1/corp/policy` | Enabled binding/user and separate reader bearer; no browser-IP/password requirement |
| POST `/api/v1/corp/egress-observation` | Single-use active probe bearer and actual resolved peer; works during disabled setup |

Do not add a blanket browser-IP/password gate before the reader or observer.
Do not redirect machine paths. The proxy preserves the observer's204 status and
single X-Corp-Probe echo. Alternative hosts never select the Corp binding.

## Prepare the binding and private client bundle

1. Open the authenticated operator page, select the intended existing enabled
   Corp subscription user, confirm permanent binding and choose
   `Создать привязку`. This identity cannot be rebound; verify the selection
   before confirming. Setup remains disabled at revision0 and publishes nothing.
2. Save the one-time generated employee password in permanent private owner
   credential storage before using it or leaving the reveal. Keep it separate
   from operator credentials. A lost reveal requires deliberate password rotation;
   loading the status page cannot recover plaintext.
3. Choose the intended reader under `Доступ клиентов к политике` and download
   `business.policy`. Archive the complete sensitive file privately. It contains
   only policy ID, exact fixed reader endpoint, reader bearer and public keys;
   it is not a standalone employee import file. Add this object to the preserved
   complete private Corp provisioning bundle, retaining every subscription,
   support and identity field. Never put it into a public/shared update.
4. Build and rehearse the private installer bridge using the client's procedure.
   Older embedded EXEs overwrite persisted provisioning at startup, so editing
   their saved JSON is insufficient. Retain journal replay floors and all support
   reports. Subsequent shared updates remain credential-free.

## Verify exits and activate deliberately

1. Use `Проверить выход` for the intended eligible servers, then
   `Обновить состояние проверки`. The job survives page closure. Saved proof
   and latest attempt are separate: a failed retry never makes old proof younger.
   A server proof requires every selected endpoint, real observer callback,
   successful TLS/echo and complete helper cleanup. Inventory/DNS/server ingress
   addresses are not exit proof. Missing/stale/changed evidence cannot grant
   browser access. Initial automatic refresh starts after30s and rotates bounded
   scans every10min; evidence is renewed after6h and expires after24h.
2. Rehearse both Business modes on the intended client. Portal TCP and HTTPS DNS
   use the exact selected direct VLESS choice; portal UDP is rejected. Verify
   public portal addresses are captured by the TUN rather than excluded by user,
   LAN or detected-route exclusions. Verify failover and every actual server
   transport in use, including Reality/XHTTP: config acceptance is insufficient
   to establish their deployed handshake or network reachability.
3. After the separately authorized activation decision and private-client
   rehearsal, confirm `Включить доступ`. The POST rechecks user/keys/fresh proof;
   the button alone grants nothing. Verify wrong IP, stale proof, wrong password,
   disabled subscription and forged forwarding fail; the intended VPN exit
   reaches login and its issued session works. Reader requests must still work
   with the employee VPN stopped, using their separate read capability.
4. At revision0 the editor starts from the embedded preset; setup did not publish
   it. Rehearse add/edit/delete, signed empty list, history restore at a greater
   revision, concurrent-save conflict and uncertain-response reconciliation.
   Default publication applies at the next connection. Apply-now needs explicit
   consent and never starts a stopped VPN. Verify two isolated intended clients,
   durable deletions across restart/update and preserved telephony/process rules.

## Rotation, shutdown and recovery

- Readers: add (maximum two), export and migrate clients, verify, then remove old.
  Never remove the last reader or infer migration from a download alone.
- Signers: add (maximum four), migrate overlapping public trust, activate, publish
  a newer revision, then retire only when no retained history needs the old key.
  Account for offline clients; server activation cannot install client trust.
- Password rotation replaces the password immediately and revokes sessions.
  `Завершить все корпоративные сессии` revokes sessions explicitly. Emergency
  `Отключить доступ` remains available even when cryptographic material is broken.
- Ordinary unchanged-IP renewal preserves sessions; changed exit authority
  revokes them. Uncertain helper cleanup poisons probing/enable until restart.
  Lost wait ownership quarantines resources without signalling reused IDs; after
  confirmed service termination inspect/remove only the retained task files.
- Before database rollback, freeze publication/access and preserve the highest
  issued revision. Restore consistently and publish newer content rather than
  lowering a client journal or deleting it. Reconcile keys and private bundles
  before enabling again. Follow the tested backup/restore procedure.

No production ingress, runtime, installer migration or activation has been
verified by this document. CI uses synthetic data and loopback fixtures; record
later delivery evidence separately with exact SHAs and redacted outcomes.
