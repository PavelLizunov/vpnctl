# Colossal Gemini swarm audit — 2026-08-24

## Executive summary

A repository-wide audit was executed as **5 iterations × 10 non-overlapping file groups** using `ninitux/gemini-3.7-flash-high`.

- First layer: **50 independent audit passes**.
- Second layer: **10 full-group verification passes + 1 cross-group synthesis pass**.
- Tail verification: **4 additional daemon/public-surface passes** after the synthesis output was truncated.
- Total Gemini agents used: **65**.
- Lenses: correctness, security, architecture/invariants, test quality, and operations.
- Baseline: the branch was clean and GitHub CI was green before the audit.
- Auditors made no code changes. Findings below are a verified remediation backlog, not fixes shipped by this report.

The verification layer retained **2 critical** and **22 important** findings with high confidence. Lower-severity findings are grouped separately. Claims seen only once in the initial sweep and not reproduced by a group verifier were omitted.

## Coverage groups

| Group | Scope | Approximate size |
|---|---|---:|
| G1 | core, crypto, host-fingerprint, SSH | 19 files / 4.2K lines |
| G2 | protocols | 31 files / 9.9K lines |
| G3 | kernels | 13 files / 7.3K lines |
| G4 | inventory implementation and migrations | 94 files / 14.7K lines |
| G5 | inventory tests and Boosty bridge | 47 files / 14.2K lines |
| G6 | CLI | 20 files / 5.1K lines |
| G7 | daemon runtime, app, probes, wizard and SSH subprocess | 27 files / 10.8K lines |
| G8 | daemon background services and alerting | 16 files / 7.5K lines |
| G9 | admin production handlers | 53 files / 21.3K lines |
| G10 | public handlers, daemon tests, scripts, specs and CI | 87 files / 31.4K lines |

## Critical findings

### AUD-001 — WgTurn backend lacks forwarding and NAT [removed-with-wgturn]

- **Status:** removed-with-wgturn (WgTurn kernel and protocol removed from codebase in PR #155)
- **File:** `crates/kernels/src/wgturn.rs:482-496` (removed)
- **Evidence:** the generated `wgturn-be` WireGuard interface contains only an INPUT filter. It does not enable `net.ipv4.ip_forward`, accept forwarding, or MASQUERADE traffic through the default egress interface.
- **Impact:** clients can establish a tunnel through the relay but forwarded internet traffic is dropped or leaves with private `10.7.0.x` source addresses.
- **Remediation & Migration:** resolved via complete WgTurn codebase removal. Migration `0049_remove_wgturn.sql` removes active inventory bindings (`server_protocols`, `server_kernels`, `grant_protocol_overrides`) while intentionally retaining `wgturn:*` secrets in SQLite as rollback material for one transition release. A later secret purge requires a separate verified cleanup release.
- **Production Deploy Gate:** this code removal must NOT be deployed to production until legacy `wgturn.service` and `wg-quick@wgturn-be` are stopped, disabled, and removed on every affected server via hoster console (strictly following the no-SSH-instruction policy).

### AUD-002 — Clean Debian 12 sing-box install can fail because fail2ban lacks python3-systemd [fixed]

- **Status:** fixed (PR #156)
- **File:** `crates/kernels/src/sing_box.rs:209-247`
- **Evidence:** setup installs `fail2ban` with `--no-install-recommends`, configures `backend = systemd`, and then requires the service to be active. On Debian 12, `python3-systemd` is recommended rather than required by the package.
- **Impact:** a clean/minimal Debian deployment can abort in `ensure_installed` when fail2ban cannot import the systemd backend.
- **Remediation:** explicitly install `fail2ban python3-systemd` during sing-box package setup. Verified with unit and installation regression tests.

## Important findings

| ID | Area | Status | Finding and impact | Minimal remediation |
|---|---|---|---|---|
| AUD-003 | SSH | fixed (PR #160) | `crates/ssh/src/russh_transport.rs:164-211` protects the initial handshake with a timeout but not RSA negotiation or public-key/password authentication. A tarpit or broken PAM stack can hang a worker indefinitely. | Wrap the complete connection/authentication pipeline in `tokio::time::timeout`. |
| AUD-004 | SSH | fixed (PR #160) | `crates/ssh/src/russh_transport.rs:52-56` compares fingerprint strings exactly, while accepted inventory shapes include padded and URL-safe base64. A fingerprint that passes validation can later fail host verification. | Normalize padding and URL-safe alphabet before comparison, or canonicalize at write time. |
| AUD-005 | Protocol | fixed (PR #158) | `crates/protocols/src/tuic_v5.rs:88-116` uses an empty password when `tuic_password` is absent, while the server omits that user. Generated clients fail authentication silently. | Return `CoreError::Render` for missing password in client config and share link. |
| AUD-006 | Protocol | fixed (PR #158) | `crates/protocols/src/hysteria2.rs:269` emits an empty password in `client_config`, although its share link rejects the same missing credential and the server omits the user. | Fail rendering when `tuic_password` is absent. |
| AUD-007 | Protocol | removed-with-wgturn (PR #155) | `crates/protocols/src/wgturn.rs:285` emits IPv6 endpoints without brackets, producing values such as `2a00::1:56000` that Go `net.SplitHostPort` rejects. | Removed with WgTurn protocol removal. Active bindings removed by migration 0049; `wgturn:*` secrets retained for 1 transition release rollback window. |
| AUD-008 | Protocol | removed-with-dns-tunnel (PR #157) | `crates/protocols/src/dns_tunnel.rs:259-275` declared no effective UDP listen port even though the kernel listened on configurable UDP 53. | Removed with DNS Tunnel protocol and kernel removal. Active bindings removed by migration 0050; `dns-tunnel:*` secrets retained for 1 transition release rollback window. |
| AUD-009 | Protocol | fixed (PR #158) | `crates/protocols/src/vless_xhttp.rs:209-210` binds Xray to `0.0.0.0`, preventing IPv6 clients from connecting on dual-stack/IPv6-only nodes. | Bind the inbound to `::` if the deployed Xray configuration supports the intended dual-stack behavior. |
| AUD-010 | Kernel | fixed (PR #156) | `crates/kernels/src/caddy.rs:233-255` reports/restarts only `caddy.service`, not the managed `caddy-vlessws.service` backend. The page can report healthy while clients receive 502. | Check and restart both units when VLESS-WS is active. |
| AUD-011 | Kernel | removed-with-dns-tunnel (PR #157) | `crates/kernels/src/dns_tunnel.rs:436-441` probed for sing-box but never installed it; absence also caused redundant slipstream uploads. | Removed with DNS Tunnel kernel removal. |
| AUD-012 | Kernel | fixed (PR #156) | First-deploy failures in kernel apply scripts leave enabled `Restart=on-failure` units crash-looping when no backup exists. (DNS Tunnel and WgTurn apply script portions removed with their respective protocols/kernels; remaining kernels hardened). | On first-deploy failure, stop/disable units and remove failing configs for remaining kernels. |
| AUD-013 | Inventory | fixed (PR #158) | `crates/inventory/src/sqlite/stats/rollups.rs:213-225` omits `servers.usage_coefficient` from monthly daily-rollup totals. Quotas undercount weighted servers. | Join `servers` and apply the coefficient consistently with other traffic queries. |
| AUD-014 | Inventory | fixed (PR #158) | `crates/inventory/src/sqlite/models.rs:701-706` slices the last four bytes of a UTF-8 Telegram token without checking a character boundary. Non-ASCII input can panic a production request. | Extract trailing characters with `chars()` or validate ASCII tokens before storage. |
| AUD-016 | Boosty | deferred-with-reason | `crates/boosty-bridge/src/sync.rs:53-69` releases the DB sync lease only on normal async completion. Cancellation can block all syncs for ten minutes. | Deferred per user request: no Boosty code changes. Lease expires automatically after TTL (10m) upon cancellation. |
| AUD-018 | CLI | fixed | `cli/src/ui.rs:15-17` calls `create_dir_all("")` for `--db inv.db`, so a valid bare relative DB path fails. | Skip directory creation for an empty parent path. |
| AUD-019 | CLI | fixed | `cli/src/cmd/render.rs:84` writes `# === kernel ... ===` headers to stdout, breaking advertised JSON and `sing-box check` pipelines. | Send metadata to stderr or suppress the header for a single rendered config. |
| AUD-020 | CLI | fixed | `backup.rs` and `migrate.rs` default to `/var/lib/vpnctl/inv.db`, while other commands use the XDG data directory. Commands can operate on different inventories. | Route all commands through `ui::resolve_db_path`. |
| AUD-021 | Runtime | fixed (PR #160) | `daemon/src/health_monitor/poller.rs:89-107` applies a historical-condition suppression gate to edge-triggered down/pressure events. Missing recovery history can suppress future real outages permanently. | Restrict the gate to level-triggered alerts or redesign the persisted state check. |
| AUD-022 | Runtime | fixed (PR #160) | Deploy-key path resolution is duplicated and inconsistent: `daemon/src/app/state.rs:90-97,188-193` ignores `VPNCTLD_DEPLOY_KEY`, and other hardcoded `DEFAULT_DEPLOY_KEY_PATH` call sites remain in admin Boosty actions, server deploy actions, legacy deploy SSE, settings rendering, user redeploy tasks and drift checks. | Centralize deploy-key resolution in one helper and use it across every production caller. |
| AUD-023 | Runtime | fixed (PR #160) | `daemon/src/ssh_subprocess.rs:508-512` uses `with_extension("pub")`; a private key `id.key` produces `id.pub`, while `ssh-keygen` creates `id.key.pub`. | Append `.pub` to the complete private-key path. |
| AUD-024 | Alerting | fixed | `daemon/src/alert_text/templates.rs` has no `server.quality.degraded` arm, so rich metrics collapse to opaque fallback text. | Add localized quality rendering and register the kind in template coverage tests. |
| AUD-025 | Alerting | in-progress | `daemon/src/quality_poller.rs:391-400` auto-acks recovered quality alerts in SQLite but never edits the Telegram alert. | Call the shared recovery notification path before/with auto-ack. |
| AUD-026 | CI | removed-with-forgejo | `.forgejo/workflows/ci.yml:29-34` runs the Python/git-based project-map check in `rust:1.85-slim-bookworm` without installing Python or Git. | Removed with Forgejo workflow removal; CI is GitHub Actions only. |

## Verified minor findings

These are lower priority but reproduced by a group verifier:

- `crates/host-fingerprint/src/lib.rs`: raw keyscan comments can become a misleading `KeygenFailed` error. [fixed in PR #160]
- `crates/ssh/src/russh_transport.rs`: stdout is discarded for non-zero commands when stderr is empty. [fixed in PR #160]
- `crates/core/src/lib.rs`: duplicate protocol IDs produce a misleading self-conflict error. [pending]
- `crates/protocols/src/naive.rs`: empty/whitespace domains now fail closed across all artefacts. [fixed]
- `crates/protocols/src/wireguard/protocol.rs`: client config now uses peer-derived addressing. [fixed]
- `crates/protocols/tests/spec_ipv6_sharelink_brackets.rs`: missing several newer protocol cases (WgTurn removed). [fixed in PR #158 / WgTurn removed in PR #155]
- `crates/kernels/src/caddy/render.rs`: Naive Caddy config does not explicitly disable HTTP/3/UDP 443. [pending]
- `crates/kernels/src/dns_tunnel.rs`: no UFW opening for its public UDP port. [removed-with-dns-tunnel]
- `crates/kernels/src/sing_box.rs`: user-removal confirmation depends on an ambient host environment variable rather than an in-band web action. [pending]
- `crates/inventory/src/sqlite/users/grants.rs`: query now projects `disabled` explicitly. [fixed]
- `crates/inventory/src/sqlite/sessions.rs`: equal timestamps now use deterministic secondary ordering. [fixed]
- `crates/inventory/tests/spec_idle_users.rs`: zero-day and equal-time fixtures are deterministic. [fixed]
- `crates/boosty-bridge/src/reconcile.rs`: duplicate upstream subscribers can duplicate report entries. [pending]
- `crates/boosty-bridge/src/sync.rs`: refresh-token persistence failure can leave applied state with stale report/timeline data. [pending]
- `crates/boosty-bridge/tests/sync_integration.rs`: one mock listener task is not aborted. [pending]
- `cli/src/cmd/registry_cmd.rs`: prints a stale hardcoded registry snapshot rather than the built registry. [pending]
- `cli/src/cmd/bootstrap.rs`: validates registry support after mutating the remote authorized_keys file. [fixed in PR #160]
- `cli/src/ui.rs`: path/formatter edge cases lack focused unit tests. [pending]
- `crates/inventory/src/sqlite/alerts.rs`: NULL server scope in latest Telegram message lookup is broader than exact NULL matching. [fixed in PR #160]
- `daemon/src/alert_sink.rs`: token redaction occurs after stderr truncation. [pending]
- `daemon/src/dns_resolver.rs`: empty input passes the character whitelist and spawns `getent`. [pending]
- `daemon/src/handlers/admin/monitoring.rs`: GeoIP mtimes bypass configured display-timezone formatting. [pending]
- `daemon/src/handlers/admin/legacy/shell.rs`: dead duplicate shell/navigation implementation remains after extraction. [pending]
- `scripts/project-map.py`: internal `tests.rs` modules are counted as production LOC. [pending]

## Rejected or intentionally omitted candidates

The verification layer explicitly rejected or omitted claims that were not sufficiently reproducible, were intentional contracts, or were duplicates of a stronger root cause. Examples:

- Axum routes with the same path and different methods do not overwrite each other.
- EventSource mutation routes have a same-origin `Sec-Fetch-Site` gate.
- CSV exports already neutralize spreadsheet-formula prefixes.
- Backup downloads already enforce safe names and canonical paths.
- Returning HTTP 200 for unknown VPNRouter device IDs is a deliberate anti-fingerprinting contract.
- Session cookies intentionally omit `Secure` for the supported LAN HTTP deployment mode.
- Claims seen only in one of the original 50 passes and not reproduced by the second-layer group verifier are not included above.

## Recommended remediation order

1. **Immediate kernel deployment blockers:** AUD-001 (removed-with-wgturn, PR #155), AUD-002 (fixed, PR #156).
2. **SSH trust and timeout reliability:** AUD-003 and AUD-004 (fixed, PR #160).
3. **Broken generated client artefacts:** AUD-005, AUD-006, AUD-009 (fixed, PR #158; AUD-007 removed-with-wgturn in PR #155, AUD-008 removed-with-dns-tunnel in PR #157).
4. **Kernel runtime reliability:** AUD-010 and AUD-012 (fixed, PR #156; AUD-011 and DNS portion of AUD-012 removed-with-dns-tunnel in PR #157).
5. **Accounting, panic and lease safety:** AUD-013 and AUD-014 (fixed, PR #158); AUD-016 (deferred-with-reason per user request).
6. **Runtime alert/deploy reliability:** AUD-021 through AUD-024 fixed (PR #160 and final remediation wave); AUD-025 in-progress until code review passes.
7. **CLI correctness:** AUD-018 through AUD-020 fixed; AUD-026 removed-with-forgejo.
8. Address minor findings opportunistically with the owning subsystem (PR #160 addressed host-fingerprint keyscan, russh stdout, bootstrap key resolution, and alert query NULL server scope).

## Remediation Definition of Done (DOD) & Deployment Rules

- **Status semantics:** Every audit item must resolve to `fixed`, `removed-with-wgturn`, `removed-with-dns-tunnel`, `removed-with-forgejo`, or `deferred-with-reason` with documented justification and regression coverage where applicable.
- **Production deploy blocker for WgTurn & DNS Tunnel removal:** The WgTurn and DNS Tunnel code removal must **NOT** be deployed to production until legacy `wgturn.service` / `wg-quick@wgturn-be` and `dns-tunnel.service` / `dns-tunnel-singbox.service` units are stopped, disabled, and removed on every affected server via hoster console (following the web-only / hoster console policy — no SSH instructions).
- **Migration & rollback invariant:** Migrations `0049_remove_wgturn.sql` and `0050_remove_dns_tunnel.sql` remove active inventory bindings (`server_protocols`, `server_kernels`, `grant_protocol_overrides`) while intentionally retaining `wgturn:*` and `dns-tunnel:*` secrets for rollback safety across one transition release. Pre-0049 and pre-0050 verified inventory snapshots must be created and verified before deployment. A later secret purge requires a separate verified cleanup release.
- **Gate compliance:** All waves require isolated regression tests, passing local/CI gates (`cargo check`, `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo deny check`), and independent review before main integration.

## Audit limitations

- This audit is static and adversarial; it does not replace live target validation for kernel installers, firewall behavior, or host distribution packaging.
- Existing green CI proves current tests and build gates pass, not that every finding above is already covered by a regression test.
- No production state, credentials, inventory rows, or live server secrets were accessed.
