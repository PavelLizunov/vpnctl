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

### AUD-001 — WgTurn backend lacks forwarding and NAT

- **File:** `crates/kernels/src/wgturn.rs:482-496`
- **Evidence:** the generated `wgturn-be` WireGuard interface contains only an INPUT filter. It does not enable `net.ipv4.ip_forward`, accept forwarding, or MASQUERADE traffic through the default egress interface.
- **Impact:** clients can establish a tunnel through the relay but forwarded internet traffic is dropped or leaves with private `10.7.0.x` source addresses.
- **Minimal fix:** persist IPv4 forwarding and render symmetric `PostUp`/`PostDown` FORWARD and MASQUERADE rules using a detected egress interface.

### AUD-002 — Clean Debian 12 sing-box install can fail because fail2ban lacks python3-systemd

- **File:** `crates/kernels/src/sing_box.rs:209-247`
- **Evidence:** setup installs `fail2ban` with `--no-install-recommends`, configures `backend = systemd`, and then requires the service to be active. On Debian 12, `python3-systemd` is recommended rather than required by the package.
- **Impact:** a clean/minimal Debian deployment can abort in `ensure_installed` when fail2ban cannot import the systemd backend.
- **Minimal fix:** explicitly install `fail2ban python3-systemd`.

## Important findings

| ID | Area | Finding and impact | Minimal remediation |
|---|---|---|---|
| AUD-003 | SSH | `crates/ssh/src/russh_transport.rs:164-211` protects the initial handshake with a timeout but not RSA negotiation or public-key/password authentication. A tarpit or broken PAM stack can hang a worker indefinitely. | Wrap the complete connection/authentication pipeline in `tokio::time::timeout`. |
| AUD-004 | SSH | `crates/ssh/src/russh_transport.rs:52-56` compares fingerprint strings exactly, while accepted inventory shapes include padded and URL-safe base64. A fingerprint that passes validation can later fail host verification. | Normalize padding and URL-safe alphabet before comparison, or canonicalize at write time. |
| AUD-005 | Protocol | `crates/protocols/src/tuic_v5.rs:88-116` uses an empty password when `tuic_password` is absent, while the server omits that user. Generated clients fail authentication silently. | Return `CoreError::Render` for missing password in client config and share link. |
| AUD-006 | Protocol | `crates/protocols/src/hysteria2.rs:269` emits an empty password in `client_config`, although its share link rejects the same missing credential and the server omits the user. | Fail rendering when `tuic_password` is absent. |
| AUD-007 | Protocol | `crates/protocols/src/wgturn.rs:285` emits IPv6 endpoints without brackets, producing values such as `2a00::1:56000` that Go `net.SplitHostPort` rejects. | Use `host_for_url` before adding the port. |
| AUD-008 | Protocol | `crates/protocols/src/dns_tunnel.rs:259-275` declares no effective UDP listen port even though the kernel listens on configurable UDP 53. Drift, conflict and quality checks miss it. | Implement `listen_ports` and secret-aware `effective_listen_ports`. |
| AUD-009 | Protocol | `crates/protocols/src/vless_xhttp.rs:209-210` binds Xray to `0.0.0.0`, preventing IPv6 clients from connecting on dual-stack/IPv6-only nodes. | Bind the inbound to `::` if the deployed Xray configuration supports the intended dual-stack behavior. |
| AUD-010 | Kernel | `crates/kernels/src/caddy.rs:233-255` reports/restarts only `caddy.service`, not the managed `caddy-vlessws.service` backend. The page can report healthy while clients receive 502. | Check and restart both units when VLESS-WS is active. |
| AUD-011 | Kernel | `crates/kernels/src/dns_tunnel.rs:436-441` probes for sing-box but never installs it; absence also causes redundant slipstream uploads. | Install sing-box or fail clearly, and separate the two presence checks. |
| AUD-012 | Kernel | First-deploy failures in `dns_tunnel_apply_script` and `wgturn_apply_script` leave enabled `Restart=on-failure` units crash-looping when no backup exists. | On first-deploy failure, stop/disable units and remove failing configs. |
| AUD-013 | Inventory | `crates/inventory/src/sqlite/stats/rollups.rs:213-225` omits `servers.usage_coefficient` from monthly daily-rollup totals. Quotas undercount weighted servers. | Join `servers` and apply the coefficient consistently with other traffic queries. |
| AUD-014 | Inventory | `crates/inventory/src/sqlite/models.rs:701-706` slices the last four bytes of a UTF-8 Telegram token without checking a character boundary. Non-ASCII input can panic a production request. | Extract trailing characters with `chars()` or validate ASCII tokens before storage. |
| AUD-016 | Boosty | `crates/boosty-bridge/src/sync.rs:53-69` releases the DB sync lease only on normal async completion. Cancellation can block all syncs for ten minutes. | Use a cancellation-safe/RAII lease guard. |
| AUD-018 | CLI | `cli/src/ui.rs:15-17` calls `create_dir_all("")` for `--db inv.db`, so a valid bare relative DB path fails. | Skip directory creation for an empty parent path. |
| AUD-019 | CLI | `cli/src/cmd/render.rs:84` writes `# === kernel ... ===` headers to stdout, breaking advertised JSON and `sing-box check` pipelines. | Send metadata to stderr or suppress the header for a single rendered config. |
| AUD-020 | CLI | `backup.rs` and `migrate.rs` default to `/var/lib/vpnctl/inv.db`, while other commands use the XDG data directory. Commands can operate on different inventories. | Route all commands through `ui::resolve_db_path`. |
| AUD-021 | Runtime | `daemon/src/health_monitor/poller.rs:89-107` applies a historical-condition suppression gate to edge-triggered down/pressure events. Missing recovery history can suppress future real outages permanently. | Restrict the gate to level-triggered alerts or redesign the persisted state check. |
| AUD-022 | Runtime | Deploy-key path resolution is duplicated and inconsistent: `daemon/src/app/state.rs:90-97,188-193` ignores `VPNCTLD_DEPLOY_KEY`, and other hardcoded `DEFAULT_DEPLOY_KEY_PATH` call sites remain in admin Boosty actions, server deploy actions, legacy deploy SSE, settings rendering, user redeploy tasks and drift checks. | Centralize deploy-key resolution in one helper and use it across every production caller. |
| AUD-023 | Runtime | `daemon/src/ssh_subprocess.rs:508-512` uses `with_extension("pub")`; a private key `id.key` produces `id.pub`, while `ssh-keygen` creates `id.key.pub`. | Append `.pub` to the complete private-key path. |
| AUD-024 | Alerting | `daemon/src/alert_text/templates.rs` has no `server.quality.degraded` arm, so rich metrics collapse to opaque fallback text. | Add localized quality rendering and register the kind in template coverage tests. |
| AUD-025 | Alerting | `daemon/src/quality_poller.rs:391-400` auto-acks recovered quality alerts in SQLite but never edits the Telegram alert. | Call the shared recovery notification path before/with auto-ack. |
| AUD-026 | CI | `.forgejo/workflows/ci.yml:29-34` runs the Python/git-based project-map check in `rust:1.85-slim-bookworm` without installing Python or Git. | Install `python3 git` with the other build dependencies. |

## Verified minor findings

These are lower priority but reproduced by a group verifier:

- `crates/host-fingerprint/src/lib.rs`: raw keyscan comments can become a misleading `KeygenFailed` error.
- `crates/ssh/src/russh_transport.rs`: stdout is discarded for non-zero commands when stderr is empty.
- `crates/core/src/lib.rs`: duplicate protocol IDs produce a misleading self-conflict error.
- `crates/protocols/src/naive.rs`: an explicitly empty domain passes validation.
- `crates/protocols/src/wireguard/protocol.rs`: `client_config` hardcodes `10.66.0.2/32` instead of peer-derived addressing.
- `crates/protocols/tests/spec_ipv6_sharelink_brackets.rs`: missing WgTurn and several newer protocol cases.
- `crates/kernels/src/caddy/render.rs`: Naive Caddy config does not explicitly disable HTTP/3/UDP 443.
- `crates/kernels/src/dns_tunnel.rs`: no UFW opening for its public UDP port.
- `crates/kernels/src/sing_box.rs`: user-removal confirmation depends on an ambient host environment variable rather than an in-band web action.
- `crates/inventory/src/sqlite/users/grants.rs`: one query omits `disabled` and relies on a row-mapper fallback.
- `crates/inventory/src/sqlite/sessions.rs`: latest GeoIP labels tie on timestamp rather than monotonic row ID.
- `crates/inventory/tests/spec_idle_users.rs`: zero-day boundary case is clock-sensitive.
- `crates/boosty-bridge/src/reconcile.rs`: duplicate upstream subscribers can duplicate report entries.
- `crates/boosty-bridge/src/sync.rs`: refresh-token persistence failure can leave applied state with stale report/timeline data.
- `crates/boosty-bridge/tests/sync_integration.rs`: one mock listener task is not aborted.
- `cli/src/cmd/registry_cmd.rs`: prints a stale hardcoded registry snapshot rather than the built registry.
- `cli/src/cmd/bootstrap.rs`: validates registry support after mutating the remote authorized_keys file.
- `cli/src/ui.rs`: path/formatter edge cases lack focused unit tests.
- `crates/inventory/src/sqlite/alerts.rs`: NULL server scope in latest Telegram message lookup is broader than exact NULL matching.
- `daemon/src/alert_sink.rs`: token redaction occurs after stderr truncation.
- `daemon/src/dns_resolver.rs`: empty input passes the character whitelist and spawns `getent`.
- `daemon/src/handlers/admin/monitoring.rs`: GeoIP mtimes bypass configured display-timezone formatting.
- `daemon/src/handlers/admin/legacy/shell.rs`: dead duplicate shell/navigation implementation remains after extraction.
- `scripts/project-map.py`: internal `tests.rs` modules are counted as production LOC.

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

1. **Immediate kernel deployment blockers:** AUD-001 and AUD-002.
2. **SSH trust and timeout reliability:** AUD-003 and AUD-004.
3. **Broken generated client artefacts:** AUD-005 through AUD-009.
4. **Kernel runtime reliability:** AUD-010 through AUD-012.
5. **Accounting, panic and lease safety:** AUD-013, AUD-014 and AUD-016.
6. **CLI correctness and CI parity:** AUD-018 through AUD-020 and AUD-026.
7. **Runtime alert/deploy reliability:** AUD-021 through AUD-025.
8. Address minor findings opportunistically with the owning subsystem.

## Audit limitations

- This audit is static and adversarial; it does not replace live target validation for kernel installers, firewall behavior, or host distribution packaging.
- Existing green CI proves current tests and build gates pass, not that every finding above is already covered by a regression test.
- No production state, credentials, inventory rows, or live server secrets were accessed.
