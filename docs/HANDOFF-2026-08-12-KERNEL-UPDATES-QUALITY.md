# vpnctl — kernel updates, Web versions and server quality handoff (2026-08-12)

## Status boundary

This feature set is **implemented in the current checkout**. Production
deployment is not confirmed. Do not describe it as live, deployed or operating
on the fleet until the production checks at the end of this document have been
recorded with their actual results.

No version number, commit hash or live metric is asserted here. Managed kernel
versions remain defined beside each kernel implementation and are displayed by
the Web UI.

## Current implementation

The CLI and daemon registries both declare the same six kernels:

| Kernel id | Installed version source | Managed policy |
|---|---|---|
| `sing-box` | `sing-box version` | minimum floor |
| `amneziawg` | installed `amneziawg-tools` package version | minimum floor |
| `wgturn` | `/etc/wgturn/.installed-sha` | exact pin |
| `caddy` | `/usr/local/bin/caddy version` | exact pin |
| `dns-tunnel` | `slipstream-server --version` | exact pin |
| `xray` | `xray version` | exact pin |

`Kernel::status()` also reports active/inactive state. The ten-minute node
probe walks the server's declared kernel ids through the registry; successful
active/version observations are stored in `node_health.kernel_versions_json`.
An unregistered kernel or failed status command remains unknown without
discarding the other node-health fields.

On server detail, **Kernel versions** shows every declared kernel, installed
build, managed floor/pin, runtime state and current/stale/unknown result. A
node-health probe older than 20 minutes is marked stale. Dashboard and the
servers list both expose a compact fleet-wide table for every reported kernel;
server detail remains the authoritative per-node view.

## Binary-only updater contract

- The timer schedule is daily `00:30 UTC` / `03:30 MSK`, after the backup
  window. `Persistent=true` catches up after downtime and
  `RandomizedDelaySec=600` spreads the actual start by up to ten minutes.
- `--all` walks servers sequentially; each server's declared kernels are also
  processed sequentially. A per-kernel failure is recorded and the remaining
  kernels continue. A fleet run continues to later servers but ends in error
  if any server failed.
- Web deploy/update and CLI deploy/update share a non-blocking, cross-process
  per-server lock under `VPNCTLD_NODE_LOCK_DIR`. Contention is refused rather
  than run concurrently.
- The updater performs status-before → `ensure_installed` → status-after.
  Package/install logic may restart the kernel service. It does **not** render
  or apply config, open firewall ports, mint secrets or call `apply_config`.
- It never starts a host reboot. A package result or the standard
  `reboot-required` marker is reported in the stream and audit payload for a
  separately planned maintenance decision.
- Each server attempt writes `kernel.update` audit data with before/after
  versions, active state, errors and reboot-required status. Failures create
  or retain `kernel.update.failed`; a later successful update auto-acks it.

The Web UI is the operator surface:

- **Servers**: **update all kernels** runs the sequential fleet stream.
- **Server detail**: **update kernels** runs one-server canary with its own
  before→after log. **Deploy** is a different action and does apply config.
- **Audit / Alerts**: confirm `kernel.update` and any
  `kernel.update.failed` outcome instead of treating an HTTP/SSE connection as
  proof of success.

## Server-quality contract and limits

The native quality poller runs every five minutes by default. From the vpnctld
measurement point it resolves each server address and sends three TCP-connect
attempts, each with a two-second timeout, to every distinct TCP ingress port
declared by the server's enabled protocols.

Signals are deliberately separated:

- **Service path**: declared TCP VPN ingress. This alone feeds the service
  score.
- **Control path**: the server's SSH port. It has its own availability/p95 and
  cannot inflate service quality.
- **ICMP**: optional secondary context. Missing `ping` or permissions produces
  no ICMP value and does not make the TCP score incomplete.

The service score is 0–100: availability 40%, TCP-attempt success/loss 30%,
p95 latency 20%, and between-sample median-RTT jitter 10%. Latency receives full
credit at or below 100 ms and zero at or above 500 ms; jitter receives full
credit at or below 10 ms and zero at or above 100 ms.

Important interpretation rules:

- A 24h or 7d score remains unknown until there are at least 12 eligible
  service batches. At the default cadence this is about one hour, not an
  immediate verdict. Component metrics may appear provisionally before the
  score.
- No resolved target address means no quality row for that tick and the state
  remains unknown.
- UDP-only servers have no TCP service targets. Their control path can still
  acquire a score, but zero-target batches do not count toward the service
  minimum and the service score remains unknown. UDP quality is not measured
  by this implementation.
- Quality has no separate stale badge. Use the recent-sample timestamps on
  server detail; rolling-window data ages out naturally. Kernel-version stale
  markers refer to the node-health probe, not to quality freshness.
- Dashboard ranks by the 24h service score descending and also shows the 7d
  score. Unknown rows are not evidence of poor or good service.
- Raw quality rows are retained for 30 days. The displayed aggregates use
  rolling 24h and 7d windows; server detail shows the most recent 12 rows from
  its 24h history.
- After a score exists, three consecutive ticks below 60 raise
  `server.quality.degraded`; three consecutive ticks at or above 75 recover it.
  Unknown scores do not create a false degraded state.

## Safe Web canary

1. In **Dashboard**, note open alerts, the target server's current health,
   sing-box rollup and quality row. Unknown or stale telemetry is a reason to
   investigate before changing the node, not a green signal.
2. In **Servers**, choose one low-impact server. Do not begin with
   **update all kernels**.
3. On **Server detail**, note all declared kernel versions/runtime states and
   recent quality samples. Click **update kernels**, not **Deploy**.
4. Keep the stream open through the terminal event. For every kernel check the
   before→after version, `active=yes`, absence of an error, and the
   reboot-required result. A service restart may briefly interrupt clients.
5. Check **Audit** for the server's `kernel.update` row and **Alerts** for
   `kernel.update.failed`. If reboot is required, stop and schedule it
   separately; vpnctl has not rebooted the host.
6. Wait for the next node-health probe (ten-minute default), then refresh
   **Server detail** and **Dashboard**. Confirm the version/runtime marker is
   current and the quality/health picture has not regressed.
7. Only after the canary remains healthy use **update all kernels** on
   **Servers**. Review every server line and the final fleet event.

The nightly timer follows the same binary-only intent. Its existence does not
mean inventory config was applied, a host was rebooted, or the production run
succeeded.

## Release and production verification

Focused checks available in this checkout:

```text
cargo test -p vpnctl-kernels --test status_versions
cargo test -p vpnctl-inventory --test spec_quality
cargo test -p vpnctl update_kernels
cargo test -p vpnctld quality_poller
cargo test -p vpnctld --test admin_smoke update_kernels
cargo test -p vpnctld --test admin_smoke quality
```

After the normal vpnctl release process installs the matching daemon, CLI and
systemd units, verify the timer on the control host without exposing its env
file or inventory:

```text
systemctl cat vpnctl-update-kernels.timer
systemctl cat vpnctl-update-kernels.service
systemctl list-timers vpnctl-update-kernels.timer --no-pager
systemctl status vpnctl-update-kernels.timer --no-pager
journalctl -u vpnctl-update-kernels.service -n 100 --no-pager
```

Production remains **unverified** until all of these are observed directly:

- the installed unit text matches the checkout and the timer is enabled with a
  future trigger;
- one Web canary completes with all declared kernels active, with its audit row
  and no open update-failure alert;
- the next node-health probe displays real all-kernel versions and does not
  show a stale probe;
- Dashboard and server detail receive real quality samples; scores remain
  unknown until the 12-sample threshold is honestly reached;
- one scheduled timer run completes and its journal, audit rows and Alerts are
  reviewed;
- any reboot-required result is handled as a separate maintenance action, not
  attributed to the timer.

Until then, release notes must say: **implemented in current checkout;
production deployment not confirmed**.
