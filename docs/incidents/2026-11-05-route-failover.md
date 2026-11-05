# Route failure: handoff for vpnctl development

Snapshot: 2026-11-05, UTC. This is a development handoff, not a live inventory.
Production identifiers below are server aliases only; subscription URLs,
client IPs, account identities, UUIDs, keys and raw configurations stay outside
Git. No vpnctl application code or schema was changed by this handoff.

Full operational evidence and the now-tracked AI egress updater are in
[homelab-infra-docs, incident snapshot](https://github.com/PavelLizunov/homelab-infra-docs/blob/0c0cce7315a9c8bbc9630437a62a64760e6c6f49/docs/incidents/vpn-route-2026-11-05.md).

## What actually failed

[observed] `vpnctld` stayed active. Direct TCP connections from homelab to
`is-new` and `infomaniak` timed out; both VPS remained reachable through
independent Swedish and Netherlands routes, with exactly matching pinned SSH
keys and active expected VPN kernels. Their uptime did not indicate reboot.
The failures began around 14:59 and 15:58 respectively, not simultaneously.

[observed] A synchronized SYN-only capture on `infomaniak` at
19:33:59–19:34:09 saw a Netherlands control SYN and its SYN-ACK, but no home
source SYN during timed-out home TCP 22/443 connections. The capture was ready
before the probes and reported zero drops. This localizes the loss before the
guest interface. For Iceland, independent access is proven but a comparable
capture was unavailable.

[unknown] The responsible external hop/operator/ACL is not established.
Traceroute silence after the first three answering hops is not a proof of
where forwarding stops. Initial keyscan errors did not prove key rotation;
independent fingerprint comparison later matched the stored keys.

[observed] The owner's suggested Cheburcheck API returned `blocked: false`,
empty `blocked_subnets` and empty provider matches for both addresses at
19:44:42/19:45:03. This is a list lookup, not a direct-connectivity measurement.
Its [FAQ](https://cheburcheck.ru/kb/faq) notes incomplete lists and separates
dynamic scanner results. At that stage no scanner job had been launched;
the subsequent dynamic checks below materially extend the finding.

[observed] At 20:00:56–20:01:12, `is-new` received 36 of 43 observer reports:
26 `tspu_block`, 9 `uncertain`, 1 `ok`. At 20:01:34–20:01:49, `infomaniak`
received 37 of 43: 26 `tspu_block`, 10 `uncertain`, 1 `ok`. All were uncached.
For each address the 26 blocking verdicts cover 16 ASNs. The sole `ok` came
from AS8369, Chelyabinsk; it means a response after the calibrated DPI hop,
not an authenticated VPN transfer. Missing/uncertain reports are not counted
as blocking. The scope was only these two affected IPs.

[inferred] This is strong independent evidence consistent with regional
TSPU/IP filtering, while an official list entry remains absent. The specific
filtering hop on the owner's path is still unknown. Retain the distinction
between list lookup, scanner classification and an actual client handshake.

[observed] The owner's proposed is-new hostname resolves to homelab's public
address instead of the inventory target. Its SSH key differs; an isolated
VLESS Reality attempt retaining is-new credentials/SNI failed with connection
reset. DNS was not changed. The hostname is not a working is-new VPN entry in
this snapshot; the full report records the owner's supplied name and evidence.

## Operational changes already made

- Management for both targets uses `jump_via=transip` (Netherlands), replacing
  the temporary `bahnhof` route. The documented CLI performed the inventory
  mutations. Expected kernel status was obtained over the pinned relay path.
- AI gateway egress is a separate service on VM 123. An old root cron updater
  installed through QEMU Guest Agent on 2026-08-17 discarded Sweden and TRANSIP
  labels and restored the unavailable Iceland route every hour. The parser,
  exact selectors and primary/reserve policy were repaired and source-tracked.
- The owner prefers Netherlands because Sweden is heavily loaded. This is a
  policy preference, not a bandwidth-capacity measurement of Netherlands.
- VPN kernels on the two targets were not restarted; client identities, grants
  and `client_detour_via` were not changed by the repair.

The old installer's requesting actor/session remains unknown. VM journal
identifies `qemu-ga` UID 0 at 2026-08-17 16:14 UTC, not the human/agent that
requested that guest command.

## Revision and active work

[observed] The inspected production CLI was `0.9.0+59477de`, matching
`/var/lib/dsh/task-worktrees/vpnctl-business-node-metadata-20261105`.
The shared primary `/var/lib/dsh/Project/vpnctld` was on older pending
`3729239`; it was not the deployed source revision. Another session is working
on Business telemetry/UI, so its current revision may have advanced since this
snapshot. Reconcile the deployed SHA with that work before implementation.

## Existing mechanisms and why they are insufficient

1. `jump_via` is static pinned management SSH routing. No automatic relay
   selection was found in the inspected deployed resolver/pollers.
2. `auto_suppress_when_unreachable` uses SSH probes (default three failed
   probes, 600-second cadence). Once relay SSH succeeds, the target looks
   healthy even if direct client VPN connections still fail. It is not the
   protocol/path health signal needed for this incident.
3. `client_detour_via` generates a new two-hop client configuration. It needs
   compatible clients and grants on both hops. URI-only legacy clients do not
   receive chained targets. Existing static IP profiles are not transparently
   redirected by changing this field.
4. Every affected account already had a grant on `transip`. Existing alternative
   nodes therefore do not require a mass grant migration, but clients still
   need a working selection/recovery mechanism.
5. Generic sing-box/Mihomo subscriptions in the inspected deployment use manual
   selectors. App-config refresh is 3600 seconds. VPNRouter has subscription-mode
   `AutoFailoverEngine`, and optional `AutoSelectBestServer` generates a same-
   protocol `urltest` pool. Custom/manual configurations have different behavior;
   these features are not a guarantee for every imported artifact or protocol.

## Next implementation slice

**Intent:** recover management and subscriber connectivity when the direct path
fails, with Netherlands preferred over Sweden, while reporting what actually
works. A reachable SSH relay is not proof of subscriber connectivity.

**Policy and state:** separate management route health from protocol health for
each measured vantage. Persist policy, selected route, last transition, failure
streak and recovery streak; use bounded probes, hysteresis and minimum dwell
time. Preserve existing SSH pins. A partially failed source network must not
silently declare a VPS globally dead or transfer every customer's traffic.

**Operator surface:** expose the preferred relay/fallback policy and current
direct/relayed/degraded states in the Web UI. Record actual transitions in the
audit log without no-op spam. Display stale/unknown observations distinctly.
Targeted external Cheburcheck enrichment is delivered in the activation below.
Its source/timestamp and regional observations remain distinct from measured
protocol health; the list lookup did not identify the connectivity failure.

**Subscriber scope:** implement and name compatible automatic selection paths
per artifact/client. A new import, a refreshed subscription, an already-running
client and an old static single-IP profile need separate acceptance cases.
Provide a migration path for artifacts that cannot switch automatically.
An outage can interrupt existing TCP sessions even when new connections recover.

**Endpoint identity:** the hostname case above had open TCP ports but reached
the wrong SSH identity and failed the intended VPN handshake. Address resolution,
service identity and protocol transfer need separate observations; port-open
alone must not be presented as a working node or a successful automatic repair.

**Acceptance scenarios for that future work:** direct SSH failure with healthy
NL relay; direct VPN-port failure with healthy relay SSH; partial regional
failure; NL failure with reserve recovery; policy retained after daemon restart;
stable return without flapping; unchanged identities/grants; fresh and stale
telemetry; compatible client recovery and explicit legacy limitations.
No forced-outage scenario or automated client test is claimed executed here.

Relevant sources to inspect at the deployed/next integration revision:

- `crates/inventory/src/jump_resolver.rs`
- `crates/ssh/src/subprocess.rs`
- `daemon/src/node_probe_poller/probe_inspector.rs`
- `daemon/src/clash_poller.rs`
- `daemon/src/node_probe_poller/{fail_state,alerts,scheduler}.rs`
- `crates/inventory/src/sqlite/servers/address.rs`
- `docs/specs/client-detour.md`
- `daemon/src/handlers/sub/{singbox,mihomo,v2ray}.rs`
- `daemon/src/handlers/vpn_router/{routes,collectors}.rs`
- VPNRouter: `VPNRouter.Core/Models/VlessConfig.cs` and
  `VPNRouter.Core/Services/{AutoFailoverEngine,ConfigGenerator.Outbounds,ConfigGenerator.OutboundBuilders}.cs`

## Validation boundary

Operational SSH/socket/HTTP probes, the controlled packet capture and the
external dynamic IP checks supplied the initial incident observations above.
That investigation did not run application builds, automated suites or forced
failover of production clients. The later Cheburcheck implementation and its
validation are recorded below. Universal automatic client redirect remains open
in `BACKLOG.md`.

## Cheburcheck activation: 2026-11-05 21:51–21:52 UTC

This is 2026-11-06 in Moscow. Source
`22ab7f0ed10d4d67d19a0f7f3de60ea273586dd5` is published in
[PR #312](https://github.com/PavelLizunov/vpnctl/pull/312), based on the previously
deployed `59477de` / PR #311. The feature PR is open; production runs its head.
Deployment source is `origin/feature/cheburcheck-integration`. This handoff branch
contains operational notes and remains separate from the deployment source.

[CI](https://github.com/PavelLizunov/vpnctl/actions/runs/42112113909) and the
[candidate package build](https://github.com/PavelLizunov/vpnctl/actions/runs/42112113847)
passed for that SHA. Local check, fmt, clippy, workspace tests and deny all exited
0; the final snapshot-lock change additionally passed check/fmt/clippy and the
12 admin contract tests, including concurrent GETs during completion. The
adapter has 36 spec-derived cases. Independent diff review findings were fixed.
CI also passed the Docker-backed SSH suites.

The static musl package's source and checksums were verified. Its daemon, CLI,
managed node artifacts and admin assets were installed with the source revision's
`scripts/deploy.sh`; vpnctld was restarted once. Health returned 200 with
`0.9.0+22ab7f0`, and systemd reported active. Existing VPS services and routing
policies were not redeployed by this feature installation.

The operator entry is **Monitoring → Cheburcheck**, also linked from each server.
`/admin/monitoring/cheburcheck` returned 401 without credentials and 200 with
credentials; both affected-node pages returned 200. Each selected node's POST
returned 303. Live validation used authenticated HTTP; browser layout review was
not run. GET pages read stored state, and there is no bulk external sweep.

Only the two affected aliases were submitted through the new panel action:

- `is-new`: start 21:51:29 UTC, finish 21:51:44 UTC. Static list miss;
  dynamic Done, 43 online observers, 41 reports: 31 `tspu_block`, 9 `uncertain`,
  1 `ok`, 2 missing, 0 cached. No service failure.
- `infomaniak`: start 21:52:11 UTC, finish 21:52:26 UTC. Static list miss;
  dynamic Done, 43 online observers, 41 reports: 32 `tspu_block`, 9 `uncertain`,
  0 `ok`, 2 missing, 0 cached. No service failure.

The journal contained exactly four Cheburcheck rows: start/result for each alias.
The pages displayed Finished/Done from those stored results. No observer IDs,
signed lookup contexts, credentials or inventory dumps are copied into this
handoff. Uncertain/missing reports do not count as filtering; `ok` is a response
after calibrated DPI, not an authenticated VPN transfer. These checks continue
to show regional filtering signals despite empty static blocklists.

Recovery options and automatic failover boundaries are now documented in the
[deployed source guide](https://github.com/PavelLizunov/vpnctl/blob/22ab7f0ed10d4d67d19a0f7f3de60ea273586dd5/docs/operations/blocked-node-recovery.md)
and [Cheburcheck contract](https://github.com/PavelLizunov/vpnctl/blob/22ab7f0ed10d4d67d19a0f7f3de60ea273586dd5/docs/specs/cheburcheck.md).
Prefer a Netherlands entry with the original VPS as exit for compatible updated
clients. Direct recovery requires a usable address/path; another prefix or
provider move is an option to discuss with the hoster. Old static profiles need
an updated artifact or a previously provisioned reserve. Automatic route changes,
new IP provisioning and end-to-end client-chain acceptance remain future work.
