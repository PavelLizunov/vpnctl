# Route failure: handoff for vpnctl development

Snapshot: 2026-11-05, UTC. This is a development handoff, not a live inventory.
Production identifiers below are server aliases only; subscription URLs,
client IPs, account identities, UUIDs, keys and raw configurations stay outside
Git. No vpnctl application code or schema was changed by this handoff.

Full operational evidence and the now-tracked AI egress updater are in
[homelab-infra-docs, incident snapshot](https://github.com/PavelLizunov/homelab-infra-docs/blob/511d877c32cdaf844185f51fe09c6183d43c33e1/docs/incidents/vpn-route-2026-11-05.md).

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
dynamic scanner results. No scanner job was launched. A public blocklist entry
is therefore unconfirmed, while the packet loss is independently observed.

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
Optional external blocklist enrichment should retain source and timestamp and
remain distinct from measured protocol health; this incident's list lookup
did not identify the actual connectivity failure.

**Subscriber scope:** implement and name compatible automatic selection paths
per artifact/client. A new import, a refreshed subscription, an already-running
client and an old static single-IP profile need separate acceptance cases.
Provide a migration path for artifacts that cannot switch automatically.
An outage can interrupt existing TCP sessions even when new connections recover.

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

Operational SSH/socket/HTTP probes and the controlled packet capture supplied
the observations above. Application builds, automated suites and forced failover
of production clients were not run. The document does not claim a universal
automatic redirect has shipped; that development remains open in `BACKLOG.md`.
