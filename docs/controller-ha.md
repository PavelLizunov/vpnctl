# Cooperating controllers (opt-in candidate)

Standalone `vpnctld` is unchanged. HA uses two controller gateways, three real
Consul voters, and an independent executor/storage witness. This candidate is
not activated in production. The witness is an availability dependency: losing
it blocks SSH operations and promotion. An unreachable controller can be replaced after the witness proves its durable
resource arm expired and the SSH epoch barrier has no unresolved action. This
version does not power-fence hosts. A suspended gateway also suspends its
own frontend until the process resumes or its service restarts.

Replication is asynchronous. A promoted controller may lose **acknowledged**
changes since the latest verified generation. `/admin/ha` shows its source age,
replication interval and promotion age limit. No zero-loss or multiwriter claim.

## Matching artifacts and initial preparation

Use identical `vpnctld` executables, these Python modules and worker environment
on all three services. Python 3.11+, unified cgroup v2, systemd with service watchdogs, OpenSSH and sshpass on the executor are required. Both
controllers need permission to manage their dedicated transient worker unit.
The gateways run separately from their workers; followers never open inventory.

1. Build the reviewed revision with `just build-release` on a [HomeLab worker](specs/agent-workflow.md#remote-builds-and-tests)
   or use the matching [CI artifacts](specs/deployment.md#2-production-facts). Inspect
   `vpnctld --ha-artifact`; copy its `executable_sha256` and `schema` into all
   configs. Migration checksums are checked independently at snapshot publication
   and promotion. Package `scripts/ha/{common,controller_ha,executor,gateway,lifecycle,observations,replica,transfer_pins,worker,worker_guard}.py`
   together under `/opt/vpnctl/ha/`. No third-party Python packages are needed.
2. Prepare three Consul voters with TLS, gossip encryption and ACLs. Gateways use
   consistent reads, TTL sessions and atomic CAS+lock transactions. Allow
   session write, operator read, and KV read/write only under the dedicated HA
   prefix. Consul's KV write ACL inherently permits deletion: operational policy
   must prohibit manually deleting/changing the lease record. Loss/rollback of
   Consul state requires all workers stopped and an explicit recovery procedure;
   never re-bootstrap an empty cluster over possibly live old controllers.
3. Issue separate control certificates, CN equal to each configured node ID,
   SAN matching its control URL, serverAuth/clientAuth EKUs, from a dedicated CA.
   Private control listeners require mTLS. They must not be exposed through the
   public reverse proxy. Retain full owner credentials before use in the owner's
   permanent store. There is no credential-generation command in this feature.
4. Adapt [controller.json](examples/ha/controller.json). `schema:0` and the build placeholder must be replaced with artifact values.
   Set the actual worker account and an independent root-owned `runtime_dir`
   (mode 0711) outside private state; its socket is owned by the worker and its
   non-secret deadline file is readable by the guard. Both controllers use the same four logical identity names and
   shared worker environment bytes; paths are local destinations. The witness
   uses `role:"witness"`, its own node/TLS/state/control settings, and
   `deploy_key` pointing to the **same existing deploy identity** as the seed.
   The witness does not run a public listener or worker and needs no inventory
   destination or identity mapping. Its executable/build/schema still match.
5. Disable automatic startup of the standalone service and stop it before actual
   cutover. Never run a standalone daemon or inventory-mutating CLI alongside HA. Start the witness
   and both gateways using [vpnctl-ha.service](examples/ha/vpnctl-ha.service).
   The seed inventory and identity files must already exist, worker stopped.
   Open `/admin/ha` on the seed address, Basic user `ha`, password from
   `admin_token_file`. Choose **Initialize stopped seed**, **Test readiness**,
   then **Resume automatic failover**. Initialization is single-use and refuses
   any existing lease history or advertised generation. Activation is separate
   from this development task; do not run these steps on production now.

Public listeners bind loopback behind the existing TLS reverse proxy, or use
`public_tls` certificate/key and bind directly with TLS. Set `public_origin` for
CSRF checks. Authoritatively overwrite `X-Real-IP` at the proxy, strip supplied
values, and list only its exact trusted address/CIDR. Workers bind loopback and
trust only the local gateway. Control-to-control forwarding uses mTLS and never
forwards more than once. No ambiguous HTTP mutation is automatically replayed.

The shared worker environment must not set a different HA socket or known-hosts
path. The supervisor supplies those plus the deploy-key path and loopback trusted
proxy list. The fixture `systemd_user` option is for isolated user-manager tests.
Do not configure an automatic restart on the transient worker: authority belongs
to the gateway, and systemd enforces its independent watchdog deadline.

## Operation and recovery

Use `/admin/ha` on either frontend for status, readiness, pausing/resuming
promotion and planned handover. Planned handover publishes a final consistent
snapshot, selects the peer, drains the worker, and releases its session. In
both observer modes, the selected peer clears the planned target once its
worker is healthy and admitted, using a settings compare-and-swap tied to its
session. Pausing automatic failover retains an existing healthy leader and
prevents acquisition of a new lease. Each operation still requires quorum and
fresh verified data.

### Observe both controllers from the VPN fleet

1. Enable `"observations": true` on both controllers. Give each gateway a
   distinct, directly routed HTTPS origin with its own valid hostname. Either
   serve TLS in the gateway or route `GET /_vpnctl_ha/health` from a local HTTPS
   reverse proxy to that gateway's loopback listener. Preserve `Content-Length`
   and the gateway response. Keep this route free of redirects, caching,
   compression, and cross-site fallback. The shared subscription URL remains
   independent.

   A reverse proxy can still answer HTTPS after its gateway fails. Use the
   [Caddy example](examples/ha/observer-health.Caddyfile) on each controller
   to return HTTP 200 with `{"node":"controller-a","status":"unavailable"}`
   for a dial failure or response-header timeout on that route to its local
   loopback gateway. Set `node` to the expected controller ID and set the
   upstream deadlines below the observer's probe deadline. Forward any HTTP
   status actually returned by the gateway. Generic HTTP 502 responses, other
   proxy errors, and TLS failures remain unknown to observers.
2. On the witness add [observer listener settings](examples/ha/observer-listener.json)
   to `witness.json` under `observer_listener`. The listener takes only probe
   reports over mTLS and uses a different CA from the HA control plane. Issue a
   separate client certificate for each VPN host. Enroll each unique leaf DER
   SHA-256 fingerprint with a short ID and its hosting network (shared network
   means shared label). At least three IDs and two networks are required.
   Replacing or removing a pin and restarting the witness revokes the old
   certificate for this listener and clears the old tally. Retain the complete
   credentials before use. Keep the listener separate from the public ingress.
3. Copy `scripts/ha/observer.py` to `/opt/vpnctl/ha/` on the VPN hosts and install
   [the service](examples/ha/vpnctl-ha-observer.service) and
   [timer](examples/ha/vpnctl-ha-observer.timer). Adapt
   [observer.json](examples/ha/observer.json) and the systemd credentials on each
   host. Enable the timer. The observer needs only outbound HTTPS to both
   controllers and the collector. It has no Consul or controller permissions.
4. Open `/admin/ha` and check the reports in **VPN server observations**. Start
   in monitoring mode and verify both sites from each hosting network. Use
   **Require observer confirmation** to require agreement for automatic
   cross-site takeover. **Observe without blocking failover** restores the
   existing automatic policy. The observer policy is shared through Consul.
   A manual planned handover still needs a fresh replica and verified fencing.

Each observation expires after twenty seconds. An opinion needs two fresh
consecutive reports and a confirmed direction needs more than half of the
configured observers with support from at least two different networks. Unknown
TLS/DNS paths and missing reports never reduce that threshold. Under
enforcement, if votes drop below the threshold, a running healthy owner can
continue and a recovered incumbent can reacquire. A new owner needs
confirmation or a planned handover.
If the owner still reaches Consul while public access is lost, it records an
automatic handover against its current session before closing the worker;
the peer rechecks approval before attempting acquisition. The witness freezes
the tally while reserving admission in Consul. The reservation must be confirmed
before the proof expires. The witness then records admission in Consul settings
using the same exact lease and the reservation index. A late or ambiguous
reservation leaves the recorded incumbent unchanged. The worker serves only
after admission is recorded, and only probe pairs started after admission can
vote on the next transfer. The authorization path still verifies resource
fencing and the latest recoverable SQLite copy.

An old node rejoins with its local worker stopped, downloads the witness's latest
immutable generation, and replaces its divergent database only after fencing.
No database merge, automatic migration or subscription-identity regeneration
occurs during promotion. Exact executable, embedded migrations, file hashes,
SQLite integrity/FKs and deployment identity must match.

The executor fsyncs an intent before every SSH dispatch. An observed remote exit (including 1..254) or a proven pre-dispatch rejection
is a completed failure returned once to its caller; it does not block later
operations. A lost result, SSH exit 255, timeout or interrupted helper is
**uncertain**, survives restart and blocks later dispatch and promotion. The status lists exact job IDs. There is no blind
retry or “mark successful” button. Remote completion/fencing must be proven
before an operator can perform recovery; this candidate deliberately has no
unsupported automatic resolution for an unreachable remote action. Preserve its
ledger and all remote evidence when recovering through the hoster's console.

For rollback, first pause promotion, stop both gateways and their dedicated
workers, prove both worker cgroups empty and resolve any executor uncertainty.
Retain the latest verified generation and existing credentials. Restore the
selected consistent generation/identities with no workers running, then start
exactly one matching standalone daemon. Keep the other stopped. Do not restore
an older Consul epoch or run standalone concurrently with HA workers.

## Isolated verification

`python3 -m unittest discover -s scripts/ha -p 'test_*.py'` runs stdlib fixture
checks. Opt in to real quorum/cgroup fault tests with:

```
VPNCTL_HA_CONSUL_BINARY=/path/to/verified/consul \
VPNCTL_HA_SYSTEMD_TESTS=1 \
python3 -m unittest discover -s scripts/ha -p test_isolated_cluster.py -v
```

They use loopback three-voter Consul, a fixture CA, temporary SQLite/identities,
fixture transports and only `vpnctl-ha-worker-fixture-{a,b}.service` transient
units. No real node commands, production keys, inventory or services are used.

Snapshot data uses fixed logical files and verified 1 MiB chunks over mTLS,
with bounded zlib decoding. Authenticated transfer pins keep one immutable
generation readable per controller while newer generations publish and prune.
Pins expire without renewal (default ten minutes, configurable
`snapshot_transfer_timeout_ms`, maximum one hour), release after download, and
are invalidated on witness restart; their hard links add bounded operational
retention without copying file data. Receivers reuse unchanged chunks from their previous
verified generation. Full-file hashes, SQLite integrity/FKs, exact migrations,
build and identity checks still precede publication. Each process uses bounded
SQLite caches; no whole inventory enters a control JSON/base64 frame. The 8 GiB
snapshot limit bounds disk use; it is not an allocation.

Operational stores keep the latest advertised generation and one previous
recovery generation, plus an in-progress generation. `snapshot_keep_generations`
may raise the two-generation minimum; `snapshot_reserve_bytes` defaults to 2 GiB.
Capacity failure degrades replication without stopping a healthy controller;
the UI shows the error and increasing snapshot age. Bulk copying, verification,
installation and pruning run separately from authority renewal. No generation is
advertised after its authority or age check fails. Failed unpublished verified
generations are removed after a later successful publication; the reserve stops
further allocations if publication cannot recover.

Set `credential_root` to an absolute directory under the operator's
`~/.local/share/agent-credentials/vpnctl-ha/` on each participating machine,
independent of operational `state_dir`. The default uses that location under the
service account's home, keyed by store path. Never include it in snapshot cleanup.
Immutable `versions/<sha256>/` directories contain complete deploy/private/public
key, known_hosts and environment bytes, plus SQLite-restorable `database.sql`
with credential/config rows and schema. The archive excludes only the explicit
pure telemetry allowlist in `replica.py`; unknown tables and token-bearing bans
are retained. Before recovery overwrites a divergent local database/identity,
archive that state too. If consistent extraction fails, `database.raw` and fixed
`db_wal`/`db_shm`/`db_journal` companions preserve the full recovery set. Restore
the raw file with companions named `<db>-wal`, `<db>-shm`, `<db>-journal`. `index.json` records project, machine, purpose, timestamp and actual
version path. Changed/deleted values remain recoverable in earlier versions;
unchanged credentials deduplicate. Retention has no TTL. Permanent credential
history necessarily grows when retained content changes; monitor its capacity
independently. Failure to archive prevents operational publication/pruning.

The independent witness reserves a durable bounded arm before the controller may
start or extend its watchdog. The record includes authenticated cgroup properties,
boot identity, epoch/session and a witness CLOCK_BOOTTIME expiry. Failed
candidates do not replace the last possibly running worker. Expired arms plus the
durable SSH barrier allow failover without contacting a dead or frozen manager.
Missing lifecycle history and unfinished SSH intents fail closed with a reason.
The old gateway rechecks authority before response headers and each streamed
chunk; stale successful responses are rejected. This fences controller resources;
it does not power off the machine or its unrelated VLESS service.

For a disposable current-size storage/codec benchmark, run
`python3 scripts/ha/benchmark_replica.py --output /tmp/ha-size.json`.
The fixture is >=1,101,983,744 bytes and limits virtual memory to 512 MiB. It uses
incompressible random telemetry, so cold transfer expands to approximately 1.47 GB
with base64; this is an honest worst-compression fixture, not a WAN measurement.
A one-row update transfers only changed chunks; unchanged cycles transfer no file
chunks. Hashing/SQLite verification still read local data. Select the promotion
age limit from measured copy time and WAN rate; the sample uses ten minutes,
not a promise that a first cold transfer over a slow WAN will fit that limit.
Real-size isolated mTLS/cgroup tests can opt in with
`VPNCTL_HA_FIXTURE_BYTES=1101983744` in addition to the flags above (fixture age
and request budgets increase explicitly). Normal CI keeps its small fixtures.

There is no automatic resolution of uncertain remote execution. The independent
witness remains an availability dependency. Production activation, topology,
certificates and external frontend routing require separate integration; this
candidate does not change current production, main, DNS or VPN nodes.

Dedicated workers also declare `Conflicts=sleep.target` and
`Before=sleep.target`. The witness checks those properties. Ordinary systemd
host sleep stops the entire cgroup before sleeping, including a frozen staged
guard, and leaves it stopped on resume. Forced hypervisor/physical freezes do
not provide a pre-sleep transaction; external controller resources still require
the fresh witness epoch/SSH barrier and gateway authority checks. There is no
host power fence or claim that userspace runs while a machine is frozen.
