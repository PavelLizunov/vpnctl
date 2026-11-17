# Cooperating controllers (opt-in candidate)

Standalone `vpnctld` is unchanged. HA uses two controller gateways, three real
Consul voters, and an independent executor/storage witness. This candidate is
not activated in production. The witness is an availability dependency: losing
it blocks SSH operations and promotion. Controller host/network failure blocks
promotion until the previous controller's cgroup can be positively fenced;
this version does not power-fence hosts. A suspended gateway also suspends its
own frontend until the process resumes or its service restarts.

Replication is asynchronous. A promoted controller may lose **acknowledged**
changes since the latest verified generation. `/admin/ha` shows its source age,
replication interval and promotion age limit. No zero-loss or multiwriter claim.

## Matching artifacts and initial preparation

Use identical `vpnctld` executables, these Python modules and worker environment
on all three services. Python 3.11+, unified cgroup v2, systemd with service watchdogs, OpenSSH and sshpass on the executor are required. Both
controllers need permission to manage their dedicated transient worker unit.
The gateways run separately from their workers; followers never open inventory.

1. Build the reviewed revision with `just build-release`. Inspect
   `vpnctld --ha-artifact`; copy its `executable_sha256` and `schema` into all
   configs. Migration checksums are checked independently at snapshot publication
   and promotion. Package `scripts/ha/{common,controller_ha,executor,gateway,replica,worker,worker_guard}.py`
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
snapshot, drains the worker, releases its session, and selects the peer. Pausing
automatic failover retains an existing healthy leader; it prevents acquisition
of a new lease. Each operation still requires quorum and fresh verified data.

An old node rejoins with its local worker stopped, downloads the witness's latest
immutable generation, and replaces its divergent database only after fencing.
No database merge, automatic migration or subscription-identity regeneration
occurs during promotion. Exact executable, embedded migrations, file hashes,
SQLite integrity/FKs and deployment identity must match.

The executor fsyncs an intent before every SSH dispatch. Any error, lost result
or interrupted helper becomes **uncertain**, survives restart and blocks every
later dispatch and promotion. The status lists exact job IDs. There is no blind
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

Immutable generations and the executor ledger currently have no automatic
pruning. Provision durable capacity for the chosen snapshot interval before
activation; do not silently discard credential-bearing history. This candidate
has no automatic resolution of uncertain remote execution and no host power
fence. Both dependencies remain visible as blocked readiness conditions.
