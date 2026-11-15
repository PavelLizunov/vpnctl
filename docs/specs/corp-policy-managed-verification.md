# Corp managed-runtime CI gate

## Scope and invariants

At green backend `3116a25`, verify the actual pinned managed sing-box artifact
through `SingBoxRunner`, using only loopback fixture services in GitHub CI.
No production network, credentials, deployment or activation is involved.
The [runtime contract](corp-policy-runtime.md) owns runner APIs and security.
This adds tests and CI wiring, not a new production API or target override.

## Independent test contract

Extend the independent runtime spec tests with ignored tests explicitly required
by the managed-artifact CI job. The test-only environment variable
`VPNCTL_CORP_TEST_SING_BOX` names the already acquired checksum-verified binary;
missing/invalid value fails these tests. Ordinary synthetic tests do not acquire
or require that artifact. All setup data/CA/private keys stay in private TempDir.
No checked-in private keys or fixture config artifacts are uploaded.

1. For TCP and WebSocket, run a second local managed sing-box as a VLESS server,
   with a random loopback port, synthetic UUID and generated TLS certificate.
   Run a separate local TLS observer fixture with the fixed Corp hostname and
   generated CA trusted by RunnerConfig. Feed the exact synthetic VLESS outbound
   to the actual SingBoxRunner, including fixture CA certificate_path. Server
   routing may override only fixed admin.corp.ninitux.com:443 to the local
   observer port; a catch-all rule rejects everything else. Production runner
   destination/SNI/path/Host/TLS verification must remain unchanged.
2. Require actual successful authenticated SOCKS + VLESS + verified observer TLS
   and exact fixed HTTP request/challenge echo, then successful owned cleanup.
   Assert no task directories remain. Test both TCP and WS; server/client WS
   transport path is `/corp-fixture/`. Do not use insecure TLS or ambient proxies.
3. For Reality and XHTTP, capture the exact private config produced by the real
   runner while a local endpoint holds its connection pending. Run the actual
   managed binary's `check -c` against it and require exit0. Assert the outbound
   equals the original supplied JSON, and the task is cleaned after failure or
   timeout. Use valid synthetic Reality public_key/short_id and exact XHTTP
   transport fields. No external handshake is attempted.
4. Boundedly own/terminate/reap every fixture child, including assertion failures.
   Use event coordination or bounded readiness checks rather than sleeps as
   evidence. Child argv/logs/configs contain only synthetic fixture values.

Pinned managed source f62085aa7cc0f3ee665ac3043d35698760a386e9 supports
route-rule `override_address`/`override_port`, inbound TLS certificate_path /
key_path and outbound TLS certificate_path. Direct-outbound overrides are
removed. XHTTP registration is client-only, so this pin cannot host an XHTTP
inbound: its config check does not certify actual XHTTP or Reality transport.
Their deployed endpoint compatibility remains an explicit delivery gate.

## Verification

The existing managed-artifact CI job acquires `/tmp/sing-box` with checksum
verification, installs the already supported Rust toolchain/cache, and runs the
explicit ignored managed tests. Failure blocks the gate. Local work permits
format/syntax/map/whitespace/secret checks only. Independent diff-only review and
all canonical exact-SHA backend checks remain mandatory. No local test/build runs.
