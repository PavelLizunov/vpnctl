# Corp owned sing-box probe runtime

## Intent and invariants

At green lifecycle baseline `79b03a1`, implement the actual Linux-only runner
and wire it to production construction/refresh. Keep test constructors disabled.
No deployment, activation, external probe, migration or credentials change is
part of this source/CI block. [Lifecycle](corp-policy-egress.md) owns challenge,
full endpoint coverage and persistence. This runner proves one selected endpoint.

Run the exact selected outbound in a private, directly executed managed sing-box
process. Authenticate a retained loopback SOCKS connection, prove that the child
owns its server-side socket, then verify HTTPS and the challenge echo on that same
connection. No ambient proxies, redirect, unauthenticated SOCKS, arbitrary target,
selector, fallback or direct data outbound. The trusted managed sing-box is a
single process with threads and does not spawn descendants or transfer sockets.
Killing a process group and reaping its leader does not establish descendant reap.

## Frozen public test seam

Add `pub mod corp_probe_runtime` with these interfaces:

```rust
pub struct RunnerConfig {
    pub executable: std::path::PathBuf,
    pub work_root: std::path::PathBuf,
    pub tls_roots: rustls::RootCertStore,
    pub work_timeout: std::time::Duration,
    pub cleanup_timeout: std::time::Duration,
}
pub struct SingBoxRunner;
impl SingBoxRunner {
    pub fn new(config: RunnerConfig) -> Result<Self, crate::corp_egress::ProbeError>;
    pub fn production() -> Result<Self, crate::corp_egress::ProbeError>;
}
// Implements existing Debug + Send + Sync + ProbeRunner.
```

Debug for both types is exactly `RunnerConfig { .. }` / `SingBoxRunner { .. }`,
including alternate formatting. Neither implements Serialize. Constructor is
an explicit Rust integration seam, never controllable by HTTP/query/form/env.
All errors use existing sanitized ProbeError, without underlying paths/IO errors.
`new` does not start a process or connect to a socket. Reject zero durations or
work_timeout >15 seconds / cleanup_timeout >2 seconds, empty roots, relative or
unsafe executable/work-root paths. Work root must already exist for `new`.
Executable must be a regular executable file, not a symlink, owned by root or
current effective uid, not group/other writable. Validate directory ancestors
as root/current uid and non-writable by group/other, rejecting symlinks; a
root-owned sticky directory such as /tmp is allowed as an ancestor. The work
root itself must be owned by current uid or root and private (0700), not a
symlink. Revalidate trust at run time before spawn; trusted owners can update the
binary, but untrusted users must not redirect it through a writable parent.

Production uses fixed `/opt/vpnctl/node-artifacts/sing-box`, work root
`/var/lib/vpnctl/corp-probes` (create privately if absent, do not chmod an unsafe
existing path), standard WebPKI roots, 15 seconds work and two seconds cleanup.
Use explicit rustls ring CryptoProvider and standard certificate/hostname/time
verification; no process-global crypto-provider mutation. Missing/unusable
runtime is unavailable and cannot enable access; startup otherwise continues.
The managed runtime artifact is the repository's 1.14.2-vpnctl.2 XHTTP-capable
build, not an arbitrary system sing-box from PATH.

## Exact configuration and ownership

- Reject malformed token (must be canonical 32-byte unpadded base64url), oversized
  outbound (>64 KiB), nonobject/non-vless outbound, missing valid tag/server/port
  or UUID, disabled TLS, or any `detour`. Do this before process launch.
- Make one fresh private0700 task directory under work_root. Create config.json
  atomically with create_new and mode0600; serialize at most128KiB. The config
  contains one SOCKS inbound bound only to 127.0.0.1, with independently random
  32-byte username/password; one outbound exactly equal to the request JSON;
  route.final set to its existing tag; local bootstrap DNS for the VPN host.
  `log.disabled=true`; no direct/fallback/selector outbounds or remote control
  APIs. The observation token must never appear in this config or any file.
- Reserve a free ephemeral loopback port, release reservation immediately before
  starting the child. A competing listener must cause failure, never acceptance.
  Only retry connection refusal while waiting for the child to listen, within
  the absolute deadline; after acquiring a TCP stream do not reconnect.
- Execute absolute binary with exactly `run -c <private-config-path>`, private
  current directory, clean environment (a fixed minimal PATH is permitted), all
  stdio null and a new process group. Tokens, UUIDs, passwords and outbound JSON
  never enter arguments/env/logs. Config path is not itself a credential.
- Own the child immediately after spawn. Keep its PID unreaped through ownership
  checking and group signalling. Safe nix waitid(Pid, WEXITED|WNOHANG|WNOWAIT)
  detects exit without reaping. Child::try_wait is forbidden before the first
  process-group signal; early child exit cannot be mistaken for a valid listener.
- Prove the retained stream's server-side ESTABLISHED socket belongs to this PID:
  reverse tuple in /proc/<pid>/net/tcp must have local = stream.peer_addr and
  remote = stream.local_addr, state01, nonzero inode. That inode must intersect
  socket:[inode] links in /proc/<pid>/fd. The TCP table alone is namespace-wide
  and insufficient. Bound proc reads/iterations and check child liveness before
  and after. Fail closed on inaccessible/malformed proc state. Retain this exact
  TcpStream through TLS and cleanup; never close/reopen it for the HTTPS request.
  A matching socket with inode0 is pending kernel accept/fd installation, not
  ownership proof or malformed proc data. Wait boundedly on the same stream
  until its nonzero inode is owned; send no SOCKS bytes before that proof.

## SOCKS and HTTPS transcript

Offer SOCKS5 username/password method02 ONLY; require selection02, RFC1929
version01 and success00. Send CONNECT with domain `admin.corp.ninitux.com`,
port443; require success, version05/reserved00 and consume the bounded address
reply for IPv4/domain/IPv6. Never resolve the observer locally or accept NO_AUTH.

Wrap the retained stream in rustls with server name `admin.corp.ninitux.com`,
ALPN only `http/1.1`, and the constructor's trusted roots. SNI/name verification
and valid CA chain are mandatory. Work happens on the same established socket.
Send exactly the fixed POST path `/api/v1/corp/egress-observation`, fixed Host,
Authorization: Bearer <token>, Content-Length: 0 and Connection: close.

Accept only HTTP/1.1 status204, bounded headers (8192 bytes / at most64 fields),
one exact case-insensitive X-Corp-Probe header with exact token value, no
Transfer-Encoding and absent or one Content-Length: 0. Reject duplicate echo,
wrong/missing echo, interim/redirect/error statuses, malformed headers, nonzero
length and any body bytes already read. Do not follow redirects. Parser loops
check absolute deadlines even when TLS returns buffered plaintext. Never log
HTTP bodies/headers or underlying TLS errors. Runner Ok requires validated
response AND complete successful cleanup; controller separately requires its
actual observer callback before persistence.

## Deadlines, cancellation and cleanup

The runner owns an independent busy/poison gate in addition to the controller.
Concurrent direct run calls return Busy without another child. available() is
false after poison or if runtime trust is unavailable; busy alone is not poison.
Compute the absolute work deadline before queuing owned blocking work. A
spawn_blocking job can own std::process::Child, TempDir and retained TcpStream;
dropping the async run future does not cancel the blocking job or release its
gate. A timeout must cancel only waiting for its result, never the owned helper.
If no cleanup acknowledgement is available within work+cleanup budgets, return
CleanupFailed and poison; queued work must check the deadline before spawning.

Every socket operation uses the remaining absolute work budget, including
connect retries, SOCKS and TLS. A Read/Write wrapper must reset underlying read/
write timeouts from this deadline on each operation, and reject elapsed time.
Retain the actual stream outside the TLS wrapper, including on TLS errors.
The bounded network contract excludes arbitrary OS scheduling, spawn and local
filesystem stalls; such uncertainty must fail closed, never certify a probe.

After every success/failure/timeout, signal the child's process group BEFORE
reaping its leader (avoid reused PID/PGID targets). Do not call killpg on a cached
ID after reap. Reap the direct child and remove the private task directory only
after confirmed exit. Drop the retained socket after cleanup. Cleanup errors or
uncertain exit return CleanupFailed, poison future work and preserve ownership
of child + directory until an owned reaper confirms termination; a blocking owner
may send an early failure result and continue reaping without another helper.
A panic after spawn needs RAII cleanup/poison or catch-unwind while retaining the
owner; JoinError after losing the child is not cleanup. Never leave secret files
because a caller disappears. Do not claim to reap arbitrary descendants. Daemon
service shutdown is additionally governed by systemd's control-group kill mode.
If the leader is confirmed reaped but directory removal fails, retain and retry
directory cleanup while remaining poisoned; eventual removal does not restore
availability. A wait error that loses child ownership must never trigger another
signal to the cached numeric PID/group.

## Integration and independent CI verification

Production app::build installs the runner in a new EgressController with UTC
clock, then starts spawn_refresh once. If production construction fails, install
an isolated disabled controller; use only a static sanitized startup warning.
No new poller/process is installed by make_app_state_for_tests or injected router.
Existing observer, operator readiness and refresh behavior remain unchanged.

Independent test writer reads this contract and the lifecycle API only, never
implementation. Write `daemon/tests/spec_corp_probe_runtime.rs` and optionally
fixtures under `daemon/tests/fixtures/corp-probe/`. No local test execution.
Tests may construct a private executable Python3 helper and generate a test CA/
leaf using CI's /usr/bin/openssl, never check in private keys. Helper reads the
actual sing-box config, binds the actual loopback socket, validates SOCKS auth,
then serves real TLS for the fixed Corp hostname and validates the HTTP request.
No external network; no mocked proc ownership or insecure certificate verifier.
Test code configures private fixture roots and shorter positive timeouts.

Cover valid transcript and exact outbound, secret file modes/removal and redacted
Debug, no token/credentials in argv/env, missing/unsafe runtime/input, failed
spawn/early exit, refused/no-auth/wrong SOCKS reply, invalid CA/hostname, wrong/
duplicate echo/redirect/large headers/body, connection stall and total work
budget, caller cancellation with eventual cleanup and busy exclusion. Negative
ownership fixture must use a listener in a different process from the helper;
it must not receive SOCKS credentials. Assert child termination/private-directory
removal after normal and error paths. Avoid SQLite/paused-clock mixing; runtime
IO tests use bounded real time and event coordination, not sleeps as proof.

Local gates are format/generated files/JS/workflow/whitespace/secrets only.
Independent diff review plus exact-SHA canonical CI, full suite, browser/static
musl and process/socket/TLS tests are required. Real managed-runtime validation
and production ingress/client activation remain later delivery checks, not
something a synthetic helper can establish.


## Candidate receipt

Implemented the explicit runner, fixed production constructor and refresh wiring.
Test app constructors stay disabled. Independent spec tests cover actual local
process/socket/TLS transcripts, foreign PID ownership, caller cancellation,
absolute trickled-response deadlines and cleanup-failure poison using private
runtime-generated CA/keys. The helper is synthetic; managed sing-box config and
live delivery verification remain separate evidence requirements.

Independent security/correctness and lifetime/test diff reviews returned no
findings. Author/lead findings were recorded before correction: completion gate,
host and proc validation, executable permission, private modes, bounded input,
cleanup error/acknowledgement and lost child ownership. Lead additionally handles
vanishing unrelated proc descriptors without admitting an unowned connection.
On lost wait ownership, the owner stops all numeric PID operations and retains
the busy gate/socket/private files until service termination; safe cleanup of
quarantined files requires confirmed service stop. No implicit recovery is claimed.

Local formatting, Python fixture syntax, JS/workflow syntax and whitespace checks
passed. Cargo metadata emitted only the expected direct-dependency lock additions,
then stopped because libsqlite3-sys source was not cached offline; no compilation
or package installation was attempted. Canonical builds/tests, actual runtime
fixtures and full browser/static-musl gates must pass at the candidate SHA in CI.
No live service, probe, deployment or activation was used.

CI follow-up at `4f459ed` (run `43713828537`): compilation, Clippy, static
musl, Docker SSH and browser verification passed. Runtime tests exposed the
pending-accept inode0 race before helper acceptance; the cancellation failures
occurred before cancellation was requested. The source now leaves ownership
pending under the existing retained-stream deadline. Two independently authored
regressions verify the actual unaccepted kernel socket, absence of SOCKS bytes,
unchanged tuple, eventual acceptance and timeout cleanup. All 14 runtime tests
require a fresh CI run; no local runtime execution occurred.
