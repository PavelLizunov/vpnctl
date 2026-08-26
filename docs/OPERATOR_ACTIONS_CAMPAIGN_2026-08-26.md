# Operator actions campaign — 2026-08-26

## Scope

Mutation behavior was exercised only on disposable SQLite databases, temporary artifact stores and disposable SSH containers. Production was checked read-only. No production user, server, grant, protocol or deployment state was changed.

## Confirmed defects fixed

1. **CLI non-root deploy privilege parity** — `RusshTransport` now distinguishes privileged managed-node execution from login-user execution, matching the production subprocess transport. Kernel deploy/upload/read operations use passwordless sudo on non-root nodes; bootstrap deploy-key installation remains in the login user's home.
2. **Duplicate server address guards** — CLI `server add` and CLI bootstrap now reject an address already registered to another server before SSH or inventory mutation.
3. **CLI user creation parity** — CLI-created users now receive a generated VPNRouter device ID while keeping bearer credentials out of normal output.
4. **Admin Delivery policy parity** — disabled users, auto-suppressed servers, hidden protocols and per-user protocol denies are excluded exactly as in `/sub`.

## Tested action families

| Family | Evidence |
|---|---|
| User create | generated UUID/TUIC/device ID; distinct device IDs; JSON secret redaction |
| Grant/revoke | lifecycle, idempotency, unknown-user rejection, FK cleanup |
| Protocol overrides | enable/disable visibility, per-user isolation, no-op audit suppression |
| Server protocol hide/unhide | visibility and no-op audit contract |
| Server removal | cascade of grants, node health, quality, alerts, assurance rows; jump references set NULL |
| Monitoring probe-all | method/CSRF rejection, empty inventory, server count audit, sequential runs |
| Delivery artifacts | hidden/denied/disabled/auto-suppressed links omitted across standard, Amnezia and AWG cards |
| Backup/restore | real `/sub`, VPNRouter and V2Ray artifact digests byte-identical after restore |
| SSH privilege API | explicit privileged vs login-user contract; robust shell quoting |
| Subprocess SSH | root/non-root sudo exec/upload/read and strict host-key Docker scenarios added |
| Russh SSH | root/non-root command wrapping unit coverage; existing Docker auth tests updated |

## Docker-only CI gates

The campaign adds a `SubprocessSshTransport` testcontainers suite. GitHub Actions remains the canonical execution environment because local macOS and Linux workers did not provide a usable Docker daemon with sufficient disk for all-target linking.

## Remaining parity gaps

The repository already covers many routes, but the route/CLI inventory found remaining slices that should not be mixed into this transport/lifecycle PR:

- CLI equivalents for user disable/enable, traffic limits and WireGuard config/rotation;
- CLI equivalents for protocol hidden state and per-grant protocol overrides;
- exhaustive admin tests for every low-risk settings POST;
- terminal-event tests for every deploy-all/user-pending/update-kernels SSE branch;
- standalone wizard password/key-push Docker suite (the underlying password and transport paths already have separate Docker coverage);
- explicit Web button for every remaining CLI-only disaster-recovery action where appropriate.

These are tracked as follow-up parity work; they are not represented as completed by this campaign.

## Verification

- Workspace `cargo check --all-targets` passed on a remote worker.
- Workspace Clippy `-D warnings` passed on macOS worker.
- Focused SSH, user, server, grant, protocol, cascade, monitoring and restore tests passed.
- Independent Gemini review of the actual final diff returned no critical or important findings.
- Production health and existing assurance state are checked separately and remain unchanged by this campaign.
