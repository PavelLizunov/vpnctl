# Spec: Independent direct and jump SSH access

## Intent & Invariants
- Show whether vpnctld can authenticate over SSH directly and through the target's configured `jump_via`, independently of VPN availability and node health.
- A success requires an authenticated, pinned SSH session executing `true`. Direct checks never use a jump, SSH config proxy, or an existing multiplexed connection. Jump checks never fall back to direct. No automatic routing, key, grant, subscription, or node-service changes.
- Run for every registered server, even without kernels. Bound connections and runtime, coalesce concurrent requests for the same inventory/server, and show unknown for missing credentials/configuration, missing measurements, future/stale observations or changed endpoint/pin/jump configuration.
- Persist latest observations across daemon restarts. Audit observation state/reason/route-identity transitions; repeated equivalent heartbeats do not spam audit. Store only typed failure reasons, never command output or credentials.

## Interface / Data Contract
Export from `vpnctl_inventory`:
```rust
enum SshAccessRoute { Direct, Jump }
enum SshAccessState { Available, Unavailable, Unknown }
enum SshAccessFailure { Timeout, Authentication, HostKey, Connection, MissingKey, InvalidRoute, Stale }
struct SshAccessCheck {
    state: SshAccessState,
    failure: Option<SshAccessFailure>,
    checked_at: chrono::DateTime<chrono::Utc>,
}
struct SshAccessStatus { direct: Option<SshAccessCheck>, jump: Option<SshAccessCheck> }
// All fields public; enums Clone + Copy + Eq + Debug; checks/status Clone + Debug.
impl SqliteInventory {
    async fn record_ssh_access(&self, target: &Server, route: SshAccessRoute,
        jump: Option<&Server>, check: &SshAccessCheck) -> Result<()>;
    async fn ssh_access_for_server(&self, server_id: &ServerId,
        now: DateTime<Utc>, max_age_secs: u64) -> Result<SshAccessStatus>;
}
```
- Direct observations require `jump=None`. Jump requires `target.jump_via`; a supplied jump must match that ID. Missing jump details may record `Unknown/InvalidRoute`. `Available` has no failure; `Unavailable` requires a failure. Reject future observations. Missing target or malformed input errors without partial writes.
- Identity includes target ID/address/port/user/pin; jump identity additionally includes configured jump ID/address/port/user/pin. Direct identity ignores `jump_via`. Changed identities return no measurement. Older/equal timestamps cannot replace a newer observation. Read freshness includes ages 0 and exactly `max_age_secs`; stale/future reads preserve the timestamp but return `Unknown/Stale`. A missing server errors.
- Admin server list and Status tab show separate Direct / Via jump server states, configured jump and check times. No configured jump is explicitly “Not configured”. EN/RU copy; unknown never looks available.
- Authenticated `POST /admin/servers/{id}/ssh-check` queues a coalesced background check and redirects to the Status tab; missing server is 404. A running check shows progress and automatically refreshes. Default periodic check every 5 minutes, freshness twice its interval; first round starts at daemon startup.

## Verification
- Independent spec tests: independent route results, restart persistence, invalid inputs, stale/future boundaries, monotonic updates, endpoint and jump changes, audit deduplication.
- Probe tests prove direct has no proxy/jump, jump has no direct fallback, failures stay typed, and concurrent requests coalesce. Admin tests pin both locales, unknown/not-configured, independent results and POST behavior.
- `cargo fmt --all`, independent diff review, `just ci` plus all five canonical cargo gates, secret scan and GitHub CI. Deploy with verified pre-migration restore snapshot, binary backup, health/version checks, live SSH observations and visual QA of both changed pages.
