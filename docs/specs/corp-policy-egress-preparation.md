# Corp egress proof preparation

## Intent and boundary

Prepare exact selected connection plans and non-disruptive renewal at green
baseline `c8d81c4`. This slice runs no processes or network probes and does not
enable access. The following runner/controller slice must prove every endpoint,
bind observations to expiring single-use challenges and revalidate the current
plan/config generation before saving evidence. Enable remains unavailable until
that complete lifecycle exists. No deployment or live migration is authorized.

The client at VPNRouter `098b7d34` pins portal TCP/DNS to the selected direct
VLESS choice and rejects portal UDP before ordinary routing. Server proof is
therefore specifically for that TCP path, not general UDP or regional health.
Pre-TUN exclusions remain a separate later client activation check.

## Timestamp-only storage renewal

Add to the existing `SqliteInventory` API:

```rust
pub async fn refresh_corp_egress(
    &self,
    expected_config_version: u64,
    previous: &[CorpVerifiedEgress],
    refreshed: &[CorpVerifiedEgress],
    actor: &str,
) -> CorpResult<CorpStatus>;
```

Both lists are complete sets. Reuse every existing egress/actor bound and
canonicalization rule from `corp-policy-store.md`. The normalized sets must
have exactly the same `(server_id, canonical IP, configuration_fingerprint)`
identities; every refreshed timestamp must be greater than or equal to its
previous timestamp. Invalid shape, identity change, duplicate, invalid actor or
backdating returns `InvalidInput`. Array order and IPv4-mapped representation
are immaterial. Zero entries/identical timestamps are valid no-op inputs.

Within FULL / BEGIN IMMEDIATE, require an existing binding (Unavailable if
absent), matching config version, and exact current normalized rows equal to
`previous`, including timestamps (Conflict for either mismatch). Require the
bound user to exist and be enabled (Unavailable), even for no-op. Binding itself
may be disabled for setup/repair. Each retained server must exist, as in the
replacement API. A no-op leaves state/audit unchanged. An actual renewal changes
only verified_at and writes one `corp.egress.refresh` audit with safe row count;
credentials, enabled state, user/policy identity, config/auth generations,
revision/history and sessions stay unchanged. Audit failure rolls back every
timestamp. Exhausted authority counters do not prevent timestamp-only renewal.

The exact previous-row comparison prevents concurrent renewals from silently
overwriting newer proof even though config_version does not advance. Two
concurrent renewals with the same previous rows permit exactly one winner.
Any IP/fingerprint/member change still uses `replace_corp_egress`, whose existing
authority/session behavior remains unchanged. No existing migrations change.

## Exact selected probe plan

Add to `vpnctld::corp_portal::eligibility`:

```rust
pub struct CorpProbePlan {
    pub server: CorpEligibleServer,
    pub outbounds: Vec<serde_json::Value>,
}
pub async fn probe_plan(
    state: &crate::AppState,
    user_id: &vpnctl_core::UserId,
    server_id: &vpnctl_core::ServerId,
) -> Result<Option<CorpProbePlan>, EligibilityError>;
```

Plan has no Serialize implementation. Its explicit Debug must expose no fields:
outbound values contain credentials and remain private to trusted daemon code.
Both ordinary and pretty Debug are exactly `CorpProbePlan { .. }`; never derive
Debug. No endpoint/HTTP serialization or logging. Keep existing sanitized
`EligibilityError` variants/messages.

Use one common inventory collection and grouping path for safe eligibility and
probe plans. Preserve all current direct-only, grant/disabled/visibility/
suppression rules, protocol-major ordering, actual-host first-wins selection
and label behavior from `corp-policy-eligibility.md`. Return None for unknown or
ineligible target (including disabled/missing user), never an unrestricted plan.
Recheck bound user before returning. Inventory failure remains
InventoryUnavailable, never None or a stale fallback.
None is returned only after a successful shared eligibility evaluation. Invalid
selected configuration anywhere still fails that evaluation, including for an
unknown target; never skip a malformed first-winning choice to promote another.

For each surviving selected choice, render its actual protocol's client_config
using the SAME SubscriptionServer secrets/server and the user's per-server UUID
from that subscription input. Keep full renderer outbound JSON unchanged,
including tag, TLS/uTLS/Reality, flow, WS path/Host and XHTTP mode. Rendering
failure or missing selected renderer is InvalidConfiguration, sanitized without
printing its error. Require an object with type vless, nonempty uuid, no detour,
a nonzero u16 server_port and server host equal to the selected normalized host
(case/bracket and IP-literal canonicalization); do not silently replace a
mismatched outbound. Keep the renderer's original server spelling in the plan.

There is exactly one outbound per selected host, in server.hosts order. A server
with Reality at its inventory address and WS at a different hostname has TWO
outbounds, both needing successful proof later. Cross-server host collisions
and same-host XHTTP siblings obey the same first-wins rules. No selector, direct
or non-VLESS siblings are added. This method only prepares a plan: it cannot
mark verified egress or change inventory/audit.

Fingerprint profile becomes `vpnrouter-business-portal-tcp-v2` and includes
each selected renderer outbound in addition to the existing canonical inputs.
Safe eligible_servers and probe_plan must return the identical fingerprint
at an unchanged snapshot; renderer-only changes must invalidate old proof.
Canonicalize object keys recursively, retain array/choice order and the prior
label/unrelated-user stability rules. This intentionally invalidates old proof
without treating inventory/DNS addresses as verified exits.

## Verification and delivery

Independent tests see this spec, the owning storage/eligibility specs and
existing spec-test fixtures, not implementation. Storage tests cover session
survival and unchanged generations/history, canonical no-op, stale versions and
previous rows, identity/backdating rejection, missing/disabled user, bounds,
audit rollback, concurrent renewal and replacement still revoking sessions.
Plan tests cover per-server UUID and Reality TLS/flow, WS host/path, XHTTP,
multi-host complete coverage, first-wins collision, safe fingerprint equality,
config change invalidation, omitted choices and sanitized errors.

Local checks are source-only. Publish reviewed code/spec tests in existing
draft PR #323; all canonical Cargo/just-ci gates and browser compatibility must
pass at its exact SHA before the runner/controller slice. Do not imply this
preparation is actual VPN proof, operator activation or a deployed portal.

## Baseline and candidate receipt

Backend `c8d81c4e37207b07bad148b287162c81686490f0`, run `43705265090`,
passed all 12 jobs. The canonical log records exit 0 for all five Cargo commands
and `just ci`; static musl, Docker SSH and browser verification also passed.
Browser artifact `14158556835` contains 30 completed scenario groups and 48
screenshots. Lead inspected the narrow operator setup/status (including its
bottom controls), password reveal and actual submitted-login/editor pages.
This verifies synthetic CI behavior only.

The preparation candidate adds the shared plan and renewal methods with 16
independent spec tests. The lead corrected IP-literal normalization before
publication. Separate source/spec and full test-diff reviews returned no
findings. The final complete-diff review, including the additional fake-renderer
regressions, also returned no findings. Local formatting, workflow/JS syntax,
generated map/CSS, whitespace and secret checks passed. Runtime checks remain
CI-only, with fresh exact-head results required. Existing
readers, portal routes, enable/probe blocking and production state are unchanged.

At `e9df92b`, Cargo check compiled the candidate, but Clippy/just ci rejected
the absent Debug implementation under the workspace's public-type lint. The
correction uses an explicit field-free Debug formatter and one additional
independent regression for ordinary/pretty formatting. No lint is suppressed
and no credential-bearing field becomes printable. Independent correction
diff review returned no findings; current-head runtime evidence remains pending.
