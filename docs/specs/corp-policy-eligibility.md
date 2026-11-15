# Corp Business server eligibility

## Intent and invariants

Compute the fixed Business client's selectable direct VLESS endpoints for the
bound inventory user. This is candidate selection, not proof of an exit IP.
Never derive an allowed IP from DNS, inventory addresses or access-log flags.
The caller must separately require a fresh verified exit observation whose
configuration fingerprint equals the current candidate's fingerprint.
The exact secret-bearing probe plan and timestamp renewal are specified in
[egress preparation](corp-policy-egress-preparation.md); preparation alone
cannot admit any exit.

## Public interface

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpEligibleServer {
    pub server_id: vpnctl_core::ServerId,
    pub label: String,
    pub hosts: Vec<String>,
    pub configuration_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EligibilityError {
    InventoryUnavailable,
    InvalidConfiguration,
}

pub async fn eligible_servers(
    state: &crate::AppState,
    user_id: &vpnctl_core::UserId,
) -> Result<Vec<CorpEligibleServer>, EligibilityError>;
```

The module is `vpnctld::corp_portal::eligibility`. Errors have static sanitized
messages; neither Debug nor Display includes credentials, URLs or inventory
error details. No builds, processes, DNS resolution or remote access occur.

## Selection contract

- Missing or disabled user returns an empty list. Inventory failures return
  `InventoryUnavailable`; they never use a stale or unrestricted fallback.
- Reuse the existing subscription inputs and share-link collectors without
  changing their behavior. Only granted `vpn-exit` nodes, visible protocols,
  unsuppressed nodes and direct connections are eligible. Ignore browser UA.
  Effective suppression follows the existing inventory opt-in: both
  `set_server_auto_suppress(&ServerId, true) -> Result<()>` and
  `set_server_suppressed(&ServerId, true) -> Result<bool>` are needed in a test
  fixture. The latter changes the observation timestamp only; a timestamp with
  auto-suppression disabled does not remove the endpoint from the subscription.
- Enumerate all direct `vless+reality` links in subscription server order, then
  `vless-ws`, then `vless+xhttp`. The fixed shipped Business runtime supports
  XHTTP. A collector that cannot render a variant contributes no endpoint.
- Parse the actual share-link authority as the client's HTTPS-based VLESS URI
  parser does. WS uses `vlessws.domain`, which can differ from the inventory
  address. Normalize bracketed IPv6 and hostname case, then retain the FIRST
  direct VLESS endpoint per parsed hostname, regardless of port or transport.
  Never deduplicate by inventory address or ServerId before this step.
- Reject unusable rendered credentials/authority as `InvalidConfiguration`:
  empty user identity/host, invalid port, invalid Reality public key (must decode
  to 32 bytes), or short ID (empty is valid; otherwise even-length hex <=16).
  Drop the client's known placeholder public key, short ID and server address
  exactly as the client parser does. Missing secrets still follow collector
  omission. This profile does not validate optional non-VLESS siblings or
  claim the entire subscription is importable.
- Group surviving choices by ServerId in first-choice order. `hosts` is that
  server's deduplicated selected hosts in choice order. `label` is its trimmed
  custom display name or existing country/server fallback, without credentials.
  Return no entry for a server with no surviving choice. Recheck the user before
  returning; a concurrent disable/deletion yields an empty list.

## Fingerprint contract

The fingerprint is exactly 64 lowercase hex SHA-256 characters over the
`vpnrouter-business-portal-tcp-v2` canonical representation, including each exact
selected renderer outbound. Its other inputs are the bound user ID, server identity and
address, SSH port/user/trusted host key and resolved pinned jump route, sorted
kernel IDs, and the selected endpoint configurations. Endpoint inputs include
their protocol, parsed hostname and share link without its display fragment,
plus relevant server secrets: `vless.*` for Reality/XHTTP, `vlessws.*` for WS,
and `vlessxhttp.*` for XHTTP. Sort secret keys and normalize object-key order;
preserve choice order. The secret-bearing material is internal only, never
returned, logged or included in Debug/errors.

Changing a selected endpoint's credential, transport settings, host, port,
server identity, kernel or pinned route must change the fingerprint. Removing a
grant, hiding/suppressing a node, disabling the user or adding a detour removes
the affected choice. An alternative transport becoming the first eligible
choice also changes the fingerprint. Renaming a display label, map insertion
order, and changing another user's credentials must not change it.

No fingerprint claims to detect out-of-band operating-system/NAT/DNS changes.
Exit observations need an expiry and periodic reprobe. The inventory reader is
not one database snapshot; request handlers must revalidate immediately before
privileged actions, and a probe must compare the current fingerprint again
before recording its result. Persistence CAS additionally protects Corp config
and credential generations.

## Verification

Spec-derived tests cover absent/disabled user, no grants, hidden/per-user-disabled
protocol, suppression, detour exclusion, missing keys, malformed Reality
credentials, placeholder rejection, actual WS host, cross-server host collisions,
protocol-major first-wins ordering, grouped hosts and empty output. Fingerprint
tests cover label stability, unrelated-user stability, secret insertion order,
credential/port/host/kernel/pinned-route change, transport replacement and
sanitized errors. CI executes tests; local work is source-only.
