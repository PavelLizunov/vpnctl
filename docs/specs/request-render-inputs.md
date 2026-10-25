# Contract: request-local render inputs

## Intent & Invariants

- App-config loads per-server render inputs once per request, in a bounded number
  of inventory queries independent of server/protocol count. No cross-request
  cache or mutable protocol state is introduced.
- Existing app-config bytes and ordering, visibility, suppression, per-server UUIDs,
  detour metadata and AWG peer ordering remain unchanged for valid inventory.
- User detail loads delivery secrets, peer credentials and artefacts only for
  Delivery; protocol controls only for Access; origin/log data only for Activity;
  lifecycle, sharing verdict and traffic summary only for Overview. The shared
  header still loads pending deploy and online/last-seen data for every tab.

## Interface / Data Contract

`SqliteInventory::subscription_render_inputs(&UserId, include_awg_peers: bool)`
returns server-ordered `SubscriptionServer` values containing metadata, effective
UUID, visible protocols and secrets. Peer lists retain `users_for_server` ordering
and effective UUID semantics, and are loaded only when requested, for servers
with AWG/WireGuard protocols. Missing users return an empty list; database errors
propagate to the handler's existing empty-response fallback. Collectors render
from these inputs without inventory queries.

## Verification Checklist

- Multi-server app-config is byte-equal, including a per-server UUID override and
  a server lacking required secrets; existing protocol/detour fixtures still pass.
- Batch inputs match individual inventory lookups; peer loading is optional.
- Non-delivery tabs remain available when another user's credential cannot decode;
  Delivery still reports the read failure. Existing admin smoke fixtures pass.
