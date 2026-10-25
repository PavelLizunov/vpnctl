# Contract: persisted WireGuard peer addresses (D7-02)

## Intent & Invariants

Legacy `wireguard` and its AmneziaWG exports retain imported client addresses
when another user is granted, disabled, removed or revoked. Disabled users keep
their reservation; revocation frees it. Rendering remains inventory-independent.
AWG2/3 retain their existing key-derived addresses and exact output bytes.

## Interface / Data Contract

- Migration `0066_grant_wg_octet.sql` adds nullable `grants.wg_octet`, unique per
  server when non-NULL. Backfill uses `1 + ROW_NUMBER()` partitioned by server,
  ordered by `users.id`, joining granted users with `disabled = 0`, exactly as
  `users_for_server` does (including users without WG keys). Disabled grants stay
  NULL. Backfill changes are audited as `grant.wg_octet.assign`.
- A new grant reserves the lowest free octet in `2..=254` in its existing
  `BEGIN IMMEDIATE` transaction. `grant_audited` records the octet in the single
  `user.grant` payload with the existing actor/source. Repeated grants are no-ops.
  The low-level inventory `grant` (imports, fixtures) allocates the same way but
  writes no audit row; its callers audit. When the /24 is full the grant is still
  created without an address (other protocols keep working); only rendering a
  WireGuard peer for it fails until a slot frees and is assigned lazily. Boosty and
  import grant creation allocate in their existing transactions too; replacing
  an imported user preserves other-server grants' addresses.
- `wg_octets_for_server` fills NULL enabled grants under `BEGIN IMMEDIATE`, using
  all grants (including disabled users) as reservations. Each lazy assignment
  writes one `grant.wg_octet.assign` row; unchanged reads write none. Exhaustion
  returns a clear error and rolls back the transaction, including its audit rows.
- Inventory-backed CLI, delivery, assurance, app-config and deployment pass these
  assignments through `RenderCtx.wg_octets`. Server `AllowedIPs`, client configs
  and all legacy WG/AWG links use the same map. A present map never falls back
  when a peer is missing or out of range. Contexts without a map retain the old
  index fallback and its overflow error for standalone rendering and tests.
- Stored addresses are part of the deployment input revision. Existing valid
  fleet configuration and export bytes remain unchanged on migration; later
  grant changes retain surviving peers' client bytes and server addresses.

## Verification

- Backfill reproduces old sorted-index addresses independently per server,
  excludes disabled/ungranted users and enforces uniqueness.
- Add/disable/remove/re-enable/revoke preserve surviving addresses; disabled
  reservations are not reused, while revoked slots are reused lowest-first.
- Concurrent lazy reads allocate once; grant and lazy exhaustion leave no partial
  mutation or audit, and repeated reads/grants write no extra audit rows.
- WG/AWG client configs, server envelopes and share links are byte-identical
  before/after supplying the map; surviving client bytes stay unchanged after
  peer changes. AWG2/3 bytes remain unaffected. HTTP coverage compares app-config,
  `/sub` variants and `/api/v1/sub` across grant changes.
