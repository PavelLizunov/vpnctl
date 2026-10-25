# Contract: Atomic server registration

## Intent & Invariants

- Web quick-add, the add-server wizard, CLI `server add`, and CLI bootstrap
  register at most one server for a canonical address, including concurrent calls.
- Reuse CDX-59 comparison: parsed IP equality for literals and ASCII
  case-insensitive equality for hostnames. Stored address spelling is unchanged.
- Existing duplicate rows remain readable. No schema migration or client wire
  format changes are required.

## Interface / Data Contract

- `SqliteInventory::register_server(&Server, actor: &str)` checks for an existing
  canonical address inside the same `BEGIN IMMEDIATE` transaction that inserts
  the server, kernels, protocols, resolved literal IP, and `server.register` audit.
- Address or ID conflicts return `SqliteInventoryError::AlreadyExists` without
  mutations or audit rows. Audit failure rolls back the entire registration.
- `server_id_for_address` shares the canonical comparison with registration.
  Its preflight use provides early feedback but does not enforce serialization.
- Low-level `add_server` retains its existing import/fixture semantics; operator
  registration entry points use `register_server` instead. Existing detailed
  caller audit events remain available alongside the atomic registration event.

## Verification Checklist

- [ ] Two concurrent registrations for IPv4, equivalent IPv6 spellings, or
  hostname case variants yield one success, one conflict, and one registration audit.
- [ ] Duplicate IDs fail without changing an existing server or adding an audit.
- [ ] A failed audit insert rolls back the server and all dependent rows.
