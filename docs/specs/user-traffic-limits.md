# Contract: user traffic limit mutations

## 1. Intent & Invariants

- Saving an unchanged traffic limit or alert threshold writes no audit row.
- Concurrent identical saves must record one actual mutation, not two.
- Preserve user limits and CLI/web form behavior, including clearing a cap.

## 2. Interface / Data Contract

- `SqliteInventory::set_user_traffic_limit` returns `Result<bool>`: true only
  when the stored limit or threshold changed; false for a no-op. Unknown users
  return an error. Change detection is part of the SQL UPDATE predicate.
- Byte limits saturate at `i64::MAX` before comparison with persisted values.
  Both nullable fields compare using SQLite's null-safe `IS NOT` operator.
- Web and CLI write `user.traffic_limit.set` only when the setter returns true,
  preserving their actor names and audit payload fields.

## 3. Verification

- Setting, changing a threshold, and clearing a cap each report a mutation.
- Repeating any save, including saturated byte limits, reports no mutation.
- Concurrent identical setter calls report exactly one mutation; concurrent
  identical web requests produce exactly one audit row.
- An unknown user remains an error rather than a successful no-op.
