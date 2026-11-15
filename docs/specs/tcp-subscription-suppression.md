# Confirmed TCP outages hide subscription routes

## Intent & invariants
- Existing completed VPN TCP quality rounds, not management SSH, drive automatic
  subscription hiding. Preserve grants, identities, protocol visibility, node
  services and cached client profiles. Clients receive changes on subscription
  refresh. TCP reachability is scoped to the named measurement network.
- Keep the per-server auto-suppress switch. New `register_server` registrations
  enable it; low-level imports/fixtures and existing stored choices are unchanged.
  Enable it for the owner's existing fleet through audited operator actions at
  rollout. No schema migration or new network probes are required.

## Interface / data contract
- `SqliteInventory::record_service_path(&ServiceQualitySample, &str, u64)` keeps
  its existing validation, incident and streak contract. In the same transaction,
  reconcile subscription suppression only for the latest path selected by
  `checked_at DESC, rowid DESC` and a sample no older than `max_gap_secs`.
  The tie-breaker is the state row's original insertion order; updating an old
  path does not make its rowid newer.
- With auto-suppress enabled, fresh `Unreachable` (the existing two consecutive
  zero-success-round confirmation) sets suppression. One failure, partial success,
  unknown/no-target input and historical/duplicate/out-of-order observations never
  newly suppress. Once suppressed, partial/unknown measurements and the first
  full-success round retain suppression. Two consecutive full successes on the
  same current path restore it, including after a daemon restart. A path change
  requires two successes on the new path; evidence from different paths is not mixed.
  Gaps and unknown/partial rounds reset the applicable streaks as before.
- Other, older measurement paths cannot hide or restore the current path's
  server. Opt-out prevents new suppression; switching it off retains the existing
  immediate restoration behavior. SSH failures/successes still manage SSH alerts
  but never change subscription suppression.
- Reuse `server.auto_suppressed` / `server.auto_restored` audit actions once per
  actual toggle, transactionally with the observation. No no-op audit spam. DB
  failures roll back both observation and toggle; malformed input changes nothing.
- All existing subscription formats, app-config, chained routes and admin
  deliveries use the existing suppression gate. The unaffected routes and the
  entire recovered response retain their exact pre-outage bytes. The switch's
  EN/RU copy explains two TCP rounds and two recovery rounds without claiming
  reachability when measurements are absent.

## Verification
- Independent spec tests cover default registration, two-round hide/restore,
  opt-out, partial/unknown/gap/reset, stale/duplicate/multi-path observations,
  persistence/reopen, error paths and exactly-once audit.
- HTTP regression covers `/sub` formats and app-config before, hidden and
  restored; compare complete recovered response bytes and preserve grants.
  A planted mutation of suppression must fail those tests. SSH regressions prove
  that neither failed nor successful SSH changes suppression.
- Independent diff review; fmt, cargo/just CI, generated-file and secret checks;
  deploy exact green artifacts with binary backup; verify production health/UI,
  audited fleet settings, current TCP state and unchanged client identities.
