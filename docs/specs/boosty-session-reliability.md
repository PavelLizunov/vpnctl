# Spec: durable Boosty sessions and trustworthy automatic provisioning

## 1. Intent & invariants

- Keep automatic provisioning for eligible paid subscribers. Never infer a
  subscriber's identity from a display name or remove existing VPN identities.
- Reuse the access token returned by OAuth until HTTP 401. Save access and
  refresh tokens together before requesting the roster, including dry runs;
  failed/cancelled roster requests must not lose the session. HTTP 403 must
  not rotate tokens: it means access to the selected blog is forbidden.
- Quick Connect imports an existing browser session, not an independent OAuth
  grant. External session revocation still requires reconnection in the admin
  UI; caching tokens cannot recover a revoked refresh credential.
- Quick Connect requires a nonempty blog, access token, refresh token and
  device ID from one import. An incomplete import fails before saving anything.
- Reject incomplete, mispositioned or duplicate subscriber pages before any
  reconciliation mutations. A changing total aborts the pass for a later retry.
  Response `offset` may identify the current start or the next position (the
  requested start plus actual returned rows); other positions are rejected.
- Recheck subscriber links in the auto-create transaction. If any link already
  exists, do not create or report another user. Intentional manual links from
  multiple VPN users to one subscriber remain supported.

## 2. Interface / data contract

`SqliteInventory::save_boosty_session(&self, expected: &BoostySettings,
access_token: &str, refresh_token: &str) -> Result<bool>`:

- Compare stored blog, access token, refresh token and device ID against
  `expected`; a mismatch returns `false` without changing or auditing anything.
- With matching credentials, atomically persist both nonempty new tokens and
  one `boosty.session.refreshed` audit row without credential values. Return
  `true`; an identical pair returns `true` without an audit row.
- Empty/whitespace-only new tokens return an error. Database/audit failures
  roll back both tokens. The bridge aborts when this save fails or returns false.

`add_boosty_user` keeps its signature and returns `AlreadyExists` when the
subscriber is already linked, before inserting anything. Successful creation
and its `boosty.provision` audit row commit together with all initial grants.
Only a committed creation appears in `SyncReport::provisioned`.

## 3. Verification checklist

- [ ] Two sync passes reuse the refreshed access token with one OAuth request;
  a later 401 renews again; roster failure/cancellation still preserves tokens.
- [ ] Session saves cover success, stale credentials, identical pairs, invalid
  new tokens and audit-trigger rollback; audit payloads contain no credentials.
- [ ] HTTP 403 never requests OAuth or changes stored credentials.
- [ ] Incomplete Quick Connect returns a web error without settings changes.
- [ ] Short/empty intermediate pages, wrong offsets, changing totals and
  duplicate subscriber IDs abort without user, lapse or report mutations.
- [ ] A complete paginated roster still creates eligible users automatically;
  an existing manual link prevents creation; retries do not report creation.
