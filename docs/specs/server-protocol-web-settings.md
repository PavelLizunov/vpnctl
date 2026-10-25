# Server protocol web settings (R3-08)

## Intent & invariants

The server detail Protocols tab exposes the REALITY handshake hostname and HY2
obfuscation password rotation. Existing protocol renderers and default client
output remain unchanged. Obfuscation passwords never appear in HTML, responses
or audit payloads.
Each actual inventory change and its audit row commit atomically; no-op saves
produce neither an audit row nor a new pending-deploy state.

## Interface / data contract

- `POST /admin/servers/{id}/reality-config` accepts the existing `listen_port`
  and optional `sni`. Omitted `sni` preserves the stored value for existing
  callers. A supplied SNI is trimmed, nonempty, at most 253 ASCII bytes, with
  DNS labels of 1–63 alphanumeric/hyphen characters, alphanumeric edges, and
  no IP literals. The form shows the stored value or `DEFAULT_REALITY_SNI`.
  Invalid input or port conflicts return 400 without mutations.
- `POST /admin/servers/{id}/hysteria2-obfs-rotate` requires HY2 enabled,
  generates a fresh password with `vpnctl_crypto::gen_password(24)`, and never
  accepts password material from the browser. Unknown servers return 404.
- Both routes use the admin authentication and same-origin CSRF middleware;
  success redirects to the server Protocols tab. REALITY records
  `server.reality.set`; HY2 records `server.secret.set`. Both mark pending
  deploy through the existing inventory query. EN/RU copy tells the operator
  to deploy, then clients refresh their subscriptions to receive the value.
- `POST /admin/servers/{id}/naive-config` and `vlessws-config` save their full
  field sets through the same audited inventory API. Changed values record
  `server.naive.set` / `server.vlessws.set` with changed key names only; saving
  identical values after deploy creates no audit row and leaves pending clear.
- Inventory API: `set_server_secrets_audited(&self, id: &ServerId, actor: &str,
  action: &str, values: &[(&str, &str)]) -> Result<bool>` atomically upserts
  changed entries and writes one audit row containing only changed key names.
  It returns whether any entries changed; unknown servers are errors, empty
  batches and identical values are no-ops. No existing setter changes behavior.

## Verification

- Admin smoke tests cover EN/RU forms, current/default SNI, valid save,
  no-op save, invalid hostnames, port validation, missing servers, rotation,
  disabled HY2 rejection and missing/cross-origin CSRF rejection.
- Naive and VLESS-WS tests cover initial save, identical resave after deploy,
  and a changed-domain save that marks pending again.
- Verify audit/pending status and absence of secret values in audit/HTML.
- Pin unchanged and intentionally updated share-link bytes through the web
  actions; unrelated protocol links remain byte-identical.
- Inventory tests cover atomic audit, no-op, concurrent equal saves and rollback
  when an audit insert fails. Compilation and test execution are left to the
  lead for this shared-machine task.
