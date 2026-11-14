# Corp browser and reader HTTP contract

## Intent and invariants

Build the fixed `https://admin.corp.ninitux.com` browser portal on the green
signing/storage foundation at `908bcacd9a1c2e41ddc058eb1d6aca47516d10da`.
This block adds host isolation, browser access and publication, and the read-only
client endpoint. Operator setup/export/actual-egress verification follows before
the feature is ready. Nothing activates an unconfigured or disabled Corp binding.

Use the existing public `vpnctld::app::router(AppState)` entry point. Tests create
an isolated `SqliteInventory`, registry through `vpnctl_kernels::build_registry`,
and state through `app::make_app_state_for_tests`. No environment mutation,
production data, real sockets, build or test execution on the control-plane host.
Storage/wire API contracts and the eligibility contract own fixture setup.

## Host and address boundary

- Dispatch Corp before legacy paths. Exactly one Host equal case-insensitively to
  `admin.corp.ninitux.com` or that name with port `443` enters the Corp router.
  A URI authority, when present with Host, must agree. Reject ambiguous/invalid
  authorities, duplicate Host fields and Corp trailing-dot/non-443-port forms.
  A missing Host remains compatible for existing legacy routes but cannot reach
  Corp through an absolute URI. A Corp request never reaches operator/public
  subscription routes, even when disabled or for unknown paths. Unknown Corp
  paths return 404. The reader path on another host returns 404.
- Corp bodies are at most 65536 bytes, including streamed/chunked bodies; legacy
  routes retain their 8192-byte cap. Both branches retain a 15-second timeout
  and common tracing. Corp timeout responses are 408 with a Russian JSON message
  and all security headers, including when the request body never completes. Never
  log raw paths, query values, credentials, cookies, body or signed documents.
- Browser requests need a real `ConnectInfo<SocketAddr>` peer. Normalize mapped
  IPv6 to IPv4. Trust X-Real-IP only from a configured trusted peer, and require
  one well-formed address in that case; missing, duplicate or malformed trusted
  forwarding evidence denies access. Untrusted X-Real-IP and all XFF do not
  establish identity. Never substitute a missing peer or trusted proxy address.
- Public pure helper for independent tests:
  `corp_portal::resolve_client_ip(headers: &HeaderMap, peer: Option<IpAddr>,
  trusted_peer: bool) -> Option<IpAddr>`. Production derives trusted_peer from
  the configured trusted-proxy set, not from a request header.
- At every browser request, require active Corp and enabled bound user; intersect
  the request IP with explicit stored verified egress and current eligible
  server/fingerprint results. Verified timestamps must be no later than now and
  at most 86400 seconds old. Inventory/DNS IPs never implicitly grant access.
  Losing the grant, protocol visibility, direct profile, matching configuration,
  enabled user or Corp state denies previously authenticated browsers too.

## Sessions and login

- GET `/`: unavailable binding -> friendly 503; disallowed IP/missing peer ->
  friendly 403 with VPN instructions, an escaped observed IP when known and a
  retry link; eligible IP without a current Corp session -> password page 200;
  eligible authenticated browser -> editor 200.
- POST `/login`: URL-encoded form with exactly `password`, 1..512 UTF-8 bytes.
  Require one exact Origin `https://admin.corp.ninitux.com`; no Referer fallback.
  Duplicate Origin/content-type or duplicate form fields are rejected. Recheck
  current eligibility after password verification. Wrong password -> 401 and no
  session. Throttle per address to five attempts per 60 seconds, with bounded
  state; a sixth attempt returns 429 and Retry-After. Keep password CPU work
  bounded through the existing shared semaphore, held inside the blocking job
  even when the HTTP request is cancelled.
- Corp passwords are Argon2id v19, parameters bounded to 8192..65536 KiB memory,
  1..4 iterations, 1..4 lanes, 16..64-byte salt and 32-byte output. Unsupported
  hashes fail closed before expensive work. A plaintext Corp password is never
  accepted. Operator BasicAuth behavior is preserved.
- Successful login returns 303 to `/` with a fresh 32-byte random session token
  in `__Host-vpnctl_corp`, Path=/, Secure, HttpOnly, SameSite=Strict, Max-Age=28800,
  and no Domain. Store only SHA-256 of that token plus a separate random CSRF
  value, using the captured auth generation. Concurrent revocation cannot issue
  a session under an old generation. Operator cookies/BasicAuth and reader
  bearer tokens never authenticate a Corp browser.
- Reject duplicate Corp cookies and relevant duplicate authorization/CSRF headers.
  Mutating session APIs and POST `/logout` need exact Origin and X-Corp-CSRF
  matching the session (constant-time); missing, forged, expired or revoked
  session -> 401; wrong Origin/CSRF -> 403. Logout revokes the stored session and
  expires the same strict cookie; response is 303 to `/`.

## Editor APIs

- GET `/api/corp/state`: session/IP gate; JSON `{revision,rules,csrf}`. Revision 0
  returns the editable EXE seed, not a persisted publication. Otherwise use the
  current exact stored policy's validated rules. Never include credentials,
  private signing keys, subscription IDs/URLs or operator data.
- POST `/api/corp/normalize`: JSON exactly `{site:string}`; requires session,
  Origin and CSRF; returns `{domain:string}` or 422. Apply wire normalization and
  reject protected/invalid editable sites. It does not mutate or audit.
- POST `/api/corp/rules`: JSON exactly `{expected_revision:u64,apply:string,
  confirm_interrupt:bool,rules:Vec<PolicyRule>}`. Rules must already be normalized
  and satisfy wire v1. `apply` is `next_connection` by default in the UI, or `now`
  only with confirm_interrupt=true. Bad input -> 422, no mutation. Stale revision
  or concurrent config/signer change -> 409, no partial overwrite. Successful
  publication signs a new complete list under the active key, at current+1, then
  atomically stores original bytes and audit. Return 200 `{revision,published_at}`.
  An empty list is valid and preserves deletions. Signer import must match its
  stored SPKI. Do not report all clients as applied or turn a stopped VPN on.
- GET `/api/corp/history`: JSON array of at most 100 newest-first entries, each
  `{revision,published_at,apply,rule_count}`; session/IP gate.
- POST `/api/corp/restore`: JSON exactly `{expected_revision:u64,revision:u64,
  apply:string,confirm_interrupt:bool}`; same write gates. Missing/pruned source
  -> 404. Revalidate historical rules and sign them as a NEW greater revision
  with current key/time and requested timing. Never lower or reset the floor.
- JSON rejects duplicate/unknown/missing fields and invalid types. Internal
  failures return a generic error, without secrets or database details. API
  errors contain a human-readable Russian `message` field. Browser pages escape
  all dynamic content. Publication timestamps are bounded positive Unix seconds.

## Reader and assets

- GET `/api/v1/corp/policy`: fixed Corp host only. Require exactly one bounded
  `Authorization: Bearer <reader-token>`; compare secrets in constant time.
  No browser IP/session/CSRF gate here: a stopped VPN client must fetch. Unknown
  credential -> 401. Missing/disabled/deleted binding -> 503. Revision 0 -> 404.
  A concurrent config rotation rejects the old captured reader version. Return
  original envelope bytes with application/json, no redirects and no-store.
  Query/path parameters cannot choose or override Corp identity/credentials.
- GET `/assets/corp.css` and `/assets/corp.js` are fixed public assets on the Corp
  host, including while disabled/denied, so instructional pages render. No
  user-controlled filesystem path or operator assets are served.
- All Corp responses, including error/fallback/body-limit responses, carry
  no-store, nosniff, DENY framing, no-referrer, noindex/nofollow and a restrictive
  CSP: scripts/styles/connect/form-action self, no inline scripts, objects,
  frames or external fonts. HTTPS ingress is a deployment prerequisite; cookies
  are always Secure and password form action uses the canonical HTTPS origin.

## Russian UI and verification

Simple responsive pages: VPN instruction -> password -> searchable site list.
Editor title `Корпоративные правила`, columns `Сайт`, `Маршрут`, `Комментарий`;
directions `Без VPN` / `Через VPN`. A pasted site or URL is normalized on the
server and shown before the user confirms adding it. Users can change direction,
edit comments, remove sites, save the complete list, view history and restore.
Primary save defaults to next connection. Applying now warns about a brief
connection interruption and requires explicit confirmation. Publication success
says rules were saved and when clients will use them, never that every client
already applied. Conflicts preserve the local draft and offer reload. Technical
tokens, key IDs, SQL, hashes and provisioning jargon stay out of the flow.
Network errors, malformed successful replies, 408 and 5xx publication/restore
responses leave publication uncertain: preserve the draft and require loading
current state before another write. A timeout may occur before or after commit;
the UI must reconcile either result without blindly resubmitting.

Independent spec tests must exercise the real router, gates, signing and storage,
including successful login/publication, wrong credentials/IP, missing/forged
peer evidence, cross-host/operator access, both apply modes, empty policy, CAS,
revocation, history/restore, unknown/duplicate fields and body limits above the
legacy 8 KiB. Copy/escaping checks pin new pages and denial text. Deterministic
synthetic narrow-width rendering is required before final feature handoff; live
deployment/client scenarios remain separate authorized operations.
