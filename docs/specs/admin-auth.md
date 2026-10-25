# Contract: admin authentication

## 1. Intent & Invariants

- Keep password verification off the async runtime and bound failed-login work.
- Preserve Basic authentication and the signed session cookie format; session
  signing must require an independent persisted installation secret.
- Reject incomplete or unsupported Argon2 PHC configuration at startup, including
  hash-less strings, invalid parameters, unsupported versions and invalid salts.

Generate the admin password's Argon2id PHC hash with `vpnctl admin hash-password`
(reads one line from stdin). No separate shell script or `argon2` executable is
needed.

## 2. Interface / Data Contract

- `GET /api/v1/stats/sub-access` uses the admin authentication middleware,
  including Basic authentication and signed sessions. It retains its URL,
  query parameters, JSON shape and `Cache-Control: no-store`. Like the admin
  UI, it permits unauthenticated local development when admin credentials are
  absent; external binds remain subject to the existing startup auth policy.
- Password verification runs in `tokio::task::spawn_blocking`.
- Without a valid session, at most five password attempts per client IP are
  admitted within 60 seconds of the first attempt. In-flight attempts reserve
  budget before verification; a successful login clears that IP's budget.
- Use `resolve_peer_real_ip` with `ConnectInfo` and the existing trusted-proxy
  policy. Missing peer metadata shares one anonymous bucket; forwarding headers
  from untrusted peers cannot select a different bucket.
- Keep at most 1024 active buckets in memory. Expired buckets are removed on the
  next password attempt; a full table evicts the oldest bucket, so many
  addresses cannot lock the operator out.
  Throttled requests return 429 with `Retry-After: 60`, without verifying a
  password. Valid session cookies bypass password throttling.
- At most four Argon2 verifications run concurrently (process-wide semaphore);
  further password attempts wait for a permit, bounding CPU use under a flood
  from many addresses. The blocking job owns the permit until verification ends,
  including when the HTTP request is cancelled or times out.
- At startup, load the installation's 32-byte OS-random session secret from
  `admin_auth_settings`, generating it once if absent. Creation and its
  `admin.session_secret.create` audit row are one `BEGIN IMMEDIATE` transaction;
  subsequent loads are read-only and add no audit row. Never log or audit the
  secret. Inventory backups preserve it.
- Derive the signing key from both this secret and the configured password
  (plaintext or PHC), so possession of a PHC alone cannot forge a session.
  Restarts preserve sessions; changing the username or password configuration
  invalidates them. The first upgrade from password-only signing invalidates
  existing cookies and requires Basic authentication again; never accept the
  old derivation as a fallback.
- Session cookies include `Path=/`, `Max-Age`, `HttpOnly` and `SameSite=Lax`.
  Add `Secure` only when `ConnectInfo` identifies a trusted proxy under
  `VPNCTLD_TRUSTED_PROXIES` and its `X-Forwarded-Proto` is exactly `https`.
  Ignore forwarding headers from untrusted peers or without peer metadata;
  missing, HTTP or ambiguous schemes do not set `Secure`. Direct HTTP admin
  access (including Tailscale) remains supported. HTTPS proxies must overwrite
  client-supplied `X-Forwarded-Proto` with the actual external scheme.
- `POST /admin/logout` expires the cookie and returns 401 with a Basic challenge
  for the same realm and `Cache-Control: no-store`. The auth middleware must not
  append a fresh session cookie to that response. There is no automatic redirect
  back into the authenticated UI. Browsers may show a login prompt; cancel it to
  remain logged out. Basic credential-cache handling depends on the browser.
- Logout clears this browser's cookie; it does not revoke copied signed cookies.

## 3. Verification

- With admin credentials configured, subscription statistics reject missing or
  invalid credentials before querying inventory; valid credentials retain the
  JSON response and `no-store` policy.
- Argon2 verification allows other tasks to progress on a single-thread runtime.
- Cancelling verification futures cannot release permits held by queued blocking
  jobs; permits return only after those jobs finish.
- PHC-only forged cookies fail middleware authentication. Sessions survive
  inventory reopen with unchanged credentials, but fail after credential changes
  or with a different installation secret.
- Concurrent secret initialization creates one shared secret and one redacted
  audit row; audit failure rolls back creation; reopening does not rotate it.
- Trusted HTTPS forwarding sets `Secure`; HTTP, missing metadata, untrusted
  forwarding and ambiguous schemes do not.
- Failures throttle the same IP before verification; another IP can log in.
- Successful authentication resets failures; valid sessions remain usable.
- Bucket capacity and expiry boundaries are enforced without sleeping in tests.
- Basic-authenticated and cookie-authenticated logout responses have exactly one
  expired cookie, a 401 challenge, and no redirect or replacement session cookie.
- Startup rejects hash-less PHC configuration on loopback and nonlocal binds,
  including with the insecure-bind override enabled.
