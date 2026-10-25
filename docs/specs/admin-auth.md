# Contract: admin authentication

## 1. Intent & Invariants

- Keep password verification off the async runtime and bound failed-login work.
- Preserve Basic authentication and existing signed session cookies.
- Reject incomplete or unsupported Argon2 PHC configuration at startup, including
  hash-less strings, invalid parameters, unsupported versions and invalid salts.

## 2. Interface / Data Contract

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
  from many addresses.
- `POST /admin/logout` expires the cookie and returns 401 with a Basic challenge
  for the same realm and `Cache-Control: no-store`. The auth middleware must not
  append a fresh session cookie to that response. There is no automatic redirect
  back into the authenticated UI. Browsers may show a login prompt; cancel it to
  remain logged out. Basic credential-cache handling depends on the browser.
- Logout clears this browser's cookie; it does not revoke copied signed cookies.

## 3. Verification

- Argon2 verification allows other tasks to progress on a single-thread runtime.
- Failures throttle the same IP before verification; another IP can log in.
- Successful authentication resets failures; valid sessions remain usable.
- Bucket capacity and expiry boundaries are enforced without sleeping in tests.
- Basic-authenticated and cookie-authenticated logout responses have exactly one
  expired cookie, a 401 challenge, and no redirect or replacement session cookie.
- Startup rejects hash-less PHC configuration on loopback and nonlocal binds,
  including with the insecure-bind override enabled.
