# Spec: start tickets for operation SSE endpoints

## 1. Intent & Invariants
- Deploy, deploy-all, update-kernels(-all), user deploy-pending and GeoIP
  update-now start work on `GET …/sse` because `EventSource` can only GET.
  The CSRF middleware covers POST only, and `Sec-Fetch-Site` is not sent to the
  plain-HTTP admin origin, so a cross-site navigation must not be able to start
  them (CDX-26).
- Every such GET starts work only with a single-use ticket bound to its exact
  path, issued by a same-origin POST that the CSRF middleware already checks.
- Viewing a page never starts an operation: the server page shows a running
  deploy and refreshes instead of opening the deploy SSE, which would queue
  another full deploy (CDX-45).
- The wizard step-2 SSE is unchanged: it already needs a single-use wizard
  session created by a CSRF-checked POST.
- A transport error closes the stream and keeps the start button disabled until
  reload: the operation may still be running. Only a reported operation failure
  or a refused start ticket permits retry from the same page.
- Starting any button-triggered or autostart SSE cancels the pending
  `data-reload-after` page refresh so it cannot interrupt the new live log.

## 2. Interface / Data contract
```text
POST /admin/sse-ticket            body: path=<SSE path>    (Origin must match Host)
  200 text/plain <ticket>         path is /admin/…/sse or /admin/settings/geoip/update-now
  400                             any other path (incl. wizard step-2)
GET  <SSE path>?ticket=<ticket>   ticket consumed; must match the path, TTL 120 s
  403 "start ticket missing or expired …"   no / wrong / reused / expired ticket
```
Tickets live in daemon memory (lost on restart, at most 256 outstanding).
`admin.js` obtains the ticket on button click, then opens the `EventSource`.

## 3. Verification checklist
- [x] Unit: single use, path binding, non-ticketed paths rejected.
- [x] Smoke: every ticketed SSE route returns 403 without a ticket and keeps its
  previous behaviour with one.
- [x] Server page during an in-flight deploy renders no `data-sse-autostart`.
- [ ] Live: deploy / update-kernels / GeoIP buttons work in a browser after
  deploy (not run).
