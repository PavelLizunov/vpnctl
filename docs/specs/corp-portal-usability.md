# Corp portal usability and diagnostic deletion

## Intent and invariants

Make the existing Corp site usable for a nontechnical owner. Retain the actual
vpnctl theme, VPN-IP/password gates, CSRF protection and signed-policy behavior.
Show ten rules per desktop page and five on narrow screens, searchable by
domain/comment and filterable by route. Mobile save actions must not overlap rows.
Changing pages/filters must preserve every draft edit; saving publishes the full
draft. Align form controls independently of hint height. Keep save actions nearby.
Diagnostics must support real deletion, not a hidden row or local preference.

Design read: an administration workspace in the existing vpnctl identity;
ENERGY 1, RHYTHM 1, MOTION 1. Pagination bounds scrolling; aligned control rows
make related fields readable; short action labels explain when changes apply.

## Diagnostic deletion interface

- DELETE `/api/corp/reports/ID` requires existing verified Corp egress, active
  session, same origin and `X-Corp-CSRF` before receiver access. The browser sends
  `{}`; the edge ignores a bounded caller body because no client fields are used.
- The Caddy edge authorizes through the existing side-effect-free normalization
  endpoint: POST `/api/corp/normalize` with a fixed example domain, original
  Cookie/Origin/CSRF and authoritative client IP. Only HTTP200 permits deletion.
  It then replaces the request body with `{}` and forwards only service authorization to DELETE
  `/internal/corp-diagnostics/reports/ID`, with the same empty JSON body.
- Success is HTTP200 `{"schema":1,"state":"deleted","freed_bytes":N}` where
  N is a nonnegative integer and describes actual live receipt/archive removal.
  The receiver returns only those fields; no raw archive or credential is exposed.
- Receiver checks enabled scoped service capability and own existing report.
  Foreign, expired and missing IDs give the same404; traversal is invalid.
  Under the shared mutation lock remove both JSON receipt and ZIP. Failure is
  explicit and must not delete foreign files. In-flight analysis cannot recreate
  a deleted report; the existing late-result discard guard remains effective.
- An upload token grants no delete right. Public support intake has no delete
  endpoint. No credentials, policy, database schema or Windows delivery changes.
- Browser confirmation names the removal of report and archive. Cancel does
  nothing. Successful deletion clears selected detail and reloads the list.
  Failure preserves visible report and shows an actionable error. Deleting a
  synthetic acceptance report must demonstrably reduce live storage.

## Deployment without builds

The owner explicitly forbids every rebuild, including the server binary. Deliver
the existing JavaScript/CSS through an exact-path Caddy static route. JavaScript
renders the new controls using DOM APIs within the existing HTML shell. The
scoped DELETE edge reuses existing authorization, and the Python receiver adds
storage removal. No Rust, Windows, toolchain or dependency compilation is needed.
Keep originals, validate Caddy configuration, test the isolated edge with synthetic
upstreams, then reload Caddy and restart only the interpreted receiver if required.

## Verification

Use targeted browser scenarios for pagination/search/filter/edit preservation,
aligned add controls, mobile/keyboard use, deletion confirm/cancel/error and
list/detail recovery. Test delete auth/CSRF/ownership, valid response projection,
receiver denial and late analysis completion. Scan known secret bytes
and redacted generic findings in GitHub history and current public assets.
No builds or full Cargo suites. Use syntax/format/secret checks, focused Python
storage/edge tests and the actual changed browser controls. Synthetic browser
scenarios are maintained for CI; do not invoke the Rust fixture exporter here.
