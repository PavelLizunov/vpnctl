# Corp portal browser verification

## Intent and invariants

Verify the current Russian portal at 320px and 420px in GitHub Actions, using
HTML and security headers exported by the real router's synthetic HTTP tests
and the repository's actual `corp.css` and `corp.js`. Do not duplicate views,
contact a running service, use production data, or run browsers/builds on the
control-plane workstation. Every browser request is fulfilled or rejected by
Playwright routing; no HTTP server is started.
WebSockets are separately intercepted and rejected before page creation, without
connecting upstream; an attempted socket is a test failure.

## Interface and data contract

- `cargo test -p vpnctld --test spec_corp_policy_http` exports `editor.html`,
  `login.html`, `denied.html`, and `unavailable.html` under `CORP_UI_OUTPUT_DIR`.
  Each matching JSON file contains the router's `{status,headers}` response
  metadata, including its content security policy. Exported `assets/corp.css`
  and `assets/corp.js` must match the candidate source bytes.
- `scripts/corp-portal-ui.mjs` loads pinned Playwright tooling from
  `CORP_UI_TOOLING_DIR` and writes PNGs to `CORP_UI_SCREENSHOT_DIR`.
  The CI job installs tooling in its temporary directory, runs the router
  test with the existing Rust cache, runs the browser scenarios, and uploads
  screenshots even when verification fails.
- API responses use fixed synthetic rules, revisions, Russian messages and
  timestamps. Record requests to verify complete-list writes, revision CAS,
  timing, explicit interruption consent, and absence of automatic retries.
- Both rules publication and restore must handle HTTP 408 before commitment
  and after commitment with a lost response. Preserve the local draft and
  block further publication/restore until explicit state reload. Reconcile
  to the unchanged or advanced revision, respectively; never blindly retry.

## Verification checklist

- [x] All four pages render using actual assets and CSP without page errors,
  unexpected requests, horizontal overflow, or clipped confirmation controls.
- [x] Normalize a pasted URL, preview, choose route/comment, add, search,
  edit, remove, and save the complete resulting list; empty lists remain valid.
- [x] Apply-now confirmation blocks submission until interruption consent;
  success copy covers connected and stopped clients without claiming universal
  application. History restores a prior list as a greater revision.
- [x] Conflict and 401 keep the draft; conflict requires reload and access loss
  disables editing. Failed history remains explicitly retryable.
- [x] All four 408 combinations preserve draft and block writes before reload;
  reconciled rules/revision and the next deliberate write use current state.
- [x] Capture login, denied, unavailable, editor, normalized preview, history,
  confirmation, long Russian success/status and error states at both widths.
- [x] Local JavaScript syntax and scoped whitespace checks pass (exit 0).
  Actionlint 1.7.12 validates workflow expressions. Browser scenarios passed
  for head 5758b2010ee24306cf19eb4576db83d7a534f1a6 in run 43700716817;
  artifact 14155914657 contains both widths. Lead inspected the principal
  login, access, editing, consent, history, error and long-text screenshots.

Independent diff-only review found that HTTP routing alone did not intercept
WebSockets. The finding was recorded before the lead added the explicit socket
block; its bounded source correction was checked without browser execution.

## Operator controls extension

The same pinned browser CI job now exports `spec_corp_operator` fixtures under
`CORP_OPERATOR_UI_OUTPUT_DIR`. `corp-operator-ui.mjs` verifies setup, populated
status (including an eligible unverified server), one-time synthetic password and
CAS-conflict pages with actual CSS/security headers at 340/420px. Browser forms
must require explicit confirmation before setup/password rotation, retain CSRF
and configuration-version fields, keep every action visible and require reload
following a conflict. Requests and WebSockets are intercepted without a server;
no production data, cookies or network are used. The existing portal scenarios
remain mandatory. At lifecycle baseline `79b03a1`, run `43711228300`, all 12
CI jobs passed. Artifact `14159864044` records 38 page/interaction groups,
including ready/running/failed/enabled operator states, native enable confirmation,
probe retry and nonmutating status reload. Lead inspected the narrow pages and
bottom controls. New source changes still require fresh exact-head CI.
