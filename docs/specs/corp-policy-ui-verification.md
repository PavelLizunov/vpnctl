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

- [ ] All four pages render using actual assets and CSP without page errors,
  unexpected requests, horizontal overflow, or clipped confirmation controls.
- [ ] Normalize a pasted URL, preview, choose route/comment, add, search,
  edit, remove, and save the complete resulting list; empty lists remain valid.
- [ ] Apply-now confirmation blocks submission until interruption consent;
  success copy covers connected and stopped clients without claiming universal
  application. History restores a prior list as a greater revision.
- [ ] Conflict and 401 keep the draft; conflict requires reload and access loss
  disables editing. Failed history remains explicitly retryable.
- [ ] All four 408 combinations preserve draft and block writes before reload;
  reconciled rules/revision and the next deliberate write use current state.
- [ ] Capture login, denied, unavailable, editor, normalized preview, history,
  confirmation, long Russian success/status and error states at both widths.
- [x] Local JavaScript syntax and scoped whitespace checks pass (exit 0).
  Workflow YAML parses. Browser execution and screenshot inspection remain
  pending until the exact candidate's CI artifacts exist.

Independent diff-only review found that HTTP routing alone did not intercept
WebSockets. The finding was recorded before the lead added the explicit socket
block; its bounded source correction was checked without browser execution.
