# Editorial icons — verification record

Scope: isolated `feat/editorial-icons`, based on `9baace9`; no main merge, push or production deployment.

## Coverage and deliberate exclusions

- Primary navigation, shared dashboard/server/user/settings tabs, favicon and bracket-dot masthead.
- Dashboard, fleet monitoring, servers, users, audit, alerts, search, Boosty, settings and backups.
- Server protocol/configuration/grant/drift controls, user delivery/access/activity controls, delete confirmations and server wizard.
- Information, warning, critical, acknowledgement, online/offline, pending/completed and version-drift indicators; action controls retain words and native semantics.
- Preserved QR and chart SVGs/tooltips, logs, Telegram formatting, secrets/masked data, prose arrows, numeric signs, native disclosure controls and ordinary linked IDs.
- The unused legacy shell topbar is not a served surface; its duplicated brand drawing delegates to the current glyph. Theme picker group uses a palette icon.
- Lucide subset: 52 symbols pinned to `a537cb6eb323b885f4c60baf3cec1a995982d167`, license in `daemon/assets/icons-LICENSE.txt`. Import script reproduces source; browser needs no network/package dependency.

## Reproducible checks

Executed locally with Rust 1.98.0. `cargo` was installed but absent from default PATH; tools were added to the command environment only. `just`, `cargo-deny`, `gitleaks` and Playwright driver were isolated in a temporary tools directory, not project dependencies.

- `cargo check --workspace --all-targets` — exit 0.
- `cargo fmt --all`, `cargo fmt --all -- --check` — exit 0.
- `cargo clippy --workspace --all-targets -- -D warnings` — exit 0.
- `cargo test -p vpnctld --test admin_smoke` — 470 passed, 1 intentionally ignored fixture export; exit 0.
- `just ci` — exit 0, including generated inventory, CSS bundle, formatting, strict Clippy, `cargo test --workspace --all-targets` and `cargo deny check`.
- `cargo deny check` — exit 0; existing duplicate-version warnings remain, no dependency changes.
- `node --check daemon/assets/admin.js` and `python3 scripts/bundle-css.py --check` — exit 0.
- `gitleaks stdin --redact < <complete task diff>` — exit 0, no leaks.

Export actual router HTML using only synthetic temporary inventory (the exporter guards against reading host keys/backups):

```sh
VPNCTL_ICON_FIXTURES=/tmp/vpnctl-icon-fixtures \
VPNCTLD_DEPLOY_KEY=/tmp/vpnctl-icon-fixtures/absent-key \
cargo test -p vpnctld --test admin_smoke \
  icon_fixtures::export_icon_fixtures -- --ignored --exact --nocapture

NODE_PATH=<directory-containing-playwright-core> \
CHROME_BIN=<local-chromium-executable> \
VPNCTL_ICON_FIXTURES=/tmp/vpnctl-icon-fixtures \
node scripts/tests/icons-browser.cjs
```

Final browser regression: exit 0, **736 offline renders and 624 SSE transitions**. The exporter produced 184 pages (23 routes/tabs, four themes, two locales). Browser regression covers desktop 1440px and mobile 390px, JavaScript enabled and disabled, all icon references/rendering, topbar/body bounds and fake SSE busy/error/transport/retry/success states. Requests are intercepted at a synthetic origin; unmatched traffic is aborted. No server or live VPN action is needed.

## Independent review and limits

Diff-only independent review caught two accessibility errors: decorative-only conditional warnings, and acknowledgement incorrectly described as resolution. Both were corrected; bilingual telemetry/acknowledgement regressions pin the distinction.

Independent visual reviewer inspected contact sheets at 16/20/24px and actual router screenshots, including mobile controls and wizard states. Contrast correction made dark success/critical strokes 7.58:1 / 7.26:1 and tooltip information icons at least 6.52:1 in sampled themes. Lowest sampled functional icon was pending in foxed theme, 3.29:1.

Existing narrow-screen content may require horizontal scrolling inside the main/table region; the action remains reachable. This task does not redesign those forms. Screenshot sampling is not exhaustive state/accessibility certification. Docker-backed ignored SSH suites, GitHub Actions and production verification were not run; no SSH/backend/protocol behavior was changed. Deploy script alone does not install admin assets: a future approved release must also deliver CSS/JS/SVG assets.
