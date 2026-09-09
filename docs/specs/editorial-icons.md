# Spec: editorial icon refresh

## 1. Intent & Invariants
- Audit all operator web surfaces; replace mixed UI glyphs and add missing navigation, action and status icons.
- Keep the paper/ink visual language and recognizable bracket-dot vpnctl mark; align favicon and masthead.
- Preserve routes, actions, labels, data, API and VPN output. QR codes, charts, prose arrows, log payloads and Telegram emoji are out of scope.
- Work in an isolated branch/worktree; no production deployment or unrelated file edits.

## 2. Interface / Data Contract
- Local SVG icons, consistent 24-unit geometry and optical weight; inherit existing theme colors.
- All four themes and both RU/EN locales remain supported, including narrow screens.
- Decorative icons are aria-hidden; status-only indicators have accessible localized names. Text button labels remain visible.
- No external browser requests, new runtime packages or JavaScript requirement for static icons.
- Dynamic SSE labels and wizard progress retain icons through busy, success and retry states.

## 3. Verification Checklist
- [x] Inventory covers all web icon placements and deliberate exclusions.
- [x] Test small sizes, four themes, both locales, narrow viewport and control states.
- [x] Pass admin tests, workspace cargo gates, CSS bundle check and secret scan.
- [x] Independent diff review and browser visual review completed.
- [x] Report local, main and production states independently; no automatic deploy.
