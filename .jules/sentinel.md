## 2026-07-10 - Strict ASCII Sanitization for HTTP Header Filenames
**Vulnerability:** HTTP `Content-Disposition` attachment filenames derived from dynamic strings (such as user or server IDs) could contain non-ASCII characters or header metacharacters, causing Axum's `HeaderValue` conversion to return `InvalidHeaderValue` errors (resulting in 500 Internal Server Error) or allowing HTTP header parameter injection.
**Learning:** `HeaderValue` in `http` / `axum` strictly requires printable ASCII (`0x20..=0x7E`). Ad-hoc filters that only strip quotes and control characters still permit non-ASCII Unicode or header punctuation like semicolons and slashes.
**Prevention:** Always sanitize dynamic strings used in HTTP header parameters by restricting them to ASCII alphanumeric characters (`a-z`, `A-Z`, `0-9`), `-`, `_`, and `.`, providing a safe non-empty fallback like `"download"`.

## 2026-07-10 - Prohibit Caching on Sensitive Attachment Downloads
**Vulnerability:** File download and CSV export endpoints (such as WireGuard configurations containing user private keys, database backup snapshots containing full inventory state/secrets, and audit/access CSV logs) were missing `Cache-Control: no-store` HTTP headers, exposing private keys and sensitive logs to browser or proxy cache persistence.
**Learning:** Returning `Content-Disposition: attachment` without explicit `Cache-Control: no-store` allows shared or browser caches to store private client configuration files, database backups, and access records.
**Prevention:** Always include `Cache-Control: no-store` on HTTP response headers for any endpoint serving sensitive file downloads, secrets, backups, or access logs.

## 2026-09-15 - Rejection of % and | Prefixes in CSV Formula Guard
**Vulnerability:** Attempted extension of CSV formula injection neutralization to cover `%` and `|` prefixes.
**Learning:** Indiscriminately prefixing `%` and `|` with a single quote alters legitimate CSV values without security benefit. In Excel/LibreOffice DDE formulas, `|` appears inside the expression following `=`, while standard formula triggers are strictly `=`, `+`, `-`, and `@`.
**Prevention:** Do not add `%` or `|` to CSV formula neutralization guards unless a reproducible exploit vector is demonstrated; stick strictly to OWASP-standard `=`, `+`, `-`, and `@` triggers.

## 2026-10-18 - Public credential endpoints and disabled-user downloads are fixed
**Vulnerability:** `/sub/{token}`, `/api/v1/sub/{token}` and `/api/v1/app/config/*` were cacheable; the WireGuard `.conf` download served disabled users.
**Learning:** Both are fixed on main: the public router sets `Cache-Control: no-store`, and the `.conf` download refuses disabled users. Tests: `public_credential_endpoints_are_not_cacheable`, `admin_user_wireguard_conf_download_refuses_disabled_user`.
**Prevention:** Before proposing a fix, check main and open PRs for the same finding; do not open another PR for an issue that already has one.

## 2026-10-25 - Error-page back link and grant-route ID validation are settled
**Vulnerability:** The HTML error page built its back link from `Referer` with its own parser instead of `sanitize_referer`; several PRs proposed format validation of user/server IDs on grant, revoke and access-CSV routes.
**Learning:** The error page now uses `sanitize_referer` (test: `admin_form_error_back_link_rejects_traversal_referer`). ID format checks on those routes add nothing: every handler looks the ID up in the inventory and answers 404 for an unknown one, and `valid_user_id` / `valid_server_id` are creation-time rules for the web form only, so applying them to existing routes would lock out IDs created by the CLI, migration or Boosty paths.
**Prevention:** Do not re-propose path-ID format validation on routes that resolve the ID through the inventory; propose it only with a reproducible wrong behaviour.
