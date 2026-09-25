## 2026-07-10 - Strict ASCII Sanitization for HTTP Header Filenames
**Vulnerability:** HTTP `Content-Disposition` attachment filenames derived from dynamic strings (such as user or server IDs) could contain non-ASCII characters or header metacharacters, causing Axum's `HeaderValue` conversion to return `InvalidHeaderValue` errors (resulting in 500 Internal Server Error) or allowing HTTP header parameter injection.
**Learning:** `HeaderValue` in `http` / `axum` strictly requires printable ASCII (`0x20..=0x7E`). Ad-hoc filters that only strip quotes and control characters still permit non-ASCII Unicode or header punctuation like semicolons and slashes.
**Prevention:** Always sanitize dynamic strings used in HTTP header parameters by restricting them to ASCII alphanumeric characters (`a-z`, `A-Z`, `0-9`), `-`, `_`, and `.`, providing a safe non-empty fallback like `"download"`.

## 2026-07-10 - Prohibit Caching on Sensitive Attachment Downloads
**Vulnerability:** File download and CSV export endpoints (such as WireGuard configurations containing user private keys, database backup snapshots containing full inventory state/secrets, and audit/access CSV logs) were missing `Cache-Control: no-store` HTTP headers, exposing private keys and sensitive logs to browser or proxy cache persistence.
**Learning:** Returning `Content-Disposition: attachment` without explicit `Cache-Control: no-store` allows shared or browser caches to store private client configuration files, database backups, and access records.
**Prevention:** Always include `Cache-Control: no-store` on HTTP response headers for any endpoint serving sensitive file downloads, secrets, backups, or access logs.
