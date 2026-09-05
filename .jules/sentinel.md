## 2026-07-10 - Strict ASCII Sanitization for HTTP Header Filenames
**Vulnerability:** HTTP `Content-Disposition` attachment filenames derived from dynamic strings (such as user or server IDs) could contain non-ASCII characters or header metacharacters, causing Axum's `HeaderValue` conversion to return `InvalidHeaderValue` errors (resulting in 500 Internal Server Error) or allowing HTTP header parameter injection.
**Learning:** `HeaderValue` in `http` / `axum` strictly requires printable ASCII (`0x20..=0x7E`). Ad-hoc filters that only strip quotes and control characters still permit non-ASCII Unicode or header punctuation like semicolons and slashes.
**Prevention:** Always sanitize dynamic strings used in HTTP header parameters by restricting them to ASCII alphanumeric characters (`a-z`, `A-Z`, `0-9`), `-`, `_`, and `.`, providing a safe non-empty fallback like `"download"`.

## 2026-07-10 - Open Redirect via Path Traversal in Referer Sanitization
**Vulnerability:** `sanitize_referer` validated that the referer path started with `/admin/`, but permitted `..`, `\`, and `//` sequences (e.g. `/admin/../..//evil.com`), which browsers resolve as protocol-relative redirects off-site to `//evil.com`.
**Learning:** `starts_with("/prefix/")` checks on URL paths are insufficient when relative path navigation (`..`), backslashes (`\`), or double slashes (`//`) are allowed in the path segment before browser normalization.
**Prevention:** Strictly reject path traversal (`..`), backslashes (`\`), and double slashes (`//`) in sanitized redirect targets to prevent open-redirect vulnerabilities.
