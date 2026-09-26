## 2026-07-10 - Strict ASCII Sanitization for HTTP Header Filenames
**Vulnerability:** HTTP `Content-Disposition` attachment filenames derived from dynamic strings (such as user or server IDs) could contain non-ASCII characters or header metacharacters, causing Axum's `HeaderValue` conversion to return `InvalidHeaderValue` errors (resulting in 500 Internal Server Error) or allowing HTTP header parameter injection.
**Learning:** `HeaderValue` in `http` / `axum` strictly requires printable ASCII (`0x20..=0x7E`). Ad-hoc filters that only strip quotes and control characters still permit non-ASCII Unicode or header punctuation like semicolons and slashes.
**Prevention:** Always sanitize dynamic strings used in HTTP header parameters by restricting them to ASCII alphanumeric characters (`a-z`, `A-Z`, `0-9`), `-`, `_`, and `.`, providing a safe non-empty fallback like `"download"`.

## 2026-09-15 - Rejection of % and | Prefixes in CSV Formula Guard
**Vulnerability:** Attempted extension of CSV formula injection neutralization to cover `%` and `|` prefixes.
**Learning:** Indiscriminately prefixing `%` and `|` with a single quote alters legitimate CSV values without security benefit. In Excel/LibreOffice DDE formulas, `|` appears inside the expression following `=`, while standard formula triggers are strictly `=`, `+`, `-`, and `@`.
**Prevention:** Do not add `%` or `|` to CSV formula neutralization guards unless a reproducible exploit vector is demonstrated; stick strictly to OWASP-standard `=`, `+`, `-`, and `@` triggers.
