## 2026-07-15 - Content-Disposition Header Filename Sanitization Pattern
**Vulnerability:** Raw file/resource identifiers (e.g. backup snapshot names, user IDs) embedded directly into `Content-Disposition: attachment; filename="..."` HTTP headers can lead to HTTP response splitting or header manipulation if they contain CRLF (`\r\n`), quotes, or control characters.
**Learning:** `daemon/src/handlers/admin/audit.rs` defines a centralized `sanitize_header_filename` helper that strips control characters, `\r`, `\n`, `"`, and `\` before embedding strings into HTTP headers.
**Prevention:** Always use `super::audit::sanitize_header_filename` when embedding dynamic strings into `Content-Disposition` attachment filenames across daemon endpoints instead of ad-hoc closures or raw format strings.
