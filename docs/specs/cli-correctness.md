# Spec: CLI inventory changes and failure reporting

## Intent & Invariants

- CLI automation must distinguish saved inventory state from applied node state,
  reject invalid input before mutation, and report generation failures to callers.
- Reuse the web user-ID validator and fingerprint audit schema. Preserve successful
  subscription bytes and audit actual mutations only.

## Interface/Data contract

- `user disable` and `user enable` update inventory only. Help and output say so;
  output lists `vpnctl deploy <id>` for each granted server still pending deploy,
  including on a no-op retry. Already deployed and ungranted servers are omitted.
- `user add` uses `vpnctl_core::valid_user_id`: 2–32 ASCII bytes from `a-z`,
  `0-9`, `.`, `_`, `-`; alphanumeric endpoints; no consecutive dots. No trimming.
  Existing stored IDs are unaffected; web validation is unchanged.
- `server secret` trims `*.listen_port` values and accepts an empty value to restore
  the protocol default, or a nonzero `u16`, matching web settings. Other values
  remain opaque. Invalid ports do not mutate inventory or create an audit row.
- `update-kernels --output json` reserves stdout for the JSON result; connection,
  TOFU and upgrade progress goes to stderr.
- `sub` returns an error and a nonzero exit code when a selected protocol is
  unknown or fails to generate a share link; no partial subscription is emitted.
  Successful text and JSON output retain their bytes.
- TOFU saves in `deploy` and `update-kernels` record `server.fingerprint.set`
  with actor `cli`, server target, and `fingerprint`, `previous`, `source` fields;
  keyscan source is `ssh-keyscan`. Reusing a pinned fingerprint creates no pin audit.

## Verification checklist

- [ ] Disable/enable identify pending servers, retry without mutation audit, and
  omit servers after a successful deploy audit.
- [ ] Invalid IDs and port values leave rows and audit unchanged; boundaries pass.
- [ ] Mocked SSH command failures preserve JSON stdout and TOFU audit on both paths.
- [ ] Share-link errors exit nonzero; successful subscription bytes stay pinned.
