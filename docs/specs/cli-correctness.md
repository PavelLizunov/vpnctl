# Spec: CLI inventory changes and failure reporting

## Intent & Invariants

- CLI automation must distinguish saved inventory state from applied node state,
  reject invalid input before mutation, and report generation failures to callers.
- Reuse the web user-ID validator and fingerprint audit schema. Preserve successful
  subscription bytes and audit actual mutations only.

## Interface/Data contract

- `user disable` and `user enable` update inventory only by default. Help and output say so;
  output lists `vpnctl deploy <id>` for each granted server still pending deploy,
  including on a no-op retry. Already deployed and ungranted servers are omitted.
  With `--deploy`, after saving the audited flag change, the command immediately
  deploys exactly that listed set through the existing CLI deploy path, using its
  default SSH key (`~/.ssh/id_ed25519`). Every listed server is attempted; any
  failure returns a nonzero exit code with per-server errors. The inventory flag
  remains saved, and a no-op retry with `--deploy` retries pending servers without
  another flag-change audit. An empty pending set succeeds without a deploy.
  `set_user_disabled_audited(&self, id: &UserId, disabled: bool, actor: &str)`
  commits the flag and canonical `user.disable` / `user.enable` audit together
  under `BEGIN IMMEDIATE`; audit failure rolls back the flag. It returns whether
  the flag changed; missing users are errors and no-op retries write no audit.
- `user add` uses `vpnctl_core::valid_user_id`: 2–32 ASCII bytes from `a-z`,
  `0-9`, `.`, `_`, `-`; alphanumeric endpoints; no consecutive dots. No trimming.
  Existing stored IDs are unaffected; web validation is unchanged.
  WireGuard keys are generated and stored as a pair by default, matching web
  creation. `--gen-wireguard` remains accepted; `--wireguard-pubkey` explicitly
  stores an external public key without a private key. The legacy admin `.conf`
  download returns 409 for a missing or empty half and points at Generate/Rotate
  on the user's Delivery tab; GET never changes keys.
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
  omit servers after a successful deploy audit. Audit failure rolls back either
  flag change; reopening and retrying preserves pending deploy without a new row.
- [ ] Both commands parse `--deploy` with an inventory-only default. Immediate
  deploy attempts exactly the pending granted set, continues after a server fails,
  returns nonzero on any failure, and succeeds without work when nothing is pending.
- [ ] Default CLI and web creation store matching WireGuard keys; explicit external
  public keys stay unchanged. Incomplete legacy downloads return 409 without mutation.
- [ ] Invalid IDs and port values leave rows and audit unchanged; boundaries pass.
- [ ] Mocked SSH command failures preserve JSON stdout and TOFU audit on both paths.
- [ ] Share-link errors exit nonzero; successful subscription bytes stay pinned.
