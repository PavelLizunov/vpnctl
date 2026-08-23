# vpnctl — agent contract

Linux-only Rust control plane for self-hosted VPN infrastructure (CLI + daemon +
admin UI, SSH-first, no node-side agent). Canonical repo
https://github.com/PavelLizunov/vpnctl, default branch `main`. `README.md`
describes the product; standing contracts live in `docs/specs/`; deferred work
lives in `BACKLOG.md`. This is the ONLY standing agent instruction file —
operational history lives in git history, not in a memory file.

## Product north-star

- Single operator; no multi-tenancy, no RBAC. Users are assumed maximally
  low-tech: for EVERY protocol the operator must be able to hand them ONE
  artefact (one QR / one URL / one file) that works on import without any user
  action. Server-side key generation is the default; anything assuming
  user-side key generation must ship a server-generated default.
- The web admin UI is the ONLY operator surface; the CLI is automation /
  scripting / disaster recovery. Nothing ships CLI-only — every operator action
  needs a web button.
- The add-server wizard (paste IP + root password → fully hardened node) is the
  flagship feature; do not degrade its end-to-end promise.

## Where work runs

- There is NO dedicated build VM (`build-1` / `uap-build-1` are retired). The
  required gate is GitHub Actions CI (`.github/workflows/ci.yml`,
  `ubuntu-latest`); the Forgejo mirror CI (`.forgejo/workflows/ci.yml`, docker
  runner) is best-effort.
- `git push` publishes to TWO remotes (GitHub primary + LAN Forgejo mirror);
  fetch goes to GitHub only. Verify `git remote -v` before pushing; never
  assume where `origin` points.
- Production daemon = VM 119 `vpnctld` (LAN `192.168.0.236`, Tailscale
  `vpnctld`). Admin UI `http://vpnctld/admin/`, health `/api/v1/health`.

## Work safely (shared tree, multiple sessions)

- One task branch + one worktree per task; use a dedicated worktree for
  main-bound work and never switch the shared tree to `main` for it.
- Never switch, clean, reset, stash, or stage another session's files. Stage
  explicit paths only, never `git add -A`.
- Re-check `git branch --show-current` before every commit and after any pull;
  a "Merge … into <branch>" line in pull output is a red flag you are not on
  the branch you expect.
- Each worktree keeps its own `target/`; do not share build dirs between
  worktrees.

## Change review workflow (BLOCKING)

1. Before committing code, run an independent review-agent (it sees ONLY the
   diff and returns findings; fix `critical` + `important`). New public APIs
   additionally need spec-tests written by a test-writer-agent that sees ONLY
   the spec, never the implementation. Prompt templates and the full gate list:
   `docs/specs/agent-workflow.md`.
2. Local gate: `just ci` (runs disk-hygiene `gc` first, then fmt-check +
   clippy `-D warnings` + test + `cargo deny`). The five underlying cargo
   commands are canonical and must pass with recorded exit codes:

   ```sh
   cargo check --workspace --all-targets
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --all-targets
   cargo deny check
   ```

   Run `cargo fmt --all` BEFORE testing, not only `--check` — agent-written
   tests and mass text-replaces are the most frequent fmt-only CI failures.
3. After push, watch CI to completion: `gh run watch <id> --exit-status`; red →
   `gh run view --log-failed` → fix. Never stack new commits on unresolved red
   CI — the next commit is either its hotfix or waits.
4. Docs-only changes still require `just ci` (fmt-check). A hotfix may skip the
   review-agent ONLY if all three hold: ≤ 5 lines, exactly one surface touched,
   no output pinned by byte-equality tests changes.

CI additionally runs gitleaks and two Docker-backed SSH suites:

```sh
docker pull lscr.io/linuxserver/openssh-server:latest
cargo test -p vpnctl-ssh --test e2e_sshd -- --ignored --nocapture
cargo test -p vpnctl-ssh --test spec_password_auth -- --ignored --nocapture
```

Release build is static musl: `just build-release`
(`cargo build --release --target x86_64-unknown-linux-musl`). The historical
zigbuild / glibc-2.36 path is retired. Changes to protocol rendering should
also run `just mutants-protocols` when the mutation tooling is installed
(advisory in CI, not blocking).

## Architecture invariants (cannot be violated)

- Kernel (node daemon) × Protocol (wire format) are orthogonal: adding either
  should take one new file + one registration line in `cli/src/registry.rs`,
  leaving core/ssh/crypto/inventory/daemon untouched. Deviations need explicit
  justification.
- Protocol rendering must not own mutable inventory state; state belongs to the
  inventory/daemon layers and per-server secrets arrive via `RenderCtx`.
  Secret-bearing protocols declare their own server secrets
  (`Protocol::server_secret_specs`) — never keep a central hard-coded protocol
  secret list.
- Every inventory mutation writes an `audit_log` row (audit on actual mutation
  only — no no-op audit spam).
- No `unwrap()` / `expect()` / `panic!()` in production paths (tests may use
  them); no `unsafe`; no `openssl-sys` / `native-tls`. Lints are centralized
  in the workspace `Cargo.toml` — do not add per-crate `#![deny]`.
- Compatibility contract: existing clients keep working byte-for-byte.
  `share_link` / `/sub` / `/api/v1/app/config` output changes require
  byte-level regression tests that fail on a planted mutation. See
  `docs/specs/migration-compatibility.md`.

## Secrets, live state, deploy

- Do not expose live secrets or data (inventory, DB contents, subscription
  URLs/tokens, SSH keys, admin passwords, deploy credentials) in chat, commits,
  logs, tests, or reports. Access production data only through approved
  operational procedures. Use placeholders in tests/examples; run gitleaks on
  the diff before push.
- Live state is OUTSIDE the repo: `/var/lib/vpnctl/inv.db`,
  `/etc/vpnctl/vpnctld.env`, `/opt/vpnctl/{vpnctld,assets}`, deploy key
  `/var/lib/vpnctl/.ssh`. Do not hand-edit `target/` or generated artifacts.
- Backups are critical: `inv.db` holds every subscription identity. Any
  destructive operation or migration needs a tested restore path — see
  `docs/specs/backup-restore.md`.
- Deploy with `scripts/deploy.sh` (builds daemon + CLI from ONE revision,
  embeds `VPNCTL_BUILD_SHA`, installs both atomically), then
  `sudo systemctl restart vpnctld`. Code changes that affect production
  behavior are NOT live until deployed and verified on the affected surface.
- Deploy-key invariant: every server visible in `/admin/servers` must have
  vpnctld's deploy pubkey in `root@<host>:~/.ssh/authorized_keys`. Never expose
  a server to users or create production grants until deploy-key reachability
  is verified; missing authorization leads to incomplete rollout — detect and
  surface it explicitly.
- Operator-action policy: alerts, error messages, and UI copy must never tell
  the operator to SSH anywhere. The daemon performs the action itself or shows
  a web button; when truly impossible, say so and point at the hoster's
  console.
- Behind a reverse proxy, set `VPNCTLD_TRUSTED_PROXIES` in
  `/etc/vpnctl/vpnctld.env`; every proxy block targeting vpnctld must
  authoritatively set `X-Real-IP` and the site config must strip any
  client-supplied value first. See `docs/specs/deployment.md`.

## Definition of done

Scoped diff; the gates pass with recorded exit codes; target-specific checks
proven or explicitly marked not-run; secret scan clean; pre-existing failures
reported separately. For a production deploy additionally: binary backup
(`sudo cp -a /opt/vpnctl/vpnctld /opt/vpnctl/vpnctld.bak-<tag>`), systemd
active, health 200, UI/version verified. A local commit is not a live release —
report `local`, `main`, and `production` state separately.

## Specs and backlog

Non-trivial features start with a one-screen micro-spec in `docs/specs/`
(Intent & Invariants → Interface/Data contract → Verification checklist),
committed alongside the code. Standing contracts: architecture, agent-workflow,
admin-ui-quality, deployment, abuse-detection, migration-compatibility,
backup-restore. Deferred work and known workaround debt live in `BACKLOG.md`.
