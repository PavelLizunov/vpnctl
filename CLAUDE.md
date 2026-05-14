# vpnctl — Claude memory

Этот файл автоматически загружается в каждый чат с Claude в проекте `vpnctl`.

## Strategic context (final goal — keep aligned)

Confirmed by Pavel 2026-05-14:

- **Operator model.** Single operator (Pavel). No multi-tenancy, no
  RBAC. `actor="admin"` everywhere in audit. Don't waste cycles on
  role abstractions.
- **Users are operator-managed, NOT self-service.** No "request access"
  flow, no user-facing portal. Notifications cover *infrastructure*
  events only (server down, sing-box crash-loop, fail2ban banned-self).
- **Web is the primary surface; CLI stays as escape hatch / scripting.**
  Anything done via CLI must also be doable via the admin UI by v1.0.
- **Add-server wizard is THE core differentiator over the bash project.**
  Operator pastes IP + root password → admin does ALL the magic
  automatically: push pubkey, create non-root user, disable password
  auth, harden SSH, install fail2ban, install sing-box, render config,
  restart, prove it's live. Streaming UX (SSE) with per-step progress.
  This is Phase E and it's the most important phase.
- **Production deployment.** LAN-only for now (homelab `192.168.0.236`).
  External exposure with OAuth/2FA is a later concern; design today
  must not make that *harder* but doesn't have to support it.
- **Mobile / responsive.** Not needed.
- **Migration from bash `vpn-control`.** **Seamless preservation** of
  every existing client. Old phones holding `vless://` / `tuic://`
  links keep working byte-for-byte after the switch. The protocols
  crate's `share_link()` MUST produce identical output to the bash
  scripts for the same secret material — there's a regression test
  due here. Migration tool reads `inventory/<IP>.env` and imports
  servers + users + grants preserving UUID and password material.
- **Backups are critical, not optional.** If `192.168.0.236` burns
  today, every sub_token is lost and every client has to re-import.
  Need: scheduled `inv.db` snapshot + asset bundle + off-site copy
  (homelab Forgejo is a candidate target) + a documented restore
  procedure.
- **Design source = me (Claude).** No Figma. The editorial voice
  ("a daily report from your homelab", sentence-case, mono CLI
  inline) lives in code + this file; consistency is on me.
- **v1.0 is far.** Defined as "everything in the roadmap shipped
  AND we have months of operating experience without rolling back".
  Until then keep cutting v0.x with no marketing stunts.

### Roadmap (current order, post-2026-05-14)

| Phase | Suffix | Status | What |
|---|---|---|---|
| A, B | shell + read-only servers/dashboard | ✅ shipped | masthead, nav, themes, dashboard KPIs |
| C-1 | users list + detail + QR | ✅ shipped | commit `aafc180` |
| C-2 | UX polish (collapsible Tweaks, copy contracts, favicon) | ✅ shipped | commit `663a653` |
| C-3.1 | writes — regenerate sub-token | ✅ shipped | commit `276e47d` |
| **C-3.2-4** | **writes — add user / grants / delete** | **next** | each web-mutation paired with `inv.audit("admin", …)` |
| **Track-1** | **abuse signal: per-user sub-fetch log + UI** | ✅ shipped | next commit |
| Track-2 | rate-limit `/sub/<token>` (per-IP, per-token), auto-deny on burst | queued | `tower-governor` or hand-rolled token bucket |
| **C-4** | **backup + restore** | queued (priority) | scheduled inv.db snapshot, off-site target, `vpnctl restore` command |
| **C-5** | **migrate from bash** | queued (priority) | `vpnctl migrate from-bash <path>` reads `inventory/*.env`, preserves UUIDs & passwords; share_link byte-equality test |
| E | add-server wizard (THE feature) | planned | IP+root → SSE-streamed bootstrap, hardening, install, deploy |
| Track-3 | clash-api polling on each node, per-user real-time conns/traffic | planned (after E) | adds clash-api to deploy, daemon poller, `vpn_connection_stats` table |
| D | audit timeline | planned | filters, search, export |
| F | monitoring | planned | sparklines (needs stats endpoint design) |
| Track-4 | UA fingerprint heuristic (roaming vs shared URL) | low priority | classifier on top of Track-1 data |
| G | infra notifications | planned | server-down / crash-loop / fail2ban-banned-self alerts |

### Three-layer visibility model (abuse detection)

The admin needs to spot abuse — primarily a subscription URL that's
been shared past one human, secondarily a single client racking up
unreasonable traffic. Three independent surfaces, each catches a
different bug class:

| Layer | Source | What it catches | What it misses | Cost to add |
|---|---|---|---|---|
| **1. /sub fetch log** | vpnctld access log → `sub_access_log` table | URL leaked / shared (many ASNs hitting one user's URL); scrapers pulling on a tight loop; UA-based "what client are they on" fingerprint | Real-time connections (clients re-fetch only periodically); device count behind NAT | LOW — Track-1, ✅ shipped |
| **2. VPN protocol stats** | sing-box `clash-api` on each node, polled by vpnctld via SSH | active connections, traffic up/down, per-user real-time | Same NAT problem; needs SSH polling overhead; new column in deploy | MEDIUM — Track-3, planned after E (wizard touches deploy anyway) |
| **3. UA fingerprint** | UA strings + IP+time+ASN clustering on Layer-1 data | Approximate "is this the same physical device roaming vs is this many devices sharing the URL" | Never exact — NAT collapses devices; clients with no UA are invisible | LOW — Track-4, low priority |

A device count **behind NAT** is roughly impossible from the server
side without client cooperation. Track-4 is the best we can do.

When making non-trivial design decisions, re-read this section first
and check the choice doesn't quietly bake in an assumption that
contradicts a confirmed answer above.

## Workflow rules (BLOCKING — must run before every commit)

Эти правила — про то, как мы (Pavel + Claude) разрабатываем `vpnctl`.
Они **обязательны** для каждой feature/refactor/fix. Хук в
`.claude/settings.json` ловит `git commit` и напоминает, если шаги
пропущены.

### Перед коммитом (после написания/правки кода)

1. **Review-agent** — независимая проверка через `Agent` (subagent_type =
   `general-purpose`), prompt из шаблона ниже. Агент не видит мой
   reasoning, только diff. Возвращает JSON списка findings. Я обрабатываю
   `critical` и `important` (фиксы), `minor` — opt-in.

2. **Test-writer-agent** — для **новой публичной функции/API** запускаю
   через `Agent` (`general-purpose`) с prompt'ом, содержащим **только
   спеку** (signatures + behavior contract), **без реализации**. Агент
   пишет тесты в отдельный файл (`tests/spec_*.rs` или
   `#[cfg(test)] mod spec_*`). Прогоняю их у себя. Тесты которые падают
   = либо bug в реализации (фиксим), либо неверная спека (правим спеку
   и регенерим тесты).

3. **Локальные gates**: `just ci` (fmt-check + clippy -D warnings + test
   + deny). Без зелёного — коммит не делать.

### После push

4. `gh run watch <id> --exit-status` — блокируюсь до конца CI.
   Если красное → `gh run view --log-failed` → fix → push повтор.

### Когда правила можно сократить

- **Чисто docs/README/CLAUDE.md правки** — пункты 1-2 пропускаем,
  пункт 3 (`just ci`) обязателен (fmt-check всё равно).
- **Hotfix < 5 строк** — review-agent можно пропустить, test-writer —
  по контексту.

## Agent prompt templates

Тексты ниже — копировать целиком в `Agent.prompt`, подставив `{...}`.

### `review-agent` prompt template

```
You are an independent code reviewer for the vpnctl Rust workspace
(github.com/PavelLizunov/vpnctl). You haven't seen the design discussion,
only the diff below.

Architectural invariants (cannot be violated):
- Kernel × Protocol orthogonality: adding a new kernel (wgturn, xray) or
  protocol (Hysteria2, WireGuard) must NOT require touching CLI, inventory,
  SSH or crypto crates.
- Protocols are STATELESS; per-server secrets arrive via RenderCtx.
- Inventory write paths must be auditable (audit_log row per mutation).
- No `unwrap()` / `expect()` / `panic!()` outside `#[cfg(test)]`.
- No `unsafe`. No `openssl-sys` / `native-tls`.

Files changed: {file list from `git diff --name-only HEAD~N..HEAD`}
Diff: {git diff HEAD~N..HEAD}

Find issues. Categories, in priority order:
1. CORRECTNESS: bugs, off-by-one, wrong error mapping, swallowed errors,
   race conditions, resource leaks, command injection in any exec(),
   path traversal in upload()/read_file(), unhandled panics.
2. ARCHITECTURE: violations of the invariants above; tight coupling;
   stateful things that should be stateless.
3. SECURITY: secrets logged to stdout/audit payload; missing host-key
   verification path; weak randomness; permission/visibility leaks.
4. TEST COVERAGE: a new public function with no test for its error path;
   tests that would pass even if the implementation was inverted.
5. LIBRARY MISUSE: anything that goes against russh / sqlx / tokio /
   clap official patterns (cite the doc if you reference it).

Output ≤300 words as a single JSON array:
[{"severity":"critical|important|minor",
  "file":"crates/.../foo.rs:42",
  "issue":"one-line description",
  "fix":"concrete change, ≤2 sentences"}]

DO NOT comment on:
- style / formatting (rustfmt handles it)
- doc completeness
- naming preferences (unless objectively confusing)
- micro-optimisations
```

### `test-writer-agent` prompt template

```
You are writing Rust tests for vpnctl, INDEPENDENT of the implementation.

CRITICAL: You have NOT seen the implementation source. Only the spec
below. If a test fails when run, that means the implementation is wrong
or the spec is ambiguous — DO NOT weaken the test to make it pass.

Crate under test: {crate name, e.g. vpnctl-inventory}
Cargo manifest deps you may use: {list, e.g. tokio, tempfile, serde_json}

Public API spec (verbatim signatures + behavior):
{paste signatures + per-function "must" rules; no impl, no internal
 helpers; if there are invariants — list them}

Behavior contract (rules every test must verify):
{e.g. "WAL journal mode is enforced after open()",
      "FK CASCADE removes grants when their user is deleted",
      "duplicate add_server returns AlreadyExists, not generic sqlx error"}

Write to {path, e.g. crates/inventory/tests/spec_inventory.rs}. Constraints:
- Each test has its own tempdir / fresh state.
- Test names describe the spec rule being checked.
- ≤300 lines total.
- Use `#[allow(clippy::unwrap_used, clippy::expect_used)]` on the test
  module (workspace lints forbid them in non-test code; tests can use
  them for setup).
- Cover at least: happy path, ONE expected-failure path, one boundary
  edge case per function.
- DO NOT add tests that just call the function and assert "no panic".
  Every test must check observable behavior against the spec.
```

### Lessons from the first real staging deploy (84.19.3.104, Debian 12)

`vpnctl bootstrap stg ... && vpnctl deploy stg` worked end-to-end after
**three** fixes that ONLY surfaced on a live node — not via review-agent
or test-writer-agent. This empirically validates the three-layer
methodology (review → spec-tests → live-staging) all together; cutting
any layer would have shipped this bug-class.

| # | Surface | What live caught | Fix |
|---|---|---|---|
| 1 | `kernels::sing_box::ensure_installed` | Minimal Debian 12 has no `curl` / `gpg` / `ca-certificates` — exec exit=127 «curl: команда не найдена». | apt-install prerequisites first; `set -eu`; `command -v sing-box` final assertion. |
| 2 | `kernels::sing_box::ensure_installed` | sing-box service crash-loops with «open /var/log/sing-box.log: permission denied» — same gotcha that's in the old vpn-control HANDBOOK. | `install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log`; recursive chown of `/etc/sing-box`. |
| 3 | `kernels::sing_box::apply_config` | `systemctl reload-or-restart` returns 0 even when the service immediately exits — deploy reports «complete» while sing-box crash-loops. Silent failure = worst kind. | After restart, poll `systemctl is-active` for up to 8 s; on failure, dump `journalctl -u sing-box -n 20` to stderr and exit 1. |

Takeaway: review/test-writer cover **bugs in code logic**; live-staging
covers **assumptions about the environment**. Both layers are required.

### Methodology for the admin SITE (six layers, post-Phase-C-2)

Phase C-2 surfaced bug classes the original three-layer
(review / spec-tests / live-deploy) workflow could not catch on
HTML-rendering code paths. The site stack now uses **six layers**,
each catching a strict subset of issues that the others miss:

| # | Layer | What it catches | What it misses |
|---|---|---|---|
| 1 | `cargo clippy --workspace --all-targets -D warnings` | API misuse, dead code, unwrap/expect/panic outside tests | Anything CSS-only or HTML-string-only |
| 2 | `cargo test --test admin_smoke` (currently 34 tests) | DOM presence, classes, routing, status codes, escaping, masking | Floating panels overlapping content, grid overflow, font-rendering issues |
| 3 | **Copy-contract tests** (subset of admin_smoke) | Backend response prefix drift, headline / deck / empty-state copy regressions | Style of NEW copy that was never pinned (additive — pin it) |
| 4 | review-agent | Logic bugs, security issues, library misuse | Whether the page actually *renders* well |
| 5 | Live-deploy + curl on `192.168.0.236` | runtime + auth + DB integration | Visual layout (curl never paints) |
| 6 | **`scripts/visual_check.py`** (headless Chrome over CDP) | Floating panel overlap, grid overflow, font fallback, anything pixels-related | Cross-browser quirks (we render only on homelab Chromium) |

Phase C-2 evidence — bugs each new layer caught that no other would:

| Bug | Caught by |
|---|---|
| Tweaks panel covered the page footer on every page | layer 6 (visual screenshot) — invisible to layers 1-5 |
| Inline `tweaks live →` indicator duplicated panel state | layer 6 — DOM-test was happy |
| SHA256 fingerprint overflowed `.ed-server__meta dd` | layer 6 — content was correct, just escaped its column |
| Backend errors used 4 different prefixes | layer 3 (copy-contract) — pre-existing inconsistency invisible to all live curl tests because each was tested in isolation |
| `auth required` had no `vpnctl admin:` prefix | layer 3 |
| Favicon missing → blank browser tab | layer 3 — would be invisible to layer 6 because Chrome shows a default square; only the explicit test caught it |

#### Run order for any user-visible UI change

```bash
# 1. Static checks (fast, runs in CI)
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p vpnctld --test admin_smoke

# 2. Live deploy to homelab (binary + CSS + favicon)
cargo build --release -p vpnctld
scp target/release/vpnctld user@192.168.0.236:/tmp/vpnctld
scp daemon/assets/{admin.css,favicon.svg} user@192.168.0.236:/tmp/
ssh user@192.168.0.236 '
  sudo install -o root -g root -m 0755 /tmp/vpnctld /opt/vpnctl/vpnctld &&
  sudo install -o root -g root -m 0644 /tmp/admin.css /opt/vpnctl/assets/admin.css &&
  sudo install -o root -g root -m 0644 /tmp/favicon.svg /opt/vpnctl/assets/favicon.svg &&
  sudo systemctl restart vpnctld'

# 3. Backend copy contract — confirm error responses match the prefix
ADMIN_PW=$(grep VPNCTLD_ADMIN_PASSWORD inventory/vpnctld-192.168.0.236.env | cut -d= -f2)
curl -sS -u "slovn:${ADMIN_PW}" http://192.168.0.236:18402/admin/users/no-such
# Expect: vpnctl admin: no such user 'no-such'

# 4. Visual gate — PNG of every page that changed
python3 scripts/visual_check.py http://192.168.0.236:18402/admin/users \
    /tmp/users.png "slovn:${ADMIN_PW}"
python3 scripts/visual_check.py http://192.168.0.236:18402/admin/users \
    /tmp/users-collapsed.png "slovn:${ADMIN_PW}" "vpnctl_tweaks=closed"

# 5. Read /tmp/*.png with the Read tool — actual eyeballs on the diff.
```

#### Backend / frontend copy contract

**Backend:** every response body in the `/admin/*` tree starts with
`vpnctl admin: `, ends with a single `\n`, and (where applicable)
includes the offending value + the allowed alternatives so the
operator can fix the request without consulting source. The
`error_text()` helper in `daemon/src/handlers/admin.rs` is the single
source of truth; auth.rs duplicates the literal prefix because the
basic-auth layer runs before the admin module is reachable. Tests in
`admin_backend_error_responses_use_unified_prefix` pin the four
canonical strings (404 user, 401 auth, 400 invalid value, 404 unknown
tweak kind).

**Frontend:** the editorial voice is sentence-case with em-dashes and
mono-font CLI commands inline (`span.ed-mono { "vpnctl user create" }`).
Every empty state must quote a literal CLI command (operators CAN'T
yet create users / servers via the web — losing the command would
strand them). `admin_frontend_section_headlines_match_voice` and
`admin_empty_states_quote_cli_commands` are the regression net. When
adding a new screen: first write the headline + deck strings, then
**add a copy-contract test for them in the same commit** so future
edits surface in code review.

#### Where MCP servers fit

We have three MCP servers wired (when their connections are healthy);
each is useful at a different point in the loop:

- **context7** — `mcp__context7__query-docs` / `resolve-library-id`.
  Use when the diff touches a dependency's API surface (axum upgrade,
  `qrcode` crate options, maud's `PreEscaped` semantics) or before
  picking a new dep. Cheaper and more current than guessing from
  training data — relevant for axum 0.8's path-param routing edge
  cases that bit us in Phase A.
- **sequential-thinking** — `mcp__sequential-thinking__sequentialthinking`.
  Use for layered layout / architecture decisions where the failure
  mode is "I picked the wrong abstraction". Phase C-2's CSS-Grid
  `justify-self: end` shrink-to-content gotcha would have been worth
  a sequential-thinking pass — instead it took two screenshot rounds
  to diagnose.
- **memory** — `mcp__memory__create_entities` etc. Use for
  cross-session state that genuinely doesn't fit in CLAUDE.md
  (e.g. a long-lived "copy catalog" mapping every user-facing string
  to its file:line + history of edits). For now CLAUDE.md is enough;
  re-evaluate when the admin UI grows past ~20 screens.

Headless Chrome runs at `http://192.168.0.142:9222` (homelab CDP
endpoint, exposed on the LAN). The script reuses the persistent tab,
disables the network cache, and accepts both basic-auth and a
synthetic Cookie header so collapsible / theme / accent states can be
captured without round-tripping through real cookie storage.

### Гочи методологии (lessons learned)

- **Hook input приходит на stdin, не в env var.** В `.claude/settings.json`
  читаем JSON через `python3 -c "..."` (или `jq`, если установлен — но в
  нашем dev-контейнере `jq` нет; `python3` есть всегда).
- **Settings watcher не подхватывает файлы созданные мид-сессии.** После
  любого редактирования `.claude/settings.json` нужно либо открыть UI
  `/hooks`, либо перезапустить Claude Code. Иначе хук молча игнорируется,
  даже если pipe-test зелёный.
- **Pipe-test обязателен** перед коммитом hook-а:
  `echo '{"tool_input":{"command":"git commit -m x"}}' | bash -c '<your cmd>'`
  должен вернуть ожидаемый вывод. Без этого силлентли break.
- **Sub-agents изолированы**: review-agent / test-writer-agent видят
  только то, что я кладу в `prompt`. Если я сошлюсь на «design discussion
  выше» — они не увидят. Brief как нового коллегу, paste'ить полный spec.

### Когда добавить новый kernel (wgturn, xray, hysteria-server)

Триггер: пользователь просит «добавь поддержку X».

Сценарий:

1. **Plan-agent** (`Agent`, `subagent_type=Plan`): «Design the file
   structure for adding kernel `X` such that no existing crate other
   than `crates/kernels/` and `cli/src/registry.rs` is touched.»
2. По плану создаю `crates/kernels/src/<x>.rs` + `pub use`.
3. `cli/src/registry.rs`: один `register_kernel`.
4. `inventory::server_secrets` — расширить конвенцию ключей (записать
   в CLAUDE.md и в doc-comment модуля).
5. Review + Test-writer — как обычно.



## Что это

Преемник bash-проекта `vpn-control`. Lightweight Linux-only CLI на Rust для
управления VPN-инфраструктурой (sing-box + расширяемые ядра/протоколы).
Цель — единственный статический musl-бинарник, без БД-сервера, без агента
на ноде, SSH-first.

## Где живёт проект (важно — GitHub-first)

| | |
|---|---|
| **Canonical home** | https://github.com/PavelLizunov/vpnctl |
| **Issues / PRs** | только на GitHub |
| **Primary CI** | GitHub Actions (`.github/workflows/ci.yml`) |
| **Mirror (LAN dev)** | http://192.168.0.207:18300/slovn/vpnctl (Forgejo) |
| **Mirror CI** | Forgejo Actions (`.forgejo/workflows/ci.yml`) — best-effort |

`origin` настроен так:
```
fetch  git@github.com:PavelLizunov/vpnctl.git
push   git@github.com:PavelLizunov/vpnctl.git              (GitHub, primary)
push   ssh://git@192.168.0.207:18222/slovn/vpnctl.git      (Forgejo, mirror)
```
`git push` улетает в оба. Если когда-то надо отключить mirror — просто
`git remote set-url --delete --push origin '.*forgejo.*'` (или удалить
конкретный URL).

## Архитектурный принцип (нельзя нарушать)

Два **независимых** trait-уровня:

| Trait | Что значит | Где живёт |
|---|---|---|
| `Kernel` | Демон на ноде, который держит соединения | `crates/kernels/src/` |
| `Protocol` | Wire-формат, предъявляемый клиенту | `crates/protocols/src/` |

`Kernel::supported_protocols()` декларирует, какие `Protocol` это ядро может
поднять. `Registry::validate_server` ловит несовместимости **до** SSH-сессии.

Добавление нового ядра (wgturn, xray, hysteria-server) или протокола
(WireGuard, Hysteria2, ShadowSocks-2022) **не требует правок** в `core`,
`ssh`, `crypto`, `inventory`, `hosters` или `cli` — только новый файл-модуль
+ одна строка регистрации в `cli/src/main.rs`.

## Структура

```
vpnctl/
├── Cargo.toml                workspace, edition 2024, MSRV 1.85
├── rust-toolchain.toml       pin: stable + clippy + rustfmt
├── deny.toml                 cargo-deny policy (no openssl-sys, no native-tls)
├── rustfmt.toml              edition 2024, max_width 100
├── justfile                  just check / test / clippy / fmt / ci / run
├── crates/
│   ├── core/                 типы + traits + Registry
│   ├── crypto/               UUID, x25519, password, short_id (3 unit tests)
│   ├── ssh/                  trait SshTransport + MockTransport (russh impl in v0.2)
│   ├── protocols/            impl Protocol — vless+reality, tuic-v5
│   ├── kernels/              impl Kernel — sing-box (полный)
│   ├── hosters/              DigitalOcean / Cloudzy / Generic
│   └── inventory/            InMemoryInventory (sqlx+sqlite in v0.2)
└── cli/                      clap бинарь `vpnctl`, subcommands: uuid, registry
```

## Lints — централизованно

Все clippy/rustc lints в `[workspace.lints]` в корневом `Cargo.toml`. Каждый
крейт включает их через `[lints] workspace = true` в своём Cargo.toml.
**Не пиши** `#![deny(...)]` или `#![forbid(unsafe_code)]` в `lib.rs` — это
дублирование.

Запрещены:
- `unsafe_code` (forbid)
- `unwrap_used`, `expect_used`, `panic`, `dbg_macro` (deny)

## Типичные команды

```bash
just check       # cargo check --workspace --all-targets
just test        # cargo test --workspace
just clippy      # cargo clippy --workspace --all-targets -- -D warnings
just fmt         # rustfmt
just fmt-check   # CI-mode rustfmt
just deny        # cargo deny check
just audit       # cargo audit
just run uuid    # cargo run --bin vpnctl -- uuid
just ci          # fmt-check + clippy + test + deny — прогон до push
```

## CI

| Where | File | What it gates |
|---|---|---|
| **GitHub Actions (primary)** | `.github/workflows/ci.yml` | check + fmt + clippy -D warnings + test + `cargo deny` + `cargo audit` |
| Forgejo Actions (mirror) | `.forgejo/workflows/ci.yml` | то же без deny/audit, в `rust:1.85-slim-bookworm` |

Зелёный GitHub CI — обязательное условие для merge в main. Forgejo — best-effort.

## Грабли

### Контейнер claude-chat не персистентит `~/.cargo` и `~/.rustup`
При рестарте контейнера Rust-тулчейн исчезает. Восстанавливается через
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal --component rust-analyzer`.
Решение на уровне инфры: добавить `~/.cargo` и `~/.rustup` в персистентные
volumes Docker compose (TODO для Pavel).

### Mirror remote — см. секцию «Где живёт проект» выше
Один `git push` уходит в оба remote. Fetch — только из GitHub.

### Без C-линкера (`cc`) на хосте cargo install ничего не соберёт
В Dockerfile claude-chat теперь зашит `build-essential` (Pavel сделал
2026-05-13). Если попадёшь в окружение без cc — поставь
`apt-get install -y build-essential pkg-config libssl-dev` от рута.

### sqlx + DATABASE_URL
Когда добавим sqlx (v0.2 milestone), для CI нужен
`cargo sqlx prepare --workspace` локально + коммит `.sqlx/` директории +
`SQLX_OFFLINE=true` в CI env.

## Связанные репо и серверы

- **Старый bash-проект `vpn-control`** — живёт пока только в локальном
  Forgejo (`slovn/vpn-control`). Там список production VPN серверов
  (`SERVERS.md`), inventory с секретами (`inventory/<IP>.env`, не коммитить!),
  и SSH-ключ `claude-dev` (`/home/user/.ssh/id_ed25519`,
  НЕ `/home/appuser/.ssh/`). Если миграция на vpnctl завершится успешно,
  старый репо уйдёт в archive.
- **Production VPN серверы** — пока не трогаем, миграция на vpnctl будет
  только когда v0.2 пройдёт интеграционный тест на staging.

## Live-deploy `vpnctld` на homelab (LAN)

`vpnctld` (admin UI + `/sub/<token>`) поднят на homelab-хосте
**192.168.0.236** и доступен с ноута Pavel'а в локальной сети:

| | |
|---|---|
| URL | http://192.168.0.236:18402/admin/ |
| Health | http://192.168.0.236:18402/api/v1/health |
| Auth | basic-auth, user `slovn`, пароль в `/etc/vpnctl/vpnctld.env` (sudo cat) |
| Бинарь | `/opt/vpnctl/vpnctld` (root:root 0755) |
| Assets | `/opt/vpnctl/assets/admin.css` |
| Inventory DB | `/var/lib/vpnctl/inv.db` (user:user 0640) |
| EnvFile | `/etc/vpnctl/vpnctld.env` (root:user 0640) |
| Systemd unit | `/etc/systemd/system/vpnctld.service` |
| Firewall | iptables INPUT: `192.168.0.0/24 → tcp/18402 ACCEPT`, persisted в `/etc/iptables/rules.v4` |

Креды для локального доступа из контейнера: `inventory/vpnctld-192.168.0.236.env`
(в проекте `vpn-control`, gitignored через `inventory/*.env`).

### Обновление бинарника / ассетов / БД

```bash
# 1. собрать (контейнер glibc 2.41, host 2.36 — binary использует max GLIBC_2.34, OK)
cd ~/vpn-control/vpnctl && cargo build --release -p vpnctld

# 2. SCP
scp target/release/vpnctld user@192.168.0.236:/tmp/vpnctld
scp daemon/assets/admin.css user@192.168.0.236:/tmp/admin.css

# 3. install + restart
ssh user@192.168.0.236 '
  sudo install -o root -g root -m 0755 /tmp/vpnctld /opt/vpnctl/vpnctld &&
  sudo install -o root -g root -m 0644 /tmp/admin.css /opt/vpnctl/assets/admin.css &&
  rm /tmp/vpnctld /tmp/admin.css &&
  sudo systemctl restart vpnctld &&
  sudo systemctl status vpnctld --no-pager | head'
```

### Грабли деплоя на 192.168.0.236

- **iptables INPUT policy DROP** — на хосте есть hand-crafted iptables (не
  UFW, не firewalld), и любой новый порт надо явно открыть + сохранить в
  `/etc/iptables/rules.v4`. Загружается из `iptables-restore.service`.
- **Бинарь динамически линкуется к glibc** — при сборке в claude-chat
  (Debian trixie, glibc 2.41) и деплое на bookworm (2.36) проверь
  `objdump -T <binary> | grep GLIBC_ | sort -u` — нужно ≤ 2.36. Сейчас
  максимум — 2.34, но новая dep может затащить 2.38+.
- **`MemoryDenyWriteExecute=true`** в systemd unit — может сломать future
  JIT (если когда-то добавим V8/wasmtime). Сейчас OK.
- **Креды в EnvironmentFile**, не в `Environment=` — `systemctl cat`
  не палит пароль в логах.

## Version snapshot (post-Track-1, 2026-05-14)

The detailed phased roadmap lives at the **top** of this file
(`Strategic context → Roadmap`). This section is the version-stamped
high-level summary so external readers (CHANGELOG, release notes) can
get oriented without reading the whole methodology block.

- **v0.1** ✅ scaffold (workspace, traits, registry, smoke binary), CI
- **v0.2** ✅ `russh` transport, `sqlx+sqlite` inventory with migrations,
  CLI subcommands (`server`, `user`, `grant`, `deploy`, `status`, `sub`),
  e2e integration test via testcontainers
- **v0.3** ✅ bootstrap fresh-node (SSH harden, fail2ban, sing-box install,
  config render), ProxyJump via russh, subscription URLs (offline-
  generated, byte-stable across rebuilds), `backon` retry layer
- **v0.4** ✅ daemon `vpnctld` + REST API + `GET /sub/<token>` + admin UI
  Phase A (editorial shell, theme/accent cookies) + Phase B
  (dashboard metrics, servers list)
- **v0.5** in progress — admin UI feature delivery
  - ✅ Phase C-1: users list + detail + inline-SVG QR (`aafc180`)
  - ✅ Phase C-2: collapsible Tweaks + footer overlap fix + favicon +
    unified backend copy contract (`d1c0578`, `663a653`)
  - ✅ Phase C-3.1: regenerate sub-token from web (`276e47d`)
  - ✅ Phase Track-1: subscription-access log + abuse-signal UI on
    user-detail (`1e91eeb`) — first abuse-detection layer
  - ⏳ Phase C-3.2-4: web add-user / grant / revoke / delete
  - ⏳ Phase Track-1.1: retention scheduler (purge runs periodically;
    UI today says "auto-purged after 30 days" but the scheduler is not
    yet wired — known gap, queued for the hardening commit)
  - ⏳ Phase Track-2: rate-limit `/sub/<token>` (per-IP + per-token
    token bucket, 429 on burst)
- **v0.6** queued — backups + migration before more features
  - ⏳ Phase C-4: scheduled `inv.db` snapshot + off-site target +
    `vpnctl restore` (the homelab `192.168.0.236` is a single point
    of failure today; no backup exists)
  - ⏳ Phase C-5: `vpnctl migrate from-bash <path>` with byte-equal
    `share_link` regression test (existing bash-vpn-control clients on
    phones MUST keep working without re-import)
- **v0.7+** Phase E (add-server wizard with SSE-streamed bootstrap),
  Phase Track-3 (clash-api real-time connections), Phase D (audit
  timeline), Phase F (monitoring), Track-4 (UA fingerprint), Phase G
  (infra notifications)
- **v1.0** far away — defined as "everything in roadmap shipped + months
  of operating experience without rolling back"

## Текущая дата контекста

См. системную инфу. Проект стартовал 2026-05-13.
