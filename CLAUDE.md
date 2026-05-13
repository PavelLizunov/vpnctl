# vpnctl — Claude memory

Этот файл автоматически загружается в каждый чат с Claude в проекте `vpnctl`.

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

## Roadmap

- **v0.1** ✅ — scaffold (workspace, traits, registry, smoke binary), CI
- **v0.2** in progress
  - ✅ `russh` транспорт (4 integration tests на live SSH)
  - ⏳ `sqlx+sqlite` inventory с миграциями
  - ⏳ CLI команды server / user / deploy / status / sub
  - ⏳ Интеграционный тест end-to-end через testcontainers
- **v0.3** — bootstrap fresh-node (ssh harden, fail2ban, UFW, BBR), ProxyJump
  через russh, subscription URLs (offline-генерация), backon retry layer
- **v0.4** — daemon `vpnctld` + REST API + `/sub/<token>` HTTP endpoint
- **v0.5** — опциональный mTLS gRPC агент на ноде для live stats

## Текущая дата контекста

См. системную инфу. Проект стартовал 2026-05-13.
