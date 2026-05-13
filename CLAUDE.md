# vpnctl — Claude memory

Этот файл автоматически загружается в каждый чат с Claude в проекте `vpnctl`.

## Что это

Преемник bash-проекта `vpn-control`. Lightweight Linux-only CLI на Rust для
управления VPN-инфраструктурой (sing-box + расширяемые ядра/протоколы).
Цель — единственный статический musl-бинарник, без БД-сервера, без агента
на ноде, SSH-first.

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

| | Где | Что проверяет |
|---|---|---|
| Forgejo Actions | `.forgejo/workflows/ci.yml` | check + fmt + clippy + test (внутри `rust:1.85-slim-bookworm`) |
| GitHub Actions | `.github/workflows/ci.yml` | то же + `cargo deny` + `cargo audit` |

Зелёный CI — обязательное условие для push в main.

## Грабли

### Контейнер claude-chat не персистентит `~/.cargo` и `~/.rustup`
При рестарте контейнера Rust-тулчейн исчезает. Восстанавливается через
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal --component rust-analyzer`.
Решение на уровне инфры: добавить `~/.cargo` и `~/.rustup` в персистентные
volumes Docker compose (TODO для Pavel).

### Mirror remote — push в оба места одной командой
```
origin fetch ssh://git@192.168.0.207:18222/slovn/vpnctl.git
origin push  ssh://git@192.168.0.207:18222/slovn/vpnctl.git    (Forgejo, primary)
origin push  git@github.com:PavelLizunov/vpnctl.git            (GitHub, mirror)
```
`git push` уходит в оба. Fetch — только из Forgejo.

### Без C-линкера (`cc`) на хосте cargo install ничего не соберёт
В Dockerfile claude-chat теперь зашит `build-essential` (Pavel сделал
2026-05-13). Если попадёшь в окружение без cc — поставь
`apt-get install -y build-essential pkg-config libssl-dev` от рута.

### sqlx + DATABASE_URL
Когда добавим sqlx (v0.2 milestone), для CI нужен
`cargo sqlx prepare --workspace` локально + коммит `.sqlx/` директории +
`SQLX_OFFLINE=true` в CI env.

## Связанные репо и серверы

- **Старый bash-проект**: `slovn/vpn-control` — там список production VPN
  серверов (`SERVERS.md`), inventory с секретами (`inventory/<IP>.env`,
  не коммитить!), и SSH-ключ `claude-dev` (`/home/user/.ssh/id_ed25519`,
  НЕ `/home/appuser/.ssh/`).
- **Production VPN серверы** — пока не трогаем, миграция на Rust будет
  только когда v0.2 пройдёт интеграционный тест на staging.

## Roadmap

- **v0.1** ✅ — scaffold (workspace, traits, registry, smoke binary), CI
- **v0.2** — `russh` транспорт, `sqlx+sqlite` inventory, CLI команды
  (server/user/deploy/status/sub), интеграционный тест
- **v0.3** — bootstrap fresh-node (ssh harden, fail2ban, UFW, BBR), ProxyJump
  через russh, subscription URLs (offline-генерация)
- **v0.4** — daemon `vpnctld` + REST API + `/sub/<token>` HTTP endpoint
- **v0.5** — опциональный mTLS gRPC агент на ноде для live stats

## Текущая дата контекста

См. системную инфу. Проект стартовал 2026-05-13.
