# Development Plan — naive via Caddy (managed by vpnctl)

**Date:** 2026-06-03 · **Author:** slovn + Claude · **Status:** proposed

## Goal

Сделать **naive с маскировкой под реальный сайт** (отдаёт `200` + настоящая страница против активного зондирования) первоклассным управляемым протоколом в `vpnctl`: оператор включает `naive` на сервере из веба → деплой ставит/настраивает Caddy с forward_proxy + ACME → пользователи получают naive в своей подписке.

### Почему Caddy, а не sing-box naive inbound
| | sing-box naive | **Caddy + forwardproxy (выбрано)** |
|---|---|---|
| не-proxy запрос | всегда `400` (tell) | **реальный сайт = `200`** |
| TLS-серт | нужен реальный, ACME в vpnctl **нет** | **встроенный ACME в Caddy** ✅ |
| эталонность | реимплементация | референс naive (klzgrad) |

Caddy закрывает обе проблемы разом, поэтому productize именно его.

---

## 1. Как ложится в архитектуру (точки расширения)

Используем уже доказанные швы (прецеденты: `amnezia_wg` рендерит текстовый INI; `wgturn` собирает бинарь через Go + 2 systemd-юнита).

- **Новый Kernel `caddy`** → `crates/kernels/src/caddy.rs` (impl `Kernel`). Рендерит **Caddyfile (текст)**, как AmneziaWG рендерит INI. Ставится сборкой через Go (xcaddy), как `wgturn`.
- **Новый Protocol `naive`** → `crates/protocols/src/naive.rs` (impl `Protocol`). `dpi_risk = Strong`. `server_inbound` отдаёт **дескриптор** (basic_auth юзеров + домен/сайт), который читает ТОЛЬКО Caddy-kernel (sing-box его не поддерживает → не трогает). `client_config` = sing-box naive **outbound** (`utls: chrome`). `share_link` = `naive+https://user:pass@domain`.
- **Регистрация:** по одной строке в `cli/src/registry.rs` (`register_kernel(Caddy)`, `register_protocol(Naive)`) + `daemon/src/app.rs::build_registry`.
- **Server model:** к `Server.kernels` добавляется `caddy`, к `enabled_protocols` — `naive`. Мульти-kernel на хост уже поддержан (`deploy.rs` итерирует kernels, фильтруя протоколы по `supported_protocols()`).

Инвариант сохраняется: трогаем только `crates/kernels/`, `crates/protocols/`, по строке в registry, + миграция БД + UI-поля. `core/ssh/crypto` не трогаем.

---

## 2. Изменения модели данных

- **Миграция `0029_naive_password`** (per-user секрет): колонка `users.naive_password`. Минтится идемпотентно в `wizard_bootstrap` и `user add` (как `tuic_password`). Username для basic_auth = `user.id`, пароль = `naive_password` (32 байта).
  - Альтернатива: переиспользовать `tuic_password` (без миграции), но связывает ротацию — **не рекомендуется**.
- **Параметры сервера** (в существующем KV `server_secrets`):
  - `caddy.domain` — домен для ACME/SNI (напр. `cdn.ninitux.top`)
  - `caddy.acme_email` — почта для Let's Encrypt
  - `caddy.site_variant` — какой статический сайт отдавать (default `generic`)
- **ServerSecretSpec:** новых серверных секретов не нужно (домен/почта — не секреты; cert管ает сам Caddy). Per-user пароль минтится через миграцию.

---

## 3. Политика портов и валидация (важно!)

Caddy-naive слушает **TCP 80 + 443**. Это конфликтует на одном хосте с:
- `vless+reality` (443), `trojan` (443).

**Решение:**
1. **Политика:** хост с `naive(Caddy)` НЕ запускает 443-протоколы sing-box. naive-борт — выделенный (или naive на альт-порту, но это бьёт по стелсу — только как опция).
2. **Cross-kernel port-conflict guard:** расширить нынешний sing-box-only `validate_config_excludes_ports` до **префлайта по всем kernels**: собрать `listen_ports()` всех включённых протоколов на сервере, упасть с понятной ошибкой при коллизии (443 REALITY × 443 Caddy). Место: `registry.validate_server()` + preflight в `deploy.rs`/`redeploy_pipeline`.

---

## 4. Caddy kernel — детали реализации

`crates/kernels/src/caddy.rs`, impl `Kernel`:

- **`ensure_installed`** (паттерн `wgturn`):
  - поставить Go (переиспользовать bootstrap Go из `wgturn.rs`);
  - `xcaddy build --with github.com/klzgrad/forwardproxy@naive` с **пиннингом SHA** (как `WGTURN_CORE_PINNED_SHA`); положить бинарь в `/usr/local/bin/caddy`;
  - systemd-юнит `caddy.service` (caddy run --config /etc/caddy/Caddyfile); data-dir для ACME `/var/lib/caddy`;
  - если есть `ufw` — открыть 80/443 (новое: сегодня firewall vpnctl не трогает — здесь добавляем точечно);
  - logrotate-фрагмент.
- **`render_config`** → Caddyfile (текст) из дескрипторов naive-протокола:
  - блок домена с `tls {acme_email}` (встроенный ACME),
  - `forward_proxy { basic_auth <user_id> <naive_password> … (по юзеру) ; hide_ip ; hide_via }`,
  - `file_server { root /var/www/naive-site }` — фоллбэк-сайт = `200`,
  - **мульти-файловый бандл** (Caddyfile + `index.html`) через тот же разделитель `====FILE: <path>====`, что использует `wgturn`.
  - дефолтный сайт — бандлится в `daemon/assets` (как остальные ассеты).
- **`apply_config`**: upload Caddyfile(+сайт) → `caddy validate` → `systemctl reload-or-restart caddy` → poll `is-active` (8s) → `journalctl` при падении. Атомарность как в sing-box.
- **`restart`/`status`**: systemctl + `caddy version`.

---

## 5. naive protocol — детали реализации

`crates/protocols/src/naive.rs`, impl `Protocol`:
- `id = "naive"`; `listen_ports = [("tcp", 443)]`; `dpi_risk = Strong`; `appears_in_sing_box_sub = true`.
- `server_inbound(ctx, users)` → дескриптор `{ "domain", "acme_email", "site_variant", "auth": [{user_id, password}…] }` (читает только Caddy-kernel).
- `client_config(ctx, user)` → sing-box naive **outbound**:
  ```json
  {"type":"naive","server":"<domain>","server_port":443,
   "username":"<user_id>","password":"<naive_password>",
   "tls":{"enabled":true,"server_name":"<domain>","utls":{"enabled":true,"fingerprint":"chrome"}}}
  ```
- `share_link(ctx, user)` → `naive+https://<user_id>:<naive_password>@<domain>#<Country>-naive`.
- `server_secret_specs` → пусто (домен/почта — параметры сервера; пароль — per-user через миграцию).

Клиент по умолчанию в подписке — **sing-box naive+utls chrome** (единый стек). Нативный бинарь `naive` (полный Chromium-фингерпринт) — опционально для самых враждебных сетей, документируем как ручной апгрейд.

---

## 6. Admin UI (обязателен паритет с вебом — правило CLAUDE.md)

- **Server-detail → protocol matrix:** `naive` со «Strong»-чипом.
- **Server settings:** поля `naive domain` + `ACME email` (т.к. они per-server). Валидация: домен задан до включения naive.
- **Toggle naive** — существующий механизм включения протокола на сервере.
- **Deploy-кнопка** уже kernel-agnostic → триггерит Caddy `ensure_installed`+`apply`.
- **Prerequisite-баннер** (vpnctl не управляет DNS): «Создай A-запись `<domain> → <ip>` и открой 80/443» с проверкой резолва (как делали руками).
- **Health:** node-probe дополнить проверкой `caddy active` + срок cert (`caddy`/openssl), вывести в server-detail и в alerts (Phase G).

---

## 7. Тесты (методология проекта)

- `crates/protocols/tests/spec_naive.rs` — `client_config` + `share_link` golden/byte-equality.
- Caddyfile golden-render тест (N юзеров + домен → детерминированный Caddyfile).
- **Port-conflict тест**: naive(443)+vless(443) на одном сервере → ошибка префлайта.
- `daemon/tests/sub_endpoint.rs` — naive появляется в envelope с тегом.
- Миграция: идемпотентность минта `naive_password`.
- Гейты: **test-writer-agent** на новые публичные API, **review-agent** на дифф, локально `cargo fmt --check + clippy -D + test`, `gh run watch`, **cargo-deny** (новых Rust-деп не ждём — kernel шеллит через SSH), затем live-deploy + smoke с телефона.
- glibc 2.36: ок (нет новых Rust-зависимостей, тянущих 2.38).

---

## 8. Фазы выката

- **Phase 0 — Spike (вручную, на `213.155.15.93`, сейчас):** переключить уже поднятый naive→Caddy руками. Результат: рабочий **golden Caddyfile**, install-скрипт (xcaddy+forwardproxy), systemd-юнит, дефолтный сайт; проверка `curl https://cdn.ninitux.top` → `200` + e2e через sing-box naive+utls клиент. Де-рискует Rust-работу и даёт фикстуры для тестов. (У нас уже есть DNS `cdn.ninitux.top` и борт.)
- **Phase 1 — Kernel+Protocol:** `caddy.rs` (install/render/apply) + `naive.rs` + registry + миграция `0029`. Гейты. Deploy на staging.
- **Phase 2 — Валидация:** cross-kernel port-conflict guard + preflight.
- **Phase 3 — Admin UI:** поля домен/почта + protocol matrix + prerequisite-баннер + health/cert.
- **Phase 4 — Прод:** доки + smoke с телефона + включение naive на выделенном хосте.

---

## 9. Решения, которые нужно подтвердить (с рекомендациями)

1. **Установка Caddy:** сборка через **xcaddy+Go** (как wgturn, рекомендую) vs готовый бинарь из релиза. → *xcaddy*
2. **Auth:** **per-user basic_auth** (мапится на юзеров vpnctl, рекомендую) vs один общий пароль. → *per-user*
3. **Сайт-фоллбэк:** **бандлить статический сайт** (рекомендую для v1) vs `reverse_proxy` на реальный апстрим (бандвидт/абуз-риски). → *static*
4. **Хост-политика:** **выделенный хост без REALITY** под naive (рекомендую) vs naive на альт-порту. → *dedicated*
5. **Клиент по умолчанию:** **sing-box naive+utls** в подписке (рекомендую) + нативный naive опцией. → *sing-box*

---

## 10. Риски и ограничения

- **Caddy apt НЕ содержит forwardproxy** → обязательна сборка (Go на хосте; время/диск на 1-vCPU борте — собирать можно и локально, заливать бинарь).
- **ACME требует DNS + 80/443** → действие оператора (DNS у регистратора; firewall — добавим точечное открытие в ensure_installed).
- **443 конфликт с REALITY** → политика + guard (Phase 2).
- **Supply chain:** пиннить SHA forwardproxy; Go-модуль фиксируем.
- **Фингерпринт клиента:** sing-box naive+utls ≈ Chrome ClientHello, но H2-слой не байт-в-байт; нативный naive — для максимума.

---

## Приложение — затрагиваемые файлы (чек-лист)
```
crates/protocols/src/naive.rs              (new)
crates/protocols/src/lib.rs                (+2 строки)
crates/protocols/tests/spec_naive.rs       (new)
crates/kernels/src/caddy.rs                (new)
crates/kernels/src/lib.rs                  (+2 строки)
crates/kernels/src/sing_box.rs             (port-guard → вынести в общий префлайт)
crates/inventory/migrations/0029_*.sql     (new)
crates/core/src/lib.rs                     (User.naive_password поле)
cli/src/registry.rs                        (+2 строки)
daemon/src/app.rs                          (build_registry +2 строки)
daemon/src/wizard_bootstrap.rs             (минт naive_password)
daemon/src/handlers/admin.rs               (UI: поля домен/почта, matrix, баннер)
daemon/assets/naive-site/index.html        (new, дефолтный сайт)
```
