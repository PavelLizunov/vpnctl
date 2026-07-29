# GOAL — Boosty bridge: довести до прода

Дата: 2026-07-10. Основание: read-only аудит модуля (сессия Claude,
2026-07-10). Документ самодостаточен — исполняющему агенту не нужен
контекст той сессии, только этот файл + CLAUDE.md репозитория.

---

## 1. Цель (одним абзацем)

Boosty→VPN мост доведён до продакшена: VPN-доступ **реально следует за
состоянием подписки на нодах** (sing-box `users[]`), а не только в
inv.db; мост **переживает сетевые сбои и ротацию refresh-токена** без
ручной реанимации; **смерть моста видна оператору** (Telegram + дашборд);
код смёржен в main, задеплоен на 192.168.0.236 и проверен на живом
подписчике блога `ninitux`.

## Обновление политики 2026-07-29

- Новому платному подписчику автоматически создаётся полноценный пользователь
  `boosty-<subscriber_id>`: UUID, TUIC-пароль, WireGuard-пара, subscription
  token и device id. В той же транзакции выдаётся доступ ко всем текущим
  серверам; за один тик создаётся не больше пяти пользователей.
- Автоотключение ждёт 14 дней от Boosty `off_time`, а при его отсутствии —
  от первого обнаружения просрочки. Возобновление подписки сбрасывает отсчёт.
- Первый недельный этап эксплуатации остаётся в безопасном режиме
  EnableOnly; полный режим включается оператором после проверки свежих
  учётных данных и результатов синхронизации.

## 2. Ожидаемый финальный результат (наблюдаемое состояние)

Когда всё готово, верно одновременно:

1. Оператор на `/admin/boosty` видит живой ростер, линкует нового
   подписчика к пользователю в два клика; после ближайшего тика (или
   «sync now») пользователь **реально подключается** к VPN — UUID
   присутствует в конфиге ноды, деплой произошёл автоматически.
2. Отвалившийся подписчик surfaced на странице; кнопка «disable»
   **реально рвёт доступ на нодах** (не только флаг в БД).
   `auto_disable_lapsed` остаётся **выключенным** в проде на первое
   время (политика «auto-provision, disable on a button»).
3. Один сбойный тик (таймаут, 500, дрейф модели) не убивает мост:
   следующий тик аутентифицируется — ротированный refresh-токен
   персистится даже при ошибке синка.
4. Мёртвые креды = алерт в Telegram + строка на `/admin/alerts` в
   течение одного тика; восстановление кредов гасит алерт.
5. `feat/boosty-bridge-main` смёржен в main через PR с зелёным GitHub
   CI; строка в roadmap CLAUDE.md добавлена; stale-копия модуля в
   codex-дереве удалена.
6. Прод: миграция применена (`/admin/backup/self-test` → PASS), бинарь
   из main, два тика подряд с рестартом демона между ними — auth жив.

## 3. Контекст: где что лежит

- **Каноничный код**: ветка `feat/boosty-bridge-main`, коммит `be72607`,
  worktree `D:\vibe-code\vpnctl-main`. Миграция `0040_boosty_bridge.sql`.
  База ветки — `68a3b1d`; main ушёл вперёд на 2 коммита (#107, #108) —
  **нужен rebase**; номер 0040 на main всё ещё свободен (main
  заканчивается на 0039).
- **Ветка НЕ запушена** на GitHub; CI модуль не видел.
- **Stale-копия**: в дереве `D:\vibe-code\vpnctl` (ветка
  `codex/ponytail-ultra-xhttp-simplify`) лежат untracked-дубли модуля с
  миграцией `0036` — коллизия с прод-миграцией `0036_notification_language`.
  Не коммитить и не деплоить оттуда; удалить после мержа (см. AC-E3).
- **Зависимость**: `boosty_api` пинится по rev на форк
  `PavelLizunov/boosty_api_rs` (локально `D:\vibe-code\boosty_api_rs`).
  Запиненный `581827e` НЕ содержит security-hardening `ee204ec`
  (redaction тела refresh-ошибки, `encode_segment`, требование
  таймаутов). Спека моста: `D:\vibe-code\boosty_api_rs\docs\IMPLEMENTATION.md`.

## 4. Критерии приёмки (MUST)

Каждый критерий проверяем; «Проверка:» говорит как. Тесты — по
конвенции проекта (spec-тесты пишутся от контракта, не от реализации).

### Блок A — живучесть auth

- **AC-A1. Ротированный refresh-токен персистится до проброса ошибки.**
  Сейчас persist стоит после `sync_once(...).await?`
  (`crates/boosty-bridge/src/lib.rs:129` — `?` раньше persist-блока
  133-138); каждый проход строит новый клиент → refresh (= ротация)
  происходит на первом же запросе, и упавший после этого fetch теряет
  новый токен → invalid_grant навсегда. Фикс: `let result = sync_once(...).await;`
  → персист → `result?`. Нарушение ADR-001 крейта — устранено.
  Проверка: тест «refresh OK → roster 500 → `sync_from_settings` = Err,
  но `get_boosty_settings().refresh_token` == новый». Потребует
  инъекции base URL в `sync_from_settings` (сейчас `BOOSTY_BASE_URL`
  захардкожен, lib.rs:23) — любой минимальный способ (параметр/вариант
  функции).
- **AC-A2. Таймауты на reqwest-клиенте.** `build_client` (lib.rs:89)
  использует `Client::new()` без таймаутов; refresh держит tokio-Mutex
  через сетевой вызов — зависшее соединение навсегда стопорит поллер и
  вешает `GET /admin/boosty`. Фикс: `Client::builder()
  .connect_timeout(10s).timeout(30s)` (требование README/CLAUDE.md
  самого крейта). Проверка: тест против сервера, который принимает
  соединение и молчит (tokio `TcpListener`) — sync завершается ошибкой,
  не виснет.
- **AC-A3. Пин boosty_api поднят до `ee204ec` или новее.** Даёт:
  обрезку тела refresh-ошибки до 200 символов (на текущем пине полное
  тело OAuth-ошибки — потенциально с эхом refresh-токена — уходит в
  journalctl, в admin-HTML баннер `sync_err` и в stderr CLI) +
  `encode_segment` для blog-slug из веб-формы. Требование: rev должен
  быть достижим с GitHub через стабильный ref (merge в master или тег в
  `boosty_api_rs` — **согласовать push с Pavel**). Проверка: Cargo.lock
  указывает новый rev; свежая сборка (CI) проходит.
- **AC-A4. Refresh-flow приоритетнее static access_token.** Сейчас
  наоборот (lib.rs:91-96), а static-токен живёт ~час → мост с обоими
  кредами умирает в течение часа. Проверка: тест — оба креда заданы →
  `client.refresh_token().await.is_some()` (клиент в refresh-режиме).

### Блок B — реальный revoke/restore на нодах (ядро цели)

- **AC-B1. Каждый applied enable/disable моста запускает redeploy
  затронутых серверов.** Пути: тик поллера (`run_tick`), кнопка
  «sync now» (`boosty_sync_now`). Механизм — тот же, что у ручного
  disable (`user_set_disabled_inner` → `spawn_user_servers_redeploy` →
  `run_deploy_all`), с audit `user.autodeploy` (trigger=`boosty.*`).
  `report.enabled`/`report.disabled` уже содержат затронутых
  пользователей. Поллеру потребуются registry + deploy-key path
  (пробросить из `app.rs::build`, по образцу существующих поллеров);
  серверы затронутых пользователей дедуплицировать в один набор перед
  деплоем. Проверка: smoke-тест, что после мостового флипа сервер
  пользователя помечен pending-deploy (см. AC-B2), + live-проверка
  AC-F3.
- **AC-B2. Pending-deploy детектор видит мостовые флипы.**
  `servers_pending_deploy_for_user` (inventory, `sqlite.rs`) ключуется
  на `user.disable`/`user.enable`, а мост пишет `boosty.disable`/
  `boosty.enable` → страховочный баннер слеп. Фикс (рекомендуемый):
  добавить `boosty.disable`,`boosty.enable` в SQL IN-список (его
  doc-comment прямо это просит). Проверка: spec/smoke-тест по образцу
  `grants_via_real_handlers_mark_server_pending_deploy`.
- **AC-B3. Кнопка `/admin/boosty/disable/{user}` ведёт себя как ручной
  disable**: запускает redeploy (как AC-B1) и аудитит только при
  фактическом изменении (`set_user_disabled` возвращает `changed`;
  сейчас хендлер `boosty_disable` аудитит безусловно — double-submit =
  спам). Проверка: тест — двойной POST → одна audit-строка; сервер
  пользователя pending-deploy.
- **AC-B4. CLI `vpnctl boosty sync --apply`** после применения печатает
  точный список серверов, требующих deploy, и команду
  (`vpnctl deploy <id>`) — либо деплоит сам. Печати достаточно (CLI —
  automation-surface). Проверка: юнит на текст вывода при непустом
  enabled/disabled.

### Блок C — fail-safe

- **AC-C1. Пустой ростер не может массово отключить пользователей.**
  Успешный ответ с `total_subscribers == 0` (опечатка blog_url → Boosty
  может 200 с пустым `data`) при auto-disable подавляет все
  Disable-действия + warning в лог. Проверка: тест
  `empty_roster_suppresses_disables` (Full-режим, пустой ростер,
  линкованный enabled-пользователь → остаётся enabled).
- **AC-C2. Ошибка API → ни одной записи в БД** (инвариант спеки,
  «fail-safe rule covered by a unit test where the API errors and
  nothing is revoked»). Сейчас выполняется по построению — запинить
  явным тестом: roster 500 → пользователи не тронуты, audit пуст.

### Блок D — наблюдаемость

- **AC-D1. Сбойный тик → admin_alert + Telegram, с дедупом и
  auto-recovery.** Kind вида `boosty.sync.failed`, warning, через
  существующий `insert_alert_if_no_unacked` (паттерн AL-1) + push
  (паттерн Bundle 4); повторный сбой не спамит; успешный тик
  auto-ack'ает (паттерн `b4608d2`). Проверка: интеграционный тест
  fail→alert, fail→no-dup, success→acked.
- **AC-D2. Auth-смерть различима в тексте алерта** (по варианту
  `BridgeError::Auth` vs остальные): «пере-выпустите креды в форме
  /admin/boosty» vs «сетевая/API ошибка, уйдёт сама». Формулировка —
  без инструкций SSH (operator-action policy). Проверка: юнит на текст.

### Блок E — ландинг

- **AC-E1. Rebase на актуальный main**; номер миграции уникален (0040
  или следующий свободный на момент rebase); doc-comment'ы `sqlite.rs`
  про «migration 0036» у boosty-секции исправлены на фактический номер.
- **AC-E2. `just ci` зелёный** (fmt-check + clippy -D warnings + tests
  + deny); review-agent по диффу прогнан (шаблон в CLAUDE.md),
  critical/important обработаны; PR в main; GitHub CI зелёный
  (`gh run watch --exit-status`). Если advisory-гейт красный на anyhow —
  забрать bump из `d62bc5b` (RUSTSEC-2026-0190, висит на старой ветке
  `feat/boosty-bridge`).
- **AC-E3. Stale-копия удалена**: после мержа удалить из дерева
  `D:\vibe-code\vpnctl` ровно 5 untracked boosty-файлов
  (`crates/boosty-bridge/`, `cli/src/cmd/boosty.rs`,
  `daemon/src/boosty_sync_poller.rs`,
  `crates/inventory/migrations/0036_boosty_bridge.sql`,
  `crates/inventory/tests/spec_boosty.rs`) — **не трогая** остальные
  изменения той сессии (multi-session правила CLAUDE.md).
- **AC-E4. Строка в roadmap-таблице CLAUDE.md** (конвенция проекта для
  shipped-фич) с итоговым описанием и коммитами.

### Блок F — прод-верификация

Деплой **только из main после мержа** (multi-session правило #5), с
бэкапом текущего бинаря, сборка `cargo zigbuild --target
x86_64-unknown-linux-gnu.2.36` + objdump-проверка ≤2.36 (см. CLAUDE.md).

- **AC-F1.** Бинарь обновлён, демон поднялся, `POST /admin/backup/self-test`
  → PASS (он сверяет max schema version с HEAD → подтверждает миграцию).
- **AC-F2.** Креды (refresh + device_id, blog=`ninitux`) введены через
  веб-форму; `/admin/boosty` показывает ростер без ошибок. Кто вводит
  креды — Pavel (рекомендуется) или передаёт агенту — см. §7.
- **AC-F3. E2E на живом линке**: link тестового подписчика ↔ тестовый
  пользователь → вручную disable → «sync now» → пользователь enabled,
  audit `boosty.enable` + `user.autodeploy`, UUID присутствует в
  `users[]` конфига ноды (проверить через деплой-SSH демона / audit
  деплоя), клиентский конфиг подключается.
- **AC-F4. Ротация переживает рестарт**: успешный тик →
  `systemctl restart vpnctld` → следующий тик успешен;
  `refresh_token` в БД изменился между тиками.
- **AC-F5. Negative**: испортить refresh_token в форме → в течение тика
  Telegram-алерт + строка на `/admin/alerts` c auth-текстом (AC-D2);
  вернуть корректные креды → recovery (auto-ack).

## 5. Желательно, но не блокер (SHOULD)

- `GET /admin/boosty` не делает живой сетевой sync на каждый просмотр
  (сейчас — DryRun-проход с ротацией токена и записью в БД на GET;
  гонка с тиком поллера даёт ложные invalid_grant). Вариант: кэш
  последнего отчёта поллера + «as of <ts>», сеть только по кнопке.
- Интервал поллера: применять без рестарта (перечитывать на тике) или
  подсказка в форме «применится после рестарта демона».
- Дедуп `mask()`/`boosty_mask_secret()` — если появится общее место.

## 6. Не входит в scope (YAGNI — не делать)

- **Маппинг уровней подписки → доступ** (`level_grants_vpn` из спеки):
  текущее «любой активный уровень = доступ» остаётся до явного решения
  Pavel (§7.1).
- Уведомления подписчикам через `send_message` (фаза D спеки).
- Grace period при lapse (дефолт EnableOnly покрывает).
- Автосоздание vpnctl-пользователя для нового подписчика (остаётся
  ручной link из surfaced-списка).
- Мульти-блог; веб-стрельба SSE-прогрессом деплоя из boosty-страницы.

## 7. Открытые вопросы к Pavel (не блокируют A–E; F2 требует №2)

1. Все ли уровни подписки дают VPN? (Если появится не-VPN тир —
   потребуется маппинг по `SubscriberLevel.id`; сейчас over-grant.)
2. Креды для прода: Pavel вводит сам через форму, или передаёт агенту?
3. Когда (и включать ли вообще) `auto_disable_lapsed=1` в проде —
   рекомендация: не раньше недели наблюдения EnableOnly-режима.

## 8. Процессные инварианты (обязательны, кратко)

- Работа — в worktree `D:\vibe-code\vpnctl-main` на
  `feat/boosty-bridge-main`. `git branch --show-current` перед каждым
  коммитом; stage только свои файлы (никогда `git add -A`).
- Перед коммитом: review-agent → `just ci`; после push —
  `gh run watch --exit-status`. Не коммитить поверх красного CI.
- Деплой на 236 — только из main, с бэкапом бинаря; push в
  `boosty_api_rs` (для AC-A3) — только с явного go Pavel.
- Стоп-условия исполнения: все MUST AC зелёные, ЛИБО блокер, требующий
  решения Pavel (§7), — тогда остановиться и спросить, не выжигая
  токены на обход.

## 9. Порядок работ (рекомендуемый)

| Фаза | Что | Закрывает |
|---|---|---|
| 1 | rebase на main + мелкие фиксы auth (persist, таймауты, приоритет refresh) + пин | AC-E1, A1, A2, A4, (A3 после go на push) |
| 2 | deploy-wiring: поллер/кнопки → redeploy + детектор + CLI-warning | AC-B1–B4 |
| 3 | fail-safe + алерты | AC-C1, C2, D1, D2 |
| 4 | ландинг: review-agent, CI, PR, merge, roadmap, зачистка stale-копии | AC-E2–E4 |
| 5 | прод: deploy, креды, e2e, negative | AC-F1–F5 |

Полный аудит с деталями находок — в чат-сессии от 2026-07-10; всё
нужное для исполнения продублировано здесь.
