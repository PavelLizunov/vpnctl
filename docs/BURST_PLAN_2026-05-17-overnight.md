# Overnight burst 2026-05-17 — план реализации остатка roadmap

Запрошено Pavel'ом перед сном. Цель — закрыть весь pending функционал
из `Strategic context → Roadmap` в `CLAUDE.md`, плюс задокументировать
итог и прогнать code-review.

## Pending до старта бурста

| # | Feature | Size | Touch surface |
|---|---|---|---|
| 1 | **Track-1.1** retention scheduler (старый `sub_access_log` purger) | S | `daemon/src/lib.rs` startup + `crates/inventory/src/sub_access.rs` |
| 2 | **L7** migrate destructive-op gate (ловит vps-is-01 ↔ 104 ошибку) | S | `cli/src/cmd/migrate.rs` only |
| 3 | **Phase G** infra notifications (server-down / sing-box crash-loop / fail2ban-banned-self) | M | `daemon/src/health_monitor.rs` (новый) + `0007_admin_alerts.sql` + admin handlers + dashboard widget |
| 4 | **Track-4** UA fingerprint heuristic | M | `daemon/src/ua_fingerprint.rs` (новый) + user-detail page |
| 5 | **Phase D** audit timeline UI (filters / search / export) | M | `daemon/src/handlers/admin/audit.rs` (новый) + `0008_audit_log_index.sql` |
| 6 | **Phase F** live stats tile (поверх существующего Track-3 поллера) | M | `/api/v1/stats/live` endpoint + dashboard tile |

Не входит:
- **Multi-server UUID split-identity policy decision** — это design call,
  не реализация (3 опции у Pavel; нельзя выбрать за него).

## Порядок выполнения

Все коммиты следуют workflow в `CLAUDE.md`:
1. review-agent ДО `git commit`
2. `cargo fmt` + `cargo clippy -D warnings` + `cargo test --workspace` зелёные
3. `git push` → `gh run watch --exit-status`
4. Если коммит трогает `daemon/src/handlers/` или `crates/protocols/` —
   live-deploy `vpnctld` на `192.168.0.236` через `cargo zigbuild --target
   x86_64-unknown-linux-gnu.2.36` + scp + install + restart + проверка
   curl'ом

Серии:

| Серия | Коммиты | Параллельность |
|---|---|---|
| **A** | #1 Track-1.1 + #2 L7 gate | последовательно (оба маленькие, разные файлы) |
| **B** | #3 Phase G + #4 Track-4 | сериально (#3 трогает migration + lib.rs; #4 затем расширяет admin handlers) |
| **C** | #5 audit timeline + #6 live stats tile | сериально (оба трогают `handlers/admin.rs`) |
| **D** | Документация: codebase analysis (LOC + features + artefacts → `docs/`) | один коммит |
| **E** | Final review-agent sweep на head…HEAD~N | параллельные агенты, по одной группе крейтов на агента |

## Per-feature spec

### #1 Track-1.1 retention scheduler

**Что**: фоновая `tokio::spawn` задача в `vpnctld::start_app()`, раз в
час вызывает `inv.prune_sub_access_older_than(Duration::from_days(30))`
+ audit `actor=system, action=retention.prune, summary={"rows_deleted":N}`.

**Почему S**: код уже есть (`retention_purger_spawns_a_runnable_task`
smoke-test был положен заранее), не хватает только wire-up в startup.

**Acceptance**: интеграционный тест ставит 100 строк с `created_at`
старше 30 дней + 10 свежих, спинит daemon, ждёт первый цикл,
ассертит что осталось 10.

### #2 L7 migrate destructive-op gate

**Что**: в `vpnctl migrate from-bash ... --apply --server <id>
--overwrite-existing` сделать pre-apply diff текущей `Server` строки
vs планируемой. Если `address` / `ssh_port` / `ssh_user` отличаются —
требовать дополнительный флаг `--i-really-mean-overwrite-address`
ИЛИ выводить полный diff + интерактивный prompt («type the old
address to confirm»). Без флага = bail с понятным сообщением.

**Почему S**: чисто CLI, одна функция-проверка перед `apply_migration_plan`.

**Acceptance**: тест с in-memory inventory: server `stg` с
`address=A`, migrate `from-bash --apply --server stg --overwrite-existing`
с `address=B` (без нового флага) → fail с сообщением содержащим
"address change", оба адреса видны.

### #3 Phase G infra notifications

**Что**:
- Migration `0007_admin_alerts.sql`: таблица `admin_alerts(id PK,
  kind TEXT, server_id, severity TEXT, summary TEXT, payload JSON,
  created_at, acked_at NULLABLE)`
- `daemon/src/health_monitor.rs`: периодический (5 min) поллер, на
  каждый сервер делает `ssh.exec("systemctl is-active sing-box")` +
  парсит exit code; держит in-memory state `previous_status` на
  сервер; на переходе `active → inactive` или `*  → failed` пишет
  alert + audit row.
- Также проверяет `journalctl -u sing-box -n 1 --since "10 min ago"`
  на crash-loop pattern (3+ restart за 10 мин).
- Также `fail2ban-client status sshd` parse'ит banned IPs; если в
  списке IP daemon'а (`/proc/net/route` default gateway или ENV
  `VPNCTLD_OUR_IP`) — alert severity=critical.
- Admin UI: новая секция на dashboard "Alerts (N unacked)" с feed'ом
  + кнопка "Ack" (POST audited mutation).
- Optional webhook: env `VPNCTLD_NOTIFY_WEBHOOK_URL`; если задан —
  POST JSON `{kind, server, severity, summary, ts}` на каждый новый
  alert (одиночные ретраи через `backon`, не блокируя поллер).

**Почему M**: новый module + migration + admin route + dashboard
edit; но логика контролируемая, без новых внешних deps.

**Acceptance**:
- unit-тест state machine `active → inactive → active` пишет 2 alert.
- интеграционный тест полного цикла на mock SSH transport.

### #4 Track-4 UA fingerprint heuristic

**Что**:
- `daemon/src/ua_fingerprint.rs`: `pub fn classify(ua: &str) -> UaClass`
  с вариантами `HiddifyAndroid | HiddifyiOS | SingboxAndroid |
  SingboxiOS | AmneziaWG | Clash | V2rayNG | NekoBox | GenericCurl |
  Browser | Unknown`. Pure function, table-driven (regex / contains).
- User detail page: в существующей `subscription-access` таблице
  колонку "User-Agent" заменить на классифицированный badge + tooltip
  с raw UA.
- Aggregation: новая view `user_ua_diversity_7d AS SELECT user_id,
  COUNT(DISTINCT ua_class) FROM sub_access_log WHERE ... GROUP BY` —
  на dashboard "heavy-users" heatmap'е (уже есть) дополнительный
  badge "3 device classes" если diversity > 2.

**Почему M**: новый module + DB view + UI edits, но без сетевой логики.

**Acceptance**: тест на 30 строках input → ассертит правильный класс
для каждого + один тест на diversity badge срабатывает на 3
непохожих UA из одного юзера.

### #5 Phase D audit timeline UI

**Что**:
- Новая страница `/admin/audit` с таблицей audit_log:
  колонки `time | actor | action | target | summary (truncated 80c) | view`
- Фильтры: actor (text input), action (select), target_type (select),
  from/to date (date inputs)
- Пагинация: `?page=N&per=50` (default 50, max 200)
- Search: `?q=<substring>` против `summary`
- Export: `/admin/audit.csv?...same filters...` — генерит CSV с теми же
  колонками для compliance / off-site grep'а
- Migration `0008_audit_log_index.sql`: `CREATE INDEX
  audit_log_created_at_idx ON audit_log(created_at DESC)` если ещё
  нет (нужен для пагинации).

**Почему M**: новые handlers + maud template + index, но никаких
новых внешних зависимостей.

**Acceptance**:
- тест что страница рендерится с реальными audit-rows
- тест что фильтр actor='system' прячет admin rows и наоборот
- тест что CSV экспорт содержит правильные заголовки + escape
  запятых внутри summary.

### #6 Phase F live stats tile (опционально, если time)

**Что**:
- Track-3 поллер уже пишет в `vpn_connection_stats`. Endpoint
  `/api/v1/stats/live?server=<id>` возвращает последний snapshot.
- Dashboard: в карточке каждого сервера показать "● 5 active · 1.2MB/s
  up" если есть свежий snapshot (<60s); иначе "○ no data".

**Acceptance**: тест что endpoint возвращает JSON с правильным shape;
тест что dashboard рендерит "no data" если poller не запущен.

## Документация (commit D)

`docs/CODEBASE_INVENTORY.md` (новый):
- LOC per крейт (`tokei` + tabular)
- LOC per top-level модуль внутри `daemon/src/` и `cli/src/`
- Feature inventory: для каждой v0.x feature — путь к impl,
  путь к тестам, путь к UI, flow в 2-3 предложения.
- Artefact inventory: binaries (`vpnctl`, `vpnctld`), endpoints
  (`/admin/*`, `/api/v1/*`, `/sub/*`), CLI subcommands (`server`,
  `user`, ...), DB migrations, env vars, systemd units, assets.

## Code review (commit E aka «post-mortem»)

Параллельные `general-purpose` review-agents:
- agent 1: `crates/` (только новые/измененные за бурст файлы)
- agent 2: `daemon/src/` (новые/измененные)
- agent 3: `cli/src/` + миграции
- агрегирую findings → коммит-патч с фиксами если важные есть.

## Live deploy после бурста

Коммиты #3 #5 #6 трогают `daemon/src/handlers/`. После CI зелёного
для каждого — единый final live-deploy на 192.168.0.236:

```
cargo zigbuild --release -p vpnctld --target x86_64-unknown-linux-gnu.2.36
scp target/x86_64-unknown-linux-gnu/release/vpnctld user@192.168.0.236:/tmp/vpnctld
scp daemon/assets/{admin.css,favicon.svg} user@192.168.0.236:/tmp/
ssh user@192.168.0.236 'sudo install -o root -g root -m 0755 /tmp/vpnctld /opt/vpnctl/vpnctld && \
  sudo install -o root -g root -m 0644 /tmp/admin.css /opt/vpnctl/assets/admin.css && \
  sudo install -o root -g root -m 0644 /tmp/favicon.svg /opt/vpnctl/assets/favicon.svg && \
  sudo systemctl restart vpnctld'
```

+ smoke-тест curl'ами что все новые endpoints отвечают.

## Stop-conditions

Если в любой момент:
- `cargo test` падает после моего изменения → откатить, диагностировать,
  не пушить пока не зелёное
- `gh run watch` красное → fix → re-push (не игнорировать)
- production VPN на 192.168.0.236 упал (`curl /api/v1/health` 503) →
  rollback бинаря до prior версии (есть бэкап `/opt/vpnctl/vpnctld.prev`
  после первого install — добавлю это в новую deploy команду)
- Token budget кончается → стопаюсь на коммите N, документирую что
  не доделано, и оставляю clean state (никаких uncommitted dirty
  файлов).

Pavel — спишь спокойно. Утром будет полный отчёт.
