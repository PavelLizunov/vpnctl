# Спецификация и Агенто-Читаемая Карта: Crate CLI (`vpnctl`)

> **Статус аудита:** Завершён сплошной построчный анализ `cli` (22 файла, 7320 строк). Полнота покрытия — 100%.

---

## 1. Назначение и Архитектурная роль CLI

`cli` (`vpnctl`) — консольный интерфейс автоматизации, скриптинга и аварийного восстановления (Disaster Recovery).
- Построен на базе библиотеки парсинга аргументов командной строки `clap` (derive-макросы).
- Инкапсулирует вызовы к `SqliteInventory`, `Registry`, `SshTransport` и генераторам ключей `vpnctl-crypto`.
- **Форматы вывода**: поддерживает форматированный текстовый человеко-читаемый вывод (таблицы, цвета) и машиночитаемый JSON (`--output json`).
  - **Инвариант безопасности**: в JSON-выводе строго заблокирована утечка секретов (приватные ключи WireGuard, пароли TUIC, sub-токены маскируются благодаря `#[serde(skip_serializing)]` на `User`).

---

## 2. Команды и Функциональные Модули (`cli/src/cmd/`)

- **`cli/src/registry.rs`**:
  - Точка сборки и единый источник правды связывания ядер и протоколов (`build() -> anyhow::Result<Registry>`).
  - Регистрирует ядра: `SingBox`, `AmneziaWg`, `Caddy`, `Xray`.
  - Регистрирует протоколы: `VlessReality`, `TuicV5`, `Hysteria2`, `Shadowsocks2022`, `WireGuard`, `AmneziaWg2`, `AmneziaWg3`, `AnyTls`, `Trojan`, `Naive`, `VlessWs`, `VlessXhttp`.
- **`cmd/server.rs`**:
  - `vpnctl server list`: перечисление всех узлов с их статусами, адресами, ядрами и включенными протоколами.
  - `vpnctl server add`: добавление сервера в базу.
  - `vpnctl server set-fingerprint`: закрепление доверенного SHA-256 отпечатка SSH хоста (поддерживает `--from-keyscan`).
  - `vpnctl server update`: обновление портов, адресов, хостеров, настройка `jump_via` (ProxyJump).
- **`cmd/user.rs`**:
  - `vpnctl user list`: список пользователей, статус активности, привязка к Boosty.
  - `vpnctl user add`: создание пользователя. Флаги `--gen-wireguard` (автоматическая генерация пары Curve25519) и `--wireguard-pubkey` (ручной импорт публичного ключа).
  - `vpnctl user disable` / `enable`: мгновенное управление soft-suspend доступом.
  - `vpnctl user regen-sub`: ротация токена подписки `/sub/<token>`.
- **`cmd/grant.rs`**:
  - `vpnctl grant add <user> <server>`: выдача доступа пользователю к серверу.
  - `vpnctl grant revoke <user> <server>`: отзыв доступа.
- **`cmd/deploy.rs`**:
  - `vpnctl deploy <server>`: накат конфигурации на удаленную ноду через SSH.
  - Выполняет префлайт портов, проверку секретов, компиляцию инбаундов через `Kernel::apply_config`, проверку синтаксиса и рестарт демона.
- **`cmd/bootstrap.rs`**:
  - Консольный аналог визарда первичного развертывания новой "чистой" ноды по root-паролю с установкой deploy-ключа.
- **`cmd/sub.rs`**:
  - `vpnctl sub render <user>`: печать готовой клиентской конфигурации или ссылок для указанного пользователя прямо в терминал.
- **`cmd/backup.rs`**:
  - `vpnctl backup create`: создание горячего бэкапа инвентаря.
  - `vpnctl backup list`, `prune`, `restore`: управление архивами и безопасное восстановление.
- **`cmd/boosty.rs`**:
  - Консольный запуск синхронизации с Boosty (`sync`), просмотр статуса подписок и ручная привязка.
- **`cmd/migrate.rs`**:
  - Миграция старых текстовых конфигураций legacy bash-скриптов в SQLite базу данных `vpnctl`.
- **`cmd/update_kernels.rs`**:
  - Массовое обновление бинарников ядер (sing-box, amneziawg, caddy, xray) на всех зарегистрированных серверах.
