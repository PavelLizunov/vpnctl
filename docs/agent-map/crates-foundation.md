# Спецификация и Агенто-Читаемая Карта: Crates Core, Crypto, Host-Fingerprint, SSH, Boosty-Bridge

> **Статус аудита:** Завершён сплошной построчный анализ. 100% покрытие исходных файлов пяти базовых библиотек.

---

## 1. `vpnctl-core` (`crates/core`)

### 1.1 Назначение и Архитектурная роль
Фундамент всей системы `vpnctl`. Определяет базовые абстракции доменной модели, контракты трейтов (`Kernel`, `Protocol`, `SshTransport`), централизованную обработку ошибок (`CoreError`), валидацию совместимости и типобезопасные идентификаторы.

### 1.2 Файловая декомпозиция и интерфейсы
- **`crates/core/src/id.rs`**:
  - Типы-обёртки: `ServerId`, `UserId`, `KernelId`, `ProtocolId`.
  - Все типы реализуют `Serialize`, `Deserialize`, `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`, `Display`.
  - Запрещают нетипизированное смешивание строк идентификаторов на уровне компилятора.
- **`crates/core/src/error.rs`**:
  - `CoreError` (на базе `thiserror`):
    - `MissingSecret { server: ServerId, key: String }` — отсутствие требуемого секрета в `RenderCtx`.
    - `UnknownKernel(KernelId)`, `UnknownProtocol(ProtocolId)` — незарегистрированные компоненты.
    - `UnsupportedProtocol { kernel: KernelId, protocol: ProtocolId }` — ядро не поддерживает протокол.
    - `Conflict(String)` — порт/конфигурационный конфликт между протоколами на ноде.
    - `Transport(String)` — сетевой или SSH-сбой.
    - `Inventory(String)` — ошибка сохранения/чтения данных.
    - `Render(String)` — ошибка сериализации/шаблонизации конфига.
    - `Io(std::io::Error)`, `Json(serde_json::Error)`.
  - Псевдоним `Result<T, CoreError>`.
- **`crates/core/src/models.rs`**:
  - `Server`: модель VPS-сервера.
    - `id: ServerId`, `address: String`, `ssh_port: u16`, `ssh_user: String`.
    - `kernels: Vec<KernelId>` — поддержка запуска нескольких ядер параллельно (например, sing-box на TCP/443 + amneziawg на UDP/51820).
    - `enabled_protocols: Vec<ProtocolId>` — включенные протоколы.
    - `trusted_host_fingerprint: Option<String>` — TOFU/закреплённый отпечаток SSH хоста.
    - `hoster: String`, `jump_via: Option<ServerId>`, `usage_coefficient: f64`.
  - `User`: модель пользователя VPN.
    - **Инвариант безопасности**: поля `tuic_password`, `wireguard_private`, `sub_token`, `vpn_router_device_id` помечены `#[serde(skip_serializing)]`. Реализован ручной `fmt::Debug` с маскированием `<redacted>`, предотвращающий случайную утечку в логи и CLI JSON.
    - `with_per_server_uuid(&self, new_uuid: &str) -> Self` — генерация изолированного контекста для per-server UUID overrides.
    - `disabled: bool` — флаг soft-suspend (приостановка доступа без удаления ключей).
  - `RenderCtx<'a>`:
    - Контекст генерации конфигураций. Реализации `Protocol` **stateless** — не содержат секретов.
    - Поля: `server: &'a Server`, `secrets: &'a HashMap<String, String>`, `peers: &'a [User]`.
    - Методы: `require(key) -> Result<&str>`, `or_default(key, default) -> &str`, `with_peers(...)`.
- **`crates/core/src/protocol.rs`**:
  - Трейт `Protocol: fmt::Debug + Send + Sync`:
    - `fn id(&self) -> ProtocolId;`
    - `fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value>;`
    - `fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value>;`
    - `fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String>;`
    - `fn listen_ports(&self) -> &'static [(&'static str, u16)];` — статические порты.
    - `fn effective_listen_ports(&self, secrets: &HashMap<String, String>) -> Vec<(&'static str, u16)>;` — динамические порты с учётом секретов сервера.
    - `fn appears_in_sing_box_sub(&self) -> bool;`
    - `fn appears_in_stock_sing_box_sub(&self) -> bool;`
    - `fn dpi_risk(&self) -> DpiRisk;` — риски блокировок (High, Moderate, Low).
    - `fn server_secret_specs(&self) -> Vec<ServerSecretSpec>;` — декларация необходимых серверных секретов для предгенерации визардом.
  - Перечисление `ServerSecretSpec`:
    - `Password { key, entropy_bytes }` (URL-safe base64).
    - `Base64Key { key, key_bytes }` (Standard base64 с паддингом для Shadowsocks-2022).
    - `X25519Keypair { private_key, public_key }` (REALITY).
    - `WireguardKeypair { private_key, public_key }` (WireGuard / AmneziaWG).
    - `ShortId { key }` (8 hex символов).
- **`crates/core/src/kernel.rs`**:
  - Трейт `Kernel: fmt::Debug + Send + Sync`:
    - `fn id(&self) -> KernelId;`
    - `fn supported_protocols(&self) -> &[ProtocolId];`
    - `async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()>;`
    - `async fn apply_config(&self, ssh: &dyn SshTransport, ctx: &RenderCtx<'_>, protocols: &[&dyn Protocol], users: &[User]) -> Result<()>;`
    - `async fn open_firewall(&self, ssh: &dyn SshTransport, ctx: &RenderCtx<'_>, protocols: &[&dyn Protocol]) -> Result<()>;`
    - `async fn restart(&self, ssh: &dyn SshTransport) -> Result<()>;`
    - `async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus>;`
- **`crates/core/src/registry.rs`**:
  - Структура `Registry`: глобальный связующий каталог ядер и протоколов.
  - Методы валидации `validate_server`:
    - Проверка поддержки каждого протокола заявленными ядрами сервера.
    - Защита от конфликта портов: обнаружение дублирующихся комбинаций `(protocol, port)` между разными протоколами на одном сервере с учётом `effective_listen_ports`.
- **`crates/core/src/transport.rs`**:
  - Трейт `SshTransport: fmt::Debug + Send + Sync`:
    - `async fn exec(&self, cmd: &str) -> Result<String>;` (привилегированное исполнение / sudo).
    - `async fn exec_unprivileged(&self, cmd: &str) -> Result<String>;` (от имени пользователя SSH без sudo).
    - `async fn upload(&self, path: &str, content: &[u8]) -> Result<()>;`
    - `async fn read_file(&self, path: &str) -> Result<Vec<u8>>;`
- **`crates/core/src/shell.rs`**:
  - `single_quote(s: &str) -> String`: каноническое экранирование аргументов для POSIX sh (`'a'\''b'`). Защищает от выполнения подстановок `$VAR`, `$(...)` и бэкблоков.
- **`crates/core/src/url_host.rs`**:
  - `host_for_url(addr: &str) -> Cow<'_, str>`: RFC 3986 §3.2.2 форматирование IPv6 адресов (оборачивание `2a00:...` в `[...]` для URI и endpoints).
- **`crates/core/src/version.rs`**:
  - `build_version() -> &'static str`: генерация строки сборки `<semver>+<short-sha>` на базе `CARGO_PKG_VERSION` и `VPNCTL_BUILD_SHA`.
- **`crates/core/src/humanize.rs`**:
  - Утилиты форматирования байт и времени (человеко-читаемый вид).

---

## 2. `vpnctl-crypto` (`crates/crypto`)

### 2.1 Назначение
Детерминированные и CSPRNG криптографические генераторы ключей, паролей и токенов. Бездисковая чистая библиотека.

### 2.2 Экспортируемые функции и строгие контракты
- `gen_uuid() -> String`: RFC 4122 UUID v4 для идентификаторов VLESS.
- `is_valid_uuid(s: &str) -> bool`: валидация формы UUID перед вставкой в базу/конфиг.
- `gen_vpn_router_device_id() -> std::io::Result<String>`: генерация 32 lowercase hex символов (16 байт энтропии) для совместимости с ninitux vpn-router.
- `is_valid_vpn_router_device_id(s: &str) -> bool`: валидация 32-hex идентификатора устройства.
- `gen_password(entropy_bytes: usize) -> std::io::Result<String>`: пароль в кодировке URL-safe base64 без паддинга (TUIC, Hysteria2 Salamander).
- `gen_base64_key(key_bytes: usize) -> std::io::Result<String>`: стандартный base64 с паддингом `=` (критично для Shadowsocks-2022 PSK, который парсится Go `base64.StdEncoding`).
- `gen_short_id() -> std::io::Result<String>`: 8 hex-символов (4 байта) для REALITY `short_id`.
- `gen_sub_token() -> std::io::Result<String>`: 32-байтный URL-safe unpadded токен (43 символа) для эндпоинта подписок `/sub/<token>`.
- `gen_x25519_keypair() -> (String, String)`: пара Curve25519 в URL-safe base64 без паддинга (для VLESS REALITY).
- `gen_wireguard_keypair() -> (String, String)`: пара Curve25519 в стандартном base64 с паддингом `=` (ровно 44 символа, совместимо с `wg genkey` / `wg pubkey`).
- `wireguard_keypair_matches(private: &str, public: &str) -> bool`: математическая валидация соответствия публичного ключа приватному (`X25519_basepoint(priv) == pub`) без утечки ключевого материала.
- `gen_amnezia_obfs() -> std::io::Result<AmneziaObfs>`:
  - Генерация пакета обфускации для AmneziaWG:
    - `jc` (junk packet count): [4, 12].
    - `jmin`, `jmax` (junk packet size): [50, 100] и [jmin+50, jmin+150].
    - `s1`, `s2` (handshake padding): [15, 150].
    - **Инвариант DPI**: строго `s2 != s1 + 56` (иначе длина handshake init 148+s1 равна длине response 92+s2, что является сигнатурой для DPI).
    - `h1..h4` (magic packet headers): 4 уникальных числа в диапазоне `[5, i32::MAX]`. Значения 1..4 исключены (это оригинальные типы пакетов WireGuard).

---

## 3. `vpnctl-host-fingerprint` (`crates/host-fingerprint`)

### 3.1 Назначение
Единый доверенный модуль валидации, сканирования и каноникализации SSH хост-ключей.

### 3.2 Ключевые механизмы и безопасность
- **Защита от Option Injection (`--`)**:
  - При вызове `ssh-keyscan` используется разделитель позиционных аргументов `--`: `["-T", "10", "-p", port, "-t", "ed25519,rsa", "--", host]`.
  - Защищает от атак, когда адрес ноды начинается с дефиса (`-f...`), что заставило бы `ssh-keyscan` интерпретировать хост как флаг чтения локального файла.
- `validate_shape(fp: &str) -> bool`: проверка префикса `SHA256:` и длины (43 символа unpadded, 44 символа padded, стандартный или url-safe алфавит).
- `canonicalize_sha256(fp: &str) -> Option<String>`: приведение любого валидного представления (padded, url-safe `-_`) к единому стандарту `SHA256:<43-char-standard-base64>`.
- `fingerprints_match(expected: &str, observed: &str) -> bool`: безопасное сравнение отпечатков после каноникализации.
- `fetch_via_keyscan(host: &str, port: u16) -> Result<String, Error>`: синхронный вызов `ssh-keyscan` + пайп в `ssh-keygen -lf -`. Приоритет отдаётся алгоритму `ssh-ed25519`.
- `fetch_all_fingerprints(host: &str, port: u16) -> Result<Vec<String>, Error>`: извлечение всех доступных отпечатков ноды для исключения ложного срабатывания дрифта ключей при временном таймауте ed25519 и ответе rsa.

---

## 4. `vpnctl-ssh` (`crates/ssh`)

### 4.1 Назначение
Реализация трейта `SshTransport`. Поддерживает два движка: асинхронный native Rust SSH клиент на базе `russh` и подпроцессный клиент OpenSSH (`SubprocessSshTransport`) для сложных сценариев (ProxyJump/Bastion).

### 4.2 Детали реализации
- **`RusshTransport`**:
  - Основан на `russh::client::Handle`. Защищён асинхронным мьютексом `tokio::sync::Mutex`.
  - Поддерживает аутентификацию по Ed25519/RSA ключам с автоматическим фолбэком на пароль при первом подключении.
  - `VerifyHandler`: реализует проверку отпечатка сервера при рукопожатии:
    - При наличии закрепленного `trusted_fingerprint` проверяет отпечаток и реджектит с `russh::Error::UnknownKey` при расхождении.
    - При отсутствии (TOFU) — сохраняет полученный отпечаток в `observed_host_fingerprint` для последующей записи в БД.
  - Методы исполнения команд:
    - Выполняет команду внутри сессионного канала. Для non-root пользователей автоматически оборачивает в `sudo -n sh -c '...'`.
    - **Потоковый инвариант**: чтение канала продолжается строго до полного завершения стрима (`None`), не прерываясь по раннему `Close`, так как некоторые серверные утилиты (`cat`, `tee`) закрывают stdin до отдачи `ExitStatus`.
  - Загрузка файлов (`upload`): передает данные через stdin удаленной команды `tee <quoted_path> >/dev/null`.
- **`SubprocessSshTransport`**:
  - Реализация через запуск системного бинарника `ssh`.
  - Используется для серверов, требующих доступ через бастион (`jump_via` / OpenSSH `ProxyJump`).
  - `prepare_pinned_jump`: создает изолированный временный каталог со своим `ssh_config` и проверенным `known_hosts`, где жестко зафиксированы отпечатки и бастиона, и целевой ноды.

---

## 5. `vpnctl-boosty-bridge` (`crates/boosty-bridge`)

### 5.1 Назначение
Модуль синхронизации и биллинга с платформой Boosty. Автоматически управляет доступом подписчиков: активный платный подписчик активируется (`disabled = false`), при неоплате или отмене — доступ мягко приостанавливается (`disabled = true`).

### 5.2 Архитектура и гарантии безопасности
- **Инвариант неприкосновенности непривязанных аккаунтов**:
  - `reconcile::reconcile(subscribers, links) -> Vec<Action>`: чистая функция без I/O. Оперирует ТОЛЬКО пользователями, у которых есть запись привязки к `subscriber_id`. Все ручные аккаунты администратора, тестовые ключи и служебные пользователи игнорируются и ни при каких условиях не могут быть отключены или изменены бриджем.
- **Гейт платной подписки (`is_vpn_eligible`)**:
  - Подписчик признается активным строго при условии `is_active() && level.price > 0.0`.
  - Бесплатные отслеживающие ("Followers") с нулевой ценой отсекаются и не получают доступ.
- **Защита от массового отключения (Fail-Safe)**:
  - Если список подписчиков вернулся пустым, либо в нем есть подписчики, но у всех `price == 0` (аномалия сериализации API Boosty или сбой токена), бридж **блокирует массовое отключение** (`suppressed_disables`), логирует предупреждение и ждет подтверждения оператора.
- **Синхронизация и распределенный лок**:
  - `sync_from_inventory`: захватывает распределенный lease-лок в SQLite (`acquire_boosty_sync_lease`) на 600 секунд + in-process `Mutex`, исключая гонки между фоновым cron-воркером и кликом оператора в Web UI.
- **Авто-провижининг (`MAX_AUTO_PROVISION_PER_TICK = 5`)**:
  - При появлении нового платного подписчика автоматически создает пользователя `boosty-<subscriber_id>` с полным комплектом ключей (UUID, WireGuard keypair, TUIC password, vpn-router device_id) и выдает гранты на серверы. Ограничение в 5 пользователей за тик защищает от скачков нагрузки.
- **Финансовая аналитика (`income_summary`)**:
  - Расчет `active_payers`, Monthly Recurring Revenue (`mrr_rub_cents`) и кумулятивной выручки (`total_revenue_rub_cents`) в копейках без потери точности с плавающей точкой.
