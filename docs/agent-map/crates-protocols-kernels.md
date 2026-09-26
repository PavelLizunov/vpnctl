# Спецификация и Агенто-Читаемая Карта: Crates Protocols & Kernels

> **Статус аудита:** Завершён сплошной построчный анализ `crates/protocols` (32 файла, 9873 строк) и `crates/kernels` (17 файлов, 7072 строк). Полнота покрытия — 100%.

---

## 1. Архитектурный принцип: Ортогональность Kernel × Protocol

Ключевой инвариант кодовой базы `vpnctl`:
- **Protocol (Формат трафика и клиентский контракт)**: описывает то, как протокол кодируется в сетевом потоке, как формируется клиентский JSON/URI/QR и какие порты он занимает. Реализации `Protocol` строго **stateless** — они не знают, на каком сервере они работают, и не хранят ключи в своих структурах; все per-server секреты запрашиваются из `RenderCtx::secrets`.
- **Kernel (Серверный системный демон)**: управляет жизненным циклом серверного процесса на VPS через SSH (`ensure_installed`, `apply_config`, `open_firewall`, `restart`, `status`). Ядро принимает коллекцию инбаундов от включенных протоколов и преобразует их в нативный формат демона (JSON для sing-box, Caddyfile для Caddy, INI для AmneziaWG/WireGuard, config.json для Xray).
- **Связывание (Registry)**: добавление нового протокола или ядра требует создания ровно одного изолированного файла и добавления одной строки регистрации в `cli/src/registry.rs` и `daemon/src/app.rs`.

---

## 2. Крейт `vpnctl-protocols` (`crates/protocols`)

### 2.1 Матрица Протоколов
| Протокол | Модуль | Транспорт / Стек | Порт (дефолт) | DPI Risk | Генерация секретов (`ServerSecretSpec`) | Поддерживающие Ядра |
|---|---|---|---|---|---|---|
| **VLESS + REALITY** | `vless_reality.rs` | TCP / TLS Mimic (uTLS `randomized`, fallback SNI `yahoo.com`) | `tcp:443` (override через `vless.listen_port`) | `Low` | `X25519Keypair` (`vless.private_key`, `vless.public_key`), `ShortId` (`vless.short_id`) | `SingBox` |
| **VLESS + WebSocket** | `vless_ws.rs` | TCP / WS + TLS (Direct, Let's Encrypt через Caddy) | `tcp:8443` (секрет `vlessws.listen_port`) | `Low` | Нет (использует `vless.uuid` и Let's Encrypt) | `Caddy` |
| **VLESS + xHTTP** | `vless_xhttp.rs` | TCP / xHTTP + REALITY (streaming HTTP chunked) | `tcp:9443` | `Low` | `Password { key: "vlessxhttp.path", entropy_bytes: 16 }` | `Xray` |
| **TUIC v5** | `tuic_v5.rs` | UDP / QUIC (bbr congestion, self-signed cert) | `udp:8443` | `Moderate` | Нет (сертификат генерируется нодой в `/etc/sing-box/cert.pem`) | `SingBox` |
| **Hysteria 2** | `hysteria2.rs` | UDP / QUIC (brutal-cc, salamander obfs) | `udp:8444` | `Moderate` | `Password { key: "hysteria2.obfs_password", entropy_bytes: 16 }` | `SingBox` |
| **Shadowsocks 2022** | `shadowsocks2022.rs`| TCP/UDP / AEAD-2022 (`2022-blake3-aes-128-gcm`) | `tcp:8388` | `Moderate` | `Base64Key { key: "ss2022.psk", key_bytes: 16 }` | `SingBox` |
| **AnyTLS** | `anytls.rs` | TCP / TLS 1.3 Multiplexed Stream | `tcp:8843` | `Moderate` | Нет (переиспользует `tuic.cert_path` и `tuic_password`) | `SingBox` |
| **Trojan** | `trojan.rs` | TCP / TLS Mimic | `tcp:8643` | `Weak` | Нет (переиспользует `tuic.cert_path` и `tuic_password`) | `SingBox` |
| **Naive** | `naive.rs` | HTTP/2 CONNECT + Chromium mimic над Caddy + real cert | `tcp:443` | `Low` | Нет (требует `naive.domain`, сертификат ACME Let's Encrypt) | `Caddy` |
| **WireGuard** | `wireguard.rs` | UDP / Noise IK | `udp:51820` | `Weak` (чистый) / `Low` (Amnezia) | `WireguardKeypair` (`wireguard.server_private_key`, `wireguard.server_public_key`) | `AmneziaWg` |
| **AmneziaWG 2.0 / 3.1** | `amneziawg.rs` | UDP / Obfuscated Noise IK (AWG fork) | `udp:51821` (v2), `udp:51822` (v3) | `Low` | `WireguardKeypair`, `HeaderProtectionKey` | `AmneziaWg` |

### 2.2 Ключевые детали реализации протоколов
- **VLESS REALITY (`vless_reality.rs`)**:
  - `REALITY_UTLS_FP`: переключен на `"randomized"` (защита от TSPU блокировок Chrome-сигнатур).
  - `DEFAULT_REALITY_SNI`: дефолтный домен маскировки переключен на `"yahoo.com"` из-за несовместимости `microsoft.com` с профилями TLS handshake.
  - Поддерживает переопределение порта через `effective_listen_ports` (секрет `vless.listen_port`), позволяя сосуществовать с VLESS-WS или Naive.
- **WireGuard IP-Addressing (`wg_addressing.rs`)**:
  - Инвариант: детерминированное распределение IP-адресов `/32` из пула `10.66.0.0/24`. Адрес клиента рассчитывается как `10.66.0.<2 + index>`, где `index` — позиция пользователя в стабильно отсортированном списке `ctx.peers` (`ORDER BY id`).
  - Лимит пула: `MAX_HOST_OCTET = 254` (до 253 пользователей на сервер).
  - Защита от коллизий: если список `peers` не пуст, но текущий `user` в нем отсутствует, выбрасывается `CoreError::Render` (fail-closed на десинхронизации).
- **URL Encoding (`encoding.rs`)**:
  - Строгие наборы экранирования RFC 3986 для `USERINFO`, `FRAGMENT` и `VLESS_FRAGMENT` (экранирование `@`, `:`, `/`, `#`).

---

## 3. Крейт `vpnctl-kernels` (`crates/kernels`)

### 3.1 Реализации Ядер
- **`SingBox` (`sing_box.rs`)**:
  - Основное мультипротокольное ядро на VPS.
  - Поддерживает протоколы: `vless-reality`, `tuic-v5`, `hysteria2`, `shadowsocks-2022`, `anytls`, `trojan`.
  - Управление версиями (`SING_BOX_VPNCTL_VERSION = 1.13.12`):
    - Поддержка архитектур `x86_64` (amd64), `aarch64` (arm64), `armv7l`. Контрольные суммы SHA-256 жестко зафиксированы в коде (`scripts.rs`).
    - Установка через скрипт `setup.sh`: настройка официального APT репозитория SagerNet или ручная раскладка бинарника, создание `systemd` юнита `sing-box.service` с изоляцией `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
  - Валидация и безопасность (`guards.rs`):
    - `validate_config_excludes_ports`: перед применением проверяет, что генерируемый JSON не занимает защищенные порты (например, SSH 22, Caddy 80/443).
    - `user_uuid_diff`: вычисляет разницу между пользователями в живом конфиге и инвентаре для обнаружения дрифта.
    - Атомарное применение: конфиг заливается во временный файл, валидируется командой `sing-box check -c ...`, и только при успехе атомарно перемещается (`mv`) с рестартом демона.
- **`AmneziaWg` (`amnezia_wg.rs`)**:
  - Специализированное ядро для WireGuard с обфускацией.
  - Устанавливает DKMS модуль ядра (`amneziawg`) и утилиты `amneziawg-tools` (`awg`, `awg-quick`).
  - Преобразует JSON-инбаунд от `WireGuard` в файл конфигурации `/etc/amnezia/amneziawg/awg0.conf`.
  - Внедряет параметры обфускации из `RenderCtx::secrets`: `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4`.
  - Firewall: через `iptables`/`nftables` открывает UDP порт и настраивает NAT (`POSTROUTING -s 10.66.0.0/24 -o <wan> -j MASQUERADE`).
- **`Caddy` (`caddy.rs`)**:
  - Ядро с реальным веб-сервером маскировки для NaiveProxy и VLESS-WS.
  - Сборка на лету через `xcaddy`: компилирует Caddy с плагином `klzgrad/forwardproxy` на ноде.
  - Автоматический ACME (Let's Encrypt / ZeroSSL) на портах 80/443.
  - Архитектура VLESS-WS: Caddy терминирует внешний TLS на порту `8443`, отдает веб-заглушку на `/`, а секретный путь проксирует на локальный loopback-порт `127.0.0.1`, где поднят легковесный `sing-box` инбаунд.
- **`Xray` (`xray.rs`)**:
  - Ядро Xray-core (версия зафиксирована: `26.3.27`) для поддержки VLESS + REALITY + xHTTP.
  - Устанавливается скачиванием статически скомпилированного ZIP-архива с GitHub Releases в `/usr/local/bin/xray`.
  - Генерирует `/usr/local/etc/xray/config.json` и управляет юнитом `xray.service`.
