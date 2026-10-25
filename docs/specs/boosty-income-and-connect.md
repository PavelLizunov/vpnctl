# Spec: Boosty Income, P&L Overview & 1-Click Quick Connect

## 1. Intent & Invariants
- What: Добавить финансовый учёт доходов с Boosty (MRR активных плательщиков, накопительный сбор блога), блок P&L с коэффициентом покрытия расходов на странице биллинга серверов, и надёжный 1-клик букмарклет для подключения Boosty без консоли разработчика (F12).
- Invariants:
  - Нулевое влияние на работу VPN-нод и трафик клиентов (чистый контур управления, Класс A).
  - Безопасность токенов: токены передаются через client-side hash fragment (`#quick_connect=...`), исключая утечку через URL в access-логи прокси или веб-сервера.
  - Защита от DOM-CSRF: скрипт-приёмник заполняет форму и выводит баннер предпросмотра с кнопкой «🔑 Подключить и синхронизировать»; сохранение и синк требуют явного подтверждения оператором.
  - Строгая валидация домена: букмарклет срабатывает только на `boosty.to` и `*.boosty.to`.
  - LocalStorage-First: букмарклет считывает активные токены (`auth`, `_clientId`) в первую очередь из `localStorage`, используя куки только как резерв.
  - Bearer-First аутентификация: при наличии `access_token` клиент обращается к API напрямую через Bearer-токен, избегая гонок и ошибок `invalid_grant` на эндпоинте `/oauth/token/`. Ротация через `refresh_token` вызывается только при необходимости продления (по 401).
  - Sync persists each rotated refresh token immediately after OAuth succeeds,
    before requesting subscribers, including during bearer recovery and dry-run.
    Persistence errors abort the pass. The roster uses the resulting bearer
    token so pagination cannot silently rotate credentials. A token rejected
    during that pass is retried by a subsequent sync.
  - Web/CLI settings saves preserve the stored refresh token unless the operator
    supplies a replacement. `set_boosty_settings` treats `refresh_token: None`
    as unchanged. Settings changes and successful refresh rotations are audited
    atomically without credential values; no-op writes add no audit entry.
  - Manual sync and Quick Connect keep sync, report handling, alert acknowledgement,
    and redeploy queuing in one task that survives cancellation of the HTTP request.
  - Reconcile enables/disables a user only if the same Boosty subscriber link and
    the expected opposite disabled state still match. The conditional update and
    its audit row commit in one transaction. Stale decisions add neither an audit
    row nor an enabled/disabled report entry or redeploy request.
  - Резервный спойлер: ручная форма настройки токенов скрыта под спойлером (`details.ed-spoiler`), основным интерфейсом остаётся 1-Click подключение.
  - Все финансовые расчёты производятся в целочисленных копейках/центах (`i64` minor units) с банковским округлением через валютный движок ЦБ; никаких `f64` в балансе.

## 2. Interface / Data Contract
- Bridge API (`vpnctl-boosty-bridge`):
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
  pub struct BoostyIncomeSummary {
      pub active_payers: usize,
      pub mrr_rub_cents: i64,
      pub total_revenue_rub_cents: i64,
  }

  impl SyncReport {
      pub fn income_summary(&self) -> BoostyIncomeSummary;
  }

  pub async fn build_client(settings: &BoostySettings, base_url: &str) -> Result<ApiClient, BridgeError>;
  pub async fn build_bearer_client(access_token: &str, base_url: &str) -> Result<ApiClient, BridgeError>;
  pub async fn build_refresh_client(refresh_token: &str, device_id: &str, base_url: &str) -> Result<ApiClient, BridgeError>;
  ```
- Inventory API: `set_boosty_user_disabled(&self, user: &UserId, subscriber_id: i64,
  disabled: bool) -> Result<bool>` returns whether the conditional update committed;
  missing, unlinked, relinked, or already-matching users return `false`.
- Web Surfaces:
  - `/admin/boosty`:
    - Статус-полоса доходов: `доход в месяц (MRR)`, `всего собрано (To Date)`, `плательщиков / всего`.
    - Карточка «1-Click Quick Connect»: перетаскиваемая ссылка-букмарклет (`javascript:...`) и кнопка копирования скрипта в буфер.
    - Баннер приёма `#quick_connect` с кнопкой «🔑 Подключить и синхронизировать» (`quick_sync_now=1`), сохраняющей настройки, включающей опрос и запускающей немедленный синк.
    - Спойлер «Резервный способ — ручная настройка и параметры» (`details.ed-spoiler`) с техническими полями.
  - `/admin/servers/billing`:
    - Секция «Финансовый баланс и окупаемость (P&L)»:
      - Карточка 1: Доход Boosty (MRR в валюте сводки с числом плательщиков).
      - Карточка 2: Расходы на серверы (месячные затраты парка).
      - Карточка 3: Чистая прибыль (Net Margin P&L) и коэффициент покрытия расходов (`покрытие расходов: X% (Y×)`).

## 3. Verification Checklist (Definition of Done)
- [ ] Cancelling a manual sync after a user flip still acknowledges sync-failure
  alerts and queues redeploy for that user.
- [ ] Unlinking/relinking between reconcile and apply skips the stale status change
  without an audit or report entry; audit insertion failure rolls back the update.
- [ ] Метод `SyncReport::income_summary()` корректно вычисляет MRR и total revenue, фильтруя неактивных и бесплатных подписчиков.
- [ ] Букмарклет считывает токены из `localStorage` (с fallback на cookies) и не требует консоли разработчика (F12).
- [ ] При наличии `access_token` клиент авторизуется без ошибки `invalid_grant`, а при 401 восстанавливает сессию через `refresh_token`.
- [ ] Ручная форма ввода скрыта под закрытым спойлером, не загромождая основной интерфейс.
- [ ] Нажатие «Подключить и синхронизировать» активирует мост и сразу запускает первоначальный синк.
- [ ] На `/admin/servers/billing` доход Boosty конвертируется по курсам ЦБ в валюту сводки и корректно рассчитывается ежемесячная чистая прибыль и коэффициент покрытия.
- [ ] Пройдены smoke-тесты (`settings_integrations.rs`, `servers.rs`) и проверки GitHub Actions CI.
