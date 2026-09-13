# Spec: Boosty Income, P&L Overview & 1-Click Quick Connect

## 1. Intent & Invariants
- What: Добавить финансовый учёт доходов с Boosty (MRR активных плательщиков, накопительный сбор блога), блок P&L с коэффициентом покрытия расходов на странице биллинга серверов, и 1-клик букмарклет для подключения Boosty без консоли разработчика (F12).
- Invariants:
  - Нулевое влияние на работу VPN-нод и трафик клиентов (чистый контур управления, Класс A).
  - Безопасность токенов: токены передаются через client-side hash fragment (`#quick_connect=...`), исключая утечку через URL в access-логи прокси или веб-сервера.
  - Защита от DOM-CSRF: скрипт-приёмник только заполняет форму и выводит баннер предпросмотра; сохранение требует явного подтверждения оператором (кнопка «Сохранить»).
  - Строгая валидация домена: букмарклет срабатывает только на `boosty.to` и `*.boosty.to`.
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
  ```
- Web Surfaces:
  - `/admin/boosty`:
    - Статус-полоса доходов: `доход в месяц (MRR)`, `всего собрано (To Date)`, `плательщиков / всего`.
    - Карточка «1-Click Quick Connect»: перетаскиваемая ссылка-букмарклет (`javascript:...`) и кнопка копирования скрипта в буфер.
    - Скрипт-приёмник `#quick_connect` с выводом баннера импорта учетных данных.
  - `/admin/servers/billing`:
    - Секция «Финансовый баланс и окупаемость (P&L)»:
      - Карточка 1: Доход Boosty (MRR в валюте сводки с числом плательщиков).
      - Карточка 2: Расходы на серверы (месячные затраты парка).
      - Карточка 3: Чистая прибыль (Net Margin P&L) и коэффициент покрытия расходов (`покрытие расходов: X% (Y×)`).

## 3. Verification Checklist (Definition of Done)
- [ ] Метод `SyncReport::income_summary()` корректно вычисляет MRR и total revenue, фильтруя неактивных и бесплатных подписчиков.
- [ ] На `/admin/boosty` отображаются карточка 1-Click подключения и статус-полоса доходов.
- [ ] На `/admin/servers/billing` доход Boosty конвертируется по курсам ЦБ в валюту сводки и корректно рассчитывается ежемесячная чистая прибыль и коэффициент покрытия.
- [ ] Букмарклет валидирует домен Boosty, а приёмник не выполняет автоматическую отправку формы (защита от DOM-CSRF).
- [ ] Пройдены smoke-тесты (`settings_integrations.rs`, `servers.rs`) и проверки GitHub Actions CI.
