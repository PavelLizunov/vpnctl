# Spec: Учёт аренды серверов и адаптивный интерфейс

## 1. Intent & Invariants
- Что: Добавить страницу учёта оплаты арендованных серверов (`/admin/servers/billing`) с отслеживанием дат, стоимости, ссылками на хостеров и кнопкой продления; устранить разрыв верстки на мобильных устройствах и перевести навигацию на русский язык.
- Инварианты:
  - Нулевое влияние на работу VPN-нод и трафик клиентов (чистый контур управления, Класс A).
  - Права на статические файлы ассетов всегда гарантируют чтение непривилегированным процессом (`0644`/`0755`).
  - Данные об оплате хранятся в отдельной таблице `server_billing` с каскадным удалением при удалении сервера.

## 2. Interface / Data Contract
- База данных: миграция `0057_server_billing.sql`:
  - `server_id` (PK, REFERENCES servers(id) ON DELETE CASCADE)
  - `due_date` (TEXT, YYYY-MM-DD)
  - `billing_cycle` (TEXT: monthly, quarterly, semi-annual, annual)
  - `amount_cents` (INTEGER)
  - `currency` (TEXT: EUR, USD, RUB, CHF)
  - `auto_renew` (INTEGER 0/1)
  - `billing_url` (TEXT optional)
  - `notes` (TEXT optional)
- Inventory API (`SqliteInventory`):
  - `get_server_billing(&self, sid: &ServerId) -> Result<Option<ServerBilling>>`
  - `list_fleet_billing(&self) -> Result<Vec<ServerBillingItem>>`
  - `set_server_billing(&self, sid: &ServerId, billing: &ServerBillingInput) -> Result<()>`
  - `advance_server_billing_cycle(&self, sid: &ServerId) -> Result<()>`
- Web:
  - Маршруты `GET /admin/servers/billing`, `POST /admin/servers/{id}/billing`, `POST /admin/servers/{id}/billing/advance`.
  - Мобильная адаптивность: контейнеры с `overflow-x: auto` для таблиц, блочные чипы счетчиков на дашборде.
  - Локализация: полноценный перевод верхней навигации при выборе языка `RU`.

## 3. Verification Checklist (Definition of Done)
- [ ] Таблица `server_billing` создаётся, каскадно очищается при удалении сервера, данные сохраняются и читаются без потерь.
- [ ] На странице `/admin/servers/billing` отображаются сводка расходов по валютам, ближайшие даты платежей и статусы (норма / предупреждение / просрочка).
- [ ] Кнопка «Продлить» сдвигает дату на один период вперёд и фиксирует действие в аудите.
- [ ] На главной странице таблица серверов не ломает экран на мобильных устройствах; верхнее меню переведено на русский в локали RU.
- [ ] Пройдены независимое diff-ревью, gitleaks, `cargo check`, `cargo deny` и тесты в GitHub Actions CI.
