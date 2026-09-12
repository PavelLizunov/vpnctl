# Spec: Multi-Currency Exchange, Dynamic Pricing & Financial Math

## 1. Intent & Invariants

- **What:** Database schema, domain models, and financial calculation
  architecture for multi-currency server billing — converting fleet costs to
  any operator-chosen display currency with configurable markup/fee
  coefficients, accurate historical spend tracking, and forward-looking burn
  rate projections.
- **Invariants:**
  - No hardcoded currencies or exchange rates — any ISO 4217 code accepted.
  - All monetary values stored as integer minor-units (cents/kopecks) to
    eliminate floating-point precision loss.
  - Exchange rates stored as integer micros (6 implicit decimal places);
    markup coefficients as integer basis points (4 implicit decimal places).
  - `i128` intermediate arithmetic prevents overflow for large amounts.
  - Historical "Total Spend" is immutable — payment snapshots record the
    converted value at payment time, never re-converted when rates change.
  - Same-currency conversions never apply markup (identity conversion).
  - Every settings mutation writes an `audit_log` row.
  - Zero impact on VPN node operation (pure management-plane, Class A).

## 2. Interface / Data Contract

### 2.1 Database Schema (migration `0058_currency_exchange.sql`)

**`currency_rates`** — exchange rate pairs:
| Column | Type | Notes |
|---|---|---|
| `base_currency` | TEXT PK | ISO 4217 (e.g. `'USD'`) |
| `target_currency` | TEXT PK | ISO 4217 (e.g. `'RUB'`) |
| `rate_micros` | INTEGER | Rate × 10⁶ (e.g. 89.5 → `89_500_000`), CHECK > 0 |
| `source` | TEXT | `'manual'`, `'ecb'`, `'cbr'`, etc. |
| `fetched_at` | TEXT | ISO-8601 UTC |

**`currency_settings`** — operator preferences (singleton, id=1):
| Column | Type | Default | Notes |
|---|---|---|---|
| `display_currency` | TEXT | `'EUR'` | Target for fleet summaries |
| `default_markup_bps` | INTEGER | `10700` | 1.07 = 7% fee, × 10⁴ |
| `markup_overrides_json` | TEXT | NULL | `{"RUB": 10700, "TRY": 11500}` |
| `rate_overrides_json` | TEXT | NULL | `{"USD/RUB": 89123456}` — precedence over rates table |
| `auto_refresh` | INTEGER | `0` | 0/1 daemon periodic fetch |

**`server_payments`** — immutable payment history:
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `server_id` | TEXT FK | → `servers(id)` ON DELETE CASCADE |
| `paid_at` | TEXT | ISO-8601 UTC, defaults to now |
| `amount_minor` | INTEGER | Source amount in minor units |
| `currency` | TEXT | Source ISO 4217 |
| `cycle` | TEXT | `monthly`/`quarterly`/`semi-annual`/`annual` |
| `converted_minor` | INTEGER | Snapshot of display-currency value at payment time |
| `display_currency` | TEXT | Target ISO 4217 at time of payment |
| `rate_micros_used` | INTEGER | Audit: rate applied |
| `markup_bps_used` | INTEGER | Audit: markup applied |
| `notes` | TEXT | Optional |

### 2.2 Financial Precision

**Storage format:**
- Monetary amounts: integer minor-units (cents, kopecks). Currencies with
  0 decimal places (JPY, KRW) store unit values directly.
- Exchange rates: `rate_micros` = rate × 1 000 000 (6 decimal precision).
- Markup coefficients: `markup_bps` = coefficient × 10 000 (basis-point
  precision). 1.07 → `10700`. 1.00 (no markup) → `10000`.

**Conversion formula:**
```
target_minor = source_minor × rate_micros × markup_bps
               ÷ (RATE_SCALE × MARKUP_SCALE)

where RATE_SCALE  = 1_000_000
      MARKUP_SCALE = 10_000
```

Intermediate arithmetic uses `i128` to prevent overflow. Result is rounded
to nearest (half-up).

**Edge cases:**
| Case | Behaviour |
|---|---|
| source == target | Identity: returns input unchanged, markup NOT applied |
| amount = 0 | Returns 0, no rate lookup needed |
| missing rate | Returns `None` — caller surfaces as "unconvertible" |
| rate ≤ 0 or markup ≤ 0 | Returns `None` (defensive rejection) |

### 2.3 Spend vs Burn Rate

| Metric | Source | Mutability |
|---|---|---|
| **Total Spend** | `SUM(server_payments.converted_minor)` — actual payments made | Immutable snapshots; never shifts with rate changes |
| **Monthly Burn** | Each server's `billing.amount_cents` normalised to monthly, converted at current rates + markup | Recalculated live from current rates |
| **Annual Burn** | `monthly_burn × 12` | Derived |

### 2.4 Rust Domain Models (`crates/inventory/src/sqlite/models.rs`)

```rust
CurrencyRate        // One exchange rate pair
CurrencySettings    // Operator preferences (display currency, markup, overrides)
CurrencySettingsInput  // Patch-semantics update payload
ServerPayment       // Immutable payment record with conversion snapshot
ServerPaymentInput  // New payment input
ConversionResult    // Result of convert_amount()
FleetBillingSummary // Fleet-wide totals + per-server breakdown
ServerBillingSummaryItem  // Per-server line in summary
```

### 2.5 Inventory API (`SqliteInventory` methods)

**Currency rates:**
- `upsert_currency_rate(&self, rate: &CurrencyRate) → Result<()>`
- `upsert_currency_rates(&self, rates: &[CurrencyRate]) → Result<()>` — bulk, single tx
- `list_currency_rates(&self) → Result<Vec<CurrencyRate>>`
- `get_rate(&self, base, target) → Result<Option<CurrencyRate>>` — checks overrides first
- `delete_currency_rate(&self, base, target) → Result<bool>`

**Settings:**
- `get_currency_settings(&self) → Result<CurrencySettings>`
- `set_currency_settings(&self, input: &CurrencySettingsInput) → Result<CurrencySettings>` — patch semantics, audit-logged

**Conversion engine:**
- `convert_amount(&self, amount_minor, source_currency, target_currency) → Result<Option<ConversionResult>>`

**Payment history:**
- `record_server_payment(&self, sid, input: &ServerPaymentInput) → Result<ServerPayment>` — snapshots conversion, audit-logged
- `list_server_payments(&self, sid) → Result<Vec<ServerPayment>>`
- `server_total_spend(&self, sid, display_currency) → Result<i64>`

**Fleet summary:**
- `get_fleet_billing_summary(&self) → Result<FleetBillingSummary>`

**Pure functions (no DB):**
- `convert_minor(source_minor, rate_micros, markup_bps) → Option<i64>`
- `monthly_equivalent(amount_minor, cycle: BillingCycle) → i64`

### 2.6 UI Controls Contract (for web admin implementation)

- **Currency dropdown:** select display currency → calls `set_currency_settings`.
- **Inline rate override:** per-pair text input → populates `rate_overrides_json`.
- **Markup coefficient:** global default + per-currency overrides visible as
  `"100 ₽ base + 7% fee = 107 ₽"` transparent breakdown.
- **One-click refresh:** button to trigger rate fetch → calls `upsert_currency_rates`.
- **Fee breakdown:** every converted amount shows source amount, rate, markup,
  and final amount.
- **Payment history:** per-server table of immutable payment records with
  original + converted amounts.

## 3. Verification Checklist (Definition of Done)

- [x] Migration `0058_currency_exchange.sql` creates all three tables, FKs
      cascade on server delete, singleton row seeded.
- [x] `convert_minor()` pure function handles identity, zero, large amounts,
      and rejects invalid rates — 10 unit tests pass.
- [x] All monetary arithmetic uses integer minor-units with `i128`
      intermediates — no floating-point anywhere in the conversion path.
- [x] Same-currency conversions return identity (no markup applied).
- [x] `CurrencySettings` supports patch-semantics update with audit logging.
- [x] Rate overrides in settings take precedence over `currency_rates` table.
- [x] `FleetBillingSummary` separates historical Total Spend (immutable
      snapshots) from forward-looking Monthly/Annual Burn (live conversion).
- [x] `cargo check -p vpnctl-inventory` passes clean.
- [x] `cargo test -p vpnctl-inventory --lib "servers::currency"` — 10/10 pass.
- [ ] Web admin UI controls (future implementation per UI controls contract).
- [ ] Daemon periodic rate fetch (when `auto_refresh = 1`, future task).
