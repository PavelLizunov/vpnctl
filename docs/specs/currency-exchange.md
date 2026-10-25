# Spec: Multi-Currency Exchange, Dynamic Pricing & Financial Math

## 1. Intent & Invariants

- **What:** Database schema, domain models, and financial calculation
  architecture for multi-currency server billing — converting fleet costs to
  any operator-chosen display currency with configurable markup/fee
  coefficients, accurate historical spend tracking, and forward-looking burn
  rate projections.
- **Invariants:**
  - No hardcoded currencies or exchange rates — any ISO 4217 code accepted.
  - All monetary values stored as integer hundredths (amount × 100) for every
    currency, regardless of its ISO 4217 exponent, to eliminate floating-point
    precision loss.
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
| `amount_minor` | INTEGER | Source amount × 100 for every currency |
| `currency` | TEXT | Source ISO 4217 |
| `cycle` | TEXT | `monthly`/`quarterly`/`semi-annual`/`annual` |
| `converted_minor` | INTEGER | Snapshot of display-currency amount × 100 at payment time |
| `display_currency` | TEXT | Target ISO 4217 at time of payment |
| `rate_micros_used` | INTEGER | Audit: rate applied |
| `markup_bps_used` | INTEGER | Audit: markup applied |
| `notes` | TEXT | Optional |

### 2.2 Financial Precision

**Storage format:**
- Monetary amounts: integer hundredths for every currency, including JPY and
  KRW: 100 JPY is stored as `10000`, just as 100 EUR is stored as `10000`.
  The `_minor` and `_cents` field suffixes both use this fixed scale.
  There is no `minor_units` column or per-currency exponent handling.
  The opening comment in migration `0058_currency_exchange.sql` incorrectly
  describes direct unit storage for JPY/KRW and a `minor_units` column in
  `currency_settings`; its actual schema and implementation use the fixed
  hundredths scale documented here. The migration is left unchanged.
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

Intermediate arithmetic uses checked `i128` operations. The implemented rule in
`convert_minor` is `(wide + divisor / 2) / divisor`, using Rust integer division
(truncation toward zero). For nonnegative monetary amounts this is rounding to
nearest with ties up (half-up), not banker's rounding. This section owns the
financial rounding contract; `monthly_equivalent` uses the same add-half-then-divide
rule with the number of months as divisor.

**Edge cases:**
| Case | Behaviour |
|---|---|
| source == target | Identity: returns input unchanged, markup NOT applied |
| amount = 0 | Returns 0, no rate lookup needed |
| missing rate | Returns `None` — caller surfaces as "unconvertible" |
| rate ≤ 0 or markup ≤ 0 | Returns `None` (defensive rejection) |
| intermediate or result overflow | Returns `None`; never wraps the converted amount |

### 2.3 Spend vs Burn Rate

| Metric | Source | Mutability |
|---|---|---|
| **Total Spend** | `converted_minor` of snapshots matching the selected display currency; a payment made in that currency counts its own `amount_minor` | Immutable; never shifts with rate changes |
| **Monthly Burn** | Each server's `billing.amount_cents` normalised to monthly, converted at current rates + markup | Recalculated live from current rates |
| **Annual Burn** | `monthly_burn × 12` | Derived |

A payment made in the selected display currency counts at its paid amount
(no conversion is involved, so legacy rows without a snapshot stay exact).
Other payments without a non-null snapshot for that currency are excluded from
Total Spend (`ServerPayment::historical_spend_in` is the one rule). The web UI
marks the subtotal incomplete and lists the affected servers. Switching the
display currency selects its stored snapshots; it never converts older payments
at current rates. Both summary paths count all recorded payments independently
of snapshot availability.

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
- `list_currency_rates(&self) → Result<Vec<CurrencyRate>>`
- `get_rate(&self, base, target) → Result<Option<CurrencyRate>>` — checks overrides first

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
- **One-click refresh:** button calls `exchange_rate_poller::refresh_exchange_rates`,
  which stores each fetched pair with `upsert_currency_rate`.
- **Fee breakdown:** every converted amount shows source amount, rate, markup,
  and final amount.
- **Payment history:** per-server table of immutable payment records with
  original + converted amounts.
- **Incomplete Total Spend:** use the existing warning style when payments lack
  snapshots for the selected display currency; mark fleet and per-server spend
  subtotals incomplete without adding live estimates to historical totals.
- **Missing rates:** monthly and annual fleet totals are marked incomplete,
  with a warning listing the missing source currencies. Profit and cost
  coverage remain unavailable until every configured cost can be converted.

### 2.7 Implemented exchange-rate refresh

The running [exchange-rate poller](../../daemon/src/exchange_rate_poller.rs) is
spawned during daemon startup. When `auto_refresh = 1`, it first refreshes after
30 seconds and then every 12 hours. It fetches EUR-based pairs from Frankfurter,
falling back to open.er-api.com; each HTTP request has a 20-second timeout.
Failed refreshes preserve cached rates. Manual rate overrides in settings retain
precedence over fetched table rows. The web refresh button invokes the same
refresh function. This section owns the current ingestion contract;
[exchange-rate-ingestion.md](exchange-rate-ingestion.md) is a historical proposal.

## 3. Verification Checklist (Definition of Done)

- [x] Migration `0058_currency_exchange.sql` creates all three tables, FKs
      cascade on server delete, singleton row seeded.
- [x] `convert_minor()` pure function handles identity, zero, large amounts,
      and rejects invalid rates — 10 unit tests pass.
- [x] All monetary arithmetic uses integer hundredths with `i128`
      intermediates — no floating-point anywhere in the conversion path.
- [x] Same-currency conversions return identity (no markup applied).
- [x] `CurrencySettings` supports patch-semantics update with audit logging.
- [x] Rate overrides in settings take precedence over `currency_rates` table.
- [x] `FleetBillingSummary` separates historical Total Spend (immutable
      snapshots) from forward-looking Monthly/Annual Burn (live conversion).
- [x] `cargo check -p vpnctl-inventory` passes clean.
- [x] `cargo test -p vpnctl-inventory --lib "servers::currency"` — 10/10 pass.
- [ ] Web admin UI controls (future implementation per UI controls contract).
- [x] Daemon periodic rate fetch (when `auto_refresh = 1`, as specified in §2.7).
