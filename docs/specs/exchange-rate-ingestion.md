# Spec: Resilient, Zero-Hardcode Exchange Rate Ingestion

**Status:** Design specification (pre-implementation)
**Author:** Agent (research assignment)
**Date:** 2026-09-12

---

## 0. Problem Statement

The billing page (`/admin/servers/billing`) currently hardcodes a fixed
currency dropdown (`EUR`, `USD`, `RUB`, `CHF`) and displays per-currency
monthly burn totals without any cross-currency normalization. The operator
cannot see a unified cost view when servers are billed in different
currencies. Exchange rates must be fetched live, cached resiliently, and
**never** block, hang, or fail the admin UI if the upstream API or network
is unavailable.

### Non-goals (explicit)

- Multi-tenancy, RBAC, or per-user currency preferences.
- Real-time (<1 min) tick-by-tick forex data.
- Paid API keys or OAuth-gated providers.
- Expanding the billing data model itself (schema, cycles, audit) — that
  already ships in migration `0057`.

---

## 1. Crate Evaluation: `iso_currency` vs Zero-Dependency Custom Parser

### 1.1 `iso_currency` (v0.5.3)

| Aspect | Assessment |
|---|---|
| License | MIT — allowed by `deny.toml` |
| Transitive deps | `iso_country` (MIT, no native code), optional `strum`, `serde`, `sqlx`, `schemars` |
| Native code | None — pure Rust |
| `deny.toml` safety | ✅ No banned crates (`openssl`, `native-tls`). All licenses in the allow-list. |
| What it provides | `Currency` enum with ISO 4217 code ↔ numeric code, symbol (`€`, `$`, `₽`), English name, territory list |
| Build deps | `proc-macro2` + `quote` (code generation at build time for the enum) |
| Binary size | ~40 KB (the full 300-currency enum + territory data) |

**Verdict: useful but not necessary for this feature.** The billing page
needs symbol rendering (`format_amount`) and rate-lookup keyed by
3-letter code string. The existing `fn format_amount(cents, currency) →
String` already handles the 4 symbols inline. Adding `iso_currency` for
a lookup table that returns `€`/`$`/`₽` is over-engineering for a
single-operator homelab tool.

### 1.2 Recommended: Custom ~50-line parser using existing deps

vpnctl already depends on `reqwest` (via `boosty-bridge`, rustls),
`serde`/`serde_json`, `chrono`, and `tokio`. The exchange rate ingestion
needs:

1. **One HTTP GET** → JSON body → `serde_json::from_str`.
2. **One SQLite UPSERT** per currency pair.
3. **One background `tokio::spawn`** on a timer.

No new crate dependencies are required. The parser is a `HashMap<String,
f64>` deserializer with 3 struct definitions. This is strictly superior
for:

- **Dependency hygiene**: zero new entries in `Cargo.lock`.
- **`deny.toml` safety**: no new license surface to audit.
- **Binary size**: no 300-currency enum when we need ≤10 rates.
- **Maintainability**: the operator controls the provider URL; the code
  is trivially readable.

**Decision: zero new crate dependencies. Use `reqwest` + `serde_json`
directly in the `daemon` crate (add `reqwest` as a direct daemon dep
with `rustls` — feature-unifies with boosty-bridge's existing dep).**

---

## 2. Provider Comparison & Recommendation

### 2.1 Provider Matrix

| Provider | URL | Key? | Base | Currencies | RUB? | Format | Update freq | Uptime risk |
|---|---|---|---|---|---|---|---|---|
| **ECB daily XML** | `https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml` | No | EUR | ~30 | ❌ Suspended since 2022-03-01 | XML | Daily ~14:10 CET | Low (institutional) |
| **ECB Data API** | `https://data-api.ecb.europa.eu/service/data/EXR/...` | No | EUR | ~30 | ❌ | SDMX-XML/CSV | Daily | Low |
| **CBR-XML-Daily** | `https://www.cbr-xml-daily.ru/daily_json.js` | No | RUB | ~40 | ✅ (base) | JSON | Daily ~11:30 MSK | Medium (community mirror, DDoS history, `Content-Type: application/javascript`) |
| **Frankfurter v2** | `https://api.frankfurter.dev/v2/rates` | No | Any | 205 (98 sources) | ✅ | JSON array | Daily | Medium (open-source project, free tier) |
| **Open ER-API** | `https://open.er-api.com/v6/latest/{BASE}` | No | Any | 161 | ✅ | JSON object | Daily | Medium (free tier of exchangerate-api.com) |
| **FloatRates** | `https://www.floatrates.com/daily/eur.json` | No | Any | ~150 | ✅ | JSON | Daily | Medium |

### 2.2 Critical finding: ECB does NOT publish EUR/RUB

> *"The ECB last published a EUR/RUB reference rate on 1 March 2022."*
> — [ECB reference rates page](https://www.ecb.europa.eu/stats/policy_and_exchange_rates/euro_reference_exchange_rates/html/index.en.html)

Since vpnctl servers are commonly billed in RUB, ECB alone is
**insufficient**. ECB XML also requires an XML parser dependency (or
manual string splitting of a well-known format) — more complexity than
JSON.

### 2.3 Recommended strategy: Frankfurter (primary) + Open ER-API (fallback)

**Primary: [Frankfurter v2](https://frankfurter.dev/)**
- Covers 205 currencies including RUB, aggregated from 98 central banks.
- Clean JSON array response, trivial to deserialize.
- No API key, no account. Open-source (self-hostable as ultimate fallback).
- Tested live (2026-09-12): returns `EUR/RUB 98.07`, `EUR/USD 1.1618`.
- Explicit `base` and `quotes` params keep responses small.

```
GET https://api.frankfurter.dev/v2/rates?base=EUR&quotes=USD,RUB,CHF,GBP,SEK
→ [{"date":"2026-09-13","base":"EUR","quote":"CHF","rate":0.94385}, ...]
```

**Fallback: [Open ER-API](https://open.er-api.com/v6/latest/EUR)**
- 161 currencies, no key, flat JSON object with `rates` map.
- Returns explicit `time_next_update_unix` — useful for smart TTL.
- Different infrastructure from Frankfurter → true diversity.

```
GET https://open.er-api.com/v6/latest/EUR
→ {"result":"success","base_code":"EUR","rates":{"USD":1.160069,"RUB":97.694,...}}
```

**Why not CBR-XML-Daily?**
- `Content-Type: application/javascript` (not `application/json`) — `reqwest`'s
  `.json()` may reject depending on strict mode; needs `.text()` + manual parse.
- RUB-denominated (inverted from the EUR base the billing page uses).
- Community-run mirror with documented DDoS history and rate limits.
- Acceptable as a user-configurable third option but not recommended as a default.

### 2.4 Provider configuration

The provider URL is **not hardcoded** — it's stored in the `settings`
table (or a dedicated `exchange_rate_config` table) so the operator can
change it from `/admin/settings` without recompiling. The daemon ships
with two built-in presets (Frankfurter, Open ER-API) and accepts any
custom URL returning a compatible JSON shape.

---

## 3. Architecture: Ingestion & Caching Lifecycle

### 3.1 Data flow diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DAEMON STARTUP                              │
│                                                                    │
│  build() ──► spawn_exchange_rate_poller(inv, http_client)          │
│                     │                                              │
│                     ▼                                              │
│              ┌─────────────┐                                       │
│              │  Timer loop │  (tick = VPNCTLD_FX_INTERVAL_SECS     │
│              │  12h default)│   env override, min 3600)            │
│              └──────┬──────┘                                       │
│                     │                                              │
│         ┌───────────▼────────────┐                                 │
│         │ fetch_rates(primary)   │ GET Frankfurter                 │
│         │    reqwest + timeout   │ connect 10s, total 30s          │
│         └───────────┬────────────┘                                 │
│                     │                                              │
│              success?                                              │
│             ╱       ╲                                              │
│           yes        no ──► fetch_rates(fallback)                  │
│            │                GET Open ER-API                        │
│            │                     │                                 │
│            │              success?                                 │
│            │             ╱       ╲                                  │
│            │           yes        no ──► log::warn, keep stale     │
│            │            │                cache, continue loop       │
│            ▼            ▼                                          │
│    ┌────────────────────────────┐                                  │
│    │  normalize_to_base("EUR") │  All rates stored as              │
│    │  + validate (rate > 0,    │  EUR-denominated for              │
│    │    finite, not NaN)       │  consistency with billing         │
│    └────────────┬───────────────┘                                  │
│                 │                                                  │
│                 ▼                                                  │
│    ┌────────────────────────────┐                                  │
│    │  UPSERT exchange_rates    │  SQLite: one row per currency     │
│    │  SET rate=?, updated_at=? │  pair (base always EUR)           │
│    │  Atomic: all-or-nothing   │                                   │
│    └────────────┬───────────────┘                                  │
│                 │                                                  │
│                 ▼                                                  │
│         audit("system",                                            │
│           "exchange_rates.refresh",                                │
│           payload: {source, count, stale: false})                  │
│                                                                    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      ADMIN UI READ PATH                            │
│                                                                    │
│  GET /admin/servers/billing                                        │
│         │                                                          │
│         ▼                                                          │
│  inv.get_exchange_rates()                                          │
│  → Vec<ExchangeRate>   (SQLite read, <1ms)                         │
│         │                                                          │
│         ▼                                                          │
│  convert_to_anchor(amount_cents, currency, rates, anchor="EUR")    │
│  → Option<i64>   (None if rate missing — display "?" not panic)    │
│         │                                                          │
│         ▼                                                          │
│  Render: per-currency subtotals + unified "≈ X.XX €" column       │
│  + "Rates as of YYYY-MM-DD HH:MM" footer                          │
│  + staleness badge if updated_at > 48h ago                         │
│                                                                    │
│  *** NEVER blocks, NEVER errors, NEVER panics ***                  │
│  Missing rates → show "—" or "?" → operator can set manual rates   │
│                                                                    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    MANUAL REFRESH BUTTON                           │
│                                                                    │
│  POST /admin/settings/exchange-rates/refresh                       │
│         │                                                          │
│         ▼                                                          │
│  Trigger one-shot fetch (same fetch_and_store logic)               │
│  → redirect back to billing page with flash                        │
│                                                                    │
│  Also: POST /admin/settings/exchange-rates                         │
│  → operator manually sets a rate (manual override flag = true)     │
│  → manual rates are NEVER overwritten by the poller                │
│                                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Offline fallback contract (priority order)

1. **Fresh cache** (updated_at < 48h) → use as-is, show date.
2. **Stale cache** (updated_at ≥ 48h) → use as-is, show staleness
   warning badge ("Rates from 3 days ago — may be inaccurate").
3. **Manual override** → operator-entered rate in `exchange_rates` with
   `source = 'manual'`; **never** overwritten by the poller.
4. **No rate at all** → display amounts in their original currency only;
   the unified total column shows "?" or "—". The page renders without
   error.
5. **Default anchor** → EUR is the base (most billing is EUR); if the
   operator's billing is entirely in one currency, no conversion needed.

### 3.3 Failure isolation guarantees

| Failure mode | Behavior |
|---|---|
| Primary API returns non-200 | Log warn, try fallback |
| Fallback API returns non-200 | Log warn, keep existing cache, schedule retry next tick |
| Both APIs timeout (30s each) | Same as above — existing cache survives |
| Response JSON is malformed | Log warn with truncated body, keep cache |
| Response contains `rate: 0` or `NaN` | Skip that currency pair, log warn |
| SQLite write fails | Log warn, cache in-memory for this tick, retry next |
| DNS resolution fails (sandboxed daemon) | Caught by reqwest timeout, same as API timeout |
| No network at all (first boot, no cache) | Page renders with "—" for converted amounts |

**Critical invariant:** The exchange rate poller is fire-and-forget. A
panicking poller task must not take down the daemon. The `tokio::spawn`
boundary + `catch_unwind` (if paranoid) ensures this. The admin UI read
path is a pure SQLite query — it cannot fail in a way that blocks page
rendering.

---

## 4. Data Contract: SQLite Schema

Migration `0058_exchange_rates.sql`:

```sql
-- Exchange rate cache for cross-currency billing normalization.
-- Base is always EUR (matches the billing page's primary currency).
-- The poller UPSERTs on refresh; manual overrides set source='manual'
-- and are never overwritten by the poller.
CREATE TABLE IF NOT EXISTS exchange_rates (
    quote_currency TEXT NOT NULL PRIMARY KEY,   -- e.g. 'USD', 'RUB', 'CHF'
    rate           REAL NOT NULL,               -- 1 EUR = ? quote_currency
    source         TEXT NOT NULL DEFAULT 'auto', -- 'auto' | 'manual'
    provider       TEXT NOT NULL DEFAULT '',     -- 'frankfurter' | 'open-er-api' | 'manual'
    fetched_at     TEXT NOT NULL,               -- ISO 8601 UTC timestamp of the upstream data
    updated_at     TEXT NOT NULL                -- ISO 8601 UTC timestamp of the local write
);

-- No separate base_currency column: base is always EUR by convention.
-- Cross-currency conversion (e.g. USD→CHF) goes through EUR:
--   amount_in_eur = amount_usd / rate_usd
--   amount_in_chf = amount_in_eur * rate_chf
```

### Why `REAL` not `INTEGER` for rate?

Exchange rates are inherently floating-point (1 EUR = 97.694297 RUB).
Integer encoding (e.g. rate × 10^6) adds complexity without meaningful
precision benefit for an advisory display — this is not an accounting
ledger, it's a "≈ €X.XX" hint for the operator. SQLite's REAL is IEEE
754 double — more than sufficient.

---

## 5. Type Definitions (Rust)

```rust
// ── daemon/src/exchange_rates.rs ──

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// A cached exchange rate row from SQLite.
#[derive(Debug, Clone)]
pub struct ExchangeRate {
    pub quote_currency: String,  // "USD", "RUB", etc.
    pub rate: f64,               // 1 EUR = rate units of quote_currency
    pub source: RateSource,
    pub provider: String,
    pub fetched_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateSource {
    Auto,
    Manual,
}

/// Frankfurter v2 response: array of rate objects.
/// GET /v2/rates?base=EUR&quotes=USD,RUB,CHF,...
#[derive(Debug, Deserialize)]
pub struct FrankfurterRate {
    pub date: String,
    pub base: String,
    pub quote: String,
    pub rate: f64,
}

/// Open ER-API response: flat object with rates map.
/// GET /v6/latest/EUR
#[derive(Debug, Deserialize)]
pub struct OpenErApiResponse {
    pub result: String,         // "success"
    pub base_code: String,      // "EUR"
    pub rates: HashMap<String, f64>,
    pub time_last_update_utc: Option<String>,
}

/// Configuration for the exchange rate poller.
#[derive(Debug, Clone)]
pub struct ExchangeRateConfig {
    /// Primary provider URL. Default: Frankfurter.
    pub primary_url: String,
    /// Fallback provider URL. Default: Open ER-API.
    pub fallback_url: String,
    /// Which currencies to fetch (empty = all available).
    /// Populated from the currencies actually used in server_billing.
    pub quotes: Vec<String>,
    /// Polling interval. Default: 12 hours. Min: 1 hour.
    pub interval: Duration,
    /// HTTP request timeout per provider. Default: 30 seconds.
    pub request_timeout: Duration,
}

impl Default for ExchangeRateConfig {
    fn default() -> Self {
        Self {
            primary_url: "https://api.frankfurter.dev/v2/rates".into(),
            fallback_url: "https://open.er-api.com/v6/latest/EUR".into(),
            quotes: vec![],  // auto-detect from billing table
            interval: Duration::from_secs(12 * 3600),
            request_timeout: Duration::from_secs(30),
        }
    }
}
```

### 5.1 Inventory API additions (`SqliteInventory`)

```rust
// ── crates/inventory/src/sqlite/exchange_rates.rs ──

impl SqliteInventory {
    /// Read all cached exchange rates. Pure read, cannot fail the UI.
    pub async fn get_exchange_rates(&self) -> Result<Vec<ExchangeRate>>;

    /// Get a single rate. Returns None if not cached.
    pub async fn get_exchange_rate(&self, quote: &str) -> Result<Option<ExchangeRate>>;

    /// Upsert auto-fetched rates. Skips rows where source='manual'.
    pub async fn upsert_auto_rates(&self, rates: &[(String, f64, &str, &str)]) -> Result<usize>;

    /// Set a manual rate override (immune to auto-refresh).
    pub async fn set_manual_rate(&self, quote: &str, rate: f64) -> Result<()>;

    /// Clear a manual override (reverts to auto on next refresh).
    pub async fn clear_manual_rate(&self, quote: &str) -> Result<()>;

    /// List distinct currencies used in server_billing (for auto-detecting
    /// which quotes to fetch — zero hardcoded currency lists).
    pub async fn billing_currencies_in_use(&self) -> Result<Vec<String>>;
}
```

### 5.2 Conversion helper (daemon-side, pure function)

```rust
/// Convert an amount from one currency to EUR using cached rates.
/// Returns None if the rate is missing — caller renders "?" / "—".
pub fn convert_to_eur(amount_cents: i64, currency: &str, rates: &[ExchangeRate]) -> Option<i64> {
    if currency == "EUR" {
        return Some(amount_cents);
    }
    let rate = rates.iter().find(|r| r.quote_currency == currency)?;
    if rate.rate <= 0.0 || !rate.rate.is_finite() {
        return None;
    }
    // amount_in_eur = amount_in_currency / rate
    // (rate = "1 EUR = X currency" → divide to get EUR)
    Some((amount_cents as f64 / rate.rate).round() as i64)
}
```

---

## 6. Poller Implementation Sketch

```rust
// ── daemon/src/exchange_rates.rs (continued) ──

/// Spawn the exchange-rate refresh poller. Same pattern as
/// `spawn_retention_purger` / `spawn_digest_scheduler`.
pub fn spawn_exchange_rate_poller(
    inv: SqliteInventory,
    config: ExchangeRateConfig,
) -> tokio::task::JoinHandle<()> {
    let client = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent("vpnctld/0.9 (homelab; +https://github.com/PavelLizunov/vpnctl)")
        .build()
        .unwrap_or_default();  // fallback to default client on builder error

    tokio::spawn(async move {
        use tokio::time::{MissedTickBehavior, interval};

        let mut tick = interval(config.interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Fire immediately on first tick (daemon startup → populate cache).
        loop {
            tick.tick().await;

            // Auto-detect currencies from billing table (zero hardcode).
            let quotes = match inv.billing_currencies_in_use().await {
                Ok(q) if !q.is_empty() => q,
                Ok(_) => {
                    tracing::debug!(
                        target = "vpnctld::exchange_rates",
                        "no currencies in billing table; skipping fetch"
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::exchange_rates",
                        error = %e,
                        "failed to read billing currencies; skipping fetch"
                    );
                    continue;
                }
            };

            // Filter out EUR (base currency — rate is always 1.0).
            let needed: Vec<&str> = quotes.iter()
                .map(|s| s.as_str())
                .filter(|c| *c != "EUR")
                .collect();

            if needed.is_empty() {
                continue; // all billing is in EUR, no conversion needed
            }

            // Try primary, then fallback.
            let result = fetch_frankfurter(&client, &config.primary_url, &needed).await
                .or_else(|e| {
                    tracing::warn!(
                        target = "vpnctld::exchange_rates",
                        error = %e,
                        "primary provider failed; trying fallback"
                    );
                    // Block is async — needs a different approach:
                    Err(e)
                });

            let rates = match result {
                Ok(r) => r,
                Err(_) => {
                    match fetch_open_er_api(&client, &config.fallback_url).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!(
                                target = "vpnctld::exchange_rates",
                                error = %e,
                                "all providers failed; keeping stale cache"
                            );
                            continue;
                        }
                    }
                }
            };

            // Validate + upsert.
            let valid: Vec<_> = rates.into_iter()
                .filter(|(_, rate)| *rate > 0.0 && rate.is_finite())
                .collect();

            match inv.upsert_auto_rates(/* ... */).await {
                Ok(n) => tracing::info!(
                    target = "vpnctld::exchange_rates",
                    count = n,
                    "exchange rates refreshed"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::exchange_rates",
                    error = %e,
                    "failed to write exchange rates; will retry next tick"
                ),
            }
        }
    })
}
```

---

## 7. Integration Points

### 7.1 Daemon startup (`app/state.rs::build()`)

```rust
// After existing scheduler spawns:
let _fx_handle = crate::exchange_rates::spawn_exchange_rate_poller(
    inv.clone(),
    ExchangeRateConfig::from_env(), // reads VPNCTLD_FX_* env vars
);
```

### 7.2 `reqwest` dependency in `daemon/Cargo.toml`

```toml
# Exchange rate fetcher. Feature-unifies with boosty-bridge's existing
# reqwest dep (both use rustls, no native-tls). No new transitive deps
# in Cargo.lock.
reqwest = { version = "0.13", default-features = false, features = ["rustls", "json"] }
```

This **adds zero new crates** to `Cargo.lock` because `reqwest` 0.13 with
`rustls` + `json` is already resolved via `boosty-bridge`. Cargo unifies
features across the workspace.

### 7.3 Billing page changes (UI)

The billing handler (`daemon/src/handlers/admin/billing.rs`) adds:

1. A `rates: Vec<ExchangeRate>` loaded at the top of the handler.
2. A `≈ X.XX €` column next to each server's amount (when the currency
   is not EUR and a rate exists).
3. A unified total in the burn-rate KPI card: "5.50 € · 500.00 ₽ ≈
   10.60 € total".
4. A footer: "Rates as of 12.09.2026 14:10 (Frankfurter)" or
   "⚠ Rates from 3 days ago — click to refresh" with a refresh button.

### 7.4 Settings page additions

On `/admin/settings`, a new "Exchange Rates" section:

- **Auto-refresh interval**: dropdown (6h / 12h / 24h / off).
- **Refresh now** button: triggers immediate one-shot fetch.
- **Manual override table**: for each currency in use, an input field to
  enter a manual rate (overrides auto). Clear button to revert to auto.
- **Provider URL**: advanced text input (pre-filled with Frankfurter).

### 7.5 Environment variables

| Variable | Default | Description |
|---|---|---|
| `VPNCTLD_FX_INTERVAL_SECS` | `43200` (12h) | Polling interval; min 3600 |
| `VPNCTLD_FX_PRIMARY_URL` | `https://api.frankfurter.dev/v2/rates` | Primary provider |
| `VPNCTLD_FX_FALLBACK_URL` | `https://open.er-api.com/v6/latest/EUR` | Fallback provider |
| `VPNCTLD_FX_TIMEOUT_SECS` | `30` | Per-request HTTP timeout |

---

## 8. Security & Sandbox Considerations

- **systemd sandbox**: The daemon already makes outbound HTTPS
  connections (Boosty API sync, Clash API polling, node probes). The
  `RestrictAddressFamilies=AF_INET AF_INET6` policy already permits
  this. No sandbox changes needed.
- **Egress scope**: Only two hardcoded hostnames (`api.frankfurter.dev`,
  `open.er-api.com`) unless operator overrides. Both are HTTPS-only.
- **No secrets**: No API keys, no tokens, no cookies. The requests are
  anonymous GETs.
- **Response trust**: The JSON response is deserialized into typed
  structs with `serde`. No `eval`, no dynamic code. Rate values are
  validated (finite, positive) before storage.
- **Operator override**: The operator can point the provider URL at a
  LAN-local cache or proxy if their daemon's network is restricted.

---

## 9. Testing Strategy

| Test | Layer | What it verifies |
|---|---|---|
| `exchange_rates::parse_frankfurter_response` | Unit (daemon) | Deserialization of known-good JSON fixture |
| `exchange_rates::parse_open_er_api_response` | Unit (daemon) | Deserialization of known-good JSON fixture |
| `exchange_rates::convert_to_eur` | Unit (daemon) | Conversion arithmetic, missing-rate → None, zero-rate → None, NaN → None |
| `exchange_rates::validate_rates` | Unit (daemon) | Rejects negative, zero, NaN, infinite rates |
| `inventory::upsert_auto_rates` | Integration (inventory) | UPSERT idempotency, manual-override immunity |
| `inventory::set_manual_rate` | Integration (inventory) | Manual flag persists, auto-refresh skips it |
| `admin_smoke::billing_with_rates` | Integration (daemon) | Page renders with rates, without rates, with stale rates |
| `admin_smoke::billing_conversion_display` | Integration (daemon) | Unified EUR total appears when rates exist, "?" when missing |

---

## 10. Implementation Phases (suggested)

| Phase | Scope | Risk |
|---|---|---|
| **P1: Schema + Inventory API** | Migration `0058`, `exchange_rates.rs` in inventory crate, CRUD methods | Low |
| **P2: Poller** | `daemon/src/exchange_rates.rs`, spawn in `build()`, env config | Medium (HTTP, error handling) |
| **P3: Billing UI integration** | Modify `billing.rs` handler to load rates and render unified totals | Low |
| **P4: Settings UI** | Manual override form, refresh button, provider config | Low |
| **P5: Tests** | Unit + integration coverage for all paths above | Low |

---

## 11. Open Questions for Operator Decision

1. **Anchor currency**: This spec assumes EUR as the normalization base
   (most servers are EUR-billed). Should the anchor be operator-configurable
   via Settings? (Adds one more column to the config but is trivial.)

2. **Retention of historical rates**: Should the system keep a rate
   history (one row per day per currency) for trend display, or is a
   single "latest" row per currency sufficient? This spec assumes
   latest-only for simplicity.

3. **First-boot behavior**: On a fresh install with no cached rates and
   no network, the billing page shows amounts in their original
   currencies with no conversion. Is a "seed" file with approximate
   rates worth shipping, or is "?" acceptable until the first successful
   fetch?

---

## Appendix A: Live API Response Samples (2026-09-12)

### Frankfurter v2

```
GET https://api.frankfurter.dev/v2/rates?base=EUR&quotes=USD,RUB,CHF,GBP,SEK
```

```json
[
  {"date":"2026-09-13","base":"EUR","quote":"CHF","rate":0.94385},
  {"date":"2026-09-13","base":"EUR","quote":"GBP","rate":0.8584},
  {"date":"2026-09-13","base":"EUR","quote":"RUB","rate":98.07},
  {"date":"2026-09-13","base":"EUR","quote":"SEK","rate":11.213},
  {"date":"2026-09-13","base":"EUR","quote":"USD","rate":1.1618}
]
```

### Open ER-API

```
GET https://open.er-api.com/v6/latest/EUR
```

```json
{
  "result": "success",
  "base_code": "EUR",
  "time_last_update_utc": "Sat, 12 Sep 2026 00:02:31 +0000",
  "time_next_update_utc": "Sun, 13 Sep 2026 00:27:41 +0000",
  "rates": {
    "USD": 1.160069,
    "RUB": 97.694297,
    "CHF": 0.946477,
    "GBP": 0.857908,
    "SEK": 11.249083,
    ...161 currencies total...
  }
}
```

### ECB Daily XML (for reference — NOT recommended as primary)

```
GET https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml
```

```xml
<gesmes:Envelope>
  <Cube>
    <Cube time="2026-09-11">
      <Cube currency="USD" rate="1.1053"/>
      <Cube currency="CHF" rate="0.9393"/>
      <!-- NO RUB since 2022-03-01 -->
    </Cube>
  </Cube>
</gesmes:Envelope>
```
