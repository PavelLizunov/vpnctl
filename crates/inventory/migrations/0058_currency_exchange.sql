-- Multi-currency exchange rates, operator display preferences, and payment history.
-- No hardcoded currencies: any ISO 4217 code is accepted.
-- All monetary values are integer minor-units (cents/kopecks) to avoid
-- floating-point precision loss.  Currencies with zero decimal places
-- (JPY, KRW) store their unit value directly — the `minor_units` column
-- in currency_settings tells the conversion engine the exponent.

-- ── Exchange rates ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS currency_rates (
    base_currency   TEXT NOT NULL,              -- ISO 4217 (e.g. 'USD')
    target_currency TEXT NOT NULL,              -- ISO 4217 (e.g. 'RUB')
    -- Rate as integer with 6 implicit decimal places (micros).
    -- 1 USD = 89.123456 RUB → stored as 89123456.
    -- Avoids TEXT/REAL precision issues in SQLite.
    rate_micros     INTEGER NOT NULL CHECK (rate_micros > 0),
    source          TEXT NOT NULL DEFAULT 'manual',  -- 'manual', 'ecb', 'cbr', etc.
    fetched_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (base_currency, target_currency)
);

-- ── Operator currency settings (singleton row, id = 1) ──────────────────

CREATE TABLE IF NOT EXISTS currency_settings (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    -- Target display currency for fleet summaries (e.g. 'RUB').
    display_currency        TEXT NOT NULL DEFAULT 'EUR',
    -- Default markup coefficient applied when converting TO this display
    -- currency (e.g. 1.07 for RUB to account for P2P/card intermediary
    -- fees).  Stored as integer with 4 implicit decimals (basis-point
    -- precision): 1.07 → 10700, 1.00 → 10000.  Applied only when
    -- source ≠ target; same-currency conversions always use 10000 (1.0).
    default_markup_bps      INTEGER NOT NULL DEFAULT 10700 CHECK (default_markup_bps > 0),
    -- Per-currency markup overrides as JSON object:
    --   {"RUB": 10700, "TRY": 11500}
    -- Keys are target currencies; values are markup in basis-point format.
    -- NULL or '{}' means use default_markup_bps for everything.
    markup_overrides_json   TEXT,
    -- Manual rate overrides as JSON object:
    --   {"USD/RUB": 89123456}
    -- Keys are "BASE/TARGET"; values are rate_micros.
    -- Takes precedence over currency_rates table rows.
    rate_overrides_json     TEXT,
    -- Whether automatic rate refresh is enabled (daemon periodic task).
    auto_refresh            INTEGER NOT NULL DEFAULT 0 CHECK (auto_refresh IN (0, 1)),
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Seed the singleton row.
INSERT OR IGNORE INTO currency_settings (id) VALUES (1);

-- ── Payment history ─────────────────────────────────────────────────────
-- Each row records an actual payment made (the operator clicked "+1 cycle"
-- or manually logged a payment).  Immutable after insert — no UPDATE path.
-- The converted fields are snapshot values at the time of payment so
-- historical totals never shift when rates change later.

CREATE TABLE IF NOT EXISTS server_payments (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id               TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    paid_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- Original payment in minor units of the source currency.
    amount_minor            INTEGER NOT NULL CHECK (amount_minor >= 0),
    currency                TEXT NOT NULL,       -- source ISO 4217
    -- Which billing cycle this payment covered.
    cycle                   TEXT NOT NULL DEFAULT 'monthly'
                            CHECK (cycle IN ('monthly', 'quarterly', 'semi-annual', 'annual')),
    -- Snapshot of the converted value at payment time (display currency).
    converted_minor         INTEGER,             -- NULL when no rate available
    display_currency        TEXT,                -- target ISO 4217 at time of payment
    -- Snapshot of the rate_micros and markup_bps used, for audit trail.
    rate_micros_used        INTEGER,
    markup_bps_used         INTEGER,
    notes                   TEXT
);

CREATE INDEX IF NOT EXISTS idx_server_payments_server ON server_payments(server_id);
CREATE INDEX IF NOT EXISTS idx_server_payments_paid_at ON server_payments(paid_at);
