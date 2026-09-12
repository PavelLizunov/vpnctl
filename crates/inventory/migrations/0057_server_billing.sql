-- Server rental billing and renewal tracker.
-- Tracks payment due dates, recurring periods, amounts, currencies, and provider links per server.

CREATE TABLE IF NOT EXISTS server_billing (
    server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    due_date TEXT NOT NULL,
    billing_cycle TEXT NOT NULL DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'quarterly', 'semi-annual', 'annual')),
    amount_cents INTEGER NOT NULL DEFAULT 0 CHECK (amount_cents >= 0),
    currency TEXT NOT NULL DEFAULT 'EUR',
    auto_renew INTEGER NOT NULL DEFAULT 0 CHECK (auto_renew IN (0, 1)),
    billing_url TEXT,
    notes TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_server_billing_due_date ON server_billing(due_date);
