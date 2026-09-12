use sqlx::Row;
use vpnctl_core::ServerId;

use crate::sqlite::{
    BillingCycle, ConversionResult, CurrencyRate, CurrencySettings, CurrencySettingsInput,
    FleetBillingSummary, Result, ServerBillingSummaryItem, ServerPayment, ServerPaymentInput,
    SqliteInventory, SqliteInventoryError,
};

// ── Constants ───────────────────────────────────────────────────────────

/// Markup basis-point value representing 1.0 (no markup).
const IDENTITY_MARKUP_BPS: i64 = 10_000;

/// Number of implicit decimals in `rate_micros` (10^6).
const RATE_SCALE: i64 = 1_000_000;

/// Number of implicit decimals in `markup_bps` (10^4).
const MARKUP_SCALE: i64 = 10_000;

// ── Conversion math (pure, no DB) ───────────────────────────────────────

/// Convert `source_minor` (integer minor-units of `source_currency`) to
/// `target_currency` using the given rate and markup.
///
/// Formula:
///   target_minor = source_minor × rate_micros / RATE_SCALE × markup_bps / MARKUP_SCALE
///
/// When source == target, `rate_micros` should be `RATE_SCALE` (1.0) and
/// `markup_bps` should be `IDENTITY_MARKUP_BPS` (1.0) — same-currency
/// conversions never apply a fee.
///
/// Uses `i128` intermediates to avoid overflow on large amounts.
///
/// Returns `None` for zero `rate_micros` or zero `markup_bps` (defensive).
pub fn convert_minor(source_minor: i64, rate_micros: i64, markup_bps: i64) -> Option<i64> {
    if rate_micros <= 0 || markup_bps <= 0 {
        return None;
    }
    let wide = source_minor as i128 * rate_micros as i128 * markup_bps as i128;
    // Rounding: add half the divisor for banker's rounding.
    let divisor = RATE_SCALE as i128 * MARKUP_SCALE as i128;
    let rounded = (wide + divisor / 2) / divisor;
    Some(rounded as i64)
}

/// Normalise a billing cycle's `amount_cents` to a monthly equivalent.
/// Uses integer arithmetic with rounding.
pub fn monthly_equivalent(amount_minor: i64, cycle: BillingCycle) -> i64 {
    let months = cycle.months() as i64;
    if months <= 1 {
        return amount_minor;
    }
    // Round to nearest: (amount + months/2) / months
    (amount_minor + months / 2) / months
}

// ── Currency rates CRUD ─────────────────────────────────────────────────

impl SqliteInventory {
    /// Upsert a single exchange rate.
    pub async fn upsert_currency_rate(&self, rate: &CurrencyRate) -> Result<()> {
        if rate.rate_micros <= 0 {
            return Err(SqliteInventoryError::Invalid(
                "rate_micros must be positive".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO currency_rates (base_currency, target_currency, rate_micros, source, fetched_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(base_currency, target_currency) DO UPDATE SET
                rate_micros = excluded.rate_micros,
                source      = excluded.source,
                fetched_at  = excluded.fetched_at",
        )
        .bind(&rate.base_currency)
        .bind(&rate.target_currency)
        .bind(rate.rate_micros)
        .bind(&rate.source)
        .bind(&rate.fetched_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Bulk-upsert exchange rates in a single transaction.
    pub async fn upsert_currency_rates(&self, rates: &[CurrencyRate]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for rate in rates {
            if rate.rate_micros <= 0 {
                return Err(SqliteInventoryError::Invalid(format!(
                    "rate_micros must be positive for {}/{}",
                    rate.base_currency, rate.target_currency
                )));
            }
            sqlx::query(
                "INSERT INTO currency_rates (base_currency, target_currency, rate_micros, source, fetched_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(base_currency, target_currency) DO UPDATE SET
                    rate_micros = excluded.rate_micros,
                    source      = excluded.source,
                    fetched_at  = excluded.fetched_at",
            )
            .bind(&rate.base_currency)
            .bind(&rate.target_currency)
            .bind(rate.rate_micros)
            .bind(&rate.source)
            .bind(&rate.fetched_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Get all stored exchange rates.
    pub async fn list_currency_rates(&self) -> Result<Vec<CurrencyRate>> {
        let rows = sqlx::query(
            "SELECT base_currency, target_currency, rate_micros, source, fetched_at
             FROM currency_rates
             ORDER BY base_currency, target_currency",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(CurrencyRate {
                base_currency: r.try_get("base_currency")?,
                target_currency: r.try_get("target_currency")?,
                rate_micros: r.try_get("rate_micros")?,
                source: r.try_get("source")?,
                fetched_at: r.try_get("fetched_at")?,
            });
        }
        Ok(out)
    }

    /// Get the rate for a specific currency pair.  Checks rate overrides
    /// in `currency_settings` first, then falls back to `currency_rates`.
    pub async fn get_rate(&self, base: &str, target: &str) -> Result<Option<CurrencyRate>> {
        // 1. Check rate overrides in settings.
        let settings = self.get_currency_settings().await?;
        let override_key = format!("{base}/{target}");
        if let Some(&micros) = settings.rate_overrides.get(&override_key) {
            return Ok(Some(CurrencyRate {
                base_currency: base.into(),
                target_currency: target.into(),
                rate_micros: micros,
                source: "override".into(),
                fetched_at: String::new(),
            }));
        }

        // 2. Fall back to direct rates table.
        let row = sqlx::query(
            "SELECT base_currency, target_currency, rate_micros, source, fetched_at
             FROM currency_rates
             WHERE base_currency = ?1 AND target_currency = ?2",
        )
        .bind(base)
        .bind(target)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            return Ok(Some(CurrencyRate {
                base_currency: r.try_get("base_currency")?,
                target_currency: r.try_get("target_currency")?,
                rate_micros: r.try_get("rate_micros")?,
                source: r.try_get("source")?,
                fetched_at: r.try_get("fetched_at")?,
            }));
        }

        // 3. Inverse rate (target -> base).
        let inv_key = format!("{target}/{base}");
        let inv_rate = if let Some(&micros) = settings.rate_overrides.get(&inv_key) {
            Some(micros)
        } else {
            sqlx::query_scalar::<_, i64>(
                "SELECT rate_micros FROM currency_rates WHERE base_currency = ?1 AND target_currency = ?2",
            )
            .bind(target)
            .bind(base)
            .fetch_optional(&self.pool)
            .await?
        };

        if let Some(inv_micros) = inv_rate {
            if inv_micros > 0 {
                let calc_micros = (RATE_SCALE as i128 * RATE_SCALE as i128
                    + inv_micros as i128 / 2)
                    / inv_micros as i128;
                return Ok(Some(CurrencyRate {
                    base_currency: base.into(),
                    target_currency: target.into(),
                    rate_micros: calc_micros as i64,
                    source: "inverse".into(),
                    fetched_at: String::new(),
                }));
            }
        }

        // 4. Triangulation via intermediate base (where X -> base and X -> target exist).
        let common: Option<(i64, i64)> = sqlx::query_as(
            "SELECT r1.rate_micros, r2.rate_micros
             FROM currency_rates r1
             JOIN currency_rates r2 ON r1.base_currency = r2.base_currency
             WHERE r1.target_currency = ?1 AND r2.target_currency = ?2
             LIMIT 1",
        )
        .bind(base)
        .bind(target)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((rate_x_base, rate_x_target)) = common {
            if rate_x_base > 0 {
                let calc_micros = (rate_x_target as i128 * RATE_SCALE as i128
                    + rate_x_base as i128 / 2)
                    / rate_x_base as i128;
                return Ok(Some(CurrencyRate {
                    base_currency: base.into(),
                    target_currency: target.into(),
                    rate_micros: calc_micros as i64,
                    source: "triangulated".into(),
                    fetched_at: String::new(),
                }));
            }
        }

        Ok(None)
    }

    /// Delete a rate for a specific currency pair.
    pub async fn delete_currency_rate(&self, base: &str, target: &str) -> Result<bool> {
        let res = sqlx::query(
            "DELETE FROM currency_rates WHERE base_currency = ?1 AND target_currency = ?2",
        )
        .bind(base)
        .bind(target)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    // ── Currency settings ───────────────────────────────────────────────

    /// Read the operator's currency display preferences.
    pub async fn get_currency_settings(&self) -> Result<CurrencySettings> {
        let row = sqlx::query(
            "SELECT display_currency, default_markup_bps, markup_overrides_json,
                    rate_overrides_json, auto_refresh
             FROM currency_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else {
            return Ok(CurrencySettings::default());
        };

        let display_currency: String = r.try_get("display_currency")?;
        let default_markup_bps: i64 = r.try_get("default_markup_bps")?;
        let auto_refresh_i: i64 = r.try_get("auto_refresh")?;

        let markup_overrides: std::collections::HashMap<String, i64> =
            match r.try_get::<Option<String>, _>("markup_overrides_json")? {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).unwrap_or_default(),
                _ => std::collections::HashMap::new(),
            };

        let rate_overrides: std::collections::HashMap<String, i64> =
            match r.try_get::<Option<String>, _>("rate_overrides_json")? {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).unwrap_or_default(),
                _ => std::collections::HashMap::new(),
            };

        Ok(CurrencySettings {
            display_currency,
            default_markup_bps,
            markup_overrides,
            rate_overrides,
            auto_refresh: auto_refresh_i == 1,
        })
    }

    /// Update operator currency settings.  Only non-`None` fields in the
    /// input are applied (patch semantics).  Writes an audit row.
    pub async fn set_currency_settings(
        &self,
        input: &CurrencySettingsInput,
    ) -> Result<CurrencySettings> {
        let mut tx = self.pool.begin().await?;

        // Read current.
        let current = {
            let row = sqlx::query(
                "SELECT display_currency, default_markup_bps, markup_overrides_json,
                        rate_overrides_json, auto_refresh
                 FROM currency_settings WHERE id = 1",
            )
            .fetch_one(&mut *tx)
            .await?;

            let markup_ov: std::collections::HashMap<String, i64> =
                match row.try_get::<Option<String>, _>("markup_overrides_json")? {
                    Some(s) if !s.is_empty() => serde_json::from_str(&s).unwrap_or_default(),
                    _ => std::collections::HashMap::new(),
                };
            let rate_ov: std::collections::HashMap<String, i64> =
                match row.try_get::<Option<String>, _>("rate_overrides_json")? {
                    Some(s) if !s.is_empty() => serde_json::from_str(&s).unwrap_or_default(),
                    _ => std::collections::HashMap::new(),
                };
            let auto_i: i64 = row.try_get("auto_refresh")?;

            CurrencySettings {
                display_currency: row.try_get("display_currency")?,
                default_markup_bps: row.try_get("default_markup_bps")?,
                markup_overrides: markup_ov,
                rate_overrides: rate_ov,
                auto_refresh: auto_i == 1,
            }
        };

        let display = input
            .display_currency
            .as_deref()
            .unwrap_or(&current.display_currency);
        let markup = input
            .default_markup_bps
            .unwrap_or(current.default_markup_bps);
        if markup <= 0 {
            return Err(SqliteInventoryError::Invalid(
                "default_markup_bps must be positive".into(),
            ));
        }
        let markup_ov = input
            .markup_overrides
            .as_ref()
            .unwrap_or(&current.markup_overrides);
        let rate_ov = input
            .rate_overrides
            .as_ref()
            .unwrap_or(&current.rate_overrides);
        let auto = input.auto_refresh.unwrap_or(current.auto_refresh);

        let markup_json = if markup_ov.is_empty() {
            None
        } else {
            Some(serde_json::to_string(markup_ov)?)
        };
        let rate_json = if rate_ov.is_empty() {
            None
        } else {
            Some(serde_json::to_string(rate_ov)?)
        };

        sqlx::query(
            "UPDATE currency_settings SET
                display_currency      = ?1,
                default_markup_bps    = ?2,
                markup_overrides_json = ?3,
                rate_overrides_json   = ?4,
                auto_refresh          = ?5,
                updated_at            = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = 1",
        )
        .bind(display)
        .bind(markup)
        .bind(markup_json.as_deref())
        .bind(rate_json.as_deref())
        .bind(if auto { 1i64 } else { 0i64 })
        .execute(&mut *tx)
        .await?;

        // Audit (no secrets).
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES ('admin', 'currency.settings.set', NULL, ?1)",
        )
        .bind(
            serde_json::to_string(&serde_json::json!({
                "display_currency": display,
                "default_markup_bps": markup,
                "auto_refresh": auto,
            }))
            .unwrap_or_default(),
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(CurrencySettings {
            display_currency: display.to_string(),
            default_markup_bps: markup,
            markup_overrides: markup_ov.clone(),
            rate_overrides: rate_ov.clone(),
            auto_refresh: auto,
        })
    }

    // ── Currency conversion engine ──────────────────────────────────────

    /// Convert an amount from one currency to another using the operator's
    /// current settings (rate overrides, markup).
    ///
    /// Returns `Ok(None)` when no rate is available for the pair.  Returns
    /// identity conversion (1:1, no markup) when source == target.
    pub async fn convert_amount(
        &self,
        amount_minor: i64,
        source_currency: &str,
        target_currency: &str,
    ) -> Result<Option<ConversionResult>> {
        // Same currency → identity, no markup.
        if source_currency == target_currency {
            return Ok(Some(ConversionResult {
                amount_minor,
                target_currency: target_currency.into(),
                rate_micros: RATE_SCALE,
                markup_bps: IDENTITY_MARKUP_BPS,
                identity: true,
            }));
        }

        // Zero amount → trivial.
        if amount_minor == 0 {
            return Ok(Some(ConversionResult {
                amount_minor: 0,
                target_currency: target_currency.into(),
                rate_micros: RATE_SCALE,
                markup_bps: IDENTITY_MARKUP_BPS,
                identity: false,
            }));
        }

        // Look up rate.
        let rate = match self.get_rate(source_currency, target_currency).await? {
            Some(r) => r,
            None => return Ok(None),
        };

        // Determine markup.
        let settings = self.get_currency_settings().await?;
        let markup = settings
            .markup_overrides
            .get(target_currency)
            .copied()
            .unwrap_or(settings.default_markup_bps);

        let converted = convert_minor(amount_minor, rate.rate_micros, markup);
        match converted {
            Some(v) => Ok(Some(ConversionResult {
                amount_minor: v,
                target_currency: target_currency.into(),
                rate_micros: rate.rate_micros,
                markup_bps: markup,
                identity: false,
            })),
            None => Ok(None),
        }
    }

    // ── Payment history ─────────────────────────────────────────────────

    /// Record a payment for a server.  Automatically snapshots the
    /// converted value at the current exchange rate + markup.
    ///
    /// Also advances the server's billing due date by one cycle (the
    /// "+1 cycle" operation).
    pub async fn record_server_payment(
        &self,
        sid: &ServerId,
        input: &ServerPaymentInput,
    ) -> Result<ServerPayment> {
        if input.amount_minor < 0 {
            return Err(SqliteInventoryError::Invalid(
                "amount_minor cannot be negative".into(),
            ));
        }

        // Snapshot the conversion at current rates.
        let settings = self.get_currency_settings().await?;
        let conversion = self
            .convert_amount(
                input.amount_minor,
                &input.currency,
                &settings.display_currency,
            )
            .await?;

        let mut tx = self.pool.begin().await?;

        // Verify server exists.
        let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM servers WHERE id = ?1")
            .bind(&sid.0)
            .fetch_optional(&mut *tx)
            .await?;
        if exists.is_none() {
            return Err(SqliteInventoryError::Invalid(format!(
                "server '{}' not found",
                sid.0
            )));
        }

        let (conv_minor, disp_cur, rate_used, markup_used) = match &conversion {
            Some(c) => (
                Some(c.amount_minor),
                Some(c.target_currency.as_str()),
                Some(c.rate_micros),
                Some(c.markup_bps),
            ),
            None => (None, None, None, None),
        };

        sqlx::query(
            "INSERT INTO server_payments
                (server_id, amount_minor, currency, cycle,
                 converted_minor, display_currency, rate_micros_used, markup_bps_used, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&sid.0)
        .bind(input.amount_minor)
        .bind(&input.currency)
        .bind(input.cycle.as_str())
        .bind(conv_minor)
        .bind(disp_cur)
        .bind(rate_used)
        .bind(markup_used)
        .bind(input.notes.as_deref())
        .execute(&mut *tx)
        .await?;

        let id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
            .fetch_one(&mut *tx)
            .await?;

        let row = sqlx::query(
            "SELECT id, server_id, paid_at, amount_minor, currency, cycle,
                    converted_minor, display_currency, rate_micros_used, markup_bps_used, notes
             FROM server_payments WHERE id = ?1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        let cycle_str: String = row.try_get("cycle")?;

        let payment = ServerPayment {
            id: row.try_get("id")?,
            server_id: ServerId(row.try_get("server_id")?),
            paid_at: row.try_get("paid_at")?,
            amount_minor: row.try_get("amount_minor")?,
            currency: row.try_get("currency")?,
            cycle: cycle_str.parse()?,
            converted_minor: row.try_get("converted_minor")?,
            display_currency: row.try_get("display_currency")?,
            rate_micros_used: row.try_get("rate_micros_used")?,
            markup_bps_used: row.try_get("markup_bps_used")?,
            notes: row.try_get("notes")?,
        };

        // Audit.
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES ('admin', 'server.payment.record', ?1, ?2)",
        )
        .bind(&sid.0)
        .bind(
            serde_json::to_string(&serde_json::json!({
                "amount_minor": input.amount_minor,
                "currency": input.currency,
                "cycle": input.cycle.as_str(),
                "converted_minor": conv_minor,
                "display_currency": disp_cur,
            }))
            .unwrap_or_default(),
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(payment)
    }

    /// List all payments for a server, newest first.
    pub async fn list_server_payments(&self, sid: &ServerId) -> Result<Vec<ServerPayment>> {
        let rows = sqlx::query(
            "SELECT id, server_id, paid_at, amount_minor, currency, cycle,
                    converted_minor, display_currency, rate_micros_used, markup_bps_used, notes
             FROM server_payments
             WHERE server_id = ?1
             ORDER BY paid_at DESC",
        )
        .bind(&sid.0)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let cycle_str: String = r.try_get("cycle")?;
            out.push(ServerPayment {
                id: r.try_get("id")?,
                server_id: ServerId(r.try_get("server_id")?),
                paid_at: r.try_get("paid_at")?,
                amount_minor: r.try_get("amount_minor")?,
                currency: r.try_get("currency")?,
                cycle: cycle_str.parse()?,
                converted_minor: r.try_get("converted_minor")?,
                display_currency: r.try_get("display_currency")?,
                rate_micros_used: r.try_get("rate_micros_used")?,
                markup_bps_used: r.try_get("markup_bps_used")?,
                notes: r.try_get("notes")?,
            });
        }
        Ok(out)
    }

    /// Historical total spend and payment count for one server in the display currency.
    pub async fn server_spend_and_count(
        &self,
        sid: &ServerId,
        display_currency: &str,
    ) -> Result<(i64, i64)> {
        let row: (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(converted_minor), 0), COUNT(*)
             FROM server_payments
             WHERE server_id = ?1 AND display_currency = ?2",
        )
        .bind(&sid.0)
        .bind(display_currency)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Historical total spend for one server in the display currency,
    /// summed from immutable payment snapshots.
    pub async fn server_total_spend(&self, sid: &ServerId, display_currency: &str) -> Result<i64> {
        let total: Option<i64> = sqlx::query_scalar(
            "SELECT COALESCE(SUM(converted_minor), 0)
             FROM server_payments
             WHERE server_id = ?1 AND display_currency = ?2",
        )
        .bind(&sid.0)
        .bind(display_currency)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    // ── Fleet billing summary ───────────────────────────────────────────

    /// Compute a unified fleet billing summary with all amounts converted
    /// to the operator's display currency.
    ///
    /// **Total Spend** = sum of historical `server_payments.converted_minor`
    /// (immutable snapshots — never re-converted).
    ///
    /// **Monthly Burn** = each server's `server_billing.amount_cents`
    /// normalised to monthly, then converted at current rates + markup.
    pub async fn get_fleet_billing_summary(&self) -> Result<FleetBillingSummary> {
        let settings = self.get_currency_settings().await?;
        let display = &settings.display_currency;

        // Per-server billing + total spend.
        let rows = sqlx::query(
            "SELECT s.id, s.display_name,
                    b.amount_cents, b.currency, b.billing_cycle,
                    COALESCE(p.total_spend, 0) AS total_spend,
                    COALESCE(p.payment_count, 0) AS payment_count
             FROM servers s
             LEFT JOIN server_billing b ON b.server_id = s.id
             LEFT JOIN (
                 SELECT server_id,
                        SUM(converted_minor) AS total_spend,
                        COUNT(*) AS payment_count
                 FROM server_payments
                 WHERE display_currency = ?1
                 GROUP BY server_id
             ) p ON p.server_id = s.id
             ORDER BY s.id",
        )
        .bind(display)
        .fetch_all(&self.pool)
        .await?;

        let mut servers = Vec::with_capacity(rows.len());
        let mut total_spend: i64 = 0;
        let mut monthly_burn: i64 = 0;
        let mut unconvertible = Vec::new();

        for r in &rows {
            let sid: String = r.try_get("id")?;
            let display_name: Option<String> = r.try_get("display_name")?;
            let spend: i64 = r.try_get("total_spend")?;
            let pcount: i64 = r.try_get("payment_count")?;
            total_spend = total_spend.saturating_add(spend);

            // Billing may not be configured for every server.
            let amount_cents: Option<i64> = r.try_get("amount_cents")?;
            let currency: Option<String> = r.try_get("currency")?;
            let cycle_str: Option<String> = r.try_get("billing_cycle")?;

            let (src_amount, src_currency, cycle) = match (amount_cents, currency, cycle_str) {
                (Some(a), Some(c), Some(cy)) => (a, c, cy.parse::<BillingCycle>()?),
                _ => {
                    servers.push(ServerBillingSummaryItem {
                        server_id: ServerId(sid),
                        display_name,
                        source_amount_minor: 0,
                        source_currency: String::new(),
                        billing_cycle: BillingCycle::Monthly,
                        converted_monthly_minor: None,
                        total_spend_minor: spend,
                        payment_count: pcount,
                    });
                    continue;
                }
            };

            let monthly_src = monthly_equivalent(src_amount, cycle);

            // Convert to display currency.
            let converted = self
                .convert_amount(monthly_src, &src_currency, display)
                .await?;

            let conv_monthly = match &converted {
                Some(c) => {
                    monthly_burn = monthly_burn.saturating_add(c.amount_minor);
                    Some(c.amount_minor)
                }
                None => {
                    if !unconvertible.contains(&sid) {
                        unconvertible.push(sid.clone());
                    }
                    None
                }
            };

            servers.push(ServerBillingSummaryItem {
                server_id: ServerId(sid),
                display_name,
                source_amount_minor: src_amount,
                source_currency: src_currency,
                billing_cycle: cycle,
                converted_monthly_minor: conv_monthly,
                total_spend_minor: spend,
                payment_count: pcount,
            });
        }

        let markup = settings
            .markup_overrides
            .get(display)
            .copied()
            .unwrap_or(settings.default_markup_bps);

        Ok(FleetBillingSummary {
            display_currency: display.clone(),
            markup_bps: markup,
            total_spend_minor: total_spend,
            monthly_burn_minor: monthly_burn,
            annual_burn_minor: monthly_burn.saturating_mul(12),
            servers,
            unconvertible,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_minor_identity() {
        // 100 EUR → 100 EUR (1:1, no markup).
        let result = convert_minor(10000, RATE_SCALE, IDENTITY_MARKUP_BPS);
        assert_eq!(result, Some(10000));
    }

    #[test]
    fn convert_minor_with_rate_and_markup() {
        // 10.00 EUR (1000 cents) × rate 89.5 (89_500_000 micros) × 1.07 markup.
        // Expected: 1000 × 89.5 × 1.07 = 95_765.0 → 95765 minor units.
        let rate = 89_500_000i64; // 89.5
        let markup = 10_700i64; // 1.07
        let result = convert_minor(1000, rate, markup);
        assert_eq!(result, Some(95765));
    }

    #[test]
    fn convert_minor_zero_amount() {
        let result = convert_minor(0, 89_500_000, 10_700);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn convert_minor_rejects_zero_rate() {
        assert_eq!(convert_minor(1000, 0, 10_000), None);
    }

    #[test]
    fn convert_minor_rejects_negative_rate() {
        assert_eq!(convert_minor(1000, -1, 10_000), None);
    }

    #[test]
    fn monthly_equivalent_monthly() {
        assert_eq!(monthly_equivalent(1000, BillingCycle::Monthly), 1000);
    }

    #[test]
    fn monthly_equivalent_annual() {
        // 12000 / 12 = 1000.
        assert_eq!(monthly_equivalent(12000, BillingCycle::Annual), 1000);
    }

    #[test]
    fn monthly_equivalent_quarterly() {
        // 3000 / 3 = 1000.
        assert_eq!(monthly_equivalent(3000, BillingCycle::Quarterly), 1000);
    }

    #[test]
    fn monthly_equivalent_rounding() {
        // (1000 + 6) / 12 = 83 (integer half-up rounding).
        assert_eq!(monthly_equivalent(1000, BillingCycle::Annual), 83);
        // (1100 + 6) / 12 = 92.
        assert_eq!(monthly_equivalent(1100, BillingCycle::Annual), 92);
    }

    #[test]
    fn convert_large_amount_no_overflow() {
        // 1_000_000_00 cents (1M EUR) × rate 89.5 × 1.07 — must not overflow.
        let result = convert_minor(100_000_000, 89_500_000, 10_700);
        assert!(result.is_some());
        // 100_000_000 × 89.5 × 1.07 = 9_576_500_000
        assert_eq!(result, Some(9_576_500_000));
    }
}
