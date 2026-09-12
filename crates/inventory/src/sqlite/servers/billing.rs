use chrono::{Datelike, NaiveDate};
use sqlx::Row;
use vpnctl_core::ServerId;

use crate::sqlite::{
    BillingCycle, Result, ServerBilling, ServerBillingInput, ServerBillingItem, SqliteInventory,
    SqliteInventoryError,
};

impl SqliteInventory {
    /// Get the billing record for a server if configured.
    pub async fn get_server_billing(&self, sid: &ServerId) -> Result<Option<ServerBilling>> {
        let row = sqlx::query(
            "SELECT server_id, due_date, billing_cycle, amount_cents, currency, auto_renew, billing_url, notes, updated_at
             FROM server_billing
             WHERE server_id = ?1",
        )
        .bind(&sid.0)
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else {
            return Ok(None);
        };

        let cycle_str: String = r.try_get("billing_cycle")?;
        let cycle: BillingCycle = cycle_str.parse()?;
        let auto_renew: i64 = r.try_get("auto_renew")?;

        Ok(Some(ServerBilling {
            server_id: ServerId(r.try_get("server_id")?),
            due_date: r.try_get("due_date")?,
            billing_cycle: cycle,
            amount_cents: r.try_get("amount_cents")?,
            currency: r.try_get("currency")?,
            auto_renew: auto_renew == 1,
            billing_url: r.try_get("billing_url")?,
            notes: r.try_get("notes")?,
            updated_at: r.try_get("updated_at")?,
        }))
    }

    /// Set or update the billing record for a server.
    ///
    /// Validates that the server exists and that `due_date` is a valid ISO-8601 date (YYYY-MM-DD).
    pub async fn set_server_billing(
        &self,
        sid: &ServerId,
        input: &ServerBillingInput,
    ) -> Result<ServerBilling> {
        validate_due_date(&input.due_date)?;

        let mut tx = self.pool.begin().await?;

        // Server must exist
        let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM servers WHERE id = ?1")
            .bind(&sid.0)
            .fetch_optional(&mut *tx)
            .await?;

        if exists.is_none() {
            return Err(SqliteInventoryError::Invalid(format!(
                "server '{}' not found in inventory",
                sid.0
            )));
        }

        sqlx::query(
            "INSERT INTO server_billing (server_id, due_date, billing_cycle, amount_cents, currency, auto_renew, billing_url, notes, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
             ON CONFLICT(server_id) DO UPDATE SET
                due_date = excluded.due_date,
                billing_cycle = excluded.billing_cycle,
                amount_cents = excluded.amount_cents,
                currency = excluded.currency,
                auto_renew = excluded.auto_renew,
                billing_url = excluded.billing_url,
                notes = excluded.notes,
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        )
        .bind(&sid.0)
        .bind(&input.due_date)
        .bind(input.billing_cycle.as_str())
        .bind(input.amount_cents)
        .bind(&input.currency)
        .bind(if input.auto_renew { 1i64 } else { 0i64 })
        .bind(input.billing_url.as_deref())
        .bind(input.notes.as_deref())
        .execute(&mut *tx)
        .await?;

        let row = sqlx::query(
            "SELECT server_id, due_date, billing_cycle, amount_cents, currency, auto_renew, billing_url, notes, updated_at
             FROM server_billing
             WHERE server_id = ?1",
        )
        .bind(&sid.0)
        .fetch_one(&mut *tx)
        .await?;

        let updated = ServerBilling {
            server_id: ServerId(row.try_get("server_id")?),
            due_date: row.try_get("due_date")?,
            billing_cycle: input.billing_cycle,
            amount_cents: row.try_get("amount_cents")?,
            currency: row.try_get("currency")?,
            auto_renew: input.auto_renew,
            billing_url: row.try_get("billing_url")?,
            notes: row.try_get("notes")?,
            updated_at: row.try_get("updated_at")?,
        };

        // Write audit log
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES ('admin', 'server.billing.set', ?1, ?2)",
        )
        .bind(&sid.0)
        .bind(serde_json::to_string(&updated).unwrap_or_default())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(updated)
    }

    /// Advance the server's billing due date by its recurring cycle (+1 month, +3 months, etc.).
    pub async fn advance_server_billing_cycle(&self, sid: &ServerId) -> Result<ServerBilling> {
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query(
            "SELECT server_id, due_date, billing_cycle, amount_cents, currency, auto_renew, billing_url, notes, updated_at
             FROM server_billing
             WHERE server_id = ?1",
        )
        .bind(&sid.0)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(r) = row else {
            return Err(SqliteInventoryError::Invalid(format!(
                "billing record for server '{}' does not exist; configure billing before advancing",
                sid.0
            )));
        };

        let current_due: String = r.try_get("due_date")?;
        let cycle_str: String = r.try_get("billing_cycle")?;
        let cycle: BillingCycle = cycle_str.parse()?;
        let next_due = advance_date_by_cycle(&current_due, cycle)?;

        sqlx::query(
            "UPDATE server_billing
             SET due_date = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE server_id = ?2",
        )
        .bind(&next_due)
        .bind(&sid.0)
        .execute(&mut *tx)
        .await?;

        let updated_row = sqlx::query(
            "SELECT server_id, due_date, billing_cycle, amount_cents, currency, auto_renew, billing_url, notes, updated_at
             FROM server_billing
             WHERE server_id = ?1",
        )
        .bind(&sid.0)
        .fetch_one(&mut *tx)
        .await?;

        let auto_renew: i64 = updated_row.try_get("auto_renew")?;
        let updated = ServerBilling {
            server_id: ServerId(updated_row.try_get("server_id")?),
            due_date: updated_row.try_get("due_date")?,
            billing_cycle: cycle,
            amount_cents: updated_row.try_get("amount_cents")?,
            currency: updated_row.try_get("currency")?,
            auto_renew: auto_renew == 1,
            billing_url: updated_row.try_get("billing_url")?,
            notes: updated_row.try_get("notes")?,
            updated_at: updated_row.try_get("updated_at")?,
        };

        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES ('admin', 'server.billing.advance', ?1, ?2)",
        )
        .bind(&sid.0)
        .bind(
            serde_json::to_string(&serde_json::json!({
                "previous_due_date": current_due,
                "new_due_date": next_due,
                "cycle": cycle.as_str(),
            }))
            .unwrap_or_default(),
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(updated)
    }

    /// List billing records for all fleet servers, ordered by due_date ascending (earliest first),
    /// with unconfigured servers placed at the end.
    pub async fn list_fleet_billing(&self) -> Result<Vec<ServerBillingItem>> {
        let rows = sqlx::query(
            "SELECT s.id, s.display_name, s.hoster, s.address,
                    b.due_date, b.billing_cycle, b.amount_cents, b.currency, b.auto_renew, b.billing_url, b.notes, b.updated_at
             FROM servers s
             LEFT JOIN server_billing b ON b.server_id = s.id
             ORDER BY
                CASE WHEN b.due_date IS NULL THEN 1 ELSE 0 END,
                b.due_date ASC,
                s.id ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("id")?;
            let display_name: Option<String> = r.try_get("display_name")?;
            let hoster: String = r.try_get("hoster")?;
            let address: String = r.try_get("address")?;

            let billing = if let Some(due_date) = r.try_get::<Option<String>, _>("due_date")? {
                let cycle_str: String = r.try_get("billing_cycle")?;
                let auto_renew: i64 = r.try_get("auto_renew")?;
                Some(ServerBilling {
                    server_id: ServerId(sid.clone()),
                    due_date,
                    billing_cycle: cycle_str.parse()?,
                    amount_cents: r.try_get("amount_cents")?,
                    currency: r.try_get("currency")?,
                    auto_renew: auto_renew == 1,
                    billing_url: r.try_get("billing_url")?,
                    notes: r.try_get("notes")?,
                    updated_at: r.try_get("updated_at")?,
                })
            } else {
                None
            };

            items.push(ServerBillingItem {
                server_id: ServerId(sid),
                display_name,
                hoster,
                address,
                billing,
            });
        }

        Ok(items)
    }
}

/// Helper to validate YYYY-MM-DD date strings.
pub fn validate_due_date(s: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|e| {
        SqliteInventoryError::Invalid(format!("date must be in YYYY-MM-DD format: {e}"))
    })
}

/// Advance a date string by a billing cycle.
pub fn advance_date_by_cycle(date_str: &str, cycle: BillingCycle) -> Result<String> {
    let date = validate_due_date(date_str)?;
    let next = add_calendar_months(date, cycle.months());
    Ok(next.format("%Y-%m-%d").to_string())
}

fn add_calendar_months(d: NaiveDate, months: u32) -> NaiveDate {
    let mut year = d.year();
    let mut month = d.month() + months;
    while month > 12 {
        year += 1;
        month -= 12;
    }
    let mut day = d.day();
    loop {
        if let Some(date) = NaiveDate::from_ymd_opt(year, month, day) {
            return date;
        }
        day = day.saturating_sub(1);
    }
}
