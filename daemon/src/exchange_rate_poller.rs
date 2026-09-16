use std::time::Duration;

use serde::Deserialize;
use vpnctl_inventory::{CurrencyRate, SqliteInventory};

/// Primary public exchange rate API (open source, no key, 205 currencies including RUB).
const PRIMARY_RATES_URL: &str = "https://api.frankfurter.dev/v2/rates?base=EUR";

/// Secondary fallback exchange rate API (open, no key, 161 currencies).
const FALLBACK_RATES_URL: &str = "https://open.er-api.com/v6/latest/EUR";

/// Default periodic refresh interval: 12 hours.
const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 12 * 3600;

#[derive(Debug, Deserialize)]
struct FrankfurterEntry {
    quote: String,
    rate: f64,
}

#[derive(Debug, Deserialize)]
struct OpenErApiResponse {
    rates: Option<std::collections::HashMap<String, f64>>,
}

/// Fetch exchange rates from the primary or fallback public provider and store them in SQLite.
pub async fn refresh_exchange_rates(inv: &SqliteInventory) -> anyhow::Result<usize> {
    refresh_exchange_rates_from_urls(inv, PRIMARY_RATES_URL, FALLBACK_RATES_URL).await
}

/// Ingest exchange rates using explicit URLs.
pub async fn refresh_exchange_rates_from_urls(
    inv: &SqliteInventory,
    primary_url: &str,
    fallback_url: &str,
) -> anyhow::Result<usize> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;

    // 1. Try Primary
    let (rates, provider) = match fetch_frankfurter_from_url(&client, primary_url).await {
        Ok(r) if !r.is_empty() => (r, "frankfurter"),
        Ok(_) | Err(_) => {
            // 2. Try Fallback
            match fetch_open_er_api_from_url(&client, fallback_url).await {
                Ok(r) if !r.is_empty() => (r, "open-er-api"),
                Ok(_) => anyhow::bail!("both exchange rate providers returned empty rates"),
                Err(e) => anyhow::bail!("failed to fetch exchange rates from both providers: {e}"),
            }
        }
    };

    let now_utc = chrono::Utc::now().to_rfc3339();
    let mut stored_count = 0usize;

    for (quote, rate_f64) in rates {
        if rate_f64 <= 0.0 || !rate_f64.is_finite() {
            continue;
        }
        let rate_micros = (rate_f64 * 1_000_000.0).round() as i64;
        if rate_micros <= 0 {
            continue;
        }

        let rate_row = CurrencyRate {
            base_currency: "EUR".to_string(),
            target_currency: quote.to_uppercase(),
            rate_micros,
            source: provider.to_string(),
            fetched_at: now_utc.clone(),
        };

        if let Err(e) = inv.upsert_currency_rate(&rate_row).await {
            tracing::warn!(target = "vpnctld::currency", error = %e, quote = %quote, "failed to upsert exchange rate");
        } else {
            stored_count += 1;
        }
    }

    tracing::info!(
        target = "vpnctld::currency",
        provider = %provider,
        count = stored_count,
        "successfully refreshed exchange rates"
    );

    Ok(stored_count)
}

async fn fetch_frankfurter_from_url(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<Vec<(String, f64)>> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("frankfurter returned HTTP status {}", resp.status());
    }
    let body = resp.text().await?;
    let entries: Vec<FrankfurterEntry> = serde_json::from_str(&body)?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        out.push((e.quote, e.rate));
    }
    Ok(out)
}

async fn fetch_open_er_api_from_url(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<Vec<(String, f64)>> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("open-er-api returned HTTP status {}", resp.status());
    }
    let body = resp.text().await?;
    let data: OpenErApiResponse = serde_json::from_str(&body)?;
    let rates_map = data
        .rates
        .ok_or_else(|| anyhow::anyhow!("missing rates object in open-er-api response"))?;
    Ok(rates_map.into_iter().collect())
}

/// Spawn the background currency exchange rates poller.
pub fn spawn_exchange_rate_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(DEFAULT_REFRESH_INTERVAL_SECS));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Consume immediate first tick so interval doesn't double-fire
        tick.tick().await;

        tokio::time::sleep(Duration::from_secs(30)).await;

        let should_initial = match inv.get_currency_settings().await {
            Ok(s) => s.auto_refresh,
            Err(_) => false,
        };

        if should_initial {
            if let Err(e) = refresh_exchange_rates(&inv).await {
                tracing::warn!(
                    target = "vpnctld::currency",
                    error = %e,
                    "initial exchange rate refresh failed; cached rates will be used"
                );
            }
        }
        if let Err(e) = inv.advance_auto_renew_servers().await {
            tracing::warn!(
                target = "vpnctld::currency",
                error = %e,
                "initial auto-advance of server billing cycles failed"
            );
        }

        loop {
            tick.tick().await;

            let should_refresh = match inv.get_currency_settings().await {
                Ok(s) => s.auto_refresh,
                Err(_) => false,
            };

            if should_refresh {
                if let Err(e) = refresh_exchange_rates(&inv).await {
                    tracing::warn!(
                        target = "vpnctld::currency",
                        error = %e,
                        "periodic exchange rate refresh failed; existing cached rates preserved"
                    );
                }
            }
            if let Err(e) = inv.advance_auto_renew_servers().await {
                tracing::warn!(
                    target = "vpnctld::currency",
                    error = %e,
                    "periodic auto-advance of server billing cycles failed"
                );
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn refresh_exchange_rates_fallback_on_primary_failure() {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .expect("open");

        // Use invalid URL for primary to trigger fallback
        let invalid_primary = "http://127.0.0.1:9/invalid-primary";
        let invalid_fallback = "http://127.0.0.1:9/invalid-fallback";

        let result =
            refresh_exchange_rates_from_urls(&inv, invalid_primary, invalid_fallback).await;
        assert!(result.is_err(), "both failing URLs must yield an error");

        // Existing rates remain intact (empty or existing)
        let rates = inv.list_currency_rates().await.unwrap();
        assert!(rates.is_empty());
    }
}
