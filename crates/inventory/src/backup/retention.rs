use std::collections::HashSet;
use std::path::Path;

use crate::sqlite::SqliteInventoryError;

use super::listing::list_snapshots;

/// Retention policy applied by `prune_snapshots`. Each field caps
/// how many snapshots survive in that age bucket:
///
///   * `keep_hourly` — keep the N newest snapshots regardless of
///     date,
///   * `keep_daily` — additionally, keep one-per-day for the N
///     newest distinct days,
///   * `keep_monthly` — additionally, keep one-per-month for the N
///     newest distinct months.
///
/// Default (`Retention::default`) is `24h / 30d / 12mo` — enough to
/// roll back a same-day mistake AND a month-old "what was the
/// inventory like before the bash migration" question without
/// running out of disk on a 4 GB partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    pub keep_hourly: usize,
    pub keep_daily: usize,
    pub keep_monthly: usize,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            keep_hourly: 24,
            keep_daily: 30,
            keep_monthly: 12,
        }
    }
}

/// Drop snapshots that don't fit the retention policy. Returns the
/// number of files removed.
///
/// Algorithm: walk snapshots newest→oldest, classify each into the
/// hourly / daily / monthly bucket. Keep it if its bucket isn't full
/// yet; otherwise delete. Files without a parseable timestamp are
/// LEFT ALONE — operator-dropped files / manually-renamed snapshots
/// shouldn't get nuked by the scheduler.
pub fn prune_snapshots(dir: &Path, policy: Retention) -> Result<u64, SqliteInventoryError> {
    let snapshots = list_snapshots(dir)?;
    let mut kept_hourly = 0usize;
    let mut kept_daily_days: HashSet<String> = HashSet::new();
    let mut kept_monthly_months: HashSet<String> = HashSet::new();
    let mut removed = 0u64;

    for snap in snapshots {
        let Some(ts) = snap.created.as_deref() else {
            // Stray / non-vpnctl file: leave alone.
            continue;
        };
        let mut keep = false;
        // Hourly bucket: the N most recent snapshots, regardless of date.
        if kept_hourly < policy.keep_hourly {
            kept_hourly = kept_hourly.saturating_add(1);
            keep = true;
        }
        // Daily bucket: first snapshot we see for each YYYY-MM-DD.
        if let Some((day, _)) = ts.split_once('T')
            && kept_daily_days.len() < policy.keep_daily
            && kept_daily_days.insert(day.to_string())
        {
            keep = true;
        }
        // Monthly bucket: first snapshot per YYYY-MM.
        if ts.len() >= 7
            && let Some(month) = ts.get(..7)
            && kept_monthly_months.len() < policy.keep_monthly
            && kept_monthly_months.insert(month.to_string())
        {
            keep = true;
        }
        if !keep {
            std::fs::remove_file(&snap.path).map_err(|e| {
                SqliteInventoryError::Invalid(format!(
                    "remove old snapshot {}: {e}",
                    snap.path.display()
                ))
            })?;
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}
