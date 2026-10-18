use std::collections::HashSet;
use std::path::Path;

use crate::sqlite::SqliteInventoryError;

use super::listing::list_snapshots;

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

pub fn prune_snapshots(dir: &Path, policy: Retention) -> Result<u64, SqliteInventoryError> {
    let snapshots = list_snapshots(dir)?;
    let mut kept_hourly = 0usize;
    let mut kept_daily_days: HashSet<String> = HashSet::new();
    let mut kept_monthly_months: HashSet<String> = HashSet::new();
    let mut removed = 0u64;

    for snap in snapshots {
        let Some(ts) = snap.created.as_deref() else {
            continue;
        };
        let mut keep = false;
        if kept_hourly < policy.keep_hourly {
            kept_hourly = kept_hourly.saturating_add(1);
            keep = true;
        }
        if let Some((day, _)) = ts.split_once('T')
            && kept_daily_days.len() < policy.keep_daily
            && kept_daily_days.insert(day.to_string())
        {
            keep = true;
        }
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
