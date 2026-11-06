use vpnctl_core::ServerId;

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::Result;

impl SqliteInventory {
    /// Full observed interface traffic, including unattributed and non-VPN bytes.
    pub async fn node_activity_bytes(
        &self,
        server_id: &ServerId,
        now: i64,
        max_age_seconds: u64,
    ) -> Result<Option<u64>> {
        if max_age_seconds == 0 {
            return Ok(None);
        }
        let Some(start) = now.checked_sub(86_400) else {
            return Ok(None);
        };
        let Some(usage) = self
            .node_nic_usage(server_id, start, now, max_age_seconds)
            .await?
        else {
            return Ok(None);
        };
        Ok((!usage.interrupted
            && usage.observed_hours >= 20
            && now.saturating_sub(usage.last_sample_ts.timestamp()) as u64 <= max_age_seconds)
            .then_some(usage.total_bytes))
    }
}
