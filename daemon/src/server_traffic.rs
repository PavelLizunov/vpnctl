use vpnctl_core::ServerId;
use vpnctl_inventory::{
    NodeNicUsage, ServerTrafficLimit, SqliteInventory, SqliteInventoryError, server_traffic_period,
};

pub(crate) struct ServerTraffic {
    pub limit: Option<ServerTrafficLimit>,
    pub period_start: i64,
    pub period_end: i64,
    pub usage: Option<NodeNicUsage>,
    pub fresh: bool,
}

pub(crate) fn max_gap_seconds() -> u64 {
    crate::config::parse_positive_secs("VPNCTLD_NODE_PROBE_INTERVAL_SECS", 600)
        .saturating_mul(2)
        .saturating_add(120)
        .min(86_400)
}

impl ServerTraffic {
    pub(crate) async fn load(
        inv: &SqliteInventory,
        sid: &ServerId,
        now: i64,
    ) -> Result<Self, SqliteInventoryError> {
        let limit = inv.get_server_traffic_limit(sid).await?;
        let (period_start, period_end) =
            server_traffic_period(now, limit.as_ref().map_or(1, |l| l.reset_day))?;
        // Exactly at reset there is no non-empty observation window yet.
        let usage = if period_start < now {
            inv.node_nic_usage(sid, period_start, now, max_gap_seconds())
                .await?
        } else {
            None
        };
        let fresh = usage.as_ref().is_some_and(|u| {
            now.saturating_sub(u.last_sample_ts.timestamp()) as u64 <= max_gap_seconds()
        });
        Ok(Self {
            limit,
            period_start,
            period_end,
            usage,
            fresh,
        })
    }

    pub(crate) fn used_bytes(&self) -> Option<u64> {
        let u = self.usage.as_ref()?;
        Some(match self.limit.as_ref().map(|l| l.direction.as_str()) {
            Some("rx") => u.rx_bytes,
            Some("tx") => u.tx_bytes,
            _ => u.total_bytes,
        })
    }

    pub(crate) fn complete(&self) -> bool {
        self.fresh && self.usage.as_ref().is_some_and(|u| u.complete)
    }

    pub(crate) fn percent(&self) -> Option<u64> {
        let limit = self.limit.as_ref()?;
        Some(
            (u128::from(self.used_bytes()?) * 100 / u128::from(limit.limit_bytes))
                .min(u128::from(u64::MAX)) as u64,
        )
    }
}
