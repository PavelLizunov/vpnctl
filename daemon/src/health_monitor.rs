mod diff;
mod fingerprint_drift;
mod poller;
mod remediation;
mod specialized_checks;

#[cfg(test)]
mod tests;

pub use diff::{AlertEvent, diff_rows};
pub(crate) use diff::{
    DISK_PRESSURE_TRIGGER_PCT, MEM_PRESSURE_TRIGGER_PCT, SINGBOX_LOG_TRIGGER_BYTES,
};
pub use fingerprint_drift::check_fingerprint_drift;
pub use poller::{scan_once, spawn_health_monitor};
pub use specialized_checks::{
    check_attribution_stall, check_sub_fetch_without_traffic, check_user_traffic_limits,
};
