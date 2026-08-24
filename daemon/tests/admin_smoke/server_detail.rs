//! Admin UI server detail integration smoke tests partitioned by domain.

#[path = "server_detail/drift_traffic.rs"]
mod drift_traffic;
#[path = "server_detail/kernels.rs"]
mod kernels;
#[path = "server_detail/overview_telemetry.rs"]
mod overview_telemetry;
#[path = "server_detail/protocols.rs"]
mod protocols;
#[path = "server_detail/setup_config.rs"]
mod setup_config;
