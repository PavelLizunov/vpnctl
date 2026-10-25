-- Retention sweeps have no server/user filter; the existing compound indexes
-- start with server_id/user_id and cannot bound these global DELETE ranges.
CREATE INDEX idx_node_health_ts ON node_health (ts);
CREATE INDEX idx_server_quality_samples_ts ON server_quality_samples (ts);
CREATE INDEX idx_vpn_user_destinations_date ON vpn_user_destinations (date);
CREATE INDEX idx_vpn_user_source_ips_date ON vpn_user_source_ips (date);
-- Sessions expire by their last observation, regardless of their start date.
CREATE INDEX idx_vpn_user_sessions_last_seen ON vpn_user_sessions (last_seen);
