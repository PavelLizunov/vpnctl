-- `peak_concurrent_ips` changed from raw IPv4 /24 buckets to ISP-scale /16
-- buckets. This table is derived telemetry; old values cannot be converted
-- because it stores only the count, not the contributing IPs. Drop the stale
-- peaks once and let the five-minute poller repopulate them.
DELETE FROM vpn_user_ip_concurrency;
