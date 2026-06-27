-- Traffic ground-truth: cumulative byte counters of each node's
-- default-route interface, captured by the node probe alongside the
-- existing infra telemetry. RAW cumulative values (not deltas) — the
-- gap computation diffs consecutive rows with a reboot/reset guard.
--
-- This is the SERVER-WIDE source of truth that catches ALL traffic on
-- the node (incl. non-sing-box protocols clash-api can't see: naive via
-- Caddy, dns-tunnel, wgturn), so the total reconciles with the hoster's
-- billing and the operator can see the attribution GAP. Additive +
-- nullable — existing rows + the 30-day retention are unaffected.
ALTER TABLE node_health ADD COLUMN nic_iface TEXT;
ALTER TABLE node_health ADD COLUMN nic_rx_bytes INTEGER;
ALTER TABLE node_health ADD COLUMN nic_tx_bytes INTEGER;
