-- Phase G follow-up — replace the unacked partial index column.
--
-- 0011 created `idx_admin_alerts_unacked ON admin_alerts(id) WHERE
-- acked_at IS NULL`. SQLite already includes the rowid implicitly
-- in every index, so storing `id` was redundant — same query plan,
-- larger footprint (~16 B/row vs ~8 B). Caught by review-agent on
-- the burst sweep; can't edit 0011 in place because sqlx verifies
-- the checksum on every startup («migration N was previously
-- applied but has been modified» = hard crash).
--
-- Drop + recreate is safe — no data lives in an index. Old index
-- and new index produce identical query plans for the dashboard
-- tile's COUNT(*) WHERE acked_at IS NULL, so there's no read-side
-- regression risk during the swap.

DROP INDEX IF EXISTS idx_admin_alerts_unacked;

CREATE INDEX IF NOT EXISTS idx_admin_alerts_unacked
    ON admin_alerts(acked_at) WHERE acked_at IS NULL;
