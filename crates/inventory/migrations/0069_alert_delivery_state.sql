-- Delivery bookkeeping is independent of operator acknowledgement and audit history.
ALTER TABLE admin_alerts ADD COLUMN telegram_delivered_at TEXT;
ALTER TABLE admin_alerts ADD COLUMN telegram_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admin_alerts ADD COLUMN telegram_next_attempt_at TEXT;
ALTER TABLE admin_alerts ADD COLUMN telegram_gave_up_at TEXT;

-- Existing message IDs prove delivery; never replay these after upgrading.
UPDATE admin_alerts
SET telegram_delivered_at = created_at
WHERE telegram_message_id IS NOT NULL;

CREATE INDEX idx_admin_alerts_telegram_pending
    ON admin_alerts(telegram_next_attempt_at, id)
    WHERE acked_at IS NULL AND telegram_delivered_at IS NULL
      AND telegram_gave_up_at IS NULL;
