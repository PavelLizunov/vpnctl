-- Telegram message id of the push for an alert — lets a later recovery
-- EDIT the original 🔴 message in place (🔴→🟢) via editMessageText
-- instead of sending a second "recovered" message. Additive + nullable:
-- a push that never happened (transport off) leaves it NULL, and the
-- recovery path falls back to a fresh message.
ALTER TABLE admin_alerts ADD COLUMN telegram_message_id TEXT;
