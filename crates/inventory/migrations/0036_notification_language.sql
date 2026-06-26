-- Notification language — operator-selectable locale for Telegram
-- alert pushes + (future) the dashboard alert surfaces.
--
-- 'en' (the rendering default when NULL) or 'ru'. Part of the
-- notification-normalization work: alert_text::render_alert reads this
-- to push the SAME structured alert in the operator's language. Additive
-- + nullable so existing rows keep working (NULL → En).
ALTER TABLE notification_settings ADD COLUMN language TEXT;
