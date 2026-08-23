//! Admin UI settings handlers — disaster recovery, GeoIP status, render/routes,
//! and Telegram/notification actions.

mod backups;
mod render;
mod system;
mod telegram;

pub(crate) use self::backups::settings_disaster_recovery_section;
pub(crate) use self::render::{
    SettingsTab, settings, settings_backups, settings_notifications, settings_system,
    settings_timezone_set,
};
pub(crate) use self::system::settings_geoip_section;
pub(crate) use self::telegram::{
    settings_digest_now, settings_notification_language, settings_telegram, settings_telegram_test,
};
