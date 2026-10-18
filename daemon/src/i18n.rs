use axum::http::HeaderMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Locale {
    #[default]
    En,
    Ru,
}

impl Locale {
    pub fn from_request(headers: &HeaderMap) -> Self {
        for cookie_hdr in headers.get_all("cookie") {
            let Ok(raw) = cookie_hdr.to_str() else {
                continue;
            };
            for kv in raw.split(';') {
                let kv = kv.trim();
                if let Some(val) = kv.strip_prefix("vpnctl_lang=") {
                    return match val {
                        "ru" => Locale::Ru,
                        _ => Locale::En,
                    };
                }
            }
        }
        if let Some(al) = headers.get("accept-language").and_then(|v| v.to_str().ok()) {
            let first = al.split(',').next().unwrap_or("").trim();
            if first.starts_with("ru") {
                return Locale::Ru;
            }
        }
        Locale::En
    }

    pub fn from_lang_code(code: Option<&str>) -> Self {
        match code {
            Some("ru") => Locale::Ru,
            _ => Locale::En,
        }
    }

    pub fn cookie_value(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ru => "ru",
        }
    }

    pub fn html_lang(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ru => "ru",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum K {
    MastSubtitle,
    NavDashboard,
    NavMonitoring,
    NavServers,
    NavUsers,
    NavAudit,
    NavAlerts,
    NavSettings,
    NavBoosty,
    NavOperator,
    FootStack,

    BtnDeploy,
    BtnSave,
    BtnHide,
    BtnUnhide,
    BtnBlock,
    BtnUnblock,
    BtnDisable,
    BtnEnable,
    BtnAck,
    BtnFilter,
    BtnReset,
    BtnExportCsv,

    PageDashboard,
    PageMonitoring,
    PageServers,
    PageUsers,
    PageAudit,
    PageAlerts,
    PageSettings,
    EyebrowServerAccess,
    EyebrowEnabledProtocols,
    EyebrowHeavyUsers,
    EyebrowAlertsLimit,
    EyebrowLiveStats,
    EyebrowTrustedFingerprint,

    EyebrowKernelRollup,
    KernelRollupOnTarget,
    KernelRollupStale,
    KernelRollupNoData,

    EyebrowDriftDetail,

    EyebrowPresence,
}

pub fn tr(loc: Locale, en: &'static str, ru: &'static str) -> &'static str {
    match loc {
        Locale::En => en,
        Locale::Ru => ru,
    }
}

pub fn n_of(
    loc: Locale,
    n: u64,
    en_one: &'static str,
    en_many: &'static str,
    ru_one: &'static str,
    ru_few: &'static str,
    ru_many: &'static str,
) -> String {
    format!(
        "{n} {}",
        noun_for(loc, n, en_one, en_many, ru_one, ru_few, ru_many)
    )
}

pub fn noun_for(
    loc: Locale,
    n: u64,
    en_one: &'static str,
    en_many: &'static str,
    ru_one: &'static str,
    ru_few: &'static str,
    ru_many: &'static str,
) -> &'static str {
    match loc {
        Locale::En => {
            if n == 1 {
                en_one
            } else {
                en_many
            }
        }
        Locale::Ru => {
            let last_two = n % 100;
            let last = n % 10;
            if (11..=14).contains(&last_two) {
                ru_many
            } else if last == 1 {
                ru_one
            } else if (2..=4).contains(&last) {
                ru_few
            } else {
                ru_many
            }
        }
    }
}

pub fn t(loc: Locale, k: K) -> &'static str {
    use K::*;
    use Locale::*;
    match (loc, k) {
        (En, MastSubtitle) => "— a daily report from your fleet",
        (Ru, MastSubtitle) => "— ежедневный отчёт по твоему парку серверов",
        (En, NavDashboard) => "Dashboard",
        (Ru, NavDashboard) => "Дашборд",
        (En, NavMonitoring) => "Monitoring",
        (Ru, NavMonitoring) => "Мониторинг",
        (En, NavServers) => "Servers",
        (Ru, NavServers) => "Серверы",
        (En, NavUsers) => "Users",
        (Ru, NavUsers) => "Пользователи",
        (En, NavAudit) => "Audit",
        (Ru, NavAudit) => "Аудит",
        (En, NavAlerts) => "Alerts",
        (Ru, NavAlerts) => "Алерты",
        (En, NavSettings) => "Settings",
        (Ru, NavSettings) => "Настройки",
        (En, NavBoosty) | (Ru, NavBoosty) => "Boosty",
        (En, NavOperator) => "operator",
        (Ru, NavOperator) => "оператор",
        (En, FootStack) => "· axum + maud",
        (Ru, FootStack) => "· axum + maud",

        (En, BtnDeploy) => "deploy →",
        (Ru, BtnDeploy) => "деплой →",
        (En, BtnSave) => "save",
        (Ru, BtnSave) => "сохранить",
        (En, BtnHide) => "hide",
        (Ru, BtnHide) => "скрыть",
        (En, BtnUnhide) => "unhide",
        (Ru, BtnUnhide) => "показать",
        (En, BtnBlock) => "block",
        (Ru, BtnBlock) => "заблокировать",
        (En, BtnUnblock) => "unblock",
        (Ru, BtnUnblock) => "разблокировать",
        (En, BtnDisable) => "disable",
        (Ru, BtnDisable) => "выключить",
        (En, BtnEnable) => "enable",
        (Ru, BtnEnable) => "включить",
        (En, BtnAck) => "ack",
        (Ru, BtnAck) => "принять",
        (En, BtnFilter) => "filter",
        (Ru, BtnFilter) => "фильтр",
        (En, BtnReset) => "reset",
        (Ru, BtnReset) => "сброс",
        (En, BtnExportCsv) => "export csv",
        (Ru, BtnExportCsv) => "экспорт csv",

        (En, PageDashboard) => "Dashboard",
        (Ru, PageDashboard) => "Дашборд",
        (En, PageMonitoring) => "Monitoring",
        (Ru, PageMonitoring) => "Мониторинг",
        (En, PageServers) => "Servers",
        (Ru, PageServers) => "Серверы",
        (En, PageUsers) => "Users",
        (Ru, PageUsers) => "Пользователи",
        (En, PageAudit) => "Audit log",
        (Ru, PageAudit) => "Журнал аудита",
        (En, PageAlerts) => "Alerts",
        (Ru, PageAlerts) => "Алерты",
        (En, PageSettings) => "Settings",
        (Ru, PageSettings) => "Настройки",
        (En, EyebrowServerAccess) => "Server access",
        (Ru, EyebrowServerAccess) => "Доступ к серверам",
        (En, EyebrowEnabledProtocols) => "Enabled protocols",
        (Ru, EyebrowEnabledProtocols) => "Включённые протоколы",
        (En, EyebrowHeavyUsers) => "Heavy users · last 24h",
        (Ru, EyebrowHeavyUsers) => "Тяжёлые пользователи · за 24ч",
        (En, EyebrowAlertsLimit) => "Limit alerts",
        (Ru, EyebrowAlertsLimit) => "Лимит-алерты",
        (En, EyebrowLiveStats) => "Live VPN stats · last 24h",
        (Ru, EyebrowLiveStats) => "Живая статистика VPN · за 24ч",
        (En, EyebrowTrustedFingerprint) => "Trusted host fingerprint",
        (Ru, EyebrowTrustedFingerprint) => "Доверенный отпечаток хоста",

        (En, EyebrowKernelRollup) => "Kernel rollup · sing-box",
        (Ru, EyebrowKernelRollup) => "Версии ядер · sing-box",
        (En, KernelRollupOnTarget) => "on target",
        (Ru, KernelRollupOnTarget) => "на целевой",
        (En, KernelRollupStale) => "stale",
        (Ru, KernelRollupStale) => "устаревших",
        (En, KernelRollupNoData) => {
            "No on-node version data yet — versions land on the next health probe."
        }
        (Ru, KernelRollupNoData) => {
            "Версий с нод ещё нет — появятся на следующей проверке здоровья."
        }

        (En, EyebrowDriftDetail) => "Drift detail · on-node UUIDs",
        (Ru, EyebrowDriftDetail) => "Детальный дрейф · UUID на ноде",

        (En, EyebrowPresence) => "Presence",
        (Ru, EyebrowPresence) => "Присутствие",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            let name = axum::http::header::HeaderName::from_bytes(k.as_bytes())
                .expect("test header name must be ASCII");
            let val = axum::http::HeaderValue::from_str(v)
                .expect("test header value must be valid bytes");
            h.append(name, val);
        }
        h
    }

    #[test]
    fn default_locale_is_en() {
        assert_eq!(Locale::from_request(&hm(&[])), Locale::En);
    }

    #[test]
    fn from_lang_code_maps_ru_else_en() {
        assert_eq!(Locale::from_lang_code(Some("ru")), Locale::Ru);
        assert_eq!(Locale::from_lang_code(Some("en")), Locale::En);
        assert_eq!(Locale::from_lang_code(Some("de")), Locale::En);
        assert_eq!(Locale::from_lang_code(Some("")), Locale::En);
        assert_eq!(Locale::from_lang_code(None), Locale::En);
    }

    #[test]
    fn cookie_wins_over_accept_language() {
        assert_eq!(
            Locale::from_request(&hm(&[
                ("cookie", "vpnctl_lang=ru; other=foo"),
                ("accept-language", "en-US,en;q=0.9"),
            ])),
            Locale::Ru
        );
        assert_eq!(
            Locale::from_request(&hm(&[
                ("cookie", "vpnctl_lang=en"),
                ("accept-language", "ru-RU,ru;q=0.9"),
            ])),
            Locale::En
        );
    }

    #[test]
    fn accept_language_ru_picks_ru() {
        assert_eq!(
            Locale::from_request(&hm(&[("accept-language", "ru-RU,ru;q=0.9,en;q=0.8")])),
            Locale::Ru
        );
        assert_eq!(
            Locale::from_request(&hm(&[("accept-language", "ru")])),
            Locale::Ru
        );
    }

    #[test]
    fn accept_language_en_picks_en() {
        assert_eq!(
            Locale::from_request(&hm(&[("accept-language", "en-US,en;q=0.9")])),
            Locale::En
        );
    }

    #[test]
    fn unknown_cookie_value_falls_back_to_en() {
        assert_eq!(
            Locale::from_request(&hm(&[("cookie", "vpnctl_lang=de")])),
            Locale::En
        );
    }

    #[test]
    fn malformed_cookie_doesnt_panic() {
        assert_eq!(
            Locale::from_request(&hm(&[("cookie", "vpnctl_lang")])),
            Locale::En
        );
        assert_eq!(
            Locale::from_request(&hm(&[("cookie", "foo=bar; vpnctl_lang=ru; baz=qux")])),
            Locale::Ru
        );
    }

    #[test]
    fn multi_cookie_header_first_match() {
        assert_eq!(
            Locale::from_request(&hm(&[
                ("cookie", "other=123; vpnctl_lang=ru"),
                ("cookie", "vpnctl_lang=en"),
            ])),
            Locale::Ru
        );
        assert_eq!(
            Locale::from_request(&hm(&[("cookie", "foo=bar"), ("cookie", "vpnctl_lang=ru"),])),
            Locale::Ru
        );
    }

    #[test]
    fn tr_inline_helper_selects_by_locale() {
        assert_eq!(tr(Locale::En, "Hello", "Привет"), "Hello");
        assert_eq!(tr(Locale::Ru, "Hello", "Привет"), "Привет");
    }

    #[test]
    fn translation_table_covers_every_key_for_both_locales() {
        let pairs = [
            (K::NavDashboard, "Dashboard", "Дашборд"),
            (K::NavServers, "Servers", "Серверы"),
            (K::NavSettings, "Settings", "Настройки"),
            (K::BtnDeploy, "deploy →", "деплой →"),
            (K::BtnHide, "hide", "скрыть"),
            (K::BtnSave, "save", "сохранить"),
            (K::EyebrowServerAccess, "Server access", "Доступ к серверам"),
            (
                K::EyebrowDriftDetail,
                "Drift detail · on-node UUIDs",
                "Детальный дрейф · UUID на ноде",
            ),
            (K::EyebrowPresence, "Presence", "Присутствие"),
        ];
        for (k, en, ru) in pairs {
            assert_eq!(t(Locale::En, k), en, "EN mismatch for {k:?}");
            assert_eq!(t(Locale::Ru, k), ru, "RU mismatch for {k:?}");
            assert_ne!(en, ru, "expected EN != RU for {k:?}");
        }
    }

    #[test]
    fn n_of_declines_english_by_one_vs_many() {
        let f = |n| {
            n_of(
                Locale::En,
                n,
                "country",
                "countries",
                "страна",
                "страны",
                "стран",
            )
        };
        assert_eq!(f(1), "1 country");
        assert_eq!(f(2), "2 countries");
        assert_eq!(f(0), "0 countries");
    }

    #[test]
    fn n_of_declines_russian_three_forms_including_teens() {
        let f = |n| {
            n_of(
                Locale::Ru,
                n,
                "country",
                "countries",
                "страна",
                "страны",
                "стран",
            )
        };
        assert_eq!(f(1), "1 страна");
        assert_eq!(f(2), "2 страны");
        assert_eq!(f(4), "4 страны");
        assert_eq!(f(5), "5 стран");
        assert_eq!(f(11), "11 стран", "11 is teens → many, not one");
        assert_eq!(f(12), "12 стран", "12 is teens → many, not few");
        assert_eq!(f(21), "21 страна");
        assert_eq!(f(22), "22 страны");
        assert_eq!(f(111), "111 стран");
        assert_eq!(f(33), "33 страны");
    }
}
