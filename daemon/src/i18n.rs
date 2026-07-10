//! Lightweight bilingual (en / ru) i18n for the vpnctld admin UI.
//!
//! Pavel 2026-05-21: «добавил русскую версию … сделал подсказки по
//! каждому пункту чтоб всем было понятно как пользоваться». Pavel is
//! the only operator, but he prefers a Russian admin shell + every
//! actionable element wears an explainer. This module is the
//! mechanism; the actual translation table lives in `t()` below.
//!
//! ── Design ───────────────────────────────────────────────────────────
//!
//! 1. **Locale enum** — `En` (default) and `Ru`. No runtime allocation:
//!    everything is `&'static str` indexed by `(Locale, K)` enum tuple.
//!
//! 2. **`K` (key) enum** — every user-visible string that gets
//!    translated has a key here. Adding `K::Foo` without populating
//!    both arms of `t()` is a compile error (exhaustive match), which
//!    means future operators can't silently ship a half-translated
//!    page.
//!
//! 3. **Locale detection** — `from_request(&HeaderMap)` looks at, in
//!    order:
//!    a. `Cookie: vpnctl_lang=ru` (operator's explicit choice)
//!    b. `Accept-Language: ru*` (browser hint)
//!    c. fallback `En`
//!
//! 4. **Operator toggle** — `[EN | RU]` chip in the masthead. Clicking
//!    `POST /admin/tweak/lang/<en|ru>` sets the cookie + 303 redirects
//!    back via the Referer (same pattern as the theme tweaks).
//!
//! ── Coverage ─────────────────────────────────────────────────────────
//!
//! First wave (this commit): nav items, footer, masthead subtitle, top-
//! level page H1s + eyebrows on Dashboard / Servers / Users / Audit /
//! Alerts / Settings, common action buttons (deploy, save, hide,
//! unhide, block, unblock, regen, ack).
//!
//! Strings still in English-only after this commit: body copy, error
//! messages, dense table contents, wizard SSE log lines. Those follow
//! in incremental passes — each can extend `K` and `t()` without
//! touching the shell or cookie plumbing.
//!
//! Mixed locale on hover: where a tooltip already exists in English
//! (typical case: 12 buttons + form fields added in `cd644b2`), the
//! tooltip stays English for now — translating those is part of the
//! body-copy wave.

use axum::http::HeaderMap;

/// User-visible language. Add a variant here ONLY if you can populate
/// every arm of `t()` for it; the exhaustive match in `t()` will fail
/// to compile otherwise (intentional safety net).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Locale {
    #[default]
    En,
    Ru,
}

impl Locale {
    /// Parse the operator's language preference from the request.
    /// Cookie wins over `Accept-Language` (explicit > inferred).
    pub fn from_request(headers: &HeaderMap) -> Self {
        // 1. Cookie. We hand-parse instead of pulling tower-cookies —
        //    one cookie, one shape, no need for a crate.
        if let Some(cookie_hdr) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
            for kv in cookie_hdr.split(';') {
                let kv = kv.trim();
                if let Some(val) = kv.strip_prefix("vpnctl_lang=") {
                    return match val {
                        "ru" => Locale::Ru,
                        _ => Locale::En,
                    };
                }
            }
        }
        // 2. Accept-Language. Cheap: just check the first 2 chars of
        //    the first language tag. Real RFC-7231 parsing is
        //    overkill — browsers send q-values + region codes, but
        //    `ru-RU,en;q=0.9` still starts with `ru` and we want Ru.
        if let Some(al) = headers.get("accept-language").and_then(|v| v.to_str().ok()) {
            let first = al.split(',').next().unwrap_or("").trim();
            if first.starts_with("ru") {
                return Locale::Ru;
            }
        }
        // 3. Default.
        Locale::En
    }

    /// Resolve a stored language code (e.g. `notification_settings.language`)
    /// into a `Locale`. `Some("ru")` → Russian; everything else
    /// (including `None` and unknown codes) → English. Used by the
    /// alert-push path + the notification-language settings control.
    pub fn from_lang_code(code: Option<&str>) -> Self {
        match code {
            Some("ru") => Locale::Ru,
            _ => Locale::En,
        }
    }

    /// The cookie value to set when the operator picks this locale.
    /// Used by the `/admin/tweak/lang/<x>` handler.
    pub fn cookie_value(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ru => "ru",
        }
    }

    /// Two-char tag for `<html lang="...">`. Browsers + screen readers
    /// honour this for hyphenation + voice selection.
    pub fn html_lang(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ru => "ru",
        }
    }
}

/// Translation keys. Adding a variant here forces a compile-time
/// failure in `t()` until every locale has an arm — that's the whole
/// point. Grouped by surface (Nav, Mast, Foot, Dash, …) for ergonomic
/// `match` patterns.
#[derive(Clone, Copy, Debug)]
pub enum K {
    // Masthead + nav + footer (rendered on every page)
    MastSubtitle,
    NavDashboard,
    NavMonitoring,
    NavServers,
    NavUsers,
    NavAudit,
    NavAlerts,
    NavSettings,
    NavBoosty,
    NavOperator, // "operator pavel" tagline
    FootStack,   // "axum + maud"

    // Common action buttons used on multiple pages.
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

    // Page-level H1s and section eyebrows.
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

    // PR-Dash informativeness cards. `KernelRollup*` back the shared
    // `kernel_floor_rollup` helper (PR-Server reuses it on the server
    // detail page), so they live in the central registry rather than
    // inline `tr()` — a single source of truth keeps the two surfaces
    // from drifting.
    EyebrowKernelRollup,
    KernelRollupOnTarget, // "on target" / "на целевой" (one server at floor)
    KernelRollupStale,    // "stale" / "устаревших" (servers below floor)
    KernelRollupNoData,   // "no version data yet" empty-state line

    // PR-Server informativeness cards on the server-detail page. Only
    // the drift-detail headline earns a `K` entry: it's the highest-
    // risk card (the only one that does a live SSH read), so pinning
    // its eyebrow centrally — and extending the i18n RU walker with it
    // — guards the operator-action-policy copy from drifting. The
    // remaining PR-Server cards use inline `tr()` (one-off paragraph
    // copy that appears exactly once).
    EyebrowDriftDetail, // "Drift detail · on-node UUIDs" / RU

    // PR-User informativeness cards on the user-detail page. The
    // online-now badge (user#1) always renders — 🟢-online or
    // offline-with-last-seen — so its eyebrow is the reliable RU-walker
    // anchor for the new user-detail surface, mirroring why
    // `EyebrowDriftDetail` earns a central entry on the server page. The
    // other six PR-User cards use inline `tr()` (one-off copy each).
    EyebrowPresence, // "Presence" / "Присутствие"
}

/// Inline-translation helper for the long tail of body copy that
/// doesn't deserve its own `K` enum entry. Trade-off vs `t()`:
///
/// - `t(loc, K::Foo)` — central registry, compile-time exhaustive,
///   ideal for re-used strings (nav items, action buttons).
/// - `tr(loc, "Foo", "Фу")` — inline pair, no registry overhead,
///   ideal for one-off paragraph copy + form labels that appear
///   exactly once in the templates.
///
/// Both args are `&'static str` to guarantee zero allocation.
/// Adding a new site uses `tr()`; promoting one to `K` makes sense
/// once it appears in 2+ places.
pub fn tr(loc: Locale, en: &'static str, ru: &'static str) -> &'static str {
    match loc {
        Locale::En => en,
        Locale::Ru => ru,
    }
}

/// `"{n} {noun}"` with the noun correctly declined for the count in
/// both locales — before this every counted noun was glued in one
/// fixed form («1 ASNs», «42 юзеров», «33 открытых алертов»), which is
/// exactly the kind of micro-sloppiness the editorial voice can't
/// afford (design review 2026-07-10).
///
/// * EN picks `en_one` for n == 1, `en_many` otherwise.
/// * RU picks `ru_one` for 1/21/31… (but not 11), `ru_few` for
///   2–4/22–24… (but not 12–14), `ru_many` for everything else —
///   the standard three-form rule.
///
/// All six forms are `&'static str`; only the final concatenation
/// allocates.
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

/// The bare declined noun for `n` — for call sites that already render
/// the number themselves (bold counters, tile values).
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

/// Translation lookup. Exhaustive — adding a `K` variant without
/// translating it for both locales is a compile error.
pub fn t(loc: Locale, k: K) -> &'static str {
    use K::*;
    use Locale::*;
    match (loc, k) {
        // ── Masthead / nav / footer ─────────────────────────────────
        (En, MastSubtitle) => "— a daily report from your homelab",
        (Ru, MastSubtitle) => "— ежедневный отчёт по твоей домашней лаборатории",
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
        // Brand name — identical in both locales.
        (En, NavBoosty) | (Ru, NavBoosty) => "Boosty",
        (En, NavOperator) => "homelab · operator pavel",
        (Ru, NavOperator) => "homelab · оператор pavel",
        (En, FootStack) => "· axum + maud",
        (Ru, FootStack) => "· axum + maud",

        // ── Common buttons ──────────────────────────────────────────
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

        // ── Page titles + eyebrows ──────────────────────────────────
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

        // ── PR-Dash kernel rollup (shared with the server detail page) ──
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

        // ── PR-Server drift-detail (server-detail page) ─────────────
        (En, EyebrowDriftDetail) => "Drift detail · on-node UUIDs",
        (Ru, EyebrowDriftDetail) => "Детальный дрейф · UUID на ноде",

        // ── PR-User presence badge (user-detail page) ───────────────
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
            h.insert(name, val);
        }
        h
    }

    #[test]
    fn default_locale_is_en() {
        assert_eq!(Locale::from_request(&hm(&[])), Locale::En);
    }

    #[test]
    fn from_lang_code_maps_ru_else_en() {
        // Drives notification-language resolution for alert pushes.
        assert_eq!(Locale::from_lang_code(Some("ru")), Locale::Ru);
        assert_eq!(Locale::from_lang_code(Some("en")), Locale::En);
        // Unknown code + absent → English (never panics, never Ru-by-accident).
        assert_eq!(Locale::from_lang_code(Some("de")), Locale::En);
        assert_eq!(Locale::from_lang_code(Some("")), Locale::En);
        assert_eq!(Locale::from_lang_code(None), Locale::En);
    }

    #[test]
    fn cookie_wins_over_accept_language() {
        // Cookie says ru, A-L says en → cookie wins.
        assert_eq!(
            Locale::from_request(&hm(&[
                ("cookie", "vpnctl_lang=ru; other=foo"),
                ("accept-language", "en-US,en;q=0.9"),
            ])),
            Locale::Ru
        );
        // Cookie says en, A-L says ru → cookie wins.
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
        // No `=` → not a valid cookie pair, skipped.
        assert_eq!(
            Locale::from_request(&hm(&[("cookie", "vpnctl_lang")])),
            Locale::En
        );
        // Multiple cookies, one valid: still picks up the right one.
        assert_eq!(
            Locale::from_request(&hm(&[("cookie", "foo=bar; vpnctl_lang=ru; baz=qux")])),
            Locale::Ru
        );
    }

    #[test]
    fn tr_inline_helper_selects_by_locale() {
        // tr() is the workhorse for body-copy translation — pin both
        // arms so a future locale addition (or accidental swap) shows
        // up here.
        assert_eq!(tr(Locale::En, "Hello", "Привет"), "Hello");
        assert_eq!(tr(Locale::Ru, "Hello", "Привет"), "Привет");
    }

    #[test]
    fn translation_table_covers_every_key_for_both_locales() {
        // If the exhaustive match in `t()` is missing an arm this
        // file wouldn't compile — this test exists to surface a
        // spot-check of representative keys + their non-empty,
        // distinct values per locale.
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
