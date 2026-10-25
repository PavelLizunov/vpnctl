use crate::handlers::admin::icons::icon;
use maud::Markup;

use crate::handlers::admin::helpers::format_msk_iso;

pub(crate) fn settings_geoip_section(lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    let dir = std::env::var_os("VPNCTLD_GEOIP_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/vpnctl/geoip"));
    let city = dir.join("GeoLite2-City.mmdb");
    let asn = dir.join("GeoLite2-ASN.mmdb");
    let describe = |p: &std::path::Path| -> Option<(u64, String)> {
        let meta = std::fs::metadata(p).ok()?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                    .map(format_msk_iso)
                    .unwrap_or_else(|| "?".to_string())
            })
            .unwrap_or_else(|| "?".to_string());
        Some((size, mtime))
    };
    let city_meta = describe(&city);
    let asn_meta = describe(&asn);
    let any_loaded = city_meta.is_some() || asn_meta.is_some();
    maud::html! {
        div #geoip.ed-art-eyebrow {
            (tr(lang, "GeoIP — IP enrichment", "GeoIP — обогащение IP-адресов"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "When the DB-IP Lite (or MaxMind GeoLite2) MMDB files are present in this dir, every new sub_access_log row is enriched with country ISO + ASN before being persisted. Old rows + dimensions the DB doesn't recognise stay NULL — render falls back to bare IP. The DBs are queried OFFLINE — no network requests during request handling.",
                "Когда в этой папке лежат файлы DB-IP Lite (или MaxMind GeoLite2) в формате MMDB, каждая новая строка sub_access_log обогащается ISO-кодом страны + ASN перед сохранением. Старые строки и dimensions, которые DB не распознала, остаются NULL — рендер откатывается к голому IP. БД читаются ОФФЛАЙН — никаких сетевых запросов на пути запроса.",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            div { (tr(lang, "dir   ", "папка ")) (dir.display()) }
            div {
                "City  "
                @match &city_meta {
                    Some((size, mtime)) => {
                        b style="color: var(--soft);" {
                            (tr(lang, "present", "загружен"))
                        }
                        " · " (size) " " (tr(lang, "bytes", "байт"))
                        " · " (tr(lang, "modified ", "изменён "))
                        (mtime)
                    }
                    None => {
                        em style="color: var(--mute);" {
                            (tr(lang, "(missing — use the «update now» button below)", "(отсутствует — нажми «обновить сейчас» ниже)"))
                        }
                    }
                }
            }
            div {
                "ASN   "
                @match &asn_meta {
                    Some((size, mtime)) => {
                        b style="color: var(--soft);" {
                            (tr(lang, "present", "загружен"))
                        }
                        " · " (size) " " (tr(lang, "bytes", "байт"))
                        " · " (tr(lang, "modified ", "изменён "))
                        (mtime)
                    }
                    None => {
                        em style="color: var(--mute);" {
                            (tr(lang, "(missing — use the «update now» button below)", "(отсутствует — нажми «обновить сейчас» ниже)"))
                        }
                    }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            @if any_loaded {
                (tr(
                    lang,
                    "Update once a month with the ",
                    "Обновлять раз в месяц кнопкой ",
                ))
            } @else {
                (tr(
                    lang,
                    "Drop fresh MMDB files into the dir + restart the daemon, or use the ",
                    "Положи свежие MMDB-файлы в папку + перезапусти демон, либо используй ",
                ))
            }
            span.ed-mono { (tr(lang, "update now", "обновить сейчас")) }
            (tr(
                lang,
                " button below. It downloads DB-IP Lite (CC-BY 4.0, no signup) and atomic-renames the .mmdb files into this dir. The new databases are used after vpnctld restarts.",
                " ниже. Она скачивает DB-IP Lite (CC-BY 4.0, без регистрации) и атомарно подменяет .mmdb-файлы в этой папке. Новые базы используются после перезапуска vpnctld.",
            ))
        }
        div style="margin: 14px 0;" {
            button id="geoip-update-now-btn"
                   type="button"
                   data-sse-url="/admin/settings/geoip/update-now"
                   data-log="geoip-update-now-log"
                   data-busy-label=(tr(lang, "running…", "запущено…"))
                   data-retry-label=(tr(lang, "retry", "повторить"))
                   style="font-family: var(--mono); font-size: 12px; padding: 6px 14px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); cursor: pointer;"
                   title=(tr(
                       lang,
                       "Spawn the geoip-update subprocess on the daemon host and stream its progress here. Same action the monthly timer fires.",
                       "Запустить подпроцесс geoip-update на хосте демона и показать прогресс здесь. То же действие, что и ежемесячный таймер.",
                   )) {
                (icon("rotate-cw")) span data-icon-label { (tr(lang, "update now", "обновить сейчас")) }
            }
            pre id="geoip-update-now-log" hidden
                style="margin: 10px 0 0; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
        }
    }
}

fn echo(raw: &str) -> String {
    raw.chars().take(80).collect()
}

pub(crate) fn normalize_public_base_url(raw: &str) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 512 {
        return Err("public URL is longer than 512 characters".into());
    }
    let url = reqwest::Url::parse(trimmed).map_err(|e| {
        format!(
            "'{}' is not a valid URL ({e}); expected e.g. 'https://vpn.example.com'",
            echo(trimmed)
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "'{}' must start with http:// or https:// (got scheme '{}')",
            echo(trimmed),
            url.scheme()
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("'{}' has no host name", echo(trimmed)));
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(format!(
            "'{}' must not contain user info, a query or a fragment",
            echo(trimmed)
        ));
    }
    Ok(Some(url.as_str().trim_end_matches('/').to_string()))
}

pub(crate) async fn settings_public_url_set(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let raw = crate::http_util::form_field(&body, "public_base_url").unwrap_or_default();
    let normalized = match normalize_public_base_url(&raw) {
        Ok(v) => v,
        Err(msg) => return crate::handlers::admin::helpers::bad_request(&msg),
    };
    if let Err(e) = state
        .inv
        .update_public_base_url_audited("admin", normalized.as_deref())
        .await
    {
        return crate::handlers::admin::helpers::internal_error(anyhow::Error::new(e));
    }
    axum::response::Redirect::to("/admin/settings/system#public-address").into_response()
}

pub(crate) fn settings_public_address_section(
    current: Result<Option<&str>, &str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let current = match current {
        Ok(v) => v,
        Err(e) => {
            return maud::html! {
                div #public-address.ed-art-eyebrow {
                    (tr(lang, "Public address", "Публичный адрес"))
                }
                p.ed-grid__mut { (tr(lang, "could not read the setting: ", "не удалось прочитать настройку: ")) (e) }
            };
        }
    };
    maud::html! {
        div #public-address.ed-art-eyebrow {
            (tr(lang, "Public address", "Публичный адрес"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            (tr(
                lang,
                "The address users' apps reach this daemon at. Subscription QR codes and app config URLs are built on it. Empty: the address this page was opened at.",
                "Адрес, по которому приложения пользователей обращаются к этому демону. На нём строятся QR-коды подписок и URL конфигурации приложений. Пусто — адрес, по которому открыта эта страница.",
            ))
        }
        form method="post"
             action="/admin/settings/public-url"
             style="display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap;" {
            label for="public-base-url" style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.10em;" {
                (tr(lang, "public URL", "публичный URL"))
            }
            input #public-base-url type="url" name="public_base_url"
                  value=(current.unwrap_or(""))
                  placeholder="https://vpn.example.com"
                  style="padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink); min-width: 280px; max-width: 100%;";
            button type="submit"
                   style="padding: 4px 12px; border: 1px solid var(--acc); background: var(--acc); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (icon("save")) (tr(lang, "save", "сохранить"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_public_base_url;

    #[test]
    fn public_base_url_normalizes_and_rejects_bad_input() {
        assert_eq!(normalize_public_base_url("  "), Ok(None));
        assert_eq!(
            normalize_public_base_url("https://vpn.example.com/"),
            Ok(Some("https://vpn.example.com".into()))
        );
        assert_eq!(
            normalize_public_base_url("https://example.com/vpn/"),
            Ok(Some("https://example.com/vpn".into()))
        );
        assert!(normalize_public_base_url("ftp://example.com").is_err());
        assert!(normalize_public_base_url("https://example.com/?a=1").is_err());
        assert!(normalize_public_base_url("https://u:p@example.com").is_err());
        assert!(normalize_public_base_url("not a url").is_err());
    }
}
