//! Readiness of the single delivery artefact shown on the user's Delivery tab.
//!
//! This module only decides which already-built URL is safe to recommend. It
//! never edits the URL, QR payload or any subscription/app response.

use url::{Host, Url};

use crate::i18n::{Locale, tr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimaryArtifactKind {
    Subscription,
    AppConfig,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PrimaryArtifact<'a> {
    pub(crate) kind: PrimaryArtifactKind,
    pub(crate) url: &'a str,
}

impl PrimaryArtifactKind {
    pub(crate) fn label(self, lang: Locale) -> &'static str {
        match self {
            Self::Subscription => tr(
                lang,
                "Hiddify / sing-box subscription",
                "Подписка Hiddify / sing-box",
            ),
            Self::AppConfig => tr(lang, "VPNRouter app config", "Конфиг приложения VPNRouter"),
        }
    }

    pub(crate) fn note(self, lang: Locale) -> &'static str {
        match self {
            Self::Subscription => tr(
                lang,
                "One URL for the subscription flow. It contains the servers and protocols the subscription currently exposes; review the per-server links below for anything missing. Other clients stay available.",
                "Один URL для подписки. Он содержит серверы и протоколы, которые подписка отдаёт сейчас; если чего-то не хватает, смотри ссылки по серверам ниже. Другие клиенты остаются доступны.",
            ),
            Self::AppConfig => tr(
                lang,
                "Device-keyed config for the VPNRouter app. It contains what the app endpoint currently exposes; other clients and per-server links remain below.",
                "Конфиг для приложения VPNRouter, привязанный к устройству. Он содержит то, что отдаёт endpoint приложения; другие клиенты и ссылки по серверам остаются ниже.",
            ),
        }
    }
}

/// Prefer the universal subscription flow; use the app-config URL only when no
/// subscription URL exists. Both strings are passed through unchanged.
pub(crate) fn primary_artifact<'a>(
    app_config_url: Option<&'a str>,
    subscription_url: Option<&'a str>,
) -> Option<PrimaryArtifact<'a>> {
    if let Some(url) = subscription_url.filter(|url| !url.is_empty()) {
        return Some(PrimaryArtifact {
            kind: PrimaryArtifactKind::Subscription,
            url,
        });
    }
    app_config_url
        .filter(|url| !url.is_empty())
        .map(|url| PrimaryArtifact {
            kind: PrimaryArtifactKind::AppConfig,
            url,
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecipientScope {
    Public,
    /// Private, link-local, CGNAT or Tailscale-style addresses. They can be
    /// perfectly valid for recipients on the same network, so they keep the
    /// copy action and only receive a scope warning.
    Private,
    Loopback,
    Unspecified,
    Invalid,
}

impl RecipientScope {
    pub(crate) fn blocks_copy(self) -> bool {
        matches!(self, Self::Loopback | Self::Unspecified | Self::Invalid)
    }

    pub(crate) fn headline(self, lang: Locale) -> &'static str {
        match self {
            Self::Public | Self::Private => "",
            Self::Loopback => tr(
                lang,
                "The share link points at loopback",
                "Ссылка ведёт на loopback",
            ),
            Self::Unspecified => tr(
                lang,
                "The share link has no usable host",
                "У ссылки нет пригодного хоста",
            ),
            Self::Invalid => tr(
                lang,
                "The share link is not a valid URL",
                "Ссылка не является корректным URL",
            ),
        }
    }

    pub(crate) fn detail(self, lang: Locale, configured: bool) -> &'static str {
        if self == Self::Invalid {
            return if configured {
                tr(
                    lang,
                    "The configured public address could not be used to build a valid link. Check Settings → System and the user's device identity, then reload this page.",
                    "Из настроенного публичного адреса не удалось собрать корректную ссылку. Проверь Настройки → Система и идентичность устройства пользователя и перезагрузи страницу.",
                )
            } else {
                tr(
                    lang,
                    "No public address is configured, so this page's address was used, and it did not form a valid link. Set the intended address in Settings → System, then reload this page.",
                    "Публичный адрес не настроен, поэтому использован адрес этой страницы, и он не образовал корректную ссылку. Укажи нужный адрес в Настройки → Система и перезагрузи страницу.",
                )
            };
        }
        if configured {
            tr(
                lang,
                "The public address in Settings → System is obviously local to this host. Replace it with an address the recipient can open, then reload this page.",
                "Публичный адрес в Настройки → Система явно локальный для этого хоста. Замени его на адрес, который сможет открыть получатель, и перезагрузи страницу.",
            )
        } else {
            tr(
                lang,
                "No public address is configured, so this page's address was used. Set the intended address in Settings → System, then reload this page.",
                "Публичный адрес не настроен, поэтому использован адрес этой страницы. Укажи нужный адрес в Настройки → Система и перезагрузи страницу.",
            )
        }
    }

    /// A network-scope hint, not a reachability verdict. Private origins can be
    /// intentional (LAN, Tailscale, private VPN) so the copy action stays.
    pub(crate) fn hint(self, lang: Locale, configured: bool) -> Option<&'static str> {
        match (self, configured) {
            (Self::Private, true) => Some(tr(
                lang,
                "The configured address is private, LAN, CGNAT or Tailscale-style. Copy is available, but the link is only usable by recipients on that network. No public reachability is assumed.",
                "Настроенный адрес приватный, LAN, CGNAT или в стиле Tailscale. Копирование доступно, но ссылка работает только для получателей в этой сети. Публичная доступность не предполагается.",
            )),
            (Self::Private, false) => Some(tr(
                lang,
                "This page was opened at a private, LAN, CGNAT or Tailscale-style address and no public address is configured. The link is only usable on that network. No public reachability is assumed.",
                "Страница открыта по приватному адресу, LAN, CGNAT или в стиле Tailscale, а публичный адрес не настроен. Ссылка работает только в этой сети. Публичная доступность не предполагается.",
            )),
            _ => None,
        }
    }
}

/// Classify the recipient host. This is deliberately a scope check, not a
/// reachability test: private addresses are allowed and annotated.
pub(crate) fn recipient_scope(url: &str) -> RecipientScope {
    let parsed = match Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return RecipientScope::Invalid,
    };
    let Some(host) = parsed.host() else {
        return RecipientScope::Invalid;
    };
    let host = match host {
        Host::Domain(name) => Host::Domain(name.trim_end_matches('.')),
        Host::Ipv6(ip) => ip.to_ipv4_mapped().map_or(Host::Ipv6(ip), Host::Ipv4),
        other => other,
    };
    match host {
        Host::Domain(name) if name == "localhost" || name.ends_with(".localhost") => {
            RecipientScope::Loopback
        }
        Host::Domain(name)
            if name.ends_with(".local")
                || name.ends_with(".lan")
                || name.ends_with(".internal")
                || name.ends_with(".home.arpa") =>
        {
            RecipientScope::Private
        }
        Host::Domain(_) => RecipientScope::Public,
        Host::Ipv4(ip) if ip.is_loopback() => RecipientScope::Loopback,
        Host::Ipv4(ip) if ip.is_unspecified() => RecipientScope::Unspecified,
        Host::Ipv4(ip) if ip.is_private() || ip.is_link_local() || is_cgnat(ip) => {
            RecipientScope::Private
        }
        Host::Ipv4(_) => RecipientScope::Public,
        Host::Ipv6(ip) if ip.is_loopback() => RecipientScope::Loopback,
        Host::Ipv6(ip) if ip.is_unspecified() => RecipientScope::Unspecified,
        Host::Ipv6(ip) if is_ipv6_local(ip) => RecipientScope::Private,
        Host::Ipv6(_) => RecipientScope::Public,
    }
}

fn is_cgnat(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_ipv6_local(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn subscription_is_preferred_over_app_config() {
        let artifact = primary_artifact(
            Some("https://vpn.example/app"),
            Some("https://vpn.example/sub"),
        )
        .expect("artifact");
        assert_eq!(artifact.kind, PrimaryArtifactKind::Subscription);
        assert_eq!(artifact.url, "https://vpn.example/sub");
    }

    #[test]
    fn app_config_is_used_when_no_subscription_url_exists() {
        let artifact = primary_artifact(Some("https://vpn.example/app"), None).expect("artifact");
        assert_eq!(artifact.kind, PrimaryArtifactKind::AppConfig);
        assert_eq!(artifact.url, "https://vpn.example/app");
        assert!(primary_artifact(None, None).is_none());
    }

    #[test]
    fn loopback_and_unspecified_hosts_block_copy() {
        for url in [
            "http://127.0.0.1:18402/sub/token",
            "http://[::1]:18402/sub/token",
            "http://localhost:18402/sub/token",
            "https://vpn.localhost./sub/token",
            "http://[::ffff:127.0.0.1]/sub/token",
        ] {
            assert_eq!(recipient_scope(url), RecipientScope::Loopback, "{url}");
            assert!(recipient_scope(url).blocks_copy(), "{url}");
        }
        for url in [
            "http://0.0.0.0:18402/sub/token",
            "http://[::]:18402/sub/token",
        ] {
            assert_eq!(recipient_scope(url), RecipientScope::Unspecified, "{url}");
            assert!(recipient_scope(url).blocks_copy(), "{url}");
        }
    }

    #[test]
    fn private_lan_and_tailscale_hosts_keep_copy_with_a_scope_hint() {
        for url in [
            "http://192.168.0.10/sub/token",
            "http://10.1.2.3/sub/token",
            "http://172.16.0.1/sub/token",
            "http://169.254.1.1/sub/token",
            "http://100.64.0.1/sub/token",
            "http://[fd12:3456::1]/sub/token",
            "http://[fe80::1]/sub/token",
            "https://vpn.lan/sub/token",
            "https://vpn.internal/sub/token",
        ] {
            let scope = recipient_scope(url);
            assert_eq!(scope, RecipientScope::Private, "{url}");
            assert!(!scope.blocks_copy(), "{url}");
            assert!(
                scope.hint(Locale::En, true).is_some(),
                "{url} must carry a configured-origin scope hint"
            );
            assert!(
                scope.hint(Locale::En, false).is_some(),
                "{url} must carry a request-host scope hint when no public base is configured"
            );
        }
    }

    #[test]
    fn public_domains_and_addresses_have_no_scope_warning() {
        for url in [
            "https://vpn.example.com/sub/token",
            "http://203.0.113.9:18402/sub/token",
            "https://[2606:4700:4700::1111]/sub/token",
        ] {
            let scope = recipient_scope(url);
            assert_eq!(scope, RecipientScope::Public, "{url}");
            assert!(!scope.blocks_copy(), "{url}");
            assert!(scope.hint(Locale::En, true).is_none(), "{url}");
        }
    }

    #[test]
    fn malformed_urls_are_reported_and_blocked() {
        assert_eq!(recipient_scope("not a url"), RecipientScope::Invalid);
        assert!(recipient_scope("not a url").blocks_copy());
    }
}
