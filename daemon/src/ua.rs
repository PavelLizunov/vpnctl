pub fn http_version_label(v: axum::http::Version) -> &'static str {
    match v {
        axum::http::Version::HTTP_09 => "HTTP/0.9",
        axum::http::Version::HTTP_10 => "HTTP/1.0",
        axum::http::Version::HTTP_11 => "HTTP/1.1",
        axum::http::Version::HTTP_2 => "HTTP/2.0",
        axum::http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
}

pub fn parse_ua_short(ua: Option<&str>) -> Option<&'static str> {
    let s = ua?;
    if s.contains("phase6-monitor") {
        return Some("phase6-monitor (canary)");
    }
    if s.contains("v2rayN") {
        return Some("v2rayN / Windows");
    }
    if s.contains("Hiddify") {
        return Some("Hiddify");
    }
    if s.contains("sing-box") {
        return Some("sing-box client");
    }
    if s.contains("clash") || s.contains("Clash") {
        return Some("Clash");
    }
    if s.contains("Shadowrocket") {
        return Some("Shadowrocket / iOS");
    }
    if s.contains("Streisand") {
        return Some("Streisand / iOS");
    }
    if s.contains("Quantumult") {
        return Some("Quantumult / iOS");
    }
    if s.contains("Stash") {
        return Some("Stash / iOS");
    }
    if s.contains("curl/") {
        return Some("curl");
    }
    if s.contains("Wget/") {
        return Some("wget");
    }
    if s.contains("Mozilla/5.0") {
        if s.contains("iPhone") || s.contains("iPad") {
            return Some("browser iOS");
        }
        if s.contains("Android") {
            return Some("browser Android");
        }
        if s.contains("Macintosh") || s.contains("Mac OS X") {
            return Some("browser macOS");
        }
        if s.contains("Windows") {
            return Some("browser Windows");
        }
        if s.contains("Linux") {
            return Some("browser Linux");
        }
        return Some("browser");
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_ua_short_buckets() {
        assert_eq!(
            parse_ua_short(Some("v2rayN/6.99")),
            Some("v2rayN / Windows")
        );
        assert_eq!(parse_ua_short(Some("Hiddify/2.5.7")), Some("Hiddify"));
        assert_eq!(parse_ua_short(Some("curl/8.5.0")), Some("curl"));
        assert_eq!(
            parse_ua_short(Some(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605"
            )),
            Some("browser iOS")
        );
        assert_eq!(
            parse_ua_short(Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")),
            Some("browser Windows")
        );
        assert_eq!(parse_ua_short(Some("unknown-thing/1.0")), None);
        assert_eq!(parse_ua_short(None), None);
    }

    #[test]
    fn phase6_monitor_is_self_identifying() {
        assert_eq!(
            parse_ua_short(Some("phase6-monitor/1.0 (Mozilla-compat probe)")),
            Some("phase6-monitor (canary)")
        );
        assert_eq!(
            parse_ua_short(Some("phase6-monitor/1.0 (v2rayN-compat probe)")),
            Some("phase6-monitor (canary)")
        );
    }
}
