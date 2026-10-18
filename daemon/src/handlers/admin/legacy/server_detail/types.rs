use maud::{Markup, html};

#[derive(serde::Deserialize, Default)]
pub(crate) struct ServerDetailQuery {
    #[serde(default)]
    pub(crate) drift: Option<String>,
    #[serde(default)]
    pub(crate) vpn_window: Option<String>,
    #[serde(default)]
    pub(crate) grant_sort: Option<String>,
}

impl ServerDetailQuery {
    pub(crate) fn drift_live(&self) -> bool {
        matches!(self.drift.as_deref(), Some("live"))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerTab {
    Status,
    Activity,
    Protocols,
    Grants,
    Setup,
}

impl ServerTab {
    pub(crate) fn slug(self) -> &'static str {
        match self {
            ServerTab::Status => "status",
            ServerTab::Activity => "activity",
            ServerTab::Protocols => "protocols",
            ServerTab::Grants => "grants",
            ServerTab::Setup => "setup",
        }
    }
}

pub(crate) fn detail_tabs(
    base: &str,
    active: &str,
    tabs: &[(&str, &str)],
    lang: crate::i18n::Locale,
) -> Markup {
    html! {
        div.ed-tabs {
            @for (slug, label) in tabs {
                a class=(if *slug == active { "ed-tab ed-tab--on" } else { "ed-tab" })
                  href=(format!("{base}/{slug}"))
                  style="cursor: pointer; text-decoration: none;" {
                    (crate::handlers::admin::icons::icon(match *slug {
                        "overview" => "layout-dashboard",
                        "status" | "activity" => "activity",
                        "protocols" => "network",
                        "access" | "grants" => "key-round",
                        "delivery" => "send",
                        "traffic" => "chart-no-axes-combined",
                        "appearance" => "palette",
                        "backups" => "archive",
                        "notifications" => "bell",
                        "abuse" | "sharing" => "shield",
                        _ => "settings-2",
                    }))
                    " " (label.strip_suffix(" ⚠").unwrap_or(label))
                    @if label.ends_with(" ⚠") {
                        " " (crate::handlers::admin::icons::status("triangle-alert", lang, "Warning", "Предупреждение"))
                    }
                }
            }
        }
    }
}
