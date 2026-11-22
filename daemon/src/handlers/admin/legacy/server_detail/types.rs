use maud::{Markup, html};

#[derive(serde::Deserialize, Default)]
pub(crate) struct ServerDetailQuery {
    #[serde(default)]
    pub(crate) drift: Option<String>,
    #[serde(default)]
    pub(crate) vpn_window: Option<String>,
    #[serde(default)]
    pub(crate) grant_sort: Option<String>,
    #[serde(default)]
    pub(crate) deploy_status: Option<String>,
}

impl ServerDetailQuery {
    pub(crate) fn drift_live(&self) -> bool {
        matches!(self.drift.as_deref(), Some("live"))
    }

    pub(crate) fn deploy_status_fragment(&self) -> bool {
        matches!(self.deploy_status.as_deref(), Some("1"))
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
        div.ed-tabs role="navigation" aria-label=(crate::i18n::tr(lang, "Page sections", "Разделы страницы")) {
            @for (slug, label) in tabs {
                a class=(if *slug == active { "ed-tab ed-tab--on" } else { "ed-tab" })
                  href=(format!("{base}/{slug}"))
                  aria-current=[(*slug == active).then_some("page")]
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
