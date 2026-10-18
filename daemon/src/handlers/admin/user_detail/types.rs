#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct UserDetailQuery {
    #[serde(default)]
    pub(crate) vpn_window: Option<String>,
    #[serde(default)]
    pub(crate) log_page: Option<i64>,
}

impl UserDetailQuery {
    pub(crate) fn log_page(&self) -> i64 {
        self.log_page.unwrap_or(0).clamp(0, 10_000)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserTab {
    Overview,
    Delivery,
    Access,
    Activity,
    Traffic,
}

impl UserTab {
    pub(crate) fn slug(self) -> &'static str {
        match self {
            UserTab::Overview => "overview",
            UserTab::Delivery => "delivery",
            UserTab::Access => "access",
            UserTab::Activity => "activity",
            UserTab::Traffic => "traffic",
        }
    }
}
