use std::collections::BTreeMap;

use axum::extract::Query as AxumQuery;
use axum::http::Uri;
use maud::{Markup, html};
use serde::{Deserialize, Serialize};

use super::client::{AuthorClient, AuthorIssue};
use super::{DASHBOARD_PATH, Overview, Source, date, money, overview_view, source_name, sources};
use crate::AppState;
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};

pub(super) const PAGE_SIZE: usize = 30;
const MAX_OFFSET: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum View {
    #[default]
    Overview,
    People,
    Money,
    Events,
    Content,
    Analytics,
    Messages,
    Automation,
    Sources,
}

impl View {
    pub(super) const ALL: [Self; 9] = [
        Self::Overview,
        Self::People,
        Self::Money,
        Self::Events,
        Self::Content,
        Self::Analytics,
        Self::Messages,
        Self::Automation,
        Self::Sources,
    ];

    fn key(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::People => "people",
            Self::Money => "money",
            Self::Events => "events",
            Self::Content => "content",
            Self::Analytics => "analytics",
            Self::Messages => "messages",
            Self::Automation => "automation",
            Self::Sources => "sources",
        }
    }

    pub(super) fn label(self, lang: Locale) -> &'static str {
        match self {
            Self::Overview => tr(lang, "Overview", "Обзор"),
            Self::People => tr(lang, "People", "Подписчики"),
            Self::Money => tr(lang, "Money", "Деньги"),
            Self::Events => tr(lang, "Events", "События"),
            Self::Content => tr(lang, "Content", "Контент"),
            Self::Analytics => tr(lang, "Analytics", "Аналитика"),
            Self::Messages => tr(lang, "Messages", "Переписки"),
            Self::Automation => tr(lang, "Delivery", "Выдача"),
            Self::Sources => tr(lang, "Sources", "Источники"),
        }
    }

    pub(super) fn url(self) -> String {
        if self == Self::Overview {
            DASHBOARD_PATH.into()
        } else {
            format!("{DASHBOARD_PATH}?view={}", self.key())
        }
    }

    pub(super) fn standalone_fragment(self) -> Option<&'static str> {
        match self {
            Self::Messages => Some("messages"),
            Self::Automation => Some("delivery"),
            _ => None,
        }
    }

    pub(super) fn standalone_label(self, lang: Locale) -> &'static str {
        match self {
            Self::Messages => tr(
                lang,
                "Manage replies in Boosty",
                "Управление ответами в Boosty",
            ),
            Self::Automation => tr(
                lang,
                "Manage delivery in Boosty",
                "Управление выдачей в Boosty",
            ),
            _ => tr(
                lang,
                "Open the standalone panel",
                "Открыть отдельную панель",
            ),
        }
    }

    fn record_sources(self) -> &'static [&'static str] {
        match self {
            Self::Money => &["donations", "postSales", "bundleSales", "holds", "payouts"],
            Self::Events => &["events", "cancellations", "observed"],
            Self::Content => &["posts", "levels", "goals"],
            Self::Analytics => &[
                "summary",
                "metrics",
                "charts",
                "visits",
                "paymentSources",
                "referrals",
                "referralUsers",
            ],
            _ => &[],
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Query {
    pub view: View,
    search: String,
    status: String,
    source: String,
    from: String,
    to: String,
    pub offset: usize,
    person: Option<String>,
    pub dialog: Option<String>,
    pub before: Option<String>,
}

impl Query {
    pub(super) fn from_uri(uri: &Uri) -> Self {
        let mut query = AxumQuery::<Self>::try_from_uri(uri)
            .map(|AxumQuery(query)| query)
            .unwrap_or_default();
        query.search = query.search.trim().to_owned();
        if query.search.len() > 200 {
            query.search.clear();
        }
        if !["active", "inactive", "missing"].contains(&query.status.as_str()) {
            query.status.clear();
        }
        if !query.view.record_sources().contains(&query.source.as_str()) {
            query.source.clear();
        }
        for value in [&mut query.from, &mut query.to] {
            if chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_err() {
                value.clear();
            }
        }
        query.offset = query.offset.min(MAX_OFFSET);
        query.person = query.person.filter(|id| {
            !id.is_empty()
                && id.len() <= 100
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        });
        query.dialog = query.dialog.filter(|id| valid_inbox_id(id));
        query.before = query.before.filter(|id| valid_inbox_id(id));
        query
    }

    pub(super) fn request(&self) -> ApiQuery<'_> {
        ApiQuery {
            view: (!self.view.record_sources().is_empty()).then(|| self.view.key()),
            search: &self.search,
            status: &self.status,
            source: &self.source,
            from: &self.from,
            to: &self.to,
            limit: PAGE_SIZE,
            offset: self.offset,
        }
    }

    fn at(&self, offset: usize) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("view", self.view.key());
        for (name, value) in [
            ("search", &self.search),
            ("status", &self.status),
            ("source", &self.source),
            ("from", &self.from),
            ("to", &self.to),
        ] {
            if !value.is_empty() {
                query.append_pair(name, value);
            }
        }
        query.append_pair("offset", &offset.to_string());
        format!("{DASHBOARD_PATH}?{}", query.finish())
    }
}

#[derive(Serialize)]
pub(super) struct ApiQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<&'static str>,
    search: &'a str,
    status: &'a str,
    source: &'a str,
    from: &'a str,
    to: &'a str,
    limit: usize,
    offset: usize,
}

#[derive(Deserialize)]
pub(super) struct Page<T> {
    pub items: Vec<T>,
    pub total: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Person {
    id: String,
    name: Option<String>,
    level: Option<String>,
    active: Option<bool>,
    paid: Option<bool>,
    present: bool,
    next_payment_at: Option<String>,
}

#[derive(Deserialize)]
struct PersonDetail {
    user: Person,
    history: Vec<History>,
    events: Vec<Record>,
    money: Vec<Record>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct History {
    observed_at: String,
    level: Option<String>,
    active: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    source: String,
    title: Option<String>,
    name: Option<String>,
    occurred_at: Option<String>,
    observed_at: Option<String>,
    amount_minor: Option<i64>,
    currency: Option<String>,
    status: Option<String>,
}

const NO_QUERY: [(&str, &str); 0] = [];

pub(super) async fn content(
    client: &AuthorClient,
    state: &AppState,
    query: &Query,
    lang: Locale,
) -> Result<Markup, AuthorIssue> {
    match query.view {
        View::Overview => Ok(overview_view(
            &client.get::<Overview>(&["overview"], &NO_QUERY).await?,
            lang,
        )),
        View::People => people(client, state, query, lang).await,
        View::Messages => super::workflows::inbox(client, query, lang).await,
        View::Automation => super::workflows::automation(client, query, lang).await,
        View::Sources => Ok(sources(
            &client.get::<Vec<Source>>(&["sources"], &NO_QUERY).await?,
            lang,
        )),
        View::Money | View::Events | View::Content | View::Analytics => {
            let page = client
                .get::<Page<Record>>(&["records"], &query.request())
                .await?;
            Ok(html! {
                (filters(query, lang))
                (records(&page.items, lang))
                (pager(query, page.total, lang))
            })
        }
    }
}

async fn people(
    client: &AuthorClient,
    state: &AppState,
    query: &Query,
    lang: Locale,
) -> Result<Markup, AuthorIssue> {
    let bindings = state.inv.list_boosty_links();
    if let Some(id) = &query.person {
        let (person, links) = tokio::join!(
            client.get::<PersonDetail>(&["users", id], &NO_QUERY),
            bindings
        );
        let person = person?;
        let links = account_links(links.map_err(|_| AuthorIssue::Unavailable)?);
        return Ok(html! {
            p { a href=(View::People.url()) { (tr(lang, "Back to people", "К подписчикам")) } }
            h2 { (person_name(&person.user)) }
            p.ed-art-deck { (person_status(&person.user, lang)) " · " (person.user.level.as_deref().unwrap_or("—")) }
            p { (tr(lang, "VPN accounts", "VPN-аккаунты")) " " (accounts(&links, &person.user.id)) }
            h3 { (tr(lang, "Subscription history", "История подписки")) }
            div.ed-grid-wrap {
                table.ed-grid {
                    thead { tr {
                        th { (tr(lang, "Date", "Дата")) }
                        th { (tr(lang, "Tier", "Тариф")) }
                        th { (tr(lang, "Status", "Статус")) }
                    } }
                    tbody { @for row in &person.history {
                        tr {
                            td { (date(Some(&row.observed_at))) }
                            td { (row.level.as_deref().unwrap_or("—")) }
                            td { (active_label(row.active, lang)) }
                        }
                    } }
                }
            }
            h3 { (tr(lang, "Payments", "Оплаты")) }
            (records(&person.money, lang))
            h3 { (View::Events.label(lang)) }
            (records(&person.events, lang))
        });
    }
    let params = query.request();
    let (page, links) = tokio::join!(client.get::<Page<Person>>(&["users"], &params), bindings);
    let page = page?;
    let links = account_links(links.map_err(|_| AuthorIssue::Unavailable)?);
    Ok(html! {
        (filters(query, lang))
        @if page.items.is_empty() {
            (empty(lang))
        } @else {
            div.ed-grid-wrap {
                table.ed-grid {
                    thead { tr {
                        th { (tr(lang, "Subscriber", "Подписчик")) }
                        th { (tr(lang, "Tier", "Тариф")) }
                        th { (tr(lang, "Subscription", "Подписка")) }
                        th { (tr(lang, "Next payment", "Следующая оплата")) }
                        th { (tr(lang, "VPN accounts", "VPN-аккаунты")) }
                    } }
                    tbody { @for person in &page.items {
                        tr {
                            td {
                                a.ed-grid__id href=(format!("{DASHBOARD_PATH}?view=people&person={}", path_segment_encode(&person.id))) {
                                    (person_name(person))
                                }
                            }
                            td { (person.level.as_deref().unwrap_or("—")) }
                            td { (person_status(person, lang)) }
                            td { (date(person.next_payment_at.as_deref())) }
                            td { (accounts(&links, &person.id)) }
                        }
                    } }
                }
            }
        }
        (pager(query, page.total, lang))
    })
}

fn account_links(rows: Vec<(vpnctl_core::UserId, i64)>) -> BTreeMap<i64, Vec<vpnctl_core::UserId>> {
    let mut result = BTreeMap::<_, Vec<_>>::new();
    for (user, subscriber) in rows {
        result.entry(subscriber).or_default().push(user);
    }
    result
}

fn accounts(links: &BTreeMap<i64, Vec<vpnctl_core::UserId>>, subscriber: &str) -> Markup {
    html! {
        @if let Some(users) = subscriber.parse().ok().and_then(|id| links.get(&id)) {
            @for (i, user) in users.iter().enumerate() {
                @if i > 0 { ", " }
                a href=(format!("/admin/users/{}", path_segment_encode(&user.0))) { (user.0) }
            }
        } @else { "—" }
    }
}

fn person_name(person: &Person) -> &str {
    person
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&person.id)
}

fn active_label(active: Option<bool>, lang: Locale) -> &'static str {
    match active {
        Some(true) => tr(lang, "Active", "Активна"),
        Some(false) => tr(lang, "Inactive", "Неактивна"),
        None => tr(lang, "Unknown", "Неизвестно"),
    }
}

fn person_status(person: &Person, lang: Locale) -> &'static str {
    match (person.present, person.active, person.paid) {
        (false, _, _) => tr(lang, "Missing from roster", "Нет в списке"),
        (true, Some(true), Some(true)) => tr(lang, "Paid", "Платная"),
        (true, Some(true), Some(false)) => tr(lang, "Free", "Бесплатная"),
        (true, active, _) => active_label(active, lang),
    }
}

fn records(items: &[Record], lang: Locale) -> Markup {
    if items.is_empty() {
        return empty(lang);
    }
    html! {
        div.ed-grid-wrap {
            table.ed-grid {
                thead { tr {
                    th { (tr(lang, "Date", "Дата")) }
                    th { (tr(lang, "Source", "Источник")) }
                    th { (tr(lang, "Record", "Запись")) }
                    th { (tr(lang, "Status", "Статус")) }
                    th.num { (tr(lang, "Amount", "Сумма")) }
                } }
                tbody { @for record in items {
                    tr {
                        td { (date(record.occurred_at.as_deref().or(record.observed_at.as_deref()))) }
                        td { (source_name(&record.source, lang)) }
                        td { (record.title.as_deref().or(record.name.as_deref()).unwrap_or("—")) }
                        td { (record.status.as_deref().unwrap_or("—")) }
                        td.num { (money(record.amount_minor, record.currency.as_deref())) }
                    }
                } }
            }
        }
    }
}

fn filters(query: &Query, lang: Locale) -> Markup {
    html! {
        form.ed-boosty-filters method="get" action=(DASHBOARD_PATH) {
            input type="hidden" name="view" value=(query.view.key());
            label {
                (tr(lang, "Search", "Поиск"))
                input type="search" name="search" maxlength="200" value=(query.search);
            }
            @if query.view == View::People {
                label {
                    (tr(lang, "Subscription", "Подписка"))
                    select name="status" {
                        @for (value, label) in [
                            ("", tr(lang, "All", "Все")),
                            ("active", active_label(Some(true), lang)),
                            ("inactive", active_label(Some(false), lang)),
                            ("missing", tr(lang, "Missing from roster", "Нет в списке")),
                        ] {
                            option value=(value) selected[query.status == value] { (label) }
                        }
                    }
                }
            } @else {
                label {
                    (tr(lang, "Source", "Источник"))
                    select name="source" {
                        option value="" { (tr(lang, "All", "Все")) }
                        @for source in query.view.record_sources() {
                            option value=(source) selected[query.source == *source] { (source_name(source, lang)) }
                        }
                    }
                }
                label { (tr(lang, "From", "С")) input type="date" name="from" value=(query.from); }
                label { (tr(lang, "To", "По")) input type="date" name="to" value=(query.to); }
            }
            button.ed-abtn type="submit" { (tr(lang, "Apply filters", "Применить")) }
        }
    }
}

pub(super) fn pager(query: &Query, total: usize, lang: Locale) -> Markup {
    let next = query.offset + PAGE_SIZE;
    html! {
        @if query.offset > 0 || next < total {
            nav.ed-boosty-pager aria-label=(tr(lang, "Pages", "Страницы")) {
                @if query.offset > 0 {
                    a.ed-abtn href=(query.at(query.offset.saturating_sub(PAGE_SIZE))) { (tr(lang, "Previous", "Назад")) }
                }
                @if next < total && next <= MAX_OFFSET {
                    a.ed-abtn href=(query.at(next)) { (tr(lang, "Next", "Далее")) }
                }
            }
        }
    }
}

pub(super) fn empty(lang: Locale) -> Markup {
    html! { p.ed-art-deck { (tr(lang, "No matching records. Change the filters or refresh Boosty.", "Записей нет. Измените фильтры или обновите данные Boosty.")) } }
}

pub(super) fn valid_inbox_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit())
}
