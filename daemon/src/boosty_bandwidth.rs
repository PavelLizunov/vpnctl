use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpnctl_core::UserId;

pub(crate) const POLICY_KEY: &str = "sing-box.boosty_bandwidth_policy";
pub(crate) const ROSTER_URL: &str = "http://127.0.0.1:3001/api/v1/roster";
const PAGE_SIZE: usize = 200;
const MAX_SUBSCRIBERS: usize = 10_000;
const MAX_PAGE_BYTES: usize = 256 * 1024;
const MAX_AGE_SECS: i64 = 5 * 60;

#[derive(Default, Deserialize, Serialize)]
pub(crate) struct TierPolicy {
    pub blog: String,
    pub levels: BTreeMap<i64, u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscriber {
    id: String,
    active: bool,
    paid: bool,
    level_id: Option<String>,
    level: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    schema_version: u32,
    blog: String,
    captured_at: String,
    complete: bool,
    stale: bool,
    total: usize,
    offset: usize,
    items: Vec<Subscriber>,
}

pub(crate) struct Roster {
    pub blog: String,
    pub captured_at: String,
    pub levels: BTreeMap<i64, String>,
    subscribers: BTreeMap<i64, i64>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum RosterIssue {
    #[error("The Boosty dashboard could not be reached. Try again when the panel is available.")]
    Unavailable,
    #[error("The Boosty dashboard has no fresh complete roster. Refresh the panel and try again.")]
    Stale,
    #[error(
        "The Boosty dashboard returned an inconsistent roster. Refresh the panel and try again."
    )]
    Invalid,
}

impl Roster {
    pub(crate) async fn fetch(url: &str) -> Result<Self, RosterIssue> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| RosterIssue::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(6), Self::read(&client, url))
            .await
            .map_err(|_| RosterIssue::Unavailable)?
    }

    async fn read(client: &reqwest::Client, url: &str) -> Result<Self, RosterIssue> {
        let mut pages = Vec::new();
        let mut offset = 0;
        loop {
            let mut response = client
                .get(url)
                .query(&[("limit", PAGE_SIZE), ("offset", offset)])
                .send()
                .await
                .map_err(|_| RosterIssue::Unavailable)?;
            match response.status() {
                reqwest::StatusCode::OK => {}
                reqwest::StatusCode::SERVICE_UNAVAILABLE => return Err(RosterIssue::Stale),
                _ => return Err(RosterIssue::Invalid),
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| RosterIssue::Unavailable)?
            {
                if body.len() + chunk.len() > MAX_PAGE_BYTES {
                    return Err(RosterIssue::Invalid);
                }
                body.extend_from_slice(&chunk);
            }
            let page: Page = serde_json::from_slice(&body).map_err(|_| RosterIssue::Invalid)?;
            page.validate(offset)?;
            offset += page.items.len();
            let last = offset == page.total;
            pages.push(page);
            if last {
                return Self::from_pages(&pages);
            }
        }
    }

    fn from_pages(pages: &[Page]) -> Result<Self, RosterIssue> {
        let first = pages.first().ok_or(RosterIssue::Invalid)?;
        let mut roster = Self {
            blog: first.blog.clone(),
            captured_at: first.captured_at.clone(),
            levels: BTreeMap::new(),
            subscribers: BTreeMap::new(),
        };
        let mut seen = HashSet::new();
        for page in pages {
            page.validate(seen.len())?;
            if page.blog != first.blog
                || page.captured_at != first.captured_at
                || page.total != first.total
            {
                return Err(RosterIssue::Invalid);
            }
            for row in &page.items {
                let id = positive_id(&row.id).ok_or(RosterIssue::Invalid)?;
                if !seen.insert(id) {
                    return Err(RosterIssue::Invalid);
                }
                if row.active
                    && row.paid
                    && let Some(level_id) = &row.level_id
                {
                    let level = positive_id(level_id).ok_or(RosterIssue::Invalid)?;
                    let label = roster.levels.entry(level).or_default();
                    if label.is_empty()
                        && let Some(name) = row.level.as_ref()
                    {
                        label.clone_from(name);
                    }
                    roster.subscribers.insert(id, level);
                }
            }
        }
        if seen.len() != first.total {
            return Err(RosterIssue::Invalid);
        }
        Ok(roster)
    }

    pub(crate) fn overrides(
        &self,
        policy: &TierPolicy,
        base: u32,
        links: &[(UserId, i64)],
        account_ids: &HashSet<&str>,
    ) -> BTreeMap<String, u32> {
        let explicitly_linked_users: HashSet<&str> =
            links.iter().map(|(user, _)| user.0.as_str()).collect();
        let explicitly_linked_subscribers: HashSet<i64> =
            links.iter().map(|(_, subscriber)| *subscriber).collect();
        let mut overrides: BTreeMap<String, u32> = links
            .iter()
            .filter_map(|(user, subscriber)| {
                let level = self.subscribers.get(subscriber)?;
                let rate = *policy.levels.get(level)?;
                (rate != base).then(|| (user.0.clone(), rate))
            })
            .collect();
        for (subscriber, level) in &self.subscribers {
            if let Some(rate) = policy
                .levels
                .get(level)
                .copied()
                .filter(|rate| *rate != base)
                && !explicitly_linked_subscribers.contains(subscriber)
            {
                let canonical = format!("boosty-{subscriber}");
                if account_ids.contains(canonical.as_str())
                    && !explicitly_linked_users.contains(canonical.as_str())
                {
                    overrides.insert(canonical, rate);
                }
            }
        }
        overrides
    }
}

impl Page {
    fn validate(&self, expected_offset: usize) -> Result<(), RosterIssue> {
        if self.schema_version != 1 || self.blog.is_empty() {
            return Err(RosterIssue::Invalid);
        }
        if !self.complete || self.stale {
            return Err(RosterIssue::Stale);
        }
        let observed_at = chrono::DateTime::parse_from_rfc3339(&self.captured_at)
            .map_err(|_| RosterIssue::Invalid)?;
        let age = chrono::Utc::now()
            .signed_duration_since(observed_at)
            .num_seconds();
        if !(-30..=MAX_AGE_SECS).contains(&age) {
            return Err(RosterIssue::Stale);
        }
        if self.total > MAX_SUBSCRIBERS
            || self.offset != expected_offset
            || self.items.len() > PAGE_SIZE
            || self.offset + self.items.len() > self.total
            || (self.items.is_empty() && self.offset != self.total)
        {
            return Err(RosterIssue::Invalid);
        }
        Ok(())
    }
}

fn positive_id(value: &str) -> Option<i64> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<i64>().ok().filter(|id| *id > 0)
}

#[cfg(test)]
mod spec_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, level_id: i64, active: bool, paid: bool) -> Subscriber {
        Subscriber {
            id: id.to_string(),
            active,
            paid,
            level_id: Some(level_id.to_string()),
            level: Some("Same label".into()),
        }
    }

    fn page(total: usize, offset: usize, items: Vec<Subscriber>) -> Page {
        Page {
            schema_version: 1,
            blog: "fixture-blog".into(),
            captured_at: chrono::Utc::now().to_rfc3339(),
            complete: true,
            stale: false,
            total,
            offset,
            items,
        }
    }

    #[test]
    fn joins_exact_tiers_to_explicit_links() -> Result<(), RosterIssue> {
        let first = page(4, 0, vec![row(1, 11, true, true), row(2, 22, true, true)]);
        let mut second = page(4, 2, vec![row(3, 11, false, true), row(4, 22, true, false)]);
        second.captured_at.clone_from(&first.captured_at);
        let roster = Roster::from_pages(&[first, second])?;
        assert_eq!(roster.levels.len(), 2);
        let policy = TierPolicy {
            blog: roster.blog.clone(),
            levels: BTreeMap::from([(11, 80), (22, 160)]),
        };
        let links = [
            ("a", 1),
            ("b", 2),
            ("b-secondary", 2),
            ("c", 3),
            ("d", 4),
            ("e", 5),
        ]
        .map(|(name, subscriber)| (UserId(name.into()), subscriber));
        assert_eq!(
            roster.overrides(&policy, 40, &links, &HashSet::new()),
            BTreeMap::from([
                ("a".into(), 80),
                ("b".into(), 160),
                ("b-secondary".into(), 160),
            ])
        );
        Ok(())
    }

    #[test]
    fn refuses_stale_duplicate_and_inconsistent_pages() {
        let first = || page(2, 0, vec![row(1, 11, true, true)]);
        let mut stale = first();
        stale.stale = true;
        assert!(Roster::from_pages(&[stale]).is_err());
        assert!(Roster::from_pages(&[first()]).is_err());
        let initial = first();
        let mut duplicate = page(2, 1, vec![row(1, 11, true, true)]);
        duplicate.captured_at.clone_from(&initial.captured_at);
        assert!(Roster::from_pages(&[initial, duplicate]).is_err());
        let initial = first();
        let mut other_blog = page(2, 1, vec![row(2, 22, true, true)]);
        other_blog.captured_at.clone_from(&initial.captured_at);
        other_blog.blog = "different-blog".into();
        assert!(Roster::from_pages(&[initial, other_blog]).is_err());
    }

    #[test]
    fn panel_delivery_ids_inherit_rates_when_no_explicit_link_claims_them()
    -> Result<(), RosterIssue> {
        let roster = Roster::from_pages(&[page(
            3,
            0,
            vec![
                row(1, 11, true, true),
                row(2, 11, true, true),
                row(3, 22, true, true),
            ],
        )])?;
        let policy = TierPolicy {
            blog: roster.blog.clone(),
            levels: BTreeMap::from([(11, 80), (22, 160)]),
        };
        let links = [(UserId("boosty-2".into()), 3)];
        let accounts = HashSet::from(["boosty-1", "boosty-2", "boosty-3"]);
        assert_eq!(
            roster.overrides(&policy, 40, &links, &accounts),
            BTreeMap::from([("boosty-1".into(), 80), ("boosty-2".into(), 160),])
        );
        Ok(())
    }
}
