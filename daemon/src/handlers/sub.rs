//! `GET /sub/<token>` — opaque-token-keyed client subscriptions.
//!
//! Existing clients keep their User-Agent-selected sing-box JSON or URI-list
//! bytes. Explicit selectors add stock sing-box JSON and Mihomo YAML while
//! reusing the same token, grant, visibility, suppression, and abuse gates.
//!
//! Phase Track-1 hook: every successful resolve (200) writes one row
//! into `sub_access_log` so the admin can see "how many distinct IPs
//! are pulling THIS user's URL". Failed resolves (404 unknown token)
//! are deliberately NOT logged — we don't want a probing attacker to
//! be able to fill the table by spamming garbage tokens.

mod handler;
mod mihomo;
mod singbox;
#[cfg(test)]
mod tests;
mod v2ray;

pub(crate) use self::handler::{get, rate_limited};
