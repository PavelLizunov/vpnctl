//! Localized, pretty alert-message rendering (ru / en) for vpnctld.
//!
//! Replaces the bare English plain-text Telegram formatter. Each
//! alert `kind` is rendered from its structured `payload` (already
//! captured in `health_monitor::AlertEvent.payload` / the
//! node-probe-poller payloads) into a localized `{icon, title, body,
//! action}`, then laid out for Telegram (HTML) or the admin UI.
//!
//! ## Why structured-payload → render-at-display
//!
//! The alert-creation sites historically baked an English `summary`
//! string. That can't be re-localized. Instead the fields live in
//! `payload` (pct, prior/current, ip, …) and the human text is produced
//! HERE, in the viewer's locale — so the SAME event pushes Russian to
//! the operator's Telegram (locale from `notification_settings.language`)
//! while the admin UI shows the request-locale.
//!
//! ## Adding a kind
//!
//! Add a `match` arm in [`render_alert`]. A `:user`/`:server` suffix
//! (e.g. `user.traffic_limit:alice`) is stripped before matching. An
//! unknown kind falls through to a neutral render rather than panicking
//! — but every SHIPPED kind has an arm, pinned by the tests below.
//!
//! ## Operator-action policy
//!
//! The `action` («что делать») line must NEVER instruct the operator to
//! `ssh root@…` / `journalctl` / `systemctl` (CLAUDE.md operator-action
//! policy) — only "open the server page → Deploy" / "check the hoster
//! panel". `action_has_no_shell_instructions` pins this.

pub mod digest;
pub mod formatting;
pub mod templates;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;

pub use digest::render_digest_html;
pub use formatting::{RenderedAlert, esc, is_silent, to_plain, to_telegram_html};
pub use templates::render_alert;
