pub mod digest;
pub mod formatting;
pub mod templates;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;

pub use digest::render_digest_html;
pub use formatting::{RenderedAlert, esc, is_silent, to_plain, to_telegram_html};
pub use templates::render_alert;
