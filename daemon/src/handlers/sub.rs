mod handler;
mod mihomo;
mod singbox;
#[cfg(test)]
mod tests;
mod v2ray;

pub(crate) use self::handler::{get, get_mihomo, rate_limited};
