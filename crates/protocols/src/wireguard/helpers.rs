use std::collections::HashMap;
use vpnctl_core::{RenderCtx, Result, User};

pub const WIREGUARD_PORT: u16 = 51820;

pub(crate) fn listen_port(secrets: &HashMap<String, String>) -> u16 {
    secrets
        .get("wireguard.listen_port")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p != 0)
        .unwrap_or(WIREGUARD_PORT)
}

pub(crate) const DEFAULT_SERVER_CIDR: &str = "10.66.0.1/24";

pub const CLIENT_PRIVKEY_PLACEHOLDER: &str = "<PASTE YOUR PRIVATE KEY HERE>";

pub fn is_valid_wg_pubkey(s: &str) -> bool {
    if s.len() != 44 {
        return false;
    }
    if !s.ends_with('=') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

pub(crate) use crate::encoding::FRAGMENT;

pub(crate) fn peer_octet_for(ctx: &RenderCtx<'_>, user: &User) -> Result<u16> {
    crate::wg_addressing::peer_octet_in_slash24(ctx, user, 2)
}
