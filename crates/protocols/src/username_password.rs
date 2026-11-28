use std::collections::{HashMap, HashSet};

use percent_encoding::utf8_percent_encode;
use serde_json::{Value, json};
use vpnctl_core::{CoreError, Result, User};

use crate::encoding::USERINFO;

pub(crate) fn setting<'a>(
    secrets: &'a HashMap<String, String>,
    key: &str,
    default: &'a str,
    allowed: &[&str],
) -> Result<&'a str> {
    let value = secrets.get(key).map_or(default, String::as_str);
    if !allowed.contains(&value) {
        return Err(CoreError::Render(format!(
            "{key} must be one of {}",
            allowed.join(", ")
        )));
    }
    Ok(value)
}

pub(crate) fn listen_port(
    secrets: &HashMap<String, String>,
    key: &str,
    default: u16,
) -> Result<u16> {
    match secrets.get(key) {
        None => Ok(default),
        Some(value) => value
            .parse()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| CoreError::Render(format!("{key} must be in 1..=65535"))),
    }
}

pub(crate) fn validate_user(user: &User, protocol: &str, allow_colon: bool) -> Result<()> {
    if user.disabled {
        return Err(CoreError::Render(format!(
            "disabled users cannot receive {protocol} configurations"
        )));
    }
    if user.id.0.is_empty() || (!allow_colon && user.id.0.contains(':')) {
        return Err(CoreError::Render(format!("invalid {protocol} username")));
    }
    if !vpnctl_crypto::is_valid_uuid(&user.uuid) {
        return Err(CoreError::Render(format!(
            "{protocol} user has an invalid UUID"
        )));
    }
    Ok(())
}

pub(crate) fn inbound_users(users: &[User], protocol: &str, allow_colon: bool) -> Vec<Value> {
    let mut names = HashSet::new();
    users
        .iter()
        .filter(|user| {
            validate_user(user, protocol, allow_colon).is_ok() && names.insert(&user.id.0)
        })
        .map(|user| json!({"username": user.id.0, "password": user.uuid}))
        .collect()
}

pub(crate) fn userinfo(user: &User) -> String {
    let username = utf8_percent_encode(&user.id.0, USERINFO);
    let password = utf8_percent_encode(&user.uuid, USERINFO);
    format!("{username}:{password}")
}
