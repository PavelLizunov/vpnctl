use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use axum::extract::Request;
use axum::http::{HeaderMap, header, uri::Authority};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{COOKIE, HOST, ORIGIN};
use crate::handlers::auth::{VERIFY_PERMITS, bounded_password_work};

pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted_peer: bool,
) -> Option<IpAddr> {
    let peer = canonical_ip(peer?);
    if !trusted_peer {
        return Some(peer);
    }
    let value = single_header(headers, "x-real-ip")?;
    value.parse().ok().map(canonical_ip)
}

pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}

pub(super) fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

pub(super) fn corp_host(request: &Request) -> Result<bool, ()> {
    let mut hosts = request.headers().get_all(header::HOST).iter();
    let Some(raw) = hosts.next() else {
        return if request.uri().authority().is_some() {
            Err(())
        } else {
            Ok(false)
        };
    };
    if hosts.next().is_some() {
        return Err(());
    }
    let raw = raw.to_str().map_err(|_| ())?;
    if let Some(uri_authority) = request.uri().authority()
        && !uri_authority.as_str().eq_ignore_ascii_case(raw)
    {
        return Err(());
    }
    let authority = raw
        .parse::<Authority>()
        .ok()
        .filter(|_| !raw.contains('@') && !raw.contains([' ', '\t', ',', '/', '\\']));
    let Some(authority) = authority else {
        return if raw.to_ascii_lowercase().contains(HOST) {
            Err(())
        } else {
            Ok(false)
        };
    };
    if !authority
        .host()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(HOST)
    {
        return Ok(false);
    }
    if !raw.eq_ignore_ascii_case(HOST) && !raw.eq_ignore_ascii_case(&format!("{HOST}:443")) {
        return Err(());
    }
    Ok(true)
}

pub(super) fn ambiguous_headers(headers: &HeaderMap) -> bool {
    ["origin", "authorization", "content-type", "x-real-ip"]
        .iter()
        .any(|name| headers.get_all(*name).iter().count() > 1)
}

pub(super) fn same_origin(headers: &HeaderMap) -> bool {
    single_header(headers, "origin") == Some(ORIGIN)
        && !matches!(single_header(headers, "sec-fetch-site"), Some("cross-site"))
}

pub(super) fn equal_secret(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    bool::from(left.ct_eq(&right))
}

pub(super) fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

pub(super) fn session_hash(headers: &HeaderMap) -> Option<String> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE).iter() {
        let header = header.to_str().ok()?;
        if header.len() > 8192 {
            return None;
        }
        for pair in header.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != COOKIE {
                continue;
            }
            if found.is_some() || value.len() != 43 {
                return None;
            }
            let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
            if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
                return None;
            }
            found = Some(token_hash(value));
        }
    }
    found
}

pub(super) fn random_token() -> Option<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).ok()?;
    Some(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

pub(super) async fn verify_password(password: Zeroizing<String>, phc: Zeroizing<String>) -> bool {
    bounded_password_work(&VERIFY_PERMITS, move || {
        let Ok(parsed) = PasswordHash::new(&phc) else {
            return false;
        };
        let Ok(params) = argon2::Params::try_from(&parsed) else {
            return false;
        };
        let mut salt = [0u8; 64];
        if parsed.algorithm.as_str() != "argon2id"
            || parsed.version != Some(19)
            || !(8192..=65536).contains(&params.m_cost())
            || !(1..=4).contains(&params.t_cost())
            || !(1..=4).contains(&params.p_cost())
            || parsed.hash.is_none_or(|hash| hash.len() != 32)
            || !parsed.salt.is_some_and(|encoded| {
                encoded
                    .decode_b64(&mut salt)
                    .is_ok_and(|bytes| (16..=64).contains(&bytes.len()))
            })
        {
            return false;
        }
        argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
    .await
    .unwrap_or(false)
}
