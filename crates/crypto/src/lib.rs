//! Чистые функции для генерации идентификаторов и ключей.
//! Никакого I/O — всё детерминируемо из RNG.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::RngCore;
use rand::TryRngCore;
use rand::rngs::OsRng;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

/// UUID v4 (RFC 4122) — для VLESS user id.
pub fn gen_uuid() -> String {
    Uuid::new_v4().to_string()
}

/// `true` if `s` is a syntactically valid RFC 4122 UUID (any version,
/// hyphenated). Used as a write-boundary gate for inputs that get
/// embedded into `inbounds[*].users[*].uuid` on a sing-box node — an
/// empty / malformed value would silently brick that user (Reality
/// handshake rejects, no telemetry signals the cause). Variant /
/// version are NOT enforced; sing-box accepts any non-empty
/// UUID-shaped string. Surfaces in `vpnctl-inventory`'s
/// `set_grant_client_uuid` (per-server UUID overrides — Phase 1 of
/// the ninitux merge) where the caller is a one-time Python import
/// script with no other sanity gate.
pub fn is_valid_uuid(s: &str) -> bool {
    !s.is_empty() && Uuid::parse_str(s).is_ok()
}

/// `true` if `s` is a 32-character lowercase hex string — the exact
/// shape ninitux's `clients.device_id` uses (e.g.
/// `a92b915032b48a2ed45ef72f4171e5f4`). Surfaces in the vpn-router
/// compat path: the Phase 3 inventory column
/// `users.vpn_router_device_id` and the handler at
/// `GET /api/v1/app/config/{device_id}` both gate on this shape so a
/// stray uuid or arbitrary string can't be written / looked up via
/// the wrong code path. Matches the nginx route's `[0-9a-f]+` regex
/// (we tighten it to exactly 32 chars to mirror subscription-server's
/// `_HEX32 = re.compile(r"^[0-9a-f]{32}$")`).
pub fn is_valid_vpn_router_device_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Криптостойкий пароль из URL-safe base64. Длина задаётся в байтах энтропии.
pub fn gen_password(entropy_bytes: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; entropy_bytes];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

/// REALITY short_id — 8 hex-символов (4 байта).
pub fn gen_short_id() -> std::io::Result<String> {
    let mut buf = [0u8; 4];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(hex::encode(buf))
}

/// Subscription token — 32-byte URL-safe base64 (43 chars unpadded). Opaque,
/// safe to put into a URL path. Never derived from user data — pure CSPRNG.
/// Used by `vpnctld` for `/sub/<token>` lookup.
pub fn gen_sub_token() -> std::io::Result<String> {
    let mut buf = [0u8; 32];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// X25519 keypair (для REALITY и для WireGuard).
/// Возвращаем (private_key_b64, public_key_b64).
///
/// `OsRng.unwrap_err()` — это легитимный API в `rand` 0.9: оборачивает
/// `TryRngCore` в `RngCore` (panic-on-failure). Поскольку `OsRng` черпает
/// энтропию из ядра ОС, реальный сбой = система не функциональна, и panic
/// — корректное поведение.
pub fn gen_x25519_keypair() -> (String, String) {
    let mut rng = OsRng.unwrap_err();
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    (
        URL_SAFE_NO_PAD.encode(sk.to_bytes()),
        URL_SAFE_NO_PAD.encode(pk.as_bytes()),
    )
}

/// WireGuard / AmneziaWG Curve25519 keypair, encoded in **standard
/// base64** with `=` padding — exactly what `wg genkey` /
/// `wg pubkey` emit. Returns `(private_key_b64, public_key_b64)`,
/// both 44 chars ending in `=`. Stored verbatim into
/// `users.wireguard_pubkey` / `users.wireguard_private` and emitted
/// straight into `[Interface] PrivateKey = …` / `[Peer] PublicKey = …`
/// in rendered `.conf` files.
///
/// **Why a separate function from `gen_x25519_keypair`:** REALITY
/// uses `base64url` no-padding, WG uses standard base64. Mixing the
/// two has caused real client breakage in the past — pin them to
/// distinct helpers so the encoding mismatch can't silently happen.
///
/// **Caller contract:** the private half is a SECRET. Whatever path
/// receives this tuple MUST:
///   * store the private into a secret column (audit-logged, masked
///     in any UI rendering),
///   * never log it,
///   * include it ONLY in the `/sub/<token>` body for the owning
///     user (transport already requires the token = bearer).
///
/// `OsRng.unwrap_err()` — same justification as `gen_x25519_keypair`.
pub fn gen_wireguard_keypair() -> (String, String) {
    let mut rng = OsRng.unwrap_err();
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    (
        STANDARD.encode(sk.to_bytes()),
        STANDARD.encode(pk.as_bytes()),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn uuid_format() {
        let u = gen_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(u.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn wireguard_keypair_is_standard_b64_44_chars_ending_eq() {
        // WG-tools convention: both halves are 32-byte Curve25519
        // values encoded in STANDARD base64 (with `=` padding); 44
        // chars total. Pinned to detect a regression to url-safe
        // (which is what `gen_x25519_keypair` uses for REALITY).
        let (priv_b64, pub_b64) = gen_wireguard_keypair();
        for s in [&priv_b64, &pub_b64] {
            assert_eq!(s.len(), 44, "WG b64 must be 44 chars, got {}: {s}", s.len());
            assert!(s.ends_with('='), "WG b64 must end with '=', got {s}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')),
                "WG b64 must be STANDARD alphabet (no - or _): {s}"
            );
        }
        assert_ne!(priv_b64, pub_b64, "private != public");
    }

    #[test]
    fn wireguard_keypair_pubkey_derives_from_private() {
        // Spec: the pubkey returned is X25519_basepoint(privkey).
        // Verified by re-running the derivation and comparing.
        let (priv_b64, pub_b64) = gen_wireguard_keypair();
        let priv_bytes = base64::engine::general_purpose::STANDARD
            .decode(&priv_b64)
            .unwrap();
        let arr: [u8; 32] = priv_bytes.try_into().expect("32-byte priv");
        let sk = x25519_dalek::StaticSecret::from(arr);
        let derived = x25519_dalek::PublicKey::from(&sk);
        let derived_b64 = base64::engine::general_purpose::STANDARD.encode(derived.as_bytes());
        assert_eq!(derived_b64, pub_b64);
    }

    #[test]
    fn wireguard_keypair_distinct_each_call() {
        let (s1, p1) = gen_wireguard_keypair();
        let (s2, p2) = gen_wireguard_keypair();
        assert_ne!(s1, s2);
        assert_ne!(p1, p2);
    }

    #[test]
    fn x25519_distinct_each_call() {
        let (s1, p1) = gen_x25519_keypair();
        let (s2, p2) = gen_x25519_keypair();
        assert_ne!(s1, s2);
        assert_ne!(p1, p2);
    }

    #[test]
    fn short_id_eight_hex_chars() -> std::io::Result<()> {
        let s = gen_short_id()?;
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn sub_token_is_url_safe_43_chars() -> std::io::Result<()> {
        let t = gen_sub_token()?;
        // 32 bytes of entropy → 43 chars unpadded URL-safe base64.
        assert_eq!(t.len(), 43, "expected 43 chars, got {}", t.len());
        // URL-safe alphabet: A-Z a-z 0-9 - _
        assert!(
            t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "non URL-safe char in {t:?}"
        );
        Ok(())
    }

    #[test]
    fn sub_token_is_unique_across_calls() -> std::io::Result<()> {
        let a = gen_sub_token()?;
        let b = gen_sub_token()?;
        assert_ne!(a, b);
        Ok(())
    }
}
