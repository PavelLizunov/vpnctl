//! Чистые функции для генерации идентификаторов и ключей.
//! Никакого I/O — всё детерминируемо из RNG.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use rand::TryRngCore;
use rand::rngs::OsRng;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

/// UUID v4 (RFC 4122) — для VLESS user id.
pub fn gen_uuid() -> String {
    Uuid::new_v4().to_string()
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

/// X25519 keypair (для REALITY и для WireGuard).
/// Возвращаем (private_key_b64, public_key_b64).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_format() {
        let u = gen_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(u.chars().filter(|c| *c == '-').count(), 4);
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
}
