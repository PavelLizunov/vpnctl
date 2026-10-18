use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::RngCore;
use rand::TryRngCore;
use rand::rngs::OsRng;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn gen_uuid() -> String {
    Uuid::new_v4().to_string()
}

pub fn is_valid_uuid(s: &str) -> bool {
    !s.is_empty() && Uuid::parse_str(s).is_ok()
}

pub fn is_valid_vpn_router_device_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn gen_vpn_router_device_id() -> std::io::Result<String> {
    let mut buf = [0u8; 16];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in &buf {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xF) as usize] as char);
    }
    Ok(out)
}

pub fn gen_password(entropy_bytes: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; entropy_bytes];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

pub fn gen_base64_key(key_bytes: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; key_bytes];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(STANDARD.encode(&buf))
}

pub fn gen_short_id() -> std::io::Result<String> {
    let mut buf = [0u8; 4];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(hex::encode(buf))
}

pub fn gen_sub_token() -> std::io::Result<String> {
    let mut buf = [0u8; 32];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

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

pub fn wireguard_keypair_matches(private: &str, public: &str) -> bool {
    fn decode(value: &str) -> Option<[u8; 32]> {
        if value.len() != 44 {
            return None;
        }
        let bytes: [u8; 32] = STANDARD.decode(value).ok()?.try_into().ok()?;
        if bytes == [0; 32] || STANDARD.encode(bytes) != value {
            return None;
        }
        Some(bytes)
    }
    let (Some(private), Some(public)) = (decode(private), decode(public)) else {
        return false;
    };
    PublicKey::from(&StaticSecret::from(private)).as_bytes() == &public
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaObfs {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s1: u32,
    pub s2: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

fn u32_in(rng: &mut OsRng, lo: u32, hi: u32) -> std::io::Result<u32> {
    debug_assert!(lo <= hi && hi < u32::MAX);
    let span = hi - lo + 1;
    let mut b = [0u8; 4];
    rng.try_fill_bytes(&mut b)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(lo + (u32::from_le_bytes(b) % span))
}

pub fn gen_amnezia_obfs() -> std::io::Result<AmneziaObfs> {
    let mut rng = OsRng;
    let jc = u32_in(&mut rng, 4, 12)?;
    let jmin = u32_in(&mut rng, 50, 100)?;
    let jmax = u32_in(&mut rng, jmin + 50, jmin + 150)?;
    let s1 = u32_in(&mut rng, 15, 150)?;
    let mut s2 = u32_in(&mut rng, 15, 150)?;
    while s2 == s1 + 56 {
        s2 = u32_in(&mut rng, 15, 150)?;
    }
    const H_LO: u32 = 5;
    const H_HI: u32 = i32::MAX as u32;
    let mut hs = [0u32; 4];
    let mut i = 0;
    while i < 4 {
        let v = u32_in(&mut rng, H_LO, H_HI)?;
        if !hs[..i].contains(&v) {
            hs[i] = v;
            i += 1;
        }
    }
    Ok(AmneziaObfs {
        jc,
        jmin,
        jmax,
        s1,
        s2,
        h1: hs[0],
        h2: hs[1],
        h3: hs[2],
        h4: hs[3],
    })
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
    fn gen_base64_key_is_standard_padded_b64_for_ss2022_psk() {
        let k16 = gen_base64_key(16).unwrap();
        assert_eq!(k16.len(), 24, "16-byte key → 24 chars, got {k16:?}");
        assert!(k16.ends_with("=="), "16-byte std b64 ends '==', got {k16}");

        let k32 = gen_base64_key(32).unwrap();
        assert_eq!(k32.len(), 44, "32-byte key → 44 chars, got {k32:?}");
        assert!(
            k32.ends_with('=') && !k32.ends_with("=="),
            "32-byte std b64 ends single '=', got {k32}"
        );

        for k in [&k16, &k32] {
            assert!(
                k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')),
                "must be STANDARD alphabet (no - or _): {k}"
            );
        }
        assert_ne!(
            gen_base64_key(16).unwrap(),
            k16,
            "two calls differ (CSPRNG)"
        );
    }

    #[test]
    fn wireguard_keypair_pubkey_derives_from_private() {
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
    fn amnezia_obfs_respects_all_constraints() {
        for _ in 0..200 {
            let o = gen_amnezia_obfs().unwrap();
            assert!((4..=12).contains(&o.jc), "jc out of range: {}", o.jc);
            assert!((50..=100).contains(&o.jmin), "jmin: {}", o.jmin);
            assert!(
                o.jmax >= o.jmin && o.jmax <= o.jmin + 150,
                "jmax {} not in [{},{}]",
                o.jmax,
                o.jmin,
                o.jmin + 150
            );
            assert!((15..=150).contains(&o.s1), "s1: {}", o.s1);
            assert!((15..=150).contains(&o.s2), "s2: {}", o.s2);
            assert_ne!(o.s2, o.s1 + 56, "s2 == s1+56 (DPI tell)");
            let hs = [o.h1, o.h2, o.h3, o.h4];
            for h in hs {
                assert!(h >= 5, "h {h} < 5 collides with a real WG msg type");
                assert!(h <= i32::MAX as u32, "h {h} exceeds i32 range");
            }
            for i in 0..4 {
                for j in (i + 1)..4 {
                    assert_ne!(hs[i], hs[j], "h1-h4 must be distinct: {hs:?}");
                }
            }
        }
    }

    #[test]
    fn amnezia_obfs_distinct_across_calls() {
        let a = gen_amnezia_obfs().unwrap();
        let b = gen_amnezia_obfs().unwrap();
        assert_ne!(
            (a.h1, a.h2, a.h3, a.h4),
            (b.h1, b.h2, b.h3, b.h4),
            "magic headers must differ per server"
        );
    }

    #[test]
    fn sub_token_is_url_safe_43_chars() -> std::io::Result<()> {
        let t = gen_sub_token()?;
        assert_eq!(t.len(), 43, "expected 43 chars, got {}", t.len());
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
