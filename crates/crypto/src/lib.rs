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

/// Mint a fresh 32-hex `vpn_router_device_id` (16 random bytes ⇒
/// 32 lowercase hex chars). Matches the shape
/// [`is_valid_vpn_router_device_id`] enforces, so the round-trip
/// `mint → store → look-up` is always valid.
///
/// **Bearer credential.** Anyone who knows this string can fetch
/// the user's full VPN config via the public
/// `/api/v1/app/config/<device_id>` endpoint. Treat with the same
/// care as `sub_token`. NEVER log this value; the web UI displays
/// it on the user-detail page (admin-gated) and embeds it into the
/// production subscription URL Pavel shares with end users.
pub fn gen_vpn_router_device_id() -> std::io::Result<String> {
    let mut buf = [0u8; 16];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    // 32 lowercase hex chars — base16 lookup table.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in &buf {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xF) as usize] as char);
    }
    Ok(out)
}

/// Криптостойкий пароль из URL-safe base64. Длина задаётся в байтах энтропии.
pub fn gen_password(entropy_bytes: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; entropy_bytes];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

/// Random raw key of `key_bytes`, encoded as **standard** base64 WITH
/// padding (NOT url-safe). For protocol secrets whose wire format is
/// base64-DECODED back to raw key material by the node daemon — e.g. a
/// Shadowsocks-2022 PSK: sing-box parses `password` with Go's
/// `base64.StdEncoding`, so a `gen_password` (url-safe, no-pad) string
/// fails to decode and the whole sing-box config is rejected. `16`
/// bytes = 128-bit key for `2022-blake3-aes-128-gcm` (→ 24 chars
/// ending `==`); `32` bytes = 256-bit for the `-aes-256-gcm` variant.
pub fn gen_base64_key(key_bytes: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; key_bytes];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(STANDARD.encode(&buf))
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

/// AmneziaWG obfuscation parameter set, minted PER SERVER. Rendered as
/// decimal strings into both the server `awg0.conf` (the `amnezia_wg`
/// kernel) and the client artefact (`.conf` / `vpn://` deep-link).
///
/// **Bidirectional vs client-only** (verified against amneziawg-go's
/// `magicHeader.Validate` + the AWG README): `s1`/`s2` (handshake-init /
/// -response padding) and `h1`-`h4` (the magic message-type headers)
/// rewrite REAL Noise packets and MUST be identical on both peers;
/// `jc`/`jmin`/`jmax` (standalone junk packets) are client-only. The
/// whole set is minted together so the bidirectional values stay
/// internally coherent and the same minted values reach the client.
///
/// Constraints enforced:
///   * `h1`-`h4` distinct + ≥ 5 — values 1-4 are the real WG message
///     types (init/response/cookie/transport); a magic header colliding
///     with them defeats the obfuscation.
///   * `s2 != s1 + 56` — the real init packet is 148+s1 bytes and the
///     response is 92+s2; equal lengths (s2 = s1+56) are a DPI tell.
///   * `jmin <= jmax`, both bounded well under the MTU.
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

/// Uniform-ish `u32` in `[lo, hi]` (inclusive). Modulo bias is
/// irrelevant here — these are obfuscation constants, not key material.
/// `hi` must be < `u32::MAX` so `hi - lo + 1` can't overflow (all
/// callers below use `hi <= i32::MAX`).
fn u32_in(rng: &mut OsRng, lo: u32, hi: u32) -> std::io::Result<u32> {
    debug_assert!(lo <= hi && hi < u32::MAX);
    let span = hi - lo + 1;
    let mut b = [0u8; 4];
    rng.try_fill_bytes(&mut b)
        .map_err(|e| std::io::Error::other(format!("rng: {e}")))?;
    Ok(lo + (u32::from_le_bytes(b) % span))
}

/// Mint a per-server [`AmneziaObfs`] set with the coherence constraints
/// documented on the struct. Pure CSPRNG (OsRng); no I/O.
pub fn gen_amnezia_obfs() -> std::io::Result<AmneziaObfs> {
    let mut rng = OsRng;
    let jc = u32_in(&mut rng, 4, 12)?;
    let jmin = u32_in(&mut rng, 50, 100)?;
    let jmax = u32_in(&mut rng, jmin + 50, jmin + 150)?;
    let s1 = u32_in(&mut rng, 15, 150)?;
    let mut s2 = u32_in(&mut rng, 15, 150)?;
    // Avoid the equal-length init/response tell (s2 == s1 + 56).
    while s2 == s1 + 56 {
        s2 = u32_in(&mut rng, 15, 150)?;
    }
    // h1-h4: distinct, ≥ 5 (avoid the real WG message types 1-4), and
    // safely within i32 range (some impls treat the header as signed).
    const H_LO: u32 = 5;
    const H_HI: u32 = i32::MAX as u32; // 2_147_483_647
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
    fn gen_base64_key_is_standard_padded_b64_for_ss2022_psk() {
        // sing-box parses the Shadowsocks-2022 `password` with Go's
        // `base64.StdEncoding`, so the key MUST be STANDARD base64 with
        // padding (NOT the url-safe `gen_password`). 16 bytes (aes-128)
        // → 24 chars ending `==`; 32 bytes (aes-256) → 44 chars ending
        // a single `=`. A regression to url-safe / unpadded here would
        // crash every node config carrying an ss2022 inbound.
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
    fn amnezia_obfs_respects_all_constraints() {
        // 200 draws to exercise the constraint branches (s2 reroll,
        // h-distinctness retry) and the range bounds.
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
            // The equal-length init/response tell must never be emitted.
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
        // Two CSPRNG draws sharing all four 31-bit magic headers is
        // astronomically unlikely — a regression to a fixed seed fires.
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
