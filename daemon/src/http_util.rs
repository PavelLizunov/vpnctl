//! HTTP-level helpers that aren't tied to any single handler surface.
//!
//! Today this is just `decode_form_value` — `application/x-www-form-
//! urlencoded` decoding that the admin handlers consume. It lives here
//! (daemon-level) rather than inline in `handlers/admin.rs` so the
//! next surface that needs to decode a form payload (a future CLI
//! `vpnctl post` command, a future `/api/v1/*` endpoint that accepts
//! form-encoded bodies) doesn't reinvent it — likely with the same
//! Latin-1 bug the prior in-handler implementation shipped before
//! commit `aef1c6b`.
//!
//! No state, no I/O — pure functions over `&str`.

/// URL-decode a form value (`application/x-www-form-urlencoded`).
/// Replaces `+` with space, `%XX` with the byte value, and assembles
/// the resulting bytes into a `String`.
///
/// **UTF-8-correct.** The pre-2026-05-17 version used `out.push(byte
/// as char)` which silently *Latin-1-decoded* every byte ≥ 0x80 —
/// e.g. `%D0%B0` (UTF-8 for Cyrillic 'а') used to render as `Ð°`
/// instead of `а`. Today's flows (user-id is ASCII-restricted,
/// fingerprint is base64-only) mask this, but every NEW form that
/// might carry international text would have shipped the bug.
/// Caught as a deferred minor in the 2026-05-16 review-agent burst
/// (`e250789` audit), addressed here.
///
/// Approach: collect decoded bytes into a `Vec<u8>` first, then
/// `String::from_utf8_lossy` so malformed UTF-8 in the input becomes
/// U+FFFD instead of a panic. Lossy is fine: validators on every
/// form field reject anything strange before it reaches the DB.
pub fn decode_form_value(s: &str) -> String {
    let mut decoded: Vec<u8> = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            // Bounds: `bytes[i+1]` and `bytes[i+2]` accessed below;
            // need `i+2 < bytes.len()` (strict-less since `bytes.len()`
            // is one past the last index). `"%20"` len 3 at i=0:
            // `2 < 3` ✓ decodes; `"%2"` len 2 at i=0: `2 < 2` ✗ falls
            // through to literal `%`. Both correct.
            b'%' if i + 2 < bytes.len() => {
                if let Ok(h) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    && let Ok(byte) = u8::from_str_radix(h, 16)
                {
                    decoded.push(byte);
                    i += 3;
                    continue;
                }
                decoded.push(b'%');
                i += 1;
            }
            other => {
                decoded.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod decode_form_value_tests {
    use super::decode_form_value;

    #[test]
    fn ascii_passthrough() {
        assert_eq!(decode_form_value("hello"), "hello");
    }

    #[test]
    fn plus_becomes_space() {
        assert_eq!(decode_form_value("hello+world"), "hello world");
    }

    #[test]
    fn hex_escapes_decode_byte() {
        assert_eq!(decode_form_value("20%2F30"), "20/30");
    }

    #[test]
    fn utf8_multibyte_assembles_correctly() {
        // %D0%B0 = U+0430 Cyrillic 'а'. Pre-fix returned "Ð°".
        assert_eq!(decode_form_value("%D0%B0"), "а");
        // Full word: «привет» = %D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82
        assert_eq!(
            decode_form_value("%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82"),
            "привет"
        );
        // 4-byte UTF-8 emoji: 🦀 = U+1F980 = F0 9F A6 80.
        assert_eq!(decode_form_value("%F0%9F%A6%80"), "🦀");
    }

    #[test]
    fn malformed_utf8_replaces_with_u_fffd_not_panic() {
        // 0xC0 starts a 2-byte sequence but isn't followed by a valid
        // continuation; lossy → U+FFFD.
        let got = decode_form_value("%C0%C0");
        assert!(got.contains('\u{FFFD}'));
    }

    #[test]
    fn invalid_hex_passes_through_verbatim() {
        // %ZZ is not valid hex — emit '%' then 'Z' 'Z' (validator on
        // the consuming side rejects it).
        assert_eq!(decode_form_value("%ZZ"), "%ZZ");
    }
}
