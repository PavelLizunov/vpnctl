//! HTTP-level helpers that aren't tied to any single handler surface.
//!
//! - [`decode_form_value`] — UTF-8-correct
//!   `application/x-www-form-urlencoded` value decoder (added 2026-05-18,
//!   commit `fdba9e0`; originally inline in `handlers/admin.rs` with a
//!   Latin-1 bug fixed in `aef1c6b`).
//! - [`form_field`] — shorthand for the `body.split('&')
//!   .find_map(|kv| kv.strip_prefix("name=")).unwrap_or("")` boilerplate
//!   followed by `decode_form_value`. Was inlined ~10× across admin
//!   handlers; consolidated here 2026-05-18 alongside `path_segment_encode`.
//! - [`path_segment_encode`] — RFC 3986 percent-encoder for a single
//!   path segment (unreserved set: `A-Z a-z 0-9 - . _ ~`, everything
//!   else as `%XX`). Was byte-identical in `handlers/admin.rs` and
//!   `wizard_bootstrap.rs` with a doc-comment in the wizard's copy
//!   explicitly admitting the duplication.
//!
//! No state, no I/O — pure functions over `&str`. Lives at the daemon
//! level (not in `vpnctl-core`) because all three helpers are
//! HTTP-shaped — `vpnctl-core` is `no-std`-friendly and shouldn't
//! grow HTTP semantics.

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

/// Extract a single field from an `application/x-www-form-urlencoded`
/// body and return its UTF-8-decoded value, or `None` if the field
/// isn't present.
///
/// Equivalent to (and replaces) two inline patterns:
///
/// ```text
/// // Pattern A — admin.rs ~10 sites, "absent = empty" simplification:
/// let raw = body.split('&')
///     .find_map(|kv| kv.strip_prefix("FIELD="))
///     .unwrap_or("");
/// let value = decode_form_value(raw);
///
/// // Pattern B — admin.rs wizard handler:
/// fn form_field(body: &str, name: &str) -> Option<String> {
///     let prefix = format!("{name}=");
///     body.split('&').find_map(|kv| kv.strip_prefix(&prefix))
///         .map(decode_form_value)
/// }
/// ```
///
/// The `Option` shape matches pattern B and is strictly more
/// expressive than pattern A — call sites that genuinely want the
/// «absent = empty» simplification just do `.unwrap_or_default()`.
/// New code should prefer matching on `Option` so that an absent
/// required field becomes a 400 instead of a silent empty-string
/// validator pass.
///
/// **Key matching rule:** `key` is matched against the raw token
/// LEFT of `=`. Callers passing arbitrary user-controlled strings as
/// `key` would let an attacker invent fields — DO NOT do that; `key`
/// must be a known compile-time-constant field name from the form's
/// schema. (All current callers pass string literals.)
pub fn form_field(body: &str, key: &str) -> Option<String> {
    let prefix_buf = format!("{key}=");
    body.split('&')
        .find_map(|kv| kv.strip_prefix(prefix_buf.as_str()))
        .map(decode_form_value)
}

/// Percent-encode a string for use as a single URL path segment.
/// Keeps RFC 3986 unreserved chars (`A-Z`, `a-z`, `0-9`, `-`, `.`,
/// `_`, `~`) verbatim; everything else is `%XX`-escaped.
///
/// Used to build admin redirect URLs that embed a `server_id` /
/// `user_id` (operator-typed `?`, `#`, `/`, spaces all need escaping
/// so the redirect URL parses on the round-trip). Avoids pulling
/// `percent-encoding` as a direct dep — sub_token / user_id /
/// server_id rarely need this in practice but it costs ~10 lines to
/// be safe.
pub fn path_segment_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod form_field_tests {
    use super::form_field;

    #[test]
    fn returns_decoded_value_for_present_key() {
        assert_eq!(
            form_field("name=alice&age=30", "name").as_deref(),
            Some("alice")
        );
        assert_eq!(
            form_field("name=alice&age=30", "age").as_deref(),
            Some("30")
        );
    }

    #[test]
    fn returns_none_for_absent_key() {
        // Distinguishes "absent" from "present-but-empty". A handler
        // that wants the legacy "absent = empty" simplification
        // appends `.unwrap_or_default()` at the call site.
        assert_eq!(form_field("name=alice", "missing"), None);
    }

    #[test]
    fn decodes_utf8_percent_escapes() {
        // The whole point of routing through decode_form_value.
        assert_eq!(
            form_field("greeting=%D0%B0", "greeting").as_deref(),
            Some("а")
        );
    }

    #[test]
    fn decodes_plus_as_space() {
        assert_eq!(
            form_field("city=New+York", "city").as_deref(),
            Some("New York")
        );
    }

    #[test]
    fn distinguishes_present_empty_from_absent() {
        // `name=` is present with an empty value; `name` is absent
        // entirely. Critical distinction for validators that want to
        // 400 on missing-required vs accept-empty.
        assert_eq!(form_field("name=", "name").as_deref(), Some(""));
        assert_eq!(form_field("other=x", "name"), None);
    }

    #[test]
    fn matches_only_exact_key_not_substring() {
        // Regression for a plausible foot-gun: if `form_field` did a
        // substring match instead of `strip_prefix("KEY=")`, asking
        // for "name" in `username=bob` would return Some("bob").
        assert_eq!(form_field("username=bob", "name"), None);
    }

    #[test]
    fn picks_first_occurrence_when_key_appears_twice() {
        // Spec follows `find_map` semantics — first match wins. Not a
        // typical situation (the form schema doesn't allow duplicates)
        // but pinning to lock the contract.
        assert_eq!(
            form_field("k=first&k=second", "k").as_deref(),
            Some("first")
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod path_segment_encode_tests {
    use super::path_segment_encode;

    #[test]
    fn unreserved_chars_pass_through() {
        // RFC 3986 unreserved set: ALPHA / DIGIT / "-" / "." / "_" / "~"
        assert_eq!(
            path_segment_encode("abcXYZ-._~0123456789"),
            "abcXYZ-._~0123456789"
        );
    }

    #[test]
    fn space_is_percent_encoded() {
        assert_eq!(path_segment_encode("hello world"), "hello%20world");
    }

    #[test]
    fn slash_is_percent_encoded_because_path_segment() {
        // Critical: `/` MUST be escaped or the segment would split into
        // two segments on the round-trip. This is the function's whole
        // reason for existing over a naive percent-encoder.
        assert_eq!(path_segment_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn query_and_fragment_metachars_escaped() {
        // `?`, `#`, `&` would all change URL meaning if left raw.
        assert_eq!(path_segment_encode("?#&"), "%3F%23%26");
    }

    #[test]
    fn high_byte_emits_uppercase_hex() {
        // Single non-ASCII byte (UTF-8 continuation): must emit %XX
        // with uppercase hex. RFC 3986 §2.1 mandates uppercase but
        // allows lowercase — we standardise on uppercase to keep
        // redirect URLs byte-stable across rebuilds.
        // 'à' = U+00E0 = C3 A0 in UTF-8.
        assert_eq!(path_segment_encode("à"), "%C3%A0");
    }

    #[test]
    fn empty_input_gives_empty_output() {
        assert_eq!(path_segment_encode(""), "");
    }
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
