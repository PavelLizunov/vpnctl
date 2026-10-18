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

pub fn form_field(body: &str, key: &str) -> Option<String> {
    let prefix_buf = format!("{key}=");
    body.split('&')
        .find_map(|kv| kv.strip_prefix(prefix_buf.as_str()))
        .map(decode_form_value)
}

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
        assert_eq!(form_field("name=alice", "missing"), None);
    }

    #[test]
    fn decodes_utf8_percent_escapes() {
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
        assert_eq!(form_field("name=", "name").as_deref(), Some(""));
        assert_eq!(form_field("other=x", "name"), None);
    }

    #[test]
    fn matches_only_exact_key_not_substring() {
        assert_eq!(form_field("username=bob", "name"), None);
    }

    #[test]
    fn picks_first_occurrence_when_key_appears_twice() {
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
        assert_eq!(path_segment_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn query_and_fragment_metachars_escaped() {
        assert_eq!(path_segment_encode("?#&"), "%3F%23%26");
    }

    #[test]
    fn high_byte_emits_uppercase_hex() {
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
        assert_eq!(decode_form_value("%D0%B0"), "а");
        assert_eq!(
            decode_form_value("%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82"),
            "привет"
        );
        assert_eq!(decode_form_value("%F0%9F%A6%80"), "🦀");
    }

    #[test]
    fn malformed_utf8_replaces_with_u_fffd_not_panic() {
        let got = decode_form_value("%C0%C0");
        assert!(got.contains('\u{FFFD}'));
    }

    #[test]
    fn invalid_hex_passes_through_verbatim() {
        assert_eq!(decode_form_value("%ZZ"), "%ZZ");
    }
}
