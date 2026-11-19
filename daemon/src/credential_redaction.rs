use std::borrow::Cow;

pub(crate) fn redact_uuid_literals(text: &str) -> Cow<'_, str> {
    const UUID_LEN: usize = 36;
    let mut output = String::new();
    let mut copied = 0;
    for (start, ch) in text.char_indices() {
        if start < copied || !ch.is_ascii_hexdigit() {
            continue;
        }
        let end = start + UUID_LEN;
        if text
            .get(start..end)
            .is_some_and(vpnctl_crypto::is_valid_uuid)
        {
            output.push_str(&text[copied..start]);
            output.push_str("<redacted UUID>");
            copied = end;
        }
    }
    if copied == 0 {
        return Cow::Borrowed(text);
    }
    output.push_str(&text[copied..]);
    Cow::Owned(output)
}

#[cfg(test)]
mod tests {
    use super::redact_uuid_literals;

    #[test]
    fn masks_multiple_uuid_literals_and_preserves_surrounding_text() {
        let text =
            "ошибка [f1c70219-0d27-4d9a-a145-0ffa00000e01] {F1C70219-0D27-4D9A-A145-0FFA00000E02}";
        assert_eq!(
            redact_uuid_literals(text),
            "ошибка [<redacted UUID>] {<redacted UUID>}"
        );
        assert_eq!(
            redact_uuid_literals("open firewall on 443"),
            "open firewall on 443"
        );
    }
}
