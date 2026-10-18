pub fn single_quote(s: &str) -> String {
    let escaped = s.replace('\'', r"'\''");
    format!("'{escaped}'")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::single_quote;

    #[test]
    fn simple_string_wraps_in_quotes() {
        assert_eq!(single_quote("hello world"), "'hello world'");
    }

    #[test]
    fn empty_string_emits_paired_quotes() {
        assert_eq!(single_quote(""), "''");
    }

    #[test]
    fn embedded_single_quote_escapes_with_close_escape_reopen() {
        assert_eq!(single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn multiple_quotes_each_escape_independently() {
        assert_eq!(single_quote("'x'"), "''\\''x'\\'''");
    }

    #[test]
    fn dollar_sign_is_literal_no_expansion() {
        assert_eq!(single_quote("$HOME"), "'$HOME'");
    }

    #[test]
    fn backtick_is_literal_no_command_substitution() {
        assert_eq!(single_quote("`whoami`"), "'`whoami`'");
    }

    #[test]
    fn newline_survives_literally() {
        assert_eq!(single_quote("line1\nline2"), "'line1\nline2'");
    }

    #[test]
    fn ssh_authorized_keys_line_round_trip() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID7example vpnctld-deploy";
        assert_eq!(single_quote(line), format!("'{line}'"));
    }
}
