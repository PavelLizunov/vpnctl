//! POSIX-sh quoting helpers shared across surfaces that build
//! remote-command strings to ship over SSH (russh transport, the
//! wizard's sshpass invocation, the CLI bootstrap helper).
//!
//! ## Why this lives in `vpnctl-core`
//!
//! Until 2026-05-18 [`single_quote`] was duplicated **three times**
//! with three different implementations producing identical output:
//!
//!   * `crates/ssh/src/russh_transport.rs::shell_quote` (terse
//!     `format!("'{escaped}'", escaped = s.replace('\'', r"'\''"))`).
//!   * `cli/src/cmd/bootstrap.rs::shell_single_quote` (same terse
//!     form).
//!   * `daemon/src/wizard_bootstrap.rs::shell_single_quote` (verbose
//!     char-by-char loop reproducing the same observable bytes).
//!
//! All three were caught by the post-`ec275c5` whole-repo duplication
//! sweep. They're consolidated here because `vpnctl-core` is already
//! a dep of all three callers (CLI, daemon, ssh crate) and the helper
//! has zero baggage (no allocator-specific behaviour, no I/O).

/// Wrap `s` in single quotes for POSIX sh, escaping embedded `'` as
/// `'\''` so the shell still sees the value as a single token.
///
/// ## Why single-quote
///
/// POSIX sh has two quoting forms: double-quote and single-quote. We
/// always use single because:
///
///   * Double-quote does parameter expansion (`$VAR`), command
///     substitution (`` ` `` and `$(…)`) and backslash escaping. A
///     user-supplied string containing `$HOME` would silently expand
///     remotely — fatal for secrets being pushed to `authorized_keys`.
///   * Single-quote is fully literal — only `'` itself needs escape.
///
/// ## Escape mechanism
///
/// Single-quoted runs cannot themselves contain a `'`. The standard
/// trick is to terminate the run, emit a backslash-escaped quote,
/// and reopen the run: `a'b` → `'a'\''b'`. The shell sees this as
/// three concatenated tokens (`a`, then a literal `'`, then `b`)
/// which assemble into the original three-character string.
///
/// ## Examples
///
/// ```
/// use vpnctl_core::shell::single_quote;
/// assert_eq!(single_quote("hello world"), "'hello world'");
/// assert_eq!(single_quote("a'b"), "'a'\\''b'");
/// assert_eq!(single_quote(""), "''");
/// // Literal `$HOME` survives — it is NOT expanded on the remote.
/// assert_eq!(single_quote("$HOME"), "'$HOME'");
/// ```
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
        // Important for the shell to see an empty token, not nothing
        // at all — `cmd ''` vs `cmd ` are semantically different.
        assert_eq!(single_quote(""), "''");
    }

    #[test]
    fn embedded_single_quote_escapes_with_close_escape_reopen() {
        // The standard POSIX trick: close the run, emit `\'`, reopen.
        // Result: `'a'\''b'`. Reading from left to right the shell
        // sees: 'a' + \' + 'b' → three tokens that concatenate to
        // the 3-byte string `a'b`.
        assert_eq!(single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn multiple_quotes_each_escape_independently() {
        // Two single-quotes → two escape sequences.
        assert_eq!(single_quote("'x'"), "''\\''x'\\'''");
    }

    #[test]
    fn dollar_sign_is_literal_no_expansion() {
        // The whole point of single-quote over double-quote: `$HOME`
        // arrives at the remote shell as the literal 5 bytes,
        // not whatever path the remote shell expands.
        assert_eq!(single_quote("$HOME"), "'$HOME'");
    }

    #[test]
    fn backtick_is_literal_no_command_substitution() {
        // Same: backtick command substitution is killed.
        assert_eq!(single_quote("`whoami`"), "'`whoami`'");
    }

    #[test]
    fn newline_survives_literally() {
        // Single-quote permits literal newlines in POSIX sh — they
        // arrive at the remote as part of the token. Useful for
        // multi-line keys being appended to `authorized_keys`.
        assert_eq!(single_quote("line1\nline2"), "'line1\nline2'");
    }

    #[test]
    fn ssh_authorized_keys_line_round_trip() {
        // Realistic input: an `ssh-ed25519` pubkey line as it would
        // arrive into the wizard's authorized_keys append step. The
        // string contains spaces (between algo / key / comment) and
        // no shell metacharacters, so the result is just the input
        // wrapped in quotes.
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID7example vpnctld-deploy";
        assert_eq!(single_quote(line), format!("'{line}'"));
    }
}
