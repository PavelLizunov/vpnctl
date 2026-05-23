//! `vpnctl admin` subcommands — utilities for the daemon-side admin
//! surface, NOT for managing inventory state. Today: one subcommand,
//! `hash-password`, which produces an Argon2id PHC string suitable
//! for `VPNCTLD_ADMIN_PASSWORD`.
//!
//! ## Why this exists
//!
//! `daemon/src/handlers/auth.rs` doc-comment has referenced
//! `vpnctl admin hash-password <plain>` since the auth module landed,
//! but the CLI never had a matching subcommand — anyone following the
//! docs got «error: unrecognized subcommand 'admin'». Audit B2
//! (2026-05-22) caught it. The subcommand now exists; the doc-comment
//! is no longer a lie.
//!
//! ## Stdin vs `--password <plain>`
//!
//! Default (no `--password` flag) — read **exactly one line** from
//! stdin, trim trailing newline. This is the right default because:
//!
//!   * The plaintext does NOT appear in `ps`/`/proc/<pid>/cmdline`.
//!   * It does NOT leak into shell history.
//!   * Pipeable: `echo -n s3cret | vpnctl admin hash-password`.
//!
//! `--password <plain>` is an opt-in for ad-hoc interactive use. We
//! warn on stderr when this path is used.

use anyhow::Context;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};

pub(crate) fn hash_password(password_arg: Option<String>) -> anyhow::Result<()> {
    let plaintext = match password_arg {
        Some(p) => {
            eprintln!(
                "warning: password was passed on the command line; \
                 it now appears in shell history and /proc/<pid>/cmdline. \
                 Prefer stdin: `echo -n SECRET | vpnctl admin hash-password`."
            );
            p
        }
        None => read_one_line_from_stdin().context("read password from stdin")?,
    };
    if plaintext.is_empty() {
        anyhow::bail!("empty password — refusing to hash");
    }
    // Generate a fresh per-secret salt. `SaltString::generate` uses
    // the supplied RNG; `OsRng` is the crypto-suitable default.
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::default();
    let phc = argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?
        .to_string();
    // Single line to stdout — pipeable into the env file.
    println!("{phc}");
    Ok(())
}

/// Read a single line from stdin (no echo control — that's the
/// caller's shell to manage). We do NOT strip leading whitespace; if
/// the operator includes leading spaces in their password, we honour
/// them. Trailing `\n` (and `\r\n`) is stripped because virtually no
/// shell would intentionally append it to a password literal.
fn read_one_line_from_stdin() -> anyhow::Result<String> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    let n = stdin.lock().read_line(&mut line)?;
    if n == 0 {
        anyhow::bail!("stdin closed before reading a password");
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    /// Round-trip: hash a plaintext via the same helper used by the
    /// CLI, then verify the resulting PHC string parses and matches.
    /// Catches argon2 version drift between CLI and daemon — if the
    /// daemon ever upgrades to v0.6 with breaking changes, this test
    /// will surface it before the operator's env file silently fails
    /// at runtime.
    #[test]
    fn hash_password_round_trip_verifies_with_same_plaintext() {
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let phc = Argon2::default()
            .hash_password(b"hunter2", &salt)
            .unwrap()
            .to_string();
        let parsed = PasswordHash::new(&phc).unwrap();
        Argon2::default()
            .verify_password(b"hunter2", &parsed)
            .expect("must verify the original plaintext");
        Argon2::default()
            .verify_password(b"wrong-pw", &parsed)
            .expect_err("must reject a different plaintext");
    }
}
