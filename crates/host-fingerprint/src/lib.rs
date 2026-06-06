//! SSH host-key fingerprint utilities — single source of truth.
//!
//! ## Why this crate exists
//!
//! Before 2026-05-18 the workspace had **three** near-duplicate
//! implementations of «shell out to `ssh-keyscan` + `ssh-keygen -lf -`
//! and return the SHA256 fingerprint of `<host>:<port>`»:
//!
//!   * `daemon/src/wizard_bootstrap.rs::ssh_keyscan_fingerprint`
//!     (async — called from the add-server SSE handler)
//!   * `daemon/src/handlers/admin.rs::keyscan_fingerprint_blocking`
//!     (sync — wrapped in `spawn_blocking` by the
//!     `POST /admin/servers/{id}/set-fingerprint` route)
//!   * `cli/src/cmd/server.rs::fetch_fingerprint_via_keyscan`
//!     (sync — called from `vpnctl server set-fingerprint --from-keyscan`)
//!
//! Plus **four** near-duplicate `is_valid_sha256_fingerprint` shape
//! validators (one per call-site above + the inventory layer's defensive
//! check at INSERT time). They had **drifted** in subtle ways:
//!
//!   * `wizard_bootstrap` was missing the `--` separator before the
//!     host argument — a flag-injection vector for inventory addresses
//!     that legitimately or maliciously start with `-`. The other two
//!     had the separator after the review-agent sweep on commit
//!     `9819538`, but the review never saw the wizard's copy because
//!     it sat outside the diff window.
//!   * The CLI + daemon validators accepted URL-safe base64
//!     (`-_` alphabet), the inventory validator did not — meaning the
//!     same fingerprint could be set via web/CLI and then fail
//!     re-validation at the inventory layer on a future call.
//!   * The CLI + daemon validators accepted 1..=44 chars, the
//!     inventory required exactly 43 or 44 — meaning a truncated
//!     `SHA256:abc` passed the surface validators and only died at
//!     the DB layer with a confusing error.
//!
//! This crate consolidates the two functions into one canonical
//! implementation that ALL three surfaces + the inventory call.
//!
//! ## Security note (the `--` separator)
//!
//! `ssh-keyscan`'s own `getopt(3)`-style argument parser treats any
//! token starting with `-` as a flag — even when passed via
//! `Command::new(...).args(...)` (the kernel-level `argv` is
//! shell-safe, but `ssh-keyscan` does its own parsing on top of it).
//! An attacker-controlled or typo'd inventory address like
//! `-fsomething` becomes `ssh-keyscan -fsomething` which reads from
//! an attacker-controlled file. The POSIX defense is the `--`
//! separator: every flag before `--` is processed normally, every
//! token after `--` is positional regardless of leading dashes.

use std::io::Write;
use std::process::{Command, Stdio};

/// Errors returnable by [`fetch_via_keyscan`].
///
/// Distinct variants per failure stage so call-sites can map to their
/// preferred error type (`anyhow::Error` / `String` / custom) with a
/// useful operator-facing message instead of an opaque «keyscan
/// failed» blob.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh-keyscan failed to spawn: {0}")]
    KeyscanSpawn(String),

    #[error(
        "ssh-keyscan for {host}:{port} exited {code:?} (host unreachable or no ed25519/rsa key?): \
         {stderr}"
    )]
    KeyscanFailed {
        host: String,
        port: u16,
        code: Option<i32>,
        stderr: String,
    },

    #[error("ssh-keyscan returned no host key for {host}:{port}")]
    KeyscanEmpty { host: String, port: u16 },

    #[error("ssh-keygen failed to spawn: {0}")]
    KeygenSpawn(String),

    #[error("ssh-keygen stdin pipe missing (Stdio::piped was ignored?)")]
    KeygenStdinPipe,

    #[error("ssh-keygen stdin write failed: {0}")]
    KeygenStdinWrite(String),

    #[error("ssh-keygen wait failed: {0}")]
    KeygenWait(String),

    #[error("ssh-keygen -lf - exited {0:?}")]
    KeygenFailed(Option<i32>),

    #[error("ssh-keygen output had no SHA256: token (got {output:?})")]
    NoFingerprintToken { output: String },
}

/// Syntactic shape check for an SSH host fingerprint.
///
/// Accepts `SHA256:<base64>` where the base64 body is:
///   * **exactly 43 chars unpadded** OR **exactly 44 chars padded** with `=`,
///   * alphabet `[A-Za-z0-9+/]` (standard) OR `[A-Za-z0-9-_]` (URL-safe),
///   * plus the padding char `=` at the tail.
///
/// Both alphabets are accepted because real `ssh-keygen` outputs the
/// standard one (`+/`) but some emitters (jq one-liners, GitHub /
/// Forgejo UI copy-buttons) substitute the URL-safe variant (`-_`).
/// SHA-256 produces 32 bytes → 43 base64 chars unpadded → 44 padded.
/// Anything outside that length is structurally invalid even before
/// we decode.
///
/// Returns `false` for every malformed input — does NOT decode the
/// base64 body, since at THIS layer we only want a fast shape sieve
/// (the operator typed something; reject obvious garbage with a clear
/// 4xx, don't wait for the SSH connect attempt to surface the bug).
pub fn validate_shape(fp: &str) -> bool {
    let Some(rest) = fp.strip_prefix("SHA256:") else {
        return false;
    };
    if !matches!(rest.len(), 43 | 44) {
        return false;
    }
    rest.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='))
}

/// Fetch the SHA256 host fingerprint of `<host>:<port>` via
/// `ssh-keyscan` piped into `ssh-keygen -lf -`.
///
/// Prefers ed25519, falls back to the first non-comment key line if
/// ed25519 is not advertised by the remote sshd (legacy Debian
/// servers / hardware appliances).
///
/// **Synchronous — async callers MUST wrap in
/// `tokio::task::spawn_blocking`.** `ssh-keyscan` can block ~5-10s on
/// an unreachable host (default `-T 10`), and calling it directly from
/// an async handler will starve a tokio worker thread.
///
/// **Security:** uses `--` separator before `host` to defend against
/// flag-injection via attacker-controlled inventory addresses. See
/// crate-level docs for the full rationale.
pub fn fetch_via_keyscan(host: &str, port: u16) -> Result<String, Error> {
    let stdout = run_keyscan(host, port)?;
    let chosen =
        pick_key_line(&String::from_utf8_lossy(&stdout)).ok_or_else(|| Error::KeyscanEmpty {
            host: host.to_string(),
            port,
        })?;
    let keygen_out = run_keygen_fingerprint(chosen.as_bytes())?;
    extract_sha256_token(&keygen_out).ok_or(Error::NoFingerprintToken {
        output: keygen_out.trim().to_string(),
    })
}

/// Fetch the SHA256 fingerprints of EVERY host key `<host>:<port>`
/// currently serves (ed25519 + rsa, per [`build_keyscan_args`]),
/// rather than the single canonical one [`fetch_via_keyscan`] picks.
///
/// ## Why this exists (drift-check robustness)
///
/// The pinned `trusted_host_fingerprint` is one specific key
/// (ed25519-preferred at pin time). A single `ssh-keyscan` invocation
/// can legitimately return only a SUBSET of the server's keys when a
/// per-algorithm probe times out under packet loss — and
/// [`pick_key_line`] then falls back to whatever line DID come back
/// (e.g. rsa). Comparing that rsa fingerprint against the ed25519 pin
/// produces a spurious «fingerprint drift» (observed on `kg`
/// 2026-06-06: the firing scan returned only the rsa key, the alert
/// auto-recovered two ticks later when ed25519 came back).
///
/// Returning the full set lets the caller ask the robust question —
/// «is the pinned key still AMONG the keys this server serves?» —
/// instead of «does this one picked key equal the pin?».
///
/// **Synchronous** — same `spawn_blocking` contract as
/// [`fetch_via_keyscan`]. **Security:** identical `--` flag-injection
/// defence (shares [`build_keyscan_args`] via [`run_keyscan`]).
pub fn fetch_all_fingerprints(host: &str, port: u16) -> Result<Vec<String>, Error> {
    let stdout = run_keyscan(host, port)?;
    let keygen_out = run_keygen_fingerprint(&stdout)?;
    let tokens = extract_all_sha256_tokens(&keygen_out);
    if tokens.is_empty() {
        return Err(Error::NoFingerprintToken {
            output: keygen_out.trim().to_string(),
        });
    }
    Ok(tokens)
}

/// Run `ssh-keyscan` for `<host>:<port>` and return its raw stdout
/// (one `<host> <key-type> <base64>` line per advertised algorithm).
///
/// Shared spawn + error-mapping core of [`fetch_via_keyscan`] and
/// [`fetch_all_fingerprints`] (extracted 2026-06-06 to keep the second
/// fetcher from copy-pasting the keyscan invocation).
fn run_keyscan(host: &str, port: u16) -> Result<Vec<u8>, Error> {
    let port_s = port.to_string();
    let args = build_keyscan_args(&port_s, host);
    let scan = Command::new("ssh-keyscan")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::KeyscanSpawn(e.to_string()))?;
    if !scan.status.success() {
        return Err(Error::KeyscanFailed {
            host: host.to_string(),
            port,
            code: scan.status.code(),
            stderr: String::from_utf8_lossy(&scan.stderr).trim().to_string(),
        });
    }
    if scan.stdout.is_empty() {
        return Err(Error::KeyscanEmpty {
            host: host.to_string(),
            port,
        });
    }
    Ok(scan.stdout)
}

/// Pipe `input` (one or more public-key lines) through
/// `ssh-keygen -lf -` and return its stdout verbatim. The caller
/// extracts the SHA256 token(s) with [`extract_sha256_token`] /
/// [`extract_all_sha256_tokens`].
///
/// Shared by both fetchers. The explicit `drop(stdin)` sends EOF —
/// without it `wait_with_output` blocks forever (the `.take()`
/// returning None would mean Stdio::piped was ignored; surfacing it
/// as an error beats a silent deadlock).
fn run_keygen_fingerprint(input: &[u8]) -> Result<String, Error> {
    let mut child = Command::new("ssh-keygen")
        .args(["-lf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::KeygenSpawn(e.to_string()))?;
    let mut stdin = child.stdin.take().ok_or(Error::KeygenStdinPipe)?;
    stdin
        .write_all(input)
        .map_err(|e| Error::KeygenStdinWrite(e.to_string()))?;
    drop(stdin);
    let keygen = child
        .wait_with_output()
        .map_err(|e| Error::KeygenWait(e.to_string()))?;
    if !keygen.status.success() {
        return Err(Error::KeygenFailed(keygen.status.code()));
    }
    Ok(String::from_utf8_lossy(&keygen.stdout).into_owned())
}

/// Walk `ssh-keyscan` stdout (one `<host> <key-type> <base64>` line
/// per algorithm) and pick the best line.
///
/// Preference order:
///   1. First `ssh-ed25519` line (modern, short, what we want).
///   2. First non-comment, non-empty line as fallback (rsa or
///      whatever the legacy server advertises).
///
/// Skips lines starting with `#` — those are status comments
/// `ssh-keyscan` emits to stderr in verbose mode, but they sometimes
/// land on stdout too depending on shell pipeline buffering.
///
/// **Positional algo match** — looks at the *second* whitespace token
/// (the key type) rather than a substring search. A perfectly legal
/// DNS hostname like `ssh-ed25519.example.com` would otherwise
/// silently promote an rsa line and we'd pin the wrong fingerprint.
pub fn pick_key_line(stdout: &str) -> Option<String> {
    let mut fallback: Option<String> = None;
    for line in stdout.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.split_whitespace().nth(1) == Some("ssh-ed25519") {
            return Some(l.to_string());
        }
        if fallback.is_none() {
            fallback = Some(l.to_string());
        }
    }
    fallback
}

/// Extract the `SHA256:<base64>` token from `ssh-keygen -lf -` stdout.
///
/// Format: `<bits> SHA256:<base64> <comment> (<ALGO>)`, so we grab
/// the first whitespace-separated token that starts with `SHA256:`.
pub fn extract_sha256_token(stdout: &str) -> Option<String> {
    stdout
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .map(str::to_owned)
}

/// Extract EVERY `SHA256:<base64>` token from `ssh-keygen -lf -`
/// output. When the daemon pipes a multi-key `ssh-keyscan` dump
/// through `ssh-keygen -lf -`, the output carries one fingerprint
/// line per host key — this returns all of them (ed25519 + rsa +
/// ecdsa), in the order ssh-keygen printed them.
///
/// Sibling of [`extract_sha256_token`] (first-only); kept separate so
/// the single-fingerprint pinning path is byte-for-byte unchanged.
pub fn extract_all_sha256_tokens(stdout: &str) -> Vec<String> {
    stdout
        .split_whitespace()
        .filter(|t| t.starts_with("SHA256:"))
        .map(str::to_owned)
        .collect()
}

/// Build the `ssh-keyscan` argv used by [`fetch_via_keyscan`].
///
/// Extracted as a `pub` helper specifically so a spec test can pin the
/// load-bearing `--` getopt separator. The contract is:
///
///   * `--` must appear immediately before `host` (every token after
///     is positional, defeating `ssh-keyscan`'s own getopt parser),
///   * `-t ed25519,rsa` requests both algorithms so legacy servers
///     without ed25519 still produce a usable host key,
///   * `-T 10` caps the connect timeout so an unreachable host fails
///     fast instead of pinning the spawn_blocking thread for 30s+.
///
/// If a future refactor reorders these and drops the `--`, the
/// flag-injection regression test in `tests/spec_host_fingerprint.rs`
/// fails immediately rather than waiting for a security audit.
pub fn build_keyscan_args<'a>(port_s: &'a str, host: &'a str) -> [&'a str; 8] {
    ["-T", "10", "-p", port_s, "-t", "ed25519,rsa", "--", host]
}
