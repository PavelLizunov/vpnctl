//! Build provenance stamp shared by every product surface.
//!
//! One string — `<semver>+<short-git-sha>` (or `<semver>+unknown`) — is
//! shown by the daemon `/api/v1/health` `build` field, the admin UI
//! masthead/footer, and `vpnctl --version`, so a deployed binary is always
//! traceable to the exact commit it came from.
//!
//! No build script and no runtime `git`: the SemVer is `CARGO_PKG_VERSION`
//! and the SHA is read at compile time from `VPNCTL_BUILD_SHA`, which the
//! deployment script exports before `cargo build` (see `scripts/deploy.sh`).
//! Builds that don't export it (release tarball, ad-hoc `cargo build`)
//! fall back to `+unknown` — provenance is best-effort, never a build
//! blocker.

/// The full provenance string for the running binary:
/// `<semver>+<short-sha>`, or `<semver>+unknown` when no SHA was supplied
/// at compile time.
///
/// Returns a memoized `&'static str` (computed once via [`std::sync::OnceLock`])
/// so it can feed clap's `#[command(version = …)]` — which needs a
/// `&'static str`, not an owned `String` — as well as serde and maud, with
/// no per-call allocation.
#[must_use]
pub fn build_version() -> &'static str {
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            with_provenance(env!("CARGO_PKG_VERSION"), option_env!("VPNCTL_BUILD_SHA"))
        })
        .as_str()
}

/// Pure core of [`build_version`], split out so the SHA validation and
/// shortening rules are unit-testable without controlling the compile-time
/// environment.
fn with_provenance(semver: &str, sha: Option<&str>) -> String {
    match sha.and_then(shorten_sha) {
        Some(sha) => format!("{semver}+{sha}"),
        None => format!("{semver}+unknown"),
    }
}

/// Validate and shorten a supplied SHA to the conventional 7-char prefix.
///
/// Accepts a 7..=64 character hex string (a `git rev-parse --short` value
/// up to a full SHA-1/SHA-256), lowercased. Returns `None` for empty,
/// non-hex, or too-short input so the caller falls back to `unknown`
/// rather than stamping garbage into the version string.
fn shorten_sha(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !(7..=64).contains(&trimmed.len()) {
        return None;
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed[..7].to_ascii_lowercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn full_sha_is_shortened_to_seven_chars() {
        let sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"; // 40 hex
        assert_eq!(with_provenance("0.9.0", Some(sha)), "0.9.0+a1b2c3d");
    }

    #[test]
    fn seven_char_sha_is_kept_verbatim() {
        assert_eq!(with_provenance("0.9.0", Some("a1b2c3d")), "0.9.0+a1b2c3d");
    }

    #[test]
    fn uppercase_sha_is_lowercased() {
        assert_eq!(with_provenance("0.9.0", Some("A1B2C3D")), "0.9.0+a1b2c3d");
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            with_provenance("0.9.0", Some("  a1b2c3d\n")),
            "0.9.0+a1b2c3d"
        );
    }

    #[test]
    fn missing_sha_falls_back_to_unknown() {
        assert_eq!(with_provenance("0.9.0", None), "0.9.0+unknown");
    }

    #[test]
    fn empty_sha_falls_back_to_unknown() {
        assert_eq!(with_provenance("0.9.0", Some("")), "0.9.0+unknown");
        assert_eq!(with_provenance("0.9.0", Some("   ")), "0.9.0+unknown");
    }

    #[test]
    fn too_short_sha_falls_back_to_unknown() {
        assert_eq!(with_provenance("0.9.0", Some("a1b2c3")), "0.9.0+unknown");
    }

    #[test]
    fn non_hex_sha_falls_back_to_unknown() {
        // Right length, but not a hex digest (e.g. a branch name).
        assert_eq!(with_provenance("0.9.0", Some("notasha")), "0.9.0+unknown");
        assert_eq!(with_provenance("0.9.0", Some("zzzzzzz")), "0.9.0+unknown");
    }

    #[test]
    fn build_version_carries_the_package_semver() {
        // Whatever the compile-time SHA, the SemVer prefix is always the
        // crate's CARGO_PKG_VERSION.
        let v = build_version();
        assert!(
            v.starts_with(&format!("{}+", env!("CARGO_PKG_VERSION"))),
            "build_version() must be prefixed by CARGO_PKG_VERSION: {v}"
        );
    }
}
