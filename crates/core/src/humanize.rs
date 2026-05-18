//! Tiny formatting helpers shared across surfaces that render byte
//! counts in operator-familiar form (admin Settings page,
//! `vpnctl backup` CLI output).
//!
//! ## Why this lives in `vpnctl-core`
//!
//! Until 2026-05-18 [`format_size_bytes`] was *byte-identical* in
//! `daemon/src/handlers/admin.rs` (Settings snapshot table) and
//! `cli/src/cmd/backup.rs` (CLI `vpnctl backup list` output) with a
//! comment at the CLI site explicitly admitting the duplication:
//! «duplicated here because the daemon module isn't a CLI dep». That
//! duplication was the second hit caught by the post-2026-05-17
//! «grep the whole repo for new ≥20-LOC functions» review pass (the
//! first being the ssh-keyscan triplication consolidated in
//! `vpnctl-host-fingerprint`).
//!
//! Both `vpnctl` (CLI) and `vpnctld` (daemon) already depend on
//! `vpnctl-core` for `ServerId` / `UserId` newtypes, so this module
//! adds zero new edges to the dependency graph — it just collapses
//! two copies of the same 14-line function into one.
//!
//! ## Why this is NOT the single source of truth for «bytes → human»
//!
//! There is a deliberate sibling helper `humanize_bytes` in
//! `daemon/src/handlers/admin.rs` (~9 call sites) that renders
//! traffic counts (uploaded / downloaded / monthly used / hourly max)
//! using **IEC** labels (`KiB / MiB / GiB / TiB / PiB`) with a
//! uniform `{:.1}` precision across all magnitudes. That presentation
//! is intentional — traffic is a network concept and the technical
//! `KiB` reads more correctly to an operator who's also looking at
//! `tcpdump` / `iftop` output. Storage sizes (backups, snapshots)
//! use the **JEDEC** labels here (`KB / MB / GB`) with a 2-decimal
//! widening at GB because at backup scale an MB-level delta is the
//! difference between «yesterday's snapshot» and «something just
//! grew» — operators want to see the 2nd decimal.
//!
//! Unifying the two helpers would force a UX decision (which label
//! set wins? does traffic get 2 decimals at GiB too?) that nobody
//! has asked to make. Until then, the rule is: **storage sizes use
//! this module; traffic counts use `humanize_bytes`**. New code
//! should match the surrounding context.

/// Render a byte count as a human-friendly short string, matching
/// `du -h`'s rounding conventions:
///
///   * `< 1024 B`         → `"<n> B"`               (no unit suffix)
///   * `< 1 MiB`          → `"<n.x> KB"`            (1 decimal)
///   * `< 1 GiB`          → `"<n.x> MB"`            (1 decimal)
///   * `≥ 1 GiB`          → `"<n.xx> GB"`           (2 decimals)
///
/// Uses binary prefixes (1 KB = 1024 B, not 1000) — same convention
/// the operator already sees from `du -h` / `ls -lh`. The unit suffix
/// nominally reads "KB / MB / GB" rather than "KiB / MiB / GiB"
/// because the surfaces this feeds (Settings page, `vpnctl backup
/// list`) explicitly target operator familiarity over standards
/// pedantry.
///
/// ## Examples
///
/// ```
/// use vpnctl_core::humanize::format_size_bytes;
/// assert_eq!(format_size_bytes(0), "0 B");
/// assert_eq!(format_size_bytes(1023), "1023 B");
/// assert_eq!(format_size_bytes(1024), "1.0 KB");
/// assert_eq!(format_size_bytes(1024 * 1024), "1.0 MB");
/// assert_eq!(format_size_bytes(1024 * 1024 * 1024), "1.00 GB");
/// ```
pub fn format_size_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if n < KB {
        format!("{n} B")
    } else if n < MB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else if n < GB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else {
        format!("{:.2} GB", n as f64 / GB as f64)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─── Bytes branch (n < 1024) ─────────────────────────────────

    #[test]
    fn zero_bytes_emits_no_unit_scaling() {
        assert_eq!(format_size_bytes(0), "0 B");
    }

    #[test]
    fn bytes_branch_uses_no_decimal_point() {
        // The < KB branch must NOT scale or add a decimal — Pavel
        // sees raw integer counts for sub-kilobyte sizes (matches
        // `du -h`).
        assert_eq!(format_size_bytes(42), "42 B");
    }

    #[test]
    fn just_below_kilobyte_boundary_stays_in_bytes_branch() {
        // 1023 is the last value the bytes branch must own. Off-by-
        // one drift would silently flip rendering to "1.0 KB" with
        // an arithmetic surprise: 1023/1024 ≈ 0.999 → format!("{:.1}")
        // rounds to "1.0" and reads identical to a real 1 KB —
        // exactly the kind of confusion this branch avoids.
        assert_eq!(format_size_bytes(1023), "1023 B");
    }

    // ─── Kilobyte branch (1024 ≤ n < 1024*1024) ──────────────────

    #[test]
    fn exact_kilobyte_boundary_uses_one_decimal() {
        assert_eq!(format_size_bytes(1024), "1.0 KB");
    }

    #[test]
    fn one_and_a_half_kilobyte_rounds_to_one_decimal() {
        // 1536 = 1.5 KiB exactly — must print "1.5 KB", not "1.50 KB"
        // (KB branch is 1-decimal; only GB widens to 2).
        assert_eq!(format_size_bytes(1536), "1.5 KB");
    }

    #[test]
    fn just_below_megabyte_boundary_stays_in_kilobyte_branch() {
        // 1024*1024 − 1 = 1048575 → 1023.999… KiB → rounds to "1024.0 KB"
        // (not "1.0 MB"). The branch test is `< MB`, evaluated on the
        // pre-rounding raw integer — so this value MUST stay in KB.
        let out = format_size_bytes(1024 * 1024 - 1);
        assert!(
            out.ends_with(" KB"),
            "value just below 1 MiB must render as KB, got {out:?}"
        );
    }

    // ─── Megabyte branch (1024*1024 ≤ n < 1024*1024*1024) ────────

    #[test]
    fn exact_megabyte_boundary_uses_one_decimal() {
        assert_eq!(format_size_bytes(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn typical_snapshot_size_renders_in_megabytes() {
        // ~7.2 MiB — a realistic `inv.db` snapshot size today.
        let bytes = (7_u64 * 1024 + 200) * 1024;
        let out = format_size_bytes(bytes);
        assert!(out.ends_with(" MB"), "got {out:?}");
        assert!(
            out.starts_with("7."),
            "7.2 MiB must render as something starting with '7.', got {out:?}"
        );
    }

    #[test]
    fn just_below_gigabyte_boundary_stays_in_megabyte_branch() {
        let out = format_size_bytes(1024 * 1024 * 1024 - 1);
        assert!(
            out.ends_with(" MB"),
            "value just below 1 GiB must render as MB, got {out:?}"
        );
    }

    // ─── Gigabyte branch (n ≥ 1024^3) ────────────────────────────

    #[test]
    fn exact_gigabyte_boundary_uses_two_decimals() {
        // GB branch widens to 2 decimals because absolute byte
        // differences matter more once you're at GB scale (a 100 MB
        // delta is visible in the 2nd decimal but invisible at 1).
        assert_eq!(format_size_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn one_and_a_half_gigabyte_uses_two_decimals() {
        // 1.5 GiB exactly — must print "1.50 GB", proving the format
        // string is `{:.2}` and not the `{:.1}` used in MB.
        let bytes = 1024_u64 * 1024 * 1024 * 3 / 2;
        assert_eq!(format_size_bytes(bytes), "1.50 GB");
    }

    #[test]
    fn very_large_gigabyte_still_renders_without_overflow() {
        // u64::MAX is ~16 EiB, well beyond our scale, but the formula
        // must not overflow / panic. f64 has enough range; assert
        // we get *some* GB string back.
        let out = format_size_bytes(u64::MAX);
        assert!(out.ends_with(" GB"), "got {out:?}");
    }
}
