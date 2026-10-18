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

    #[test]
    fn zero_bytes_emits_no_unit_scaling() {
        assert_eq!(format_size_bytes(0), "0 B");
    }

    #[test]
    fn bytes_branch_uses_no_decimal_point() {
        assert_eq!(format_size_bytes(42), "42 B");
    }

    #[test]
    fn just_below_kilobyte_boundary_stays_in_bytes_branch() {
        assert_eq!(format_size_bytes(1023), "1023 B");
    }

    #[test]
    fn exact_kilobyte_boundary_uses_one_decimal() {
        assert_eq!(format_size_bytes(1024), "1.0 KB");
    }

    #[test]
    fn one_and_a_half_kilobyte_rounds_to_one_decimal() {
        assert_eq!(format_size_bytes(1536), "1.5 KB");
    }

    #[test]
    fn just_below_megabyte_boundary_stays_in_kilobyte_branch() {
        let out = format_size_bytes(1024 * 1024 - 1);
        assert!(
            out.ends_with(" KB"),
            "value just below 1 MiB must render as KB, got {out:?}"
        );
    }

    #[test]
    fn exact_megabyte_boundary_uses_one_decimal() {
        assert_eq!(format_size_bytes(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn typical_snapshot_size_renders_in_megabytes() {
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

    #[test]
    fn exact_gigabyte_boundary_uses_two_decimals() {
        assert_eq!(format_size_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn one_and_a_half_gigabyte_uses_two_decimals() {
        let bytes = 1024_u64 * 1024 * 1024 * 3 / 2;
        assert_eq!(format_size_bytes(bytes), "1.50 GB");
    }

    #[test]
    fn very_large_gigabyte_still_renders_without_overflow() {
        let out = format_size_bytes(u64::MAX);
        assert!(out.ends_with(" GB"), "got {out:?}");
    }
}
