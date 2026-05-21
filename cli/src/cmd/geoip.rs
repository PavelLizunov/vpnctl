//! `vpnctl geoip-update` — fetch DB-IP Lite City + ASN MMDB files,
//! validate them, atomic-install into `$VPNCTLD_GEOIP_DIR` (default
//! `/var/lib/vpnctl/geoip`).
//!
//! Why DB-IP Lite (not MaxMind GeoLite2): CC-BY 4.0, no signup, no
//! license key, no 30-day EULA-mandated deletion. Native MMDB
//! format — drops straight into `maxminddb::Reader`. Update cadence
//! is monthly (URLs are `dbip-{city,asn}-lite-YYYY-MM.mmdb.gz`).
//!
//! Pavel 2026-05-21: «начинай это [GeoIP / device fingerprint]».
//!
//! Flow per file:
//!   1. Compute current month (UTC). If GET returns 404, retry
//!      previous month (the new monthly file usually publishes on
//!      the 1st-2nd; we don't want the operator's update to fail
//!      on the 1st morning).
//!   2. Stream the .mmdb.gz to a `.partial` file in the target dir.
//!   3. Decompress gz → `.partial.mmdb` (same dir, same FS, so the
//!      atomic rename in step 5 is real-atomic).
//!   4. Validate by opening + looking up a known IP (`8.8.8.8`).
//!   5. `fs::rename(.partial.mmdb, GeoLite2-City.mmdb)` —
//!      same-FS rename is atomic on POSIX (single inode op).
//!   6. Drop the .partial.gz file.
//!
//! The daemon reader uses the MaxMind-style filenames
//! (`GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb`) so this command's
//! output filenames match — operator can run BOTH the MaxMind
//! `geoipupdate` tool AND this command into the same dir without
//! the daemon noticing the difference.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::{Datelike, NaiveDate, Utc};
use futures_util::StreamExt;

/// Which DB-IP Lite file to fetch. Same URL prefix, different
/// `kind` segment. The daemon reader supports either one missing
/// (lookup just returns None for the missing dimension).
#[derive(Copy, Clone, Debug)]
enum DbKind {
    City,
    Asn,
}

impl DbKind {
    fn url_segment(self) -> &'static str {
        match self {
            DbKind::City => "city",
            DbKind::Asn => "asn",
        }
    }
    /// MaxMind-compatible output filename — `GeoLite2-City.mmdb`
    /// etc. Lets the daemon read either MaxMind or DB-IP output
    /// from the same path without a config switch.
    fn output_filename(self) -> &'static str {
        match self {
            DbKind::City => "GeoLite2-City.mmdb",
            DbKind::Asn => "GeoLite2-ASN.mmdb",
        }
    }
    fn human(self) -> &'static str {
        match self {
            DbKind::City => "City",
            DbKind::Asn => "ASN",
        }
    }
}

fn url_for(kind: DbKind, month: NaiveDate) -> String {
    format!(
        "https://download.db-ip.com/free/dbip-{seg}-lite-{year}-{mm:02}.mmdb.gz",
        seg = kind.url_segment(),
        year = month.year(),
        mm = month.month(),
    )
}

/// Entry point: `vpnctl geoip-update [--dir /var/lib/vpnctl/geoip]`.
pub(crate) async fn run(dir: Option<PathBuf>) -> Result<()> {
    let dir = match dir {
        Some(d) => d,
        None => std::env::var_os("VPNCTLD_GEOIP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/vpnctl/geoip")),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("create geoip dir {}", dir.display()))?;
    println!("vpnctl geoip-update — target dir: {}", dir.display());

    let client = reqwest::Client::builder()
        .user_agent("vpnctl-geoip-update/0.1 (+https://github.com/PavelLizunov/vpnctl)")
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .context("build reqwest client")?;

    let now = Utc::now().date_naive();
    let this_month = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .ok_or_else(|| anyhow!("compute current month"))?;
    // Compute previous month manually — chrono Months crate would be
    // overkill for this two-step fallback.
    let prev_month = if this_month.month() == 1 {
        NaiveDate::from_ymd_opt(this_month.year() - 1, 12, 1)
    } else {
        NaiveDate::from_ymd_opt(this_month.year(), this_month.month() - 1, 1)
    }
    .ok_or_else(|| anyhow!("compute previous month"))?;

    for kind in [DbKind::City, DbKind::Asn] {
        match fetch_one(&client, kind, this_month, &dir).await {
            Ok(path) => {
                println!(
                    "  ✓ {} → {} ({} bytes)",
                    kind.human(),
                    path.display(),
                    std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
                );
            }
            Err(e_now) => {
                eprintln!(
                    "  ⚠ {} current-month fetch failed ({e_now:?}); retrying previous month",
                    kind.human()
                );
                match fetch_one(&client, kind, prev_month, &dir).await {
                    Ok(path) => println!(
                        "  ✓ {} (prev month) → {} ({} bytes)",
                        kind.human(),
                        path.display(),
                        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
                    ),
                    Err(e_prev) => {
                        return Err(anyhow!(
                            "{} update failed (current month: {e_now:?}; previous month: {e_prev:?})",
                            kind.human()
                        ));
                    }
                }
            }
        }
    }
    println!("done. restart vpnctld for the new DBs to load.");
    Ok(())
}

/// Fetch one (kind, month) pair: download .gz → decompress → validate
/// → atomic rename. Caller decides whether to retry with a different
/// month on failure.
async fn fetch_one(
    client: &reqwest::Client,
    kind: DbKind,
    month: NaiveDate,
    dir: &Path,
) -> Result<PathBuf> {
    let url = url_for(kind, month);
    let final_path = dir.join(kind.output_filename());
    let tmp_gz = dir.join(format!("{}.partial.gz", kind.output_filename()));
    let tmp_mmdb = dir.join(format!("{}.partial", kind.output_filename()));

    // 1. Stream the .gz to disk (so we don't buffer 100 MB in RAM).
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        // Bubble the status so the caller can decide on retry.
        return Err(anyhow!("HTTP {} for {url}", resp.status()));
    }
    {
        let mut out = std::fs::File::create(&tmp_gz)
            .with_context(|| format!("create {}", tmp_gz.display()))?;
        let mut stream = resp.bytes_stream();
        use std::io::Write;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("stream {url}"))?;
            out.write_all(&chunk).context("write gz chunk")?;
        }
        out.sync_all().context("fsync gz")?;
    }

    // 2. Decompress to a sibling .partial file (same FS = atomic rename).
    {
        let gz_in =
            std::fs::File::open(&tmp_gz).with_context(|| format!("open {}", tmp_gz.display()))?;
        let mut decoder = flate2::read::GzDecoder::new(gz_in);
        let mut out = std::fs::File::create(&tmp_mmdb)
            .with_context(|| format!("create {}", tmp_mmdb.display()))?;
        std::io::copy(&mut decoder, &mut out).context("gz → mmdb decompress")?;
        out.sync_all().context("fsync mmdb")?;
    }

    // 3. Validate by opening + looking up a known IP. Better to
    //    fail here than silently install a corrupt file.
    validate_mmdb(&tmp_mmdb, kind).with_context(|| format!("validate {}", tmp_mmdb.display()))?;

    // 4. Atomic rename. Drop the .gz; keep .mmdb at the final name.
    std::fs::rename(&tmp_mmdb, &final_path)
        .with_context(|| format!("rename {} → {}", tmp_mmdb.display(), final_path.display()))?;
    let _ = std::fs::remove_file(&tmp_gz);
    Ok(final_path)
}

/// Open the .mmdb and probe a known public IP — confirms the file
/// isn't truncated / not-an-mmdb / wrong-schema. Uses 8.8.8.8 (always
/// in any reasonable GeoIP DB).
fn validate_mmdb(path: &Path, kind: DbKind) -> Result<()> {
    use maxminddb::geoip2;
    let reader = maxminddb::Reader::open_readfile(path)
        .with_context(|| format!("maxminddb open {}", path.display()))?;
    let probe = "8.8.8.8"
        .parse()
        .context("parse 8.8.8.8 (compile-time should never fail)")?;
    let lookup = reader.lookup(probe).context("validate-probe lookup")?;
    match kind {
        DbKind::City => {
            let _city = lookup
                .decode::<geoip2::City>()
                .context("validate-probe decode City")?
                .ok_or_else(|| anyhow!("validate-probe: City record missing for 8.8.8.8"))?;
        }
        DbKind::Asn => {
            let _asn = lookup
                .decode::<geoip2::Asn>()
                .context("validate-probe decode Asn")?
                .ok_or_else(|| anyhow!("validate-probe: ASN record missing for 8.8.8.8"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn url_for_january_uses_two_digit_month() {
        let m = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        assert_eq!(
            url_for(DbKind::City, m),
            "https://download.db-ip.com/free/dbip-city-lite-2026-01.mmdb.gz"
        );
    }

    #[test]
    fn url_for_december() {
        let m = NaiveDate::from_ymd_opt(2026, 12, 1).unwrap();
        assert_eq!(
            url_for(DbKind::Asn, m),
            "https://download.db-ip.com/free/dbip-asn-lite-2026-12.mmdb.gz"
        );
    }

    #[test]
    fn output_filenames_match_maxmind_convention() {
        // Daemon reads `GeoLite2-{City,ASN}.mmdb` from the dir —
        // either MaxMind's geoipupdate OR this command must drop
        // files at those exact paths so the daemon is source-
        // agnostic.
        assert_eq!(DbKind::City.output_filename(), "GeoLite2-City.mmdb");
        assert_eq!(DbKind::Asn.output_filename(), "GeoLite2-ASN.mmdb");
    }
}
