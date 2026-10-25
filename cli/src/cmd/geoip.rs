use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::{Datelike, NaiveDate, Utc};
use futures_util::StreamExt;

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

async fn fetch_one(
    client: &reqwest::Client,
    kind: DbKind,
    month: NaiveDate,
    dir: &Path,
) -> Result<PathBuf> {
    let url = url_for(kind, month);
    let final_path = dir.join(kind.output_filename());
    let (tmp_gz, tmp_mmdb) = partial_paths(dir, kind);

    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
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

    {
        let gz_in =
            std::fs::File::open(&tmp_gz).with_context(|| format!("open {}", tmp_gz.display()))?;
        let mut decoder = flate2::read::GzDecoder::new(gz_in);
        let mut out = std::fs::File::create(&tmp_mmdb)
            .with_context(|| format!("create {}", tmp_mmdb.display()))?;
        std::io::copy(&mut decoder, &mut out).context("gz → mmdb decompress")?;
        out.sync_all().context("fsync mmdb")?;
    }

    validate_mmdb(&tmp_mmdb, kind).with_context(|| format!("validate {}", tmp_mmdb.display()))?;

    std::fs::rename(&tmp_mmdb, &final_path)
        .with_context(|| format!("rename {} → {}", tmp_mmdb.display(), final_path.display()))?;
    let _ = std::fs::remove_file(&tmp_gz);
    Ok(final_path)
}

fn partial_paths(dir: &Path, kind: DbKind) -> (PathBuf, PathBuf) {
    let prefix = format!("{}.{}", kind.output_filename(), std::process::id());
    (
        dir.join(format!("{prefix}.partial.gz")),
        dir.join(format!("{prefix}.partial")),
    )
}

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
    fn partial_paths_are_scoped_to_the_updater_process() {
        let dir = Path::new("/tmp/geoip");
        let (gz, mmdb) = partial_paths(dir, DbKind::City);
        let prefix = format!("GeoLite2-City.mmdb.{}", std::process::id());
        assert_eq!(gz, dir.join(format!("{prefix}.partial.gz")));
        assert_eq!(mmdb, dir.join(format!("{prefix}.partial")));
        assert_ne!(partial_paths(dir, DbKind::Asn), (gz, mmdb));
    }

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
        assert_eq!(DbKind::City.output_filename(), "GeoLite2-City.mmdb");
        assert_eq!(DbKind::Asn.output_filename(), "GeoLite2-ASN.mmdb");
    }
}
