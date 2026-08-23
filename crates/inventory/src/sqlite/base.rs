use super::*;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{SqlitePool, migrate::Migrator};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Expose the embedded `Migrator` to sibling modules — currently
/// `backup::restore_from` uses it to validate that an incoming
/// snapshot's schema is at-or-above the current binary's expected
/// version before atomically swapping it over the live DB.
pub(crate) fn migrator() -> &'static Migrator {
    &MIGRATOR
}

/// Convert sqlx UNIQUE constraint violations to `AlreadyExists`. Other
/// sqlx errors propagate untouched.
pub(crate) fn map_unique<T>(
    res: std::result::Result<T, sqlx::Error>,
    what: impl std::fmt::Display,
) -> Result<T> {
    match res {
        Ok(v) => Ok(v),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            Err(SqliteInventoryError::AlreadyExists(what.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

/// Our OWN infrastructure egress IPs that must never count as a real
/// client source-IP (2026-06-16, Pavel). The homelab NAT egress
/// `83.97.108.34` is where every LAN box exits — the control-plane curl
/// tests, the phase6-monitor canary, the claude-chat proxy, and any
/// browser-opened `/sub` check all appear as this IP, so without the
/// exclusion it dominates the per-user source-IP counter (it was 656 of
/// ninitux's 723 hits — 90% pure test noise). VPN SERVER addresses are
/// excluded separately via `(SELECT address FROM servers)` because a user
/// who hops node A→B briefly shows node A's egress as their source while
/// the old session drains. Extend this list if more control-plane egresses
/// appear; keep it NON-EMPTY (an empty `NOT IN ()` is a SQL error — the
/// query layer guards by omitting the clause when empty).
pub const OUR_EGRESS_CONTROL_IPS: &[&str] = &["83.97.108.34"];

/// SQL `WHERE`-fragment (NOT prefixed with `AND`) that keeps only REAL
/// external client IPs in column `col`, dropping every flavour of OUR OWN
/// infrastructure (2026-06-16, Pavel — «всё ещё вижу 192.168.0.200 LAN curl
/// … Likely-shared показывает те же цифры»):
///   - RFC 1918 / loopback / link-local — the homelab LAN (every box is
///     `192.168.0.x`; a real client never appears as a private IP because
///     nginx resolves the true client via `X-Forwarded-For`, so a private
///     `ip` row is always our own tooling hitting the daemon directly),
///   - VPN server addresses (`SELECT address FROM servers` — a node hop or
///     full-tunnel egress),
///   - the control egress(es) in [`OUR_EGRESS_CONTROL_IPS`].
///
/// Single source of truth so the abuse-origins list, the breakdowns, the
/// likely-shared summary, and the source-IP counter all agree on «what is a
/// real client». Mirrors the daemon's `ip_kind::classify_ip` logic in SQL.
/// Inlined literals are safe — every value is our own constant (servers via
/// sub-SELECT), never user input. `172.16-31/12` is matched with GLOB
/// char-ranges so a real `172.0-15` / `172.32+` client is NOT dropped.
pub(crate) fn real_client_ip_predicate(col: &str) -> String {
    let control_clause = if OUR_EGRESS_CONTROL_IPS.is_empty() {
        String::new()
    } else {
        let list = OUR_EGRESS_CONTROL_IPS
            .iter()
            .map(|ip| format!("'{ip}'"))
            .collect::<Vec<_>>()
            .join(",");
        format!(" AND {col} NOT IN ({list})")
    };
    format!(
        "{col} NOT LIKE '10.%' AND {col} NOT LIKE '127.%' \
         AND {col} NOT LIKE '192.168.%' AND {col} NOT LIKE '169.254.%' \
         AND {col} NOT GLOB '172.1[6-9].*' AND {col} NOT GLOB '172.2[0-9].*' \
         AND {col} NOT GLOB '172.3[0-1].*' \
         AND {col} <> '0.0.0.0' AND {col} <> '::' AND {col} <> '::1' \
         AND {col} NOT LIKE 'fc%' AND {col} NOT LIKE 'fd%' \
         AND {col} NOT LIKE 'fe8%' AND {col} NOT LIKE 'fe9%' \
         AND {col} NOT LIKE 'fea%' AND {col} NOT LIKE 'feb%' \
         AND {col} NOT IN (SELECT address FROM servers) \
         AND {col} NOT IN (SELECT address FROM server_resolved_addresses){control_clause}"
    )
}

pub(crate) fn canonical_ip_text(ip: &str) -> String {
    ip.parse::<std::net::IpAddr>()
        .map_or_else(|_| ip.chars().take(45).collect(), |ip| ip.to_string())
}

/// Collapse an IP to its access-network key for sharing-detection counting
/// (2026-06-17; IPv6-corrected 2026-07-29; IPv4 carrier-pool corrected
/// 2026-07-30). IPv4 → its ISP-scale `/16`
/// (`"91.79.36.72"` → `"91.79"`); IPv6 → its `/64` prefix
/// (`"2001:db8::1"` → `"2001:db8:0:0::/64"`). Mobile carriers rotate a
/// single device across many adjacent `/24`s, so `/16` matches the existing
/// UA-sharing heuristic and avoids counting one carrier pool as several
/// people. A real shared sub spanning different providers usually still
/// crosses `/16`s. This is intentionally conservative: false negatives are
/// cheaper than accusing a normal mobile user.
///
/// Parsed with std [`std::net::IpAddr`] so the IPv6 `/64` collapse is exact:
/// the old string-prefix version returned every IPv6 privacy address verbatim,
/// which made one phone's rotating temporary addresses look like many distinct
/// networks (the strongest, rotation-immune concurrency signal — exactly the
/// false positive this function exists to prevent). Malformed input parses to
/// nothing and is returned verbatim so it stays a single safe bucket rather
/// than panicking or silently merging unrelated garbage.
pub fn network_key(ip: &str) -> String {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        // /16 — one ISP-scale bucket, matching `ip_slash16`.
        Ok(IpAddr::V4(v4)) => {
            let [a, b, _, _] = v4.octets();
            format!("{a}.{b}")
        }
        // /64 — keep the first four hextets in a canonical fixed-width form
        // so every address in one /64 collapses to the SAME key (privacy
        // addresses only vary in the low 64 bits).
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        // Malformed — keep verbatim (one safe bucket, no panic).
        Err(_) => ip.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct SqliteInventory {
    pub(crate) pool: SqlitePool,
}

impl SqliteInventory {
    /// Internal-ish accessor for the underlying `SqlitePool`. Currently
    /// used by the `backup` module to run `VACUUM INTO` (which can't go
    /// through a typed query because the target path isn't bindable).
    /// `pub(crate)` keeps the door closed for external callers — pool
    /// is owned state, not API.
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Open (or create) DB at `path`, apply pragmas, run migrations.
    pub async fn open(path: &Path) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(path.to_str().ok_or_else(|| {
                SqliteInventoryError::Invalid(format!("non-utf8 path: {path:?}"))
            })?)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            // synchronous=NORMAL (vs the SQLite default of FULL): in WAL
            // mode NORMAL never fsyncs on every commit, only at checkpoint.
            // FULL was stalling unrelated writers (dns_ptr_cache, node_health,
            // admin_alerts, vpn_user_sessions) 1-5s under checkpoint pressure.
            // SQLite docs: NORMAL in WAL is durability-safe — it can never
            // corrupt the DB; the only window is losing the last few committed
            // transactions on a power loss / OS crash, which is acceptable for
            // this stats/inventory daemon. See sqlite.org WAL docs + forum
            // thread 9d6f13e.
            .pragma("synchronous", "NORMAL")
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        MIGRATOR.run(&pool).await?;

        // Backfill: every user must have a non-null sub_token after open().
        // Migration 0002 adds the column nullable; we fill it here so the
        // rest of the code can rely on `User.sub_token` being Some.
        backfill_sub_tokens(&pool).await?;

        Ok(Self { pool })
    }

    /// Force-close all pooled connections. Useful in tests.
    pub async fn close(self) {
        self.pool.close().await;
    }
}

/// Extract the `/16` network prefix from a v4 IP literal as a
/// string (`"192.168.0.1"` → `Some("192.168")`). Returns `None`
/// for v6 addresses (no meaningful prefix without ASN data) or
/// malformed strings. Used by the Track-4 UA fingerprint heuristic
/// to count distinct ISP-ish networks per UA.
pub(crate) fn ip_slash16(ip: &str) -> Option<String> {
    // Reject v6 cheaply — colons don't appear in v4 dotted-quad.
    if ip.contains(':') {
        return None;
    }
    let mut parts = ip.split('.');
    let a = parts.next()?;
    let b = parts.next()?;
    let _ = parts.next()?; // third octet must exist (else not v4)
    if a.is_empty() || b.is_empty() {
        return None;
    }
    if !a.bytes().all(|x| x.is_ascii_digit()) || !b.bytes().all(|x| x.is_ascii_digit()) {
        return None;
    }
    Some(format!("{a}.{b}"))
}

/// Escape SQLite LIKE metacharacters (`\`, `%`, `_`) so user-supplied
/// substrings match LITERALLY rather than as patterns. Caller MUST
/// pair this with `ESCAPE '\\'` in the LIKE clause. Without escaping,
/// a filter input of `user_` would match `user.` (the `.` slot is
/// any char per `_`) and `%` would match everything.
pub(crate) fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Walk users whose sub_token is NULL after migrate, generate one each.
/// Idempotent — a second call sees no rows.
async fn backfill_sub_tokens(pool: &SqlitePool) -> Result<()> {
    // Wrap in a transaction so two concurrent `open()` calls can't race on
    // the same NULL row. sqlx::Transaction holds an `IMMEDIATE` write lock
    // on first write; the loser blocks until the winner commits, then sees
    // no NULLs and does nothing. On crash mid-loop the txn rolls back —
    // next open retries cleanly, no half-state.
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT id FROM users WHERE sub_token IS NULL")
        .fetch_all(&mut *tx)
        .await?;
    for r in rows {
        let id: String = r.try_get("id")?;
        let token = vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?;
        sqlx::query("UPDATE users SET sub_token = ?1 WHERE id = ?2")
            .bind(&token)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
