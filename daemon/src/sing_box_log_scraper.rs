//! Phase 4d — sing-box log scraping for exact per-connection
//! `user_id` attribution. Workaround for NM-11 (clash-api drops
//! the `user` field from wire format) — sing-box itself logs
//! every accepted VLESS / TUIC / Trojan handshake with the
//! `user_id` from inventory in `[…]` brackets.
//!
//! ## Log format (sing-box ≥1.10 standard `info` level)
//!
//! Two-step pattern, ONE connection identified by `<conn_id>`:
//!
//! 1. ```text
//!    +0000 2026-05-21 19:39:43 INFO [539162786 0ms] inbound/vless[vless-in]: inbound connection from 31.135.234.102:2810
//!    ```
//!    Inbound accept — has source `IP:port`, no user yet.
//!
//! 2. ```text
//!    +0000 2026-05-21 19:39:43 INFO [539162786 51ms] inbound/vless[vless-in]: [main-brat] inbound connection to 149.154.167.220:443
//!    ```
//!    After auth — same `<conn_id>=539162786`, now carries
//!    `[main-brat]` = our `users.id`.
//!
//! Matching the two lines by `<conn_id>` yields
//! `(source_ip:port) → user_id`.
//!
//! ## Why not use regex
//!
//! The format is rigid enough that `str::find` + `split_whitespace`
//! handles every line. Adding `regex` would inflate the binary
//! (~300 KB) and pull in a non-trivial syntax tree at parse time
//! for what amounts to two anchored prefix lookups per line.
//!
//! ## Why store source `IP:port` not just IP
//!
//! Source ports change every TCP dial, so `(IP, port)` is unique
//! per connection in clash-api's snapshot. Same `(IP, port)` in
//! the log = same connection in the snapshot. Joining on just IP
//! would collapse all connections from one device (e.g. main-brat
//! holds 22 connections from 31.135.234.102 — different source
//! ports each) into one bucket, losing the per-conn precision.
//!
//! ## Cache eviction
//!
//! Each scrape REPLACES the previous map for that server. Long-
//! lived connections that started further back than `tail -n N`
//! lines covers will be missing → UI shows `—` for those. With
//! 10 000 lines per scrape (~5 min of activity on a busy node),
//! coverage is >99 % for typical sessions; a few stale
//! long-lived ones fall through to the sub_access correlation
//! fallback.

use std::collections::HashMap;

use vpnctl_core::SshTransport;

/// Default tail length per scrape. Bigger = more long-lived
/// connections covered, more bytes pulled over SSH per tick.
/// At ~100 bytes/line, 10 000 lines = ~1 MiB transfer; quick over
/// SSH on the LAN-local poller path. Env-overridable
/// (`VPNCTLD_SINGBOX_LOG_TAIL`) for tuning without recompile.
pub const DEFAULT_TAIL_LINES: usize = 10_000;

/// Default log path on a sing-box deploy. Same path baked into
/// `crates/kernels/src/sing_box.rs::apply_config`'s `install
/// -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log`
/// bootstrap step. Env-overridable via `VPNCTLD_SINGBOX_LOG_PATH`.
pub const DEFAULT_LOG_PATH: &str = "/var/log/sing-box.log";

/// Per-(source_ip, source_port) → `user_id` map. Strings on both
/// sides because that's what clash-api gives us and what
/// `users.id` is.
pub type AttributionMap = HashMap<(String, String), String>;

/// Allowed prefixes for the env override. Defence-in-depth: the
/// scrape runs as root on the VPN node; if an operator (or a
/// future config-injection bug) sets the env to `/etc/shadow`,
/// we'd happily slurp its bytes and surface them in `tracing`
/// debug. Whitelist to typical sing-box log locations.
const ALLOWED_LOG_PREFIXES: &[&str] = &["/var/log/", "/var/lib/sing-box/"];

/// Resolve the path to scrape (env override > default). The env
/// override is gated to a small whitelist of prefixes; out-of-
/// range values fall back to the default and log a warn.
pub fn resolve_log_path() -> String {
    match std::env::var("VPNCTLD_SINGBOX_LOG_PATH") {
        Ok(p)
            if ALLOWED_LOG_PREFIXES
                .iter()
                .any(|prefix| p.starts_with(prefix)) =>
        {
            p
        }
        Ok(p) => {
            tracing::warn!(
                target = "vpnctld::sing_box_log_scraper",
                path = %p,
                "VPNCTLD_SINGBOX_LOG_PATH outside the allowed prefixes ({:?}); falling back to default",
                ALLOWED_LOG_PREFIXES
            );
            DEFAULT_LOG_PATH.to_string()
        }
        Err(_) => DEFAULT_LOG_PATH.to_string(),
    }
}

/// Resolve the tail length (env override > default), parseable +
/// non-zero. Invalid → default.
pub fn resolve_tail_lines() -> usize {
    std::env::var("VPNCTLD_SINGBOX_LOG_TAIL")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_TAIL_LINES)
}

/// Parse a tail of sing-box log into an attribution map. Pure
/// function — testable without SSH / FS.
pub fn parse_attribution(log: &str) -> AttributionMap {
    // Per-conn_id we accumulate (source_ip:port) from the
    // "inbound connection from ..." line + user_id from the
    // "[user] inbound ..." line. When both halves are known,
    // emit one (ip, port) → user entry.
    //
    // Duplicate-`from`-line behaviour: PRESERVE THE FIRST source
    // we observed for a given conn_id (review-agent Phase 4d #4).
    // sing-box re-emits accept lines on mux re-keying with the
    // SAME conn_id; the FIRST source is the authentic one. This
    // also defends against the rare case where `tail -n N`
    // straddles a log-rotation boundary and the same conn_id
    // gets reused for a different connection on the new file.
    let mut by_conn: HashMap<&str, ConnHalves<'_>> = HashMap::new();
    for line in log.lines() {
        let Some((conn_id, after_id)) = extract_conn_id(line) else {
            continue;
        };
        if let Some((ip, port)) = extract_source(after_id) {
            by_conn
                .entry(conn_id)
                .or_default()
                .source
                .get_or_insert((ip, port));
        } else if let Some(user) = extract_user(after_id) {
            by_conn.entry(conn_id).or_default().user.get_or_insert(user);
        }
    }

    let mut out: AttributionMap = HashMap::new();
    for (_id, halves) in by_conn {
        if let (Some((ip, port)), Some(user)) = (halves.source, halves.user) {
            out.insert((ip.to_string(), port.to_string()), user.to_string());
        }
    }
    out
}

/// Scrape a sing-box log over SSH and parse the result. Errors
/// from SSH bubble up as `anyhow::Error`; an empty log file
/// returns an empty map.
pub async fn scrape<T: SshTransport + ?Sized>(
    ssh: &T,
    log_path: &str,
    tail_lines: usize,
) -> anyhow::Result<AttributionMap> {
    let cmd = build_tail_cmd(log_path, tail_lines);
    let stdout = ssh.exec(&cmd).await?;
    Ok(parse_attribution(&stdout))
}

/// Build the shell command that tails the attribution-relevant
/// sing-box log lines. Reads the most-recent ROTATED sibling
/// `{log}.1` FIRST (older — uncompressed thanks to logrotate's
/// `delaycompress`), THEN the live `{log}` (newer), each tailed
/// to its last `tail_lines` lines.
///
/// Why read `.1` too: the deploy's logrotate fragment uses
/// `copytruncate`, which truncates the live file in place at
/// rotation — so right after a daily rotation the live `{log}`
/// has lost the pre-rotation "inbound connection from …" accept
/// lines that long-lived connections still need for attribution.
/// Those accept lines now live in `{log}.1`. Reading `.1` then
/// `{log}` in chronological order restores the straddling history.
///
/// `for f in … ; do tail -n N "$f" 2>/dev/null; done` — per-file
/// `tail` (NOT `tail a b`, which would interleave `==> file <==`
/// header banners into the stream and corrupt parsing). The
/// `2>/dev/null` makes a missing `.1` (no rotation yet) a no-op
/// rather than an error. Order matters: `.1` (older) before the
/// live file (newer) so `parse_attribution`'s "preserve FIRST
/// source per conn_id" keeps the authentic pre-rotation source.
///
/// Defensive single-quote strip on the path (the env override is
/// operator-trusted, but we never trust user-typed config). The
/// canonical path `/var/log/sing-box.log` is shell-safe.
fn build_tail_cmd(log_path: &str, tail_lines: usize) -> String {
    let log = log_path.replace('\'', "");
    format!("for f in '{log}.1' '{log}'; do tail -n {tail_lines} \"$f\" 2>/dev/null; done")
}

#[derive(Default)]
struct ConnHalves<'a> {
    source: Option<(&'a str, &'a str)>,
    user: Option<&'a str>,
}

/// Find the connection id inside `[<id> <age>]` and return
/// `(<id>, &line[after_close_bracket..])`. Returns None when the
/// first `[…]` doesn't look like a sing-box connection id (e.g.
/// startup-log or unrelated tooling line).
fn extract_conn_id(line: &str) -> Option<(&str, &str)> {
    let open = line.find('[')?;
    let rel_close = line[open + 1..].find(']')?;
    let inside = &line[open + 1..open + 1 + rel_close];
    // sing-box format: "<digits> <age>" or "<digits>" (rarely).
    let id = inside.split_whitespace().next()?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let after = &line[open + 1 + rel_close + 1..];
    Some((id, after))
}

/// Parse the source IP and port from the inbound-accept suffix.
///
/// sing-box logs the source side in TWO marker forms depending on
/// the transport of the inbound:
///
/// - stream / TCP (VLESS, Trojan): `inbound connection from <addr>`
/// - packet / UDP (Hysteria2, TUIC): `inbound packet connection from <addr>`
///
/// Both carry the same `<addr>` shape, in either of:
///
/// - IPv4 source: `83.97.108.34:55512`
/// - IPv6 source: `[2a00:1450::1]:55512` (sing-box bracket-wraps
///   IPv6 source addresses just like destinations)
///
/// We match whichever marker occurs and advance past it; the
/// address parsing below is shared. NM-11 follow-up: before this,
/// only the stream marker matched, so UDP-only users (e.g. a
/// hysteria2-only client) got no `(source_ip, port) → user` pair
/// and showed "No live stats yet" despite their packet user-line
/// being parsed fine by `extract_user`.
fn extract_source(after_id: &str) -> Option<(&str, &str)> {
    // The two markers are disjoint substrings (the packet form has
    // "packet " where the stream form has "connection " right after
    // "inbound "), so order doesn't affect correctness; probe the
    // packet form first as the readable "more specific" branch.
    let tail = if let Some(idx) = after_id.find("inbound packet connection from ") {
        &after_id[idx + "inbound packet connection from ".len()..]
    } else {
        let idx = after_id.find("inbound connection from ")?;
        &after_id[idx + "inbound connection from ".len()..]
    };
    // Take up to the first whitespace; error-variant lines append
    // `: reason` AFTER the address, success lines end at EOL.
    let addr_end = tail
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(tail.len());
    let addr = &tail[..addr_end];

    // IPv6 bracketed form first — `[2a00:…::1]:55512`. Strip the
    // outer brackets so the returned IP is the raw address (matches
    // what clash-api emits for `sourceIP`).
    if let Some(after_open) = addr.strip_prefix('[') {
        if let Some((ip, port)) = after_open.rsplit_once("]:") {
            if !ip.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                return Some((ip, port));
            }
        }
        return None;
    }

    // IPv4 fallback — split from the right on ':' so the port is
    // the last segment; IP keeps any dotted-quad structure.
    let (ip, port) = addr.rsplit_once(':')?;
    if ip.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((ip, port))
}

/// Parse the user_id from the "[user] inbound …" form. The line
/// shape is `inbound/vless[<inbound_name>]: [<user>] inbound …`.
/// We anchor on the literal `"]: ["` separator (close of the
/// inbound-name bracket immediately followed by the open of the
/// user bracket) — far less ambiguous than `rfind('[')` walks
/// which could pick the wrong opener if user_ids ever contain
/// nested brackets (review-agent Phase 4d #1).
fn extract_user(after_id: &str) -> Option<&str> {
    let sep_idx = after_id.find("]: [")?;
    let user_start = sep_idx + "]: [".len();
    let rest = &after_id[user_start..];
    let user_end = rest.find(']')?;
    let user = &rest[..user_end];
    if user.is_empty() || user.contains([' ', ']', '[']) {
        return None;
    }
    // Verify this user bracket is actually followed by " inbound"
    // (not " outbound" / " http" / etc) — discriminator against
    // false matches in non-inbound log lines.
    let after_close = &rest[user_end + 1..];
    if !after_close.starts_with(" inbound") {
        return None;
    }
    // Sanity — user_id is `[a-z0-9._-]{2,32}` per the inventory
    // convention. We don't validate strictly here (the inventory
    // already does on add_user); just trim obvious garbage.
    Some(user)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
+0000 2026-05-21 19:39:43 INFO [539162786 0ms] inbound/vless[vless-in]: inbound connection from 31.135.234.102:2810
+0000 2026-05-21 19:39:43 INFO [638256431 0ms] inbound/vless[vless-in]: inbound connection from 31.135.234.102:2809
+0000 2026-05-21 19:39:43 INFO [3264400240 0ms] inbound/vless[vless-in]: inbound connection from 178.35.106.202:62189
+0000 2026-05-21 19:39:43 INFO [3264400240 90ms] inbound/vless[vless-in]: [abukarov_tk] inbound packet connection to 35.217.1.178:50005
+0000 2026-05-21 19:39:43 INFO [3264400240 90ms] outbound/direct[direct]: outbound packet connection
+0000 2026-05-21 19:39:43 INFO [539162786 51ms] inbound/vless[vless-in]: [main-brat] inbound connection to 149.154.167.220:443
+0000 2026-05-21 19:39:43 INFO [539162786 51ms] outbound/direct[direct]: outbound connection to 149.154.167.220:443
+0000 2026-05-21 19:39:43 INFO [638256431 52ms] inbound/vless[vless-in]: [main-brat] inbound connection to 149.154.167.220:443
+0000 2026-05-21 19:39:45 ERROR [1402369434 1m31s] inbound/vless[vless-in]: process connection from 178.173.106.221:18314: mux connection closed: read frame header: EOF
+0000 2026-05-21 19:39:47 INFO [1268087823 0ms] inbound/vless[vless-in]: inbound connection from 46.146.84.17:28539
+0000 2026-05-21 19:39:47 INFO [1268087823 87ms] inbound/vless[vless-in]: [alicemoren1991] inbound connection to 184.24.77.168:80
+0000 2026-05-21 19:39:44 INFO [2608154907 0ms] inbound/vless[vless-in]: inbound connection from 109.126.224.56:61242
+0000 2026-05-21 19:39:44 INFO [2608154907 92ms] inbound/vless[vless-in]: [vouvaivah] inbound connection to [2a00:1450:4001:c17::66]:443
";

    #[test]
    fn parse_attribution_matches_three_known_users_in_sample() {
        let m = parse_attribution(SAMPLE);
        // 31.135.234.102:2810 and :2809 both go to main-brat
        assert_eq!(
            m.get(&("31.135.234.102".into(), "2810".into()))
                .map(|s| s.as_str()),
            Some("main-brat"),
            "main-brat (port 2810) must resolve"
        );
        assert_eq!(
            m.get(&("31.135.234.102".into(), "2809".into()))
                .map(|s| s.as_str()),
            Some("main-brat"),
            "main-brat (port 2809) must resolve"
        );
        // 178.35.106.202:62189 → abukarov_tk (packet conn variant)
        assert_eq!(
            m.get(&("178.35.106.202".into(), "62189".into()))
                .map(|s| s.as_str()),
            Some("abukarov_tk"),
            "abukarov_tk must resolve (packet-connection variant of log line)"
        );
        // 46.146.84.17:28539 → alicemoren1991
        assert_eq!(
            m.get(&("46.146.84.17".into(), "28539".into()))
                .map(|s| s.as_str()),
            Some("alicemoren1991")
        );
        // 109.126.224.56:61242 → vouvaivah (destination is IPv6, must
        // not break our source-only IPv4 parser)
        assert_eq!(
            m.get(&("109.126.224.56".into(), "61242".into()))
                .map(|s| s.as_str()),
            Some("vouvaivah"),
            "vouvaivah must resolve even though dest is IPv6 [bracketed]"
        );
    }

    #[test]
    fn parse_attribution_skips_inbound_without_matching_user_line() {
        // 178.173.106.221:18314 only appears as ERROR (no user line)
        let m = parse_attribution(SAMPLE);
        assert!(
            !m.contains_key(&("178.173.106.221".into(), "18314".into())),
            "ERROR-only connections must not appear in the attribution map"
        );
    }

    #[test]
    fn parse_attribution_skips_inbound_with_no_inbound_from_line() {
        // 638256431 also has user but I have its `from` line in
        // SAMPLE. Edge case: if a user line lands WITHOUT its `from`
        // companion (log was rotated mid-stream), the conn_id has
        // user but no source → no entry emitted.
        let partial = "+0000 2026-05-21 19:39:43 INFO [99999999 51ms] inbound/vless[vless-in]: [orphan] inbound connection to 1.2.3.4:443\n";
        let m = parse_attribution(partial);
        assert!(
            m.is_empty(),
            "user line without prior `from` line must NOT emit an entry"
        );
    }

    #[test]
    fn parse_attribution_handles_empty_input() {
        let m = parse_attribution("");
        assert!(m.is_empty());
    }

    #[test]
    fn extract_conn_id_skips_lines_with_no_brackets() {
        let line = "no brackets here";
        assert!(extract_conn_id(line).is_none());
    }

    #[test]
    fn extract_conn_id_skips_non_numeric_first_chunk() {
        // Hypothetical sing-box future log line where first bracket
        // wraps a non-numeric tag. Must not crash; just skip.
        let line = "[some-tag info] something";
        assert!(extract_conn_id(line).is_none());
    }

    #[test]
    fn extract_source_returns_ip_and_port_from_canonical_line() {
        let after = " inbound/vless[vless-in]: inbound connection from 83.97.108.34:55512";
        let (ip, port) = extract_source(after).expect("must parse");
        assert_eq!(ip, "83.97.108.34");
        assert_eq!(port, "55512");
    }

    #[test]
    fn extract_source_parses_packet_form() {
        // UDP inbounds (hysteria2, tuic) log the source with an extra
        // "packet " token: `inbound packet connection from <addr>`.
        // Before the fix this returned None → no attribution for
        // UDP-only users.
        let after =
            " inbound/hysteria2[hy2-in]: inbound packet connection from 136.169.158.27:11837";
        let (ip, port) = extract_source(after).expect("must parse packet form");
        assert_eq!(ip, "136.169.158.27");
        assert_eq!(port, "11837");
    }

    #[test]
    fn extract_source_still_parses_stream_form() {
        // Regression guard: the TCP/stream marker must keep working
        // after the packet-form branch was added.
        let after = " inbound/vless[vless-in]: inbound connection from 83.97.108.34:55512";
        let (ip, port) = extract_source(after).expect("must parse stream form");
        assert_eq!(ip, "83.97.108.34");
        assert_eq!(port, "55512");
    }

    #[test]
    fn extract_source_rejects_non_digit_port() {
        let after = " inbound/vless[vless-in]: inbound connection from 1.2.3.4:abc";
        assert!(extract_source(after).is_none());
    }

    #[test]
    fn extract_user_returns_user_id_from_canonical_line() {
        let after = " inbound/vless[vless-in]: [main-brat] inbound connection to 1.2.3.4:443";
        assert_eq!(extract_user(after), Some("main-brat"));
    }

    #[test]
    fn extract_user_returns_user_id_for_packet_connection_variant() {
        let after = " inbound/vless[vless-in]: [abukarov_tk] inbound packet connection to 35.217.1.178:50005";
        assert_eq!(extract_user(after), Some("abukarov_tk"));
    }

    #[test]
    fn extract_user_returns_none_for_outbound_line() {
        let after = " outbound/direct[direct]: outbound connection to 1.2.3.4:443";
        assert!(extract_user(after).is_none());
    }

    #[test]
    fn extract_user_returns_none_for_error_process_connection_line() {
        let after = " inbound/vless[vless-in]: process connection from 1.2.3.4:5: mux connection closed: read frame header: EOF";
        assert!(extract_user(after).is_none());
    }

    // ── Log-rotation survival: read rotated sibling + live ────────

    #[test]
    fn build_tail_cmd_reads_rotated_sibling_then_live_in_order() {
        let cmd = build_tail_cmd("/var/log/sing-box.log", 10_000);
        // Both the rotated sibling and the live file must be read.
        let dot1 = "/var/log/sing-box.log.1";
        let live = "/var/log/sing-box.log";
        let dot1_idx = cmd
            .find(dot1)
            .expect("command must reference the rotated sibling .1");
        // The live path also appears as a prefix of `.1`; find the
        // live reference that is NOT the `.1` occurrence by looking
        // for the live path followed by a non-`.` char (the closing
        // quote in the loop list).
        let live_quoted = format!("{live}'");
        let live_idx = cmd
            .rfind(&live_quoted)
            .expect("command must reference the live log path");
        assert!(
            dot1_idx < live_idx,
            "rotated sibling .1 (older) must be read BEFORE the live file (newer) so \
             parse_attribution preserves the authentic pre-rotation source: cmd = {cmd}"
        );
    }

    #[test]
    fn build_tail_cmd_carries_the_tail_line_count() {
        let cmd = build_tail_cmd("/var/log/sing-box.log", 4242);
        assert!(
            cmd.contains("tail -n 4242"),
            "tail line count must be honoured: {cmd}"
        );
    }

    #[test]
    fn build_tail_cmd_strips_single_quotes_from_path() {
        // The single-quote strip keeps the operator-trusted env
        // override from breaking out of the single-quoted loop list.
        // After stripping, the ONLY single quotes left are the 4 that
        // wrap the two loop-list items ('{log}.1' and '{log}').
        let cmd = build_tail_cmd("/var/log/sing-'box'.log", 100);
        assert_eq!(
            cmd.matches('\'').count(),
            4,
            "stray single quotes from the path must be stripped, leaving only the 4 \
             loop-list quotes: {cmd}"
        );
    }

    #[test]
    fn resolve_log_path_default_when_env_unset() {
        // SAFETY: env writes are process-global. The default fallback
        // is the only branch we can test without an unsafe env::set.
        // Just verify the constant.
        assert_eq!(DEFAULT_LOG_PATH, "/var/log/sing-box.log");
    }

    // ── Phase 4d review-agent #2: IPv6 source ─────────────────────

    #[test]
    fn extract_source_parses_ipv6_bracketed_address() {
        let after = " inbound/vless[vless-in]: inbound connection from [2a00:1450::1]:55512";
        let (ip, port) = extract_source(after).expect("must parse IPv6 source");
        assert_eq!(ip, "2a00:1450::1", "brackets must be stripped");
        assert_eq!(port, "55512");
    }

    #[test]
    fn extract_source_rejects_ipv6_with_missing_close_bracket() {
        let after = " inbound/vless[vless-in]: inbound connection from [2a00:1450::1:55512";
        assert!(extract_source(after).is_none());
    }

    // ── Phase 4d review-agent #1: extract_user via anchor ─────────

    #[test]
    fn extract_user_uses_separator_anchor_not_walk_back() {
        // Defensive against nested-bracket ambiguity. The anchor
        // `]: [` makes the user bracket unambiguous regardless of
        // what the inbound name is.
        let after =
            " inbound/vless[some-weird-name]: [main-brat] inbound connection to 1.2.3.4:443";
        assert_eq!(extract_user(after), Some("main-brat"));
    }

    #[test]
    fn extract_user_rejects_user_bracket_followed_by_outbound() {
        // If sing-box ever emits `[name] outbound …` we must NOT
        // pick it as a user attribution.
        let after = " outbound/direct[direct]: [direct] outbound connection";
        assert!(extract_user(after).is_none());
    }

    // ── Phase 4d review-agent #4: duplicate `from` line ───────────

    #[test]
    fn parse_attribution_preserves_first_source_on_duplicate_from_line() {
        // Same conn_id, two `from` lines (mux re-keying / rotation
        // straddle) + one user line. The FIRST source wins so the
        // user is attributed to the authentic original IP, not a
        // later replay or reused conn_id.
        let log = "\
INFO [12345 0ms] inbound/vless[vless-in]: inbound connection from 1.1.1.1:1000
INFO [12345 1s] inbound/vless[vless-in]: inbound connection from 9.9.9.9:9000
INFO [12345 2s] inbound/vless[vless-in]: [first-user] inbound connection to 8.8.8.8:443
";
        let m = parse_attribution(log);
        assert_eq!(
            m.get(&("1.1.1.1".into(), "1000".into()))
                .map(|s| s.as_str()),
            Some("first-user"),
            "first source 1.1.1.1:1000 must win"
        );
        assert!(
            !m.contains_key(&("9.9.9.9".into(), "9000".into())),
            "duplicate replay source 9.9.9.9:9000 must NOT shadow the original"
        );
    }

    // ── NM-11 follow-up: UDP (hysteria2/tuic) packet-form source ──

    #[test]
    fn parse_attribution_attributes_hysteria2_packet_user() {
        // End-to-end proof of the fix. A hysteria2-only user logs BOTH
        // halves in packet form under one conn_id: the source line
        // (`inbound packet connection from <ip:port>`) + the post-auth
        // user line (`[someuser] inbound packet connection to <dst>`).
        // Before the fix the source half was dropped → NULL attribution
        // (this is the `rectuspc` symptom observed live on server `cdn`).
        let log = "\
+0000 2026-06-12 10:00:00 INFO [777 0ms] inbound/hysteria2[hy2-in]: inbound packet connection from 136.169.158.27:11837
+0000 2026-06-12 10:00:00 INFO [777 5ms] inbound/hysteria2[hy2-in]: [someuser] inbound packet connection to 8.8.8.8:443
";
        let m = parse_attribution(log);
        assert_eq!(
            m.get(&("136.169.158.27".into(), "11837".into()))
                .map(|s| s.as_str()),
            Some("someuser"),
            "hysteria2 packet-form source+user must produce a (ip,port)→user entry"
        );
    }
}
