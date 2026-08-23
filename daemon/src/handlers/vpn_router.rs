//! `GET /api/v1/app/config/{device_id}` — ninitux subscription-server
//! compatibility endpoint (Phase 3 of the migration plan in
//! `docs/COMPREHENSIVE_AUDIT_2026-05-19.md`).
//!
//! Goal: every client that today fetches its config via
//! `https://ninitux.com/api/v1/app/config/<device_id>` continues to
//! work after nginx (Phase 5) cuts that path over to vpnctld. The
//! response shape mirrors subscription-server's `app/routers/subscription.py`
//! byte-for-byte:
//!
//!   * HTTP 200 always — anti-fingerprinting against probes that
//!     would otherwise tell a missing device_id from a valid one
//!     via the status code. NB: subscription-server (and therefore
//!     this handler, to preserve byte-equivalence) does NOT
//!     constant-length the response body — a registered device's
//!     base64 blob is much larger than the empty string returned for
//!     the unregistered raw path, so Content-Length still leaks
//!     state. Inherited limitation, not a regression. A future
//!     hardening pass could pad the empty response to a typical
//!     blob length, but that breaks byte-equivalence with the
//!     Python service and would need to be applied to both sides
//!     simultaneously.
//!   * Inventory read errors (DB outage, schema drift) collapse to
//!     the `device_not_registered` shape rather than 5xx — preserves
//!     anti-fingerprinting and lets the daemon keep serving other
//!     paths. Operator-visible signal lives in `tracing::error!`
//!     under target=`vpnctld::vpn_router` (read via `journalctl -u
//!     vpnctld`). Wiring this into `admin_alerts` is Phase G work,
//!     deferred.
//!   * Rate-limited at the handler level (item-3, 2026-06-01) via the
//!     shared `RateLimiter`, two axes. (1) per-`device_id`, post-resolve
//!     — THE per-user limit, each device_id its own bucket. (2)
//!     per-source-IP anti-flood vs random-device_id scraping, BUT only
//!     for NON-VPN-egress IPs: a VPN-connected client's refresh egresses
//!     its node so vpnctld sees the SERVER's IP, and N users on one
//!     server would otherwise share one per-IP bucket and throttle each
//!     other (Pavel: "33 обновления если все будут на одном конфиге").
//!     `is_known_server_address` exempts our egress IPs; they rely on
//!     per-device_id. Throttle-only (429 + Retry-After) — NO persistent
//!     ban, so a misbehaving app or an egress IP can't lock users out.
//!   * UA-based content negotiation. Standard VPN clients
//!     (Streisand, v2rayNG, Shadowrocket, Hiddify, sing-box, …) get
//!     `text/plain; charset=utf-8` with the raw base64 subscription.
//!     Browsers / curl / the custom «VPN Router» app get the JSON
//!     wrapper (`status, app, version, update_available, config,
//!     check_interval, timestamp` in that exact key order).
//!   * Base64-of-newline-joined-`vless://` URIs as the payload.
//!   * Per-server `client_uuid` taken from `grants.client_uuid` set
//!     by the Phase 2 import; the VLESS render uses ninitux's
//!     specific query-param order (`type, security, pbk, fp, sni,
//!     sid, spx, flow`) — NOT vpnctld's existing `share_link()`
//!     format (which is bash-script-derived + pinned by
//!     `vless_happy_path_byte_equal` — leaving it untouched).
//!   * Fragment label `"{server_stripped} {port} {client_name}"`
//!     where `server_stripped = "vps-de-01"` → `"de-01"`. Full URL
//!     encoding (spaces → `%20`, hyphens kept).
//!
//! KNOWN GAP — multi-SNI inbounds:
//!   Subscription-server emits ONE vless URI per VLESS inbound per
//!   granted server (vps-de-01 has 2, vps-is-01 has 3). vpnctld
//!   today only tracks a single VLESS inbound per server in
//!   `server_secrets` (no `vless.extra_sni_1` etc.). This handler
//!   emits ONE URI per granted server, byte-equivalent on the
//!   primary inbound (port 443 + default REALITY SNI), but missing the
//!   secondary/tertiary failover URIs. Acceptable for migration —
//!   clients still connect via the primary URI; failover redundancy
//!   on secondary ports is lost until vpnctld grows multi-inbound
//!   per-protocol support. Document this in the Phase 4 A/B report.

mod collectors;
mod compat;
mod routes;

#[cfg(test)]
mod tests;

pub(crate) use self::compat::*;
pub(crate) use self::routes::*;
