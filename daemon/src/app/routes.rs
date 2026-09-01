//! Axum Router construction for the public API and admin UI.

use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::routing::{get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info_span;

use crate::handlers;
use crate::handlers::auth::BasicAuth;

use super::state::AppState;

/// Pulled out so tests can inject a state pointed at a tempdir DB.
pub fn router(state: AppState) -> Router {
    // Trace-layer span uses MatchedPath ("/sub/{token}") instead of the raw
    // URI ("/sub/<actual-secret-token>"). Otherwise every subscriber's token
    // would land in INFO-level logs and any aggregator downstream — that's a
    // critical leak (review-agent caught it before it shipped).
    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        let matched = req
            .extensions()
            .get::<MatchedPath>()
            .map_or("<unknown>", MatchedPath::as_str);
        info_span!("http", method = %req.method(), path = matched)
    });

    let admin_router = admin_router(state.clone());

    // Security headers on public/API routes are applied via `route_layer` so they
    // attach ONLY to matched public routes and do not leak on unmatched 404
    // probes (e.g. `/etc/passwd`), preserving the anti-fingerprinting contract.
    let public_router = Router::new()
        .route("/api/v1/health", get(handlers::health::get))
        // Phase F monitoring stats (NOT behind admin auth — exposes
        // only aggregate counts, no per-IP/per-token details).
        .route("/api/v1/stats/sub-access", get(handlers::stats::sub_access))
        .route("/sub/{token}", get(handlers::sub::get))
        .route("/api/v1/sub/{token}", get(handlers::sub::get_mihomo))
        // Phase 3 — ninitux subscription-server compat endpoint
        // (`https://ninitux.com/api/v1/app/config/<device_id>`). Same
        // response shape as subscription-server; nginx on 192.168.0.207
        // cuts over from subscription-server:8100 → vpnctld:18402 in
        // Phase 5. See `docs/COMPREHENSIVE_AUDIT_2026-05-19.md` and
        // `handlers/vpn_router.rs` for the byte-equivalence contract.
        // Phase 3 happy path + defense-in-depth catch-all in ONE
        // wildcard route. The handler dispatches based on `tail`
        // shape (single 32-hex segment → device lookup; anything
        // else → canonical `device_not_registered` shape). See
        // `handlers/vpn_router.rs::get_config` for the dispatch
        // contract + why we can't split this into `{device_id}` +
        // `{*tail}` separate routes (matchit 0.8.4 panics on the
        // overlap). Bare-prefix routes (no device_id at all) point
        // at a sibling `get_config_root_catchall` because the `*tail`
        // wildcard requires ≥1 segment.
        .route(
            "/api/v1/app/config/{*tail}",
            get(handlers::vpn_router::get_config),
        )
        .route(
            "/api/v1/app/config",
            get(handlers::vpn_router::get_config_root_catchall),
        )
        .route(
            "/api/v1/app/config/",
            get(handlers::vpn_router::get_config_root_catchall),
        )
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                axum::http::HeaderValue::from_static("nosniff"),
            ),
        )
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::X_FRAME_OPTIONS,
                axum::http::HeaderValue::from_static("DENY"),
            ),
        )
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("no-referrer"),
            ),
        );

    public_router
        .with_state(state)
        .merge(admin_router)
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(RequestBodyLimitLayer::new(8 * 1024)) // GET only — paranoia
        .layer(trace_layer)
}

/// `/admin/*` subtree. Phase A: shell + tweaks + static assets, all
/// behind basic-auth IF env vars present (otherwise open — useful for
/// local smoke).
pub(crate) fn admin_router(state: AppState) -> Router {
    use crate::handlers::admin;

    // Prefer the runtime assets dir: the compile-time build directory may
    // be deleted after a production deploy while the daemon keeps running.
    let assets_dir: PathBuf = [
        PathBuf::from("assets"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets"),
        PathBuf::from("daemon/assets"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| PathBuf::from("daemon/assets"));

    // Explicit routes instead of `nest("/admin", ...)` — axum 0.8's nest
    // does NOT auto-match the trailing-slash variant of the inner "/" route
    // (so `/admin` works but `/admin/` 404s). Explicitly register both.
    // `nest_service` is fine for static — its prefix-match handles the
    // trailing slash naturally.
    //
    // Phase A section routes render the same shell with `active_nav` set
    // and a placeholder body; real content lands in subsequent phases.
    // Without these, clicking a nav anchor 404'd.
    //
    // Each section is registered with AND without the trailing slash —
    // axum 0.8 routes match exactly, so `/admin/users` and `/admin/users/`
    // would otherwise diverge (200 vs 404). Same reason `/admin` and
    // `/admin/` are both wired for dashboard.
    let with_admin = Router::new()
        .route("/admin", get(admin::dashboard))
        .route("/admin/", get(admin::dashboard))
        // ui-audit follow-up — dashboard split into 2 sub-route tabs
        // (overview / activity), KPI glance stays as chrome. Explicit
        // routes; bare `/admin/` + `/admin/overview` render overview.
        .route("/admin/overview", get(admin::dashboard))
        .route("/admin/activity", get(admin::dashboard_activity))
        .route("/admin/sharing", get(admin::sharing))
        .route("/admin/sharing/", get(admin::sharing))
        .route("/admin/monitoring", get(admin::monitoring))
        .route("/admin/monitoring/", get(admin::monitoring))
        // v2 3a — manual probe sweep. POST-only (state-changing: writes
        // node_health rows) so the Origin CSRF middleware covers it.
        .route(
            "/admin/monitoring/probe-all",
            post(admin::monitoring_probe_all),
        )
        .route("/admin/servers", get(admin::servers))
        .route("/admin/servers/", get(admin::servers))
        // Phase H chunk 3: server detail page with live telemetry +
        // declared-vs-observed drift section. Reads
        // `inv.latest_node_health` + `inv.recent_node_health_for_server`;
        // empty-state until chunk 4 wires the periodic poller.
        .route("/admin/servers/{id}", get(admin::server_detail))
        .route("/admin/servers/{id}/", get(admin::server_detail))
        // ui-audit §3-§4 — server_detail split into 5 sub-route tabs.
        // Explicit routes (not a `{tab}` catch-all) so existing GET
        // sub-paths (delete-confirm, deploy/sse…) can't collide and an
        // unknown tab 404s through the normal fallback. Bare
        // `/admin/servers/{id}` + `/status` both render the status tab.
        .route("/admin/servers/{id}/status", get(admin::server_detail))
        .route(
            "/admin/servers/{id}/activity",
            get(admin::server_detail_activity),
        )
        .route(
            "/admin/servers/{id}/protocols",
            get(admin::server_detail_protocols_tab),
        )
        .route(
            "/admin/servers/{id}/grants",
            // GET = the grants tab; POST = the v2 3d grant bar
            // (user id as a form field).
            get(admin::server_detail_grants_tab).post(admin::server_grant_user_form),
        )
        .route("/admin/servers/{id}/setup", get(admin::server_detail_setup))
        // Phase v0.8 — TOFU pin via web. Manual paste OR auto-detect
        // via ssh-keyscan (form's `mode` field).
        .route(
            "/admin/servers/{id}/set-fingerprint",
            post(admin::server_set_fingerprint),
        )
        .route(
            "/admin/servers/{id}/routing-policy",
            post(admin::server_set_routing_policy),
        )
        .route(
            "/admin/servers/{id}/client-detour",
            post(admin::server_set_client_detour_via),
        )
        // Display name (migration 0029). Operator pins the friendly
        // subscription label end users see ({Country} VLESS ~user);
        // blank clears it back to the country-map fallback.
        .route(
            "/admin/servers/{id}/display-name",
            post(admin::server_set_display_name),
        )
        // Naive (Caddy) per-server config — operator sets naive.domain +
        // naive.acme_email (server_secrets) consumed by the caddy kernel's
        // Caddyfile render + Caddy's built-in ACME (Let's Encrypt).
        .route(
            "/admin/servers/{id}/naive-config",
            post(admin::server_set_naive_config),
        )
        // vless-ws (Caddy) per-server config — operator sets vlessws.domain
        // + vlessws.acme_email + vlessws.listen_port (server_secrets); the
        // secret ws path is auto-minted at deploy. Consumed by the caddy
        // kernel's vless-ws bundle render + Caddy's built-in ACME.
        .route(
            "/admin/servers/{id}/vlessws-config",
            post(admin::server_set_vlessws_config),
        )
        // VLESS+REALITY per-server listen port — operator sets
        // vless.listen_port (blank = default 443) when a co-tenant owns
        // 443; validated against every other protocol's effective port
        // at save time (PR #139 review finding 7).
        .route(
            "/admin/servers/{id}/reality-config",
            post(admin::server_set_reality_config),
        )
        // Auto-suppress opt-in (migration 0030). Toggle whether the
        // server is auto-hidden from subscriptions while unreachable
        // (health monitor sets/clears the runtime suppressed_at flag).
        .route(
            "/admin/servers/{id}/auto-suppress",
            post(admin::server_set_auto_suppress),
        )
        // naive↔HY2 UDP-pairing opt-in (migration 0031, UX-3).
        .route(
            "/admin/servers/{id}/udp-pair",
            post(admin::server_set_udp_pair),
        )
        // Delete a server from inventory (retype-to-confirm, mirrors user
        // delete). GET renders the confirm page; POST does the cascade
        // delete + audits server.remove.
        .route(
            "/admin/servers/{id}/delete-confirm",
            get(admin::server_delete_confirm),
        )
        .route("/admin/servers/{id}/delete", post(admin::server_delete))
        // Reserved-ports list (migration 0028). Operator pins ports
        // the daemon must never touch via sing-box — a sing-box
        // pre-apply guard refuses any rendered inbound on a
        // reserved port. Used for co-tenant scenarios (legacy
        // 3x-ui Docker on :443 sharing the host with vpnctl's
        // sing-box on :8443).
        .route(
            "/admin/servers/{id}/reserved-ports",
            post(admin::server_set_reserved_ports),
        )
        // Quick-add — register an existing server in inventory with
        // default kernel + protocols. Distinct from the
        // Phase-E wizard at `/admin/servers/new` (which bootstraps a
        // fresh node from scratch).
        .route("/admin/servers/quick-add", post(admin::server_quick_add))
        // The operator-facing Deploy button (per CLAUDE.md "Web is
        // the ONLY operator surface"). Bootstraps every missing
        // server-secret + audits. SSH-touching parts (install kernel
        // + apply config) are tracked separately as web-deploy-apply
        // TODO — gated until the daemon ships with a working SSH
        // path on bookworm-2.36.
        .route("/admin/servers/{id}/deploy", post(admin::server_deploy))
        // SSE-streamed re-deploy (item-1, 2026-05-31). EventSource (GET)
        // endpoint that streams per-step progress + a terminal ok/error
        // so the operator sees what's happening and how it finished —
        // unlike the POST above, which 303-redirected as "success" even
        // when sing-box crash-looped. Same-origin guarded in-handler.
        .route(
            "/admin/servers/{id}/deploy/sse",
            get(admin::server_deploy_sse),
        )
        // "Deploy all" (2026-06-03) — SSE-streamed re-deploy of EVERY
        // server in one click, so a newly-added user's UUID reaches all
        // nodes without per-server clicks. 3-segment path — no clash with
        // the {id} routes above. Same-origin guarded in-handler.
        .route(
            "/admin/servers/deploy-all/sse",
            get(admin::servers_deploy_all_sse),
        )
        // "Update kernels" (update-kernels PR2) — SSE-streamed kernel
        // BINARY upgrade (ensure_installed only, no config render/apply),
        // so it works on inventory-drift nodes without the DG-1 guard.
        // Same-origin guarded in-handler.
        .route(
            "/admin/servers/{id}/update-kernels/sse",
            get(admin::server_update_kernels_sse),
        )
        // "Update all kernels" — fleet-wide kernel binary upgrade in one
        // streamed pass. 3-segment path — no clash with the {id} routes
        // above (same trick as deploy-all/sse). Same-origin guarded
        // in-handler.
        .route(
            "/admin/servers/update-kernels-all/sse",
            get(admin::servers_update_kernels_all_sse),
        )
        // Migration 0018: per-(server, protocol) hide flag + per-(user,
        // server, protocol) deny override. 4 POST handlers — server-
        // level chip is on /admin/servers/{id}; per-user grid is on
        // /admin/users/{id} (rendered with checkboxes that POST these
        // URLs). See handlers/admin.rs `server_protocol_hide` etc.
        .route(
            "/admin/servers/{sid}/protocols/{pid}/hide",
            post(admin::server_protocol_hide),
        )
        .route(
            "/admin/servers/{sid}/protocols/{pid}/unhide",
            post(admin::server_protocol_unhide),
        )
        .route(
            "/admin/users/{uid}/grants/{sid}/protocols/{pid}/disable",
            post(admin::grant_protocol_disable),
        )
        .route(
            "/admin/users/{uid}/grants/{sid}/protocols/{pid}/enable",
            post(admin::grant_protocol_enable),
        )
        // Server-side grant mutations (Pavel iter B). Identical mutation
        // to /admin/users/{id}/grants/{server_id} but the redirect goes
        // to the server detail page so the operator stays where they
        // started. URL shape mirrors the user-side equivalents.
        .route(
            "/admin/servers/{sid}/grants/{uid}",
            post(admin::server_grant_user),
        )
        .route(
            "/admin/servers/{sid}/grants/{uid}/revoke",
            post(admin::server_revoke_user),
        )
        // Server protocols toggle — inventory-only mutation; the
        // operator runs `vpnctl deploy <server>` from the CLI to
        // push. Routes are split into enable/disable rather than
        // a single toggle so the operator's intent is in the URL
        // (audit-friendly + handles double-submit gracefully).
        .route(
            "/admin/servers/{id}/protocols/{proto}/enable",
            post(admin::server_enable_protocol),
        )
        .route(
            "/admin/servers/{id}/protocols/{proto}/disable",
            post(admin::server_disable_protocol),
        )
        // Multi-kernel: same enable/disable shape for kernels.
        // Adding amneziawg to a sing-box node = first step before
        // enabling wireguard protocol.
        .route(
            "/admin/servers/{id}/kernels/{kernel}/enable",
            post(admin::server_enable_kernel),
        )
        .route(
            "/admin/servers/{id}/kernels/{kernel}/disable",
            post(admin::server_disable_kernel),
        )
        // Phase E sub-iter 4a: add-server wizard step 1.
        // GET renders the form (IP + root password); POST validates,
        // stashes to a server-side session keyed by HttpOnly cookie,
        // and 303s to the step-2 stub. Sub-iter 4b will replace the
        // step-2 stub with the SSE-streamed bootstrap log.
        .route("/admin/servers/new", get(admin::wizard_new))
        .route("/admin/servers/new/", get(admin::wizard_new))
        .route("/admin/servers/new", post(admin::wizard_new_submit))
        .route("/admin/servers/new/", post(admin::wizard_new_submit))
        .route("/admin/servers/new/step-2", get(admin::wizard_step2_stub))
        .route("/admin/servers/new/step-2/", get(admin::wizard_step2_stub))
        // Phase E sub-iter 4b — SSE source for the step-2 page.
        // EventSource attaches here, the daemon streams BootstrapEvents
        // as named SSE events (step / ok / error). Single-shot:
        // the handler consumes the wizard session on attach (refresh
        // falls back to a "session missing" page with a "start over"
        // link). See `wizard_step2_sse` + `crate::wizard_bootstrap`
        // for the pipeline.
        .route(
            "/admin/servers/new/step-2/sse",
            get(admin::wizard_step2_sse),
        )
        .route("/admin/users", get(admin::users))
        .route("/admin/users/", get(admin::users))
        // Phase C-3.2: web add-user form posts here. Form has one
        // field (`id`); the rest of the user (UUID, tuic_password,
        // sub_token) is minted server-side.
        .route("/admin/users", post(admin::user_create))
        .route("/admin/users/", post(admin::user_create))
        // User detail: `/admin/users/<id>` (with and without trailing
        // slash). Path param doesn't capture an empty segment, so
        // `/admin/users/` continues to hit the list above.
        .route("/admin/users/{id}", get(admin::user_detail))
        .route("/admin/users/{id}/", get(admin::user_detail))
        // ui-audit §3-§4 — user_detail split into 5 sub-route tabs.
        // Explicit routes; bare `/admin/users/{id}` + `/overview` render
        // the overview tab. Existing GET sub-paths (delete-confirm,
        // wireguard/conf/{sid}, deploy-all/sse) can't collide.
        .route("/admin/users/{id}/overview", get(admin::user_detail))
        .route(
            "/admin/users/{id}/delivery",
            get(admin::user_detail_delivery),
        )
        .route("/admin/users/{id}/access", get(admin::user_detail_access))
        .route("/admin/users/{id}/access.csv", get(admin::user_access_csv))
        // R2 polish — the pending-deploy banner's button deploys ONLY
        // the pending set (was the fleet-wide deploy-all). GET because
        // EventSource can't POST; guarded in-handler by the same
        // Sec-Fetch-Site predicate as the other SSE deploy triggers.
        .route(
            "/admin/users/{id}/deploy-pending/sse",
            get(admin::user_deploy_pending_sse),
        )
        .route(
            "/admin/users/{id}/activity",
            get(admin::user_detail_activity),
        )
        .route("/admin/users/{id}/traffic", get(admin::user_detail_traffic))
        // Phase C-3 writes (Users). Each write goes via POST so a casual
        // GET (link preview, prefetch, search-bot) cannot mutate state.
        .route(
            "/admin/users/{id}/sub-token/regenerate",
            post(admin::user_regen_sub_token),
        )
        // Mint a per-user tuic_password for a user that has none. naive +
        // Hysteria2 reuse this field, so without it those protocols
        // silently drop from the user's subscription (cdn 2026-06-07).
        .route(
            "/admin/users/{id}/tuic-password/mint",
            post(admin::user_mint_tuic_password),
        )
        // Rotate the WireGuard keypair. Both halves replaced
        // atomically; previous pubkey will fall off the server's
        // [Peer] block on the next `vpnctl deploy`. UI lives on
        // the user-detail page (see `WireGuard keypair` section).
        .route(
            "/admin/users/{id}/wireguard/regenerate",
            post(admin::user_regen_wireguard),
        )
        // Download a drag-drop-ready WG `.conf` file for this
        // (user, server) pair. Works in EVERY WG client — official
        // WG app, Hiddify, AmneziaVPN's "File with settings"
        // picker. Universal fallback even when neither
        // `wireguard://?conf=` (Flow B) nor `vpn://...` (Flow C)
        // is what the recipient's app expects.
        .route(
            "/admin/users/{id}/wireguard/conf/{server_id}",
            get(admin::user_wireguard_conf_download),
        )
        // Pavel iter D.6c — per-user monthly bandwidth cap +
        // alert threshold. POST takes limit_gib + threshold_pct;
        // 0 / empty / non-numeric limit clears the cap.
        .route(
            "/admin/users/{id}/traffic-limit",
            post(admin::user_set_traffic_limit),
        )
        // Phase C-3.3: per-(user, server) grant + revoke. Both POST (HTML
        // forms can't easily DELETE), both idempotent at the SQL layer
        // but audited every time so re-grant attempts show in the
        // timeline. The `/revoke` suffix keeps URL routing
        // unambiguous: `…/grants/{id}` = grant, `…/grants/{id}/revoke`
        // = revoke. Same path-param tuple `(user_id, server_id)`.
        .route(
            "/admin/users/{id}/grants/{server_id}",
            post(admin::user_grant_server),
        )
        .route(
            "/admin/users/{id}/grants/{server_id}/revoke",
            post(admin::user_revoke_server),
        )
        // Phase C-3.4 — destructive: GET shows a double-submit confirm
        // form, POST deletes only if `confirm=<exact-id>` matches.
        .route(
            "/admin/users/{id}/delete-confirm",
            get(admin::user_delete_confirm),
        )
        .route("/admin/users/{id}/delete", post(admin::user_delete))
        // B2 (audit 2026-05-22, shipped 2026-05-23) — bulk
        // grant / revoke on a server detail page. Grant-all
        // is safe (idempotent, reversible per user) → no
        // confirm. Revoke-all is destructive (operator might
        // mass-disable access by mistake) → double-submit
        // confirm via the same shape as user delete.
        .route(
            "/admin/servers/{id}/grants/_grant-all",
            post(admin::server_grant_all_users),
        )
        .route(
            "/admin/servers/{id}/grants/_revoke-all",
            post(admin::server_revoke_all_users),
        )
        // B1.user — soft suspend / restore.  Disabled users get an
        // empty sub config (see sub.rs / vpn_router.rs) until
        // re-enabled. Idempotent: re-POSTing same target state is
        // a no-op redirect.
        .route(
            "/admin/users/{id}/disable",
            post(admin::user_set_disabled_true),
        )
        .route(
            "/admin/users/{id}/enable",
            post(admin::user_set_disabled_false),
        )
        // A5 (audit 2026-05-22, shipped 2026-05-23) — fleet-wide
        // search across users / servers / alerts. See handler doc
        // for why audit isn't part of the same surface.
        .route("/admin/search", get(admin::search))
        .route("/admin/audit", get(admin::audit))
        .route("/admin/audit/", get(admin::audit))
        // Phase D — CSV export uses the same filter query string as
        // the HTML timeline. Distinct path so browsers + curl can
        // hit it directly without a form submission.
        .route("/admin/audit.csv", get(admin::audit_csv))
        // Phase G — operator-facing alerts feed + ack action. The
        // dashboard tile links to /admin/alerts; ack POST is per-id.
        .route("/admin/alerts", get(admin::alerts))
        .route("/admin/alerts/", get(admin::alerts))
        .route("/admin/alerts/{id}/ack", post(admin::alert_ack))
        .route("/admin/alerts/ack-all", post(admin::alert_ack_all))
        .route(
            "/admin/alerts/ack-family/{prefix}",
            post(admin::alert_ack_family),
        )
        .route("/admin/settings", get(admin::settings))
        .route("/admin/settings/", get(admin::settings))
        // ui-audit §5 Phase 3 — settings split into 4 sub-route tabs.
        // Explicit routes; bare `/admin/settings` + `/appearance` render
        // the appearance tab. Existing POST sub-paths (telegram, timezone,
        // geoip/update-now, digest-now, notification-language) can't collide.
        .route("/admin/settings/appearance", get(admin::settings))
        .route("/admin/settings/backups", get(admin::settings_backups))
        .route(
            "/admin/settings/notifications",
            get(admin::settings_notifications),
        )
        .route("/admin/settings/system", get(admin::settings_system))
        // Boosty subscription bridge.
        .route("/admin/boosty", get(admin::boosty_page))
        .route("/admin/boosty/settings", post(admin::boosty_settings_save))
        .route("/admin/boosty/sync", post(admin::boosty_sync_now))
        .route("/admin/boosty/link", post(admin::boosty_link))
        .route("/admin/boosty/unlink/{user}", post(admin::boosty_unlink))
        .route("/admin/boosty/disable/{user}", post(admin::boosty_disable))
        // 2026-05-23 — operator-configurable display TZ. POST writes
        // inventory + invalidates the global cache so subsequent
        // page renders use the new zone immediately.
        .route(
            "/admin/settings/timezone",
            post(admin::settings_timezone_set),
        )
        // Phase 3c — Settings GeoIP «update now» SSE source. Streams
        // the live stdout/stderr of `vpnctl geoip-update` as named
        // SSE events (step / ok / error). GET because EventSource
        // only does GET; the action is idempotent (no state mutation
        // beyond the disk file the subprocess writes itself + an
        // audit row). See `geoip_update_runner` for the subprocess
        // pattern (std::process::Command, NOT tokio::process —
        // glibc-2.39 hazard explained in the module doc).
        .route(
            "/admin/settings/geoip/update-now",
            get(admin::settings_geoip_update_now_sse),
        )
        // Phase G chunk 3 — Telegram bot config POST. Singleton row;
        // empty inputs = clear/disable. CSRF middleware (Origin check)
        // runs ahead of this, so a cross-origin form-post can't write.
        .route("/admin/settings/telegram", post(admin::settings_telegram))
        // Notification-normalization — operator-selectable alert language
        // (ru / en). Drives render_alert at push time.
        .route(
            "/admin/settings/notification-language",
            post(admin::settings_notification_language),
        )
        // On-demand fleet digest (the daily scheduler sends it too).
        .route(
            "/admin/settings/digest-now",
            post(admin::settings_digest_now),
        )
        // Phase G chunk 3 part 2 — synchronous test-send so the
        // operator can verify credentials without waiting for an
        // actual alert. Surfaces curl/API errors as 502.
        .route(
            "/admin/settings/telegram/test",
            post(admin::settings_telegram_test),
        )
        // Phase G chunk 3.5 follow-up — recovery action for servers
        // added without wizard (quick-add / migrate-from-bash). One-
        // shot password-auth SSH + pubkey append; same logic as
        // wizard step 3. See server_push_deploy_key doc-comment.
        .route(
            "/admin/servers/{id}/push-deploy-key",
            post(admin::server_push_deploy_key),
        )
        // Phase C-4 — manual snapshot trigger + per-file download.
        // Download is GET (so a normal `<a download>` works); snapshot
        // trigger is POST (it mutates filesystem state + writes an
        // audit row). Filename validation in the handler keeps `..`
        // and absolute paths out of the backup dir.
        .route("/admin/backup/snapshot", post(admin::backup_snapshot_now))
        .route("/admin/backup/download/{name}", get(admin::backup_download))
        // Phase 5c — restore self-test. POST runs `verify_snapshot`
        // against the latest local snapshot in a tempdir (no touch
        // to live inv.db) and renders an HTML report. URL is
        // bookmarkable so the operator can browser-back to a stale
        // report if they realise mid-investigation they wanted to
        // compare with the previous run.
        .route("/admin/backup/self-test", post(admin::backup_self_test))
        .route("/admin/tweak/{kind}", post(admin::set_tweak))
        // Pavel 2026-05-26: ends the «постоянно пароль ввожу» loop.
        // Session cookie is HttpOnly so JS can't clear it directly;
        // a server-side POST that emits `Max-Age=0` is the only way
        // to log out without nuking the entire browser profile.
        .route("/admin/logout", post(admin::logout))
        .nest_service("/admin/assets", ServeDir::new(&assets_dir))
        .with_state(state);

    // CSRF guard runs FIRST (outermost layer), so basic-auth never even
    // gets a chance to validate credentials on a cross-origin POST. This
    // also means the 403 lands without consuming the auth check, so an
    // attacker can't probe whether a given user/password combo is valid
    // via a CSRF flow.
    // `route_layer` (NOT `layer`) for the same anti-fingerprinting
    // reason as the auth layer below: `.layer()` wraps the router's
    // default 404 fallback, so a POST to any unrelated path (e.g.
    // /etc/passwd) returned `403 vpnctl admin: csrf — Origin (or
    // Referer) must match Host` + the Host/Origin/Referer dump —
    // identifying the backend as vpnctld. Caught by pre-monitoring
    // vuln scan 2026-05-20. `route_layer` confines the CSRF check
    // to matched admin routes; unmatched paths fall through to
    // axum's default 404 with no body.
    let with_csrf = with_admin.route_layer(axum::middleware::from_fn(
        crate::handlers::csrf::require_same_origin,
    ));

    // Security-headers layer for the admin tree. Defense-in-depth
    // against XSS (CSP), MIME-sniffing attacks (nosniff), clickjacking
    // (frame-ancestors / X-Frame-Options), and referrer leakage to
    // any external resource we might fetch (none today, but pre-pin).
    // Added 2026-05-18 per security audit. Notes:
    //   * `script-src 'self' 'unsafe-inline'` — we use inline `style=`
    //     attrs heavily (maud-generated). `unsafe-inline` for STYLE
    //     not SCRIPT — script is `'self'` only. No inline `<script>`
    //     today.
    //   * `connect-src 'self'` — pre-blocks future XSS attempts to
    //     exfil via fetch() to evil.com.
    //   * `frame-ancestors 'none'` is the modern equivalent of
    //     X-Frame-Options: DENY; we set both for old browsers.
    // All five `SetResponseHeaderLayer`s use `route_layer` so the
    // headers attach ONLY to responses from matched admin routes.
    // With `.layer()` the headers also flowed into axum's default
    // 404 fallback, producing a distinctive header fingerprint on
    // any unrelated path (CSP with `frame-ancestors 'none'; form-
    // action 'self'`, Permissions-Policy with the full sensor-deny
    // list, etc) — `curl -I http://192.168.0.236:18402/etc/passwd`
    // returned an HTML-admin-shaped 404 with admin-only response
    // headers. Caught by pre-monitoring vuln scan 2026-05-20.
    let with_security_headers = with_csrf
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::CONTENT_SECURITY_POLICY,
                axum::http::HeaderValue::from_static(
                    "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; \
                 font-src 'self' https://fonts.gstatic.com; \
                 connect-src 'self'; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'self'",
                ),
            ),
        )
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                axum::http::HeaderValue::from_static("nosniff"),
            ),
        )
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::X_FRAME_OPTIONS,
                axum::http::HeaderValue::from_static("DENY"),
            ),
        )
        // Referrer-Policy: SAME-ORIGIN, not no-referrer.
        //
        // The 2026-05-18 security-audit shipped `no-referrer` which
        // stripped Referer from EVERY outbound request — including
        // our own same-origin form POSTs. Combined with browsers
        // that send `Origin: null` for opaque-origin contexts
        // (privacy mode, sandboxed iframe, certain extensions), this
        // 100%-bricks the CSRF middleware: both Origin and Referer
        // are unusable → every POST/PUT/DELETE/PATCH gets blocked
        // with «Origin (or Referer) header required and must match
        // Host». Pavel hit this in prod 2026-05-19 and couldn't
        // mutate ANYTHING through /admin/*.
        //
        // `same-origin` keeps the privacy guarantee that nothing
        // leaks to external sites (admin tree doesn't link out
        // anyway) AND keeps Referer alive on our own POSTs so the
        // CSRF middleware's Origin→Referer fallback works.
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("same-origin"),
            ),
        )
        // `Permissions-Policy` deprecates Feature-Policy. Block every
        // sensor + device API we don't use (= all of them).
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::HeaderName::from_static("permissions-policy"),
                axum::http::HeaderValue::from_static(
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                 magnetometer=(), microphone=(), payment=(), usb=()",
                ),
            ),
        );

    match BasicAuth::from_env() {
        Ok(Some(auth)) => {
            // `route_layer` (NOT `layer`) so the auth challenge fires ONLY
            // on matched admin routes. With `.layer()` the middleware
            // wrapped axum's fallback too: every unrelated path (e.g.
            // `/etc/passwd`, `/`, `/foo`) reaching this router returned
            // `401 WWW-Authenticate: Basic realm="vpnctl admin"` —
            // identifying the backend as vpnctld to any probe. Caught by
            // pre-monitoring vuln scan 2026-05-20 (`curl
            // http://192.168.0.236:18402/etc/passwd` → 401 admin realm).
            //
            // `route_layer` leaves unmatched paths with axum's default
            // 404 (no body, no admin realm). Matched `/admin/*` routes
            // still get the auth check — same UX for legitimate operators,
            // no fingerprint leak for probes hitting random paths.
            with_security_headers.route_layer(axum::middleware::from_fn_with_state(
                auth,
                crate::handlers::auth::require_basic_auth,
            ))
        }
        // Auth intentionally unset (env vars missing/empty) — local-smoke
        // path. The startup gate (`assert_auth_safe_for_addr`) already
        // refused a non-loopback bind in this state, so reaching here
        // means a loopback bind where open admin is acceptable.
        Ok(None) => with_security_headers,
        // Malformed credential config (a `$argon2…` password that doesn't
        // parse). FAIL CLOSED — lock the admin tree behind a 503 rather
        // than fall through to an unauthenticated router. Unreachable on a
        // live daemon: the startup gate refuses to boot on this verdict.
        // Kept as a belt-and-braces guarantee that the router can NEVER be
        // built in a fail-open state (the pre-2026-06-04 bug).
        Err(e) => {
            tracing::error!(
                target = "vpnctld::auth",
                error = %e,
                "admin auth config malformed — locking admin tree (fail closed)"
            );
            with_security_headers.route_layer(axum::middleware::from_fn(
                crate::handlers::auth::deny_all_misconfigured,
            ))
        }
    }
}
