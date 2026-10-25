use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
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

pub fn router(state: AppState) -> Router {
    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        let matched = req
            .extensions()
            .get::<MatchedPath>()
            .map_or("<unknown>", MatchedPath::as_str);
        info_span!("http", method = %req.method(), path = matched)
    });

    let admin_router = admin_router(state.clone());

    let public_router = Router::new()
        .route("/api/v1/health", get(handlers::health::get))
        .route("/sub/{token}", get(handlers::sub::get))
        .route("/api/v1/sub/{token}", get(handlers::sub::get_mihomo))
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
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
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
        .layer(RequestBodyLimitLayer::new(8 * 1024))
        .layer(trace_layer)
}

pub(crate) fn admin_assets_dir() -> PathBuf {
    [
        PathBuf::from("assets"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets"),
        PathBuf::from("daemon/assets"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| PathBuf::from("daemon/assets"))
}

pub(super) fn validate_admin_assets(dir: &Path) -> anyhow::Result<()> {
    for name in ["admin.js", "admin.css", "icons.svg", "favicon.svg"] {
        let path = dir.join(name);
        let file = std::fs::File::open(&path).with_context(|| {
            format!(
                "vpnctld refuses to start: required admin asset {} is missing or unreadable",
                path.display()
            )
        })?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "vpnctld refuses to start: required admin asset {} is not a regular file",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn admin_router(state: AppState) -> Router {
    use crate::handlers::admin;

    let assets_dir = admin_assets_dir();
    let auth = BasicAuth::from_env(&state.admin_session_secret);

    let with_admin = Router::new()
        .route(
            "/api/v1/stats/sub-access",
            get(handlers::stats::sub_access).layer(
                tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                    axum::http::header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("no-store"),
                ),
            ),
        )
        .route("/admin", get(admin::dashboard))
        .route("/admin/", get(admin::dashboard))
        .route("/admin/overview", get(admin::dashboard))
        .route("/admin/activity", get(admin::dashboard_activity))
        .route("/admin/sharing", get(admin::sharing))
        .route("/admin/sharing/", get(admin::sharing))
        .route("/admin/monitoring", get(admin::monitoring))
        .route("/admin/monitoring/", get(admin::monitoring))
        .route(
            "/admin/monitoring/probe-all",
            post(admin::monitoring_probe_all),
        )
        .route("/admin/servers", get(admin::servers))
        .route("/admin/servers/", get(admin::servers))
        .route("/admin/servers/billing", get(admin::servers_billing))
        .route("/admin/servers/billing/", get(admin::servers_billing))
        .route(
            "/admin/servers/billing/settings",
            post(admin::billing_update_settings),
        )
        .route(
            "/admin/servers/billing/refresh-rates",
            post(admin::billing_refresh_rates),
        )
        .route(
            "/admin/servers/{id}/billing",
            post(admin::server_set_billing),
        )
        .route(
            "/admin/servers/{id}/billing/advance",
            post(admin::server_advance_billing),
        )
        .route("/admin/servers/{id}", get(admin::server_detail))
        .route("/admin/servers/{id}/", get(admin::server_detail))
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
            get(admin::server_detail_grants_tab).post(admin::server_grant_user_form),
        )
        .route("/admin/servers/{id}/setup", get(admin::server_detail_setup))
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
        .route(
            "/admin/servers/{id}/display-name",
            post(admin::server_set_display_name),
        )
        .route(
            "/admin/servers/{id}/naive-config",
            post(admin::server_set_naive_config),
        )
        .route(
            "/admin/servers/{id}/vlessws-config",
            post(admin::server_set_vlessws_config),
        )
        .route(
            "/admin/servers/{id}/reality-config",
            post(admin::server_set_reality_config),
        )
        .route(
            "/admin/servers/{id}/hysteria2-obfs-rotate",
            post(admin::server_rotate_hysteria2_obfs),
        )
        .route(
            "/admin/servers/{id}/auto-suppress",
            post(admin::server_set_auto_suppress),
        )
        .route(
            "/admin/servers/{id}/udp-pair",
            post(admin::server_set_udp_pair),
        )
        .route(
            "/admin/servers/{id}/delete-confirm",
            get(admin::server_delete_confirm),
        )
        .route("/admin/servers/{id}/delete", post(admin::server_delete))
        .route(
            "/admin/servers/{id}/reserved-ports",
            post(admin::server_set_reserved_ports),
        )
        .route("/admin/servers/quick-add", post(admin::server_quick_add))
        .route("/admin/sse-ticket", post(admin::sse_ticket))
        .route("/admin/servers/{id}/deploy", post(admin::server_deploy))
        .route(
            "/admin/servers/{id}/deploy/sse",
            get(admin::server_deploy_sse),
        )
        .route(
            "/admin/servers/deploy-all/sse",
            get(admin::servers_deploy_all_sse),
        )
        .route(
            "/admin/servers/{id}/update-kernels/sse",
            get(admin::server_update_kernels_sse),
        )
        .route(
            "/admin/servers/update-kernels-all/sse",
            get(admin::servers_update_kernels_all_sse),
        )
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
        .route(
            "/admin/servers/{sid}/grants/{uid}",
            post(admin::server_grant_user),
        )
        .route(
            "/admin/servers/{sid}/grants/{uid}/revoke",
            post(admin::server_revoke_user),
        )
        .route(
            "/admin/servers/{id}/protocols/{proto}/enable",
            post(admin::server_enable_protocol),
        )
        .route(
            "/admin/servers/{id}/protocols/{proto}/disable",
            post(admin::server_disable_protocol),
        )
        .route(
            "/admin/servers/{id}/kernels/{kernel}/enable",
            post(admin::server_enable_kernel),
        )
        .route(
            "/admin/servers/{id}/kernels/{kernel}/disable",
            post(admin::server_disable_kernel),
        )
        .route("/admin/servers/new", get(admin::wizard_new))
        .route("/admin/servers/new/", get(admin::wizard_new))
        .route("/admin/servers/new", post(admin::wizard_new_submit))
        .route("/admin/servers/new/", post(admin::wizard_new_submit))
        .route("/admin/servers/new/step-2", get(admin::wizard_step2_stub))
        .route("/admin/servers/new/step-2/", get(admin::wizard_step2_stub))
        .route(
            "/admin/servers/new/step-2/sse",
            get(admin::wizard_step2_sse),
        )
        .route("/admin/users", get(admin::users))
        .route("/admin/users/", get(admin::users))
        .route("/admin/users", post(admin::user_create))
        .route("/admin/users/", post(admin::user_create))
        .route("/admin/users/{id}", get(admin::user_detail))
        .route("/admin/users/{id}/", get(admin::user_detail))
        .route("/admin/users/{id}/overview", get(admin::user_detail))
        .route(
            "/admin/users/{id}/delivery",
            get(admin::user_detail_delivery),
        )
        .route("/admin/users/{id}/access", get(admin::user_detail_access))
        .route("/admin/users/{id}/access.csv", get(admin::user_access_csv))
        .route(
            "/admin/users/{id}/deploy-pending/sse",
            get(admin::user_deploy_pending_sse),
        )
        .route(
            "/admin/users/{id}/activity",
            get(admin::user_detail_activity),
        )
        .route("/admin/users/{id}/traffic", get(admin::user_detail_traffic))
        .route(
            "/admin/users/{id}/sub-token/regenerate",
            post(admin::user_regen_sub_token),
        )
        .route(
            "/admin/users/{id}/tuic-password/mint",
            post(admin::user_mint_tuic_password),
        )
        .route(
            "/admin/users/{id}/wireguard/regenerate",
            post(admin::user_regen_wireguard),
        )
        .route(
            "/admin/users/{id}/wireguard/conf/{server_id}",
            get(admin::user_wireguard_conf_download),
        )
        .route(
            "/admin/users/{id}/amneziawg/{version}/conf/{server_id}",
            get(admin::user_amneziawg_conf_download),
        )
        .route(
            "/admin/users/{id}/traffic-limit",
            post(admin::user_set_traffic_limit),
        )
        .route(
            "/admin/users/{id}/grants/{server_id}",
            post(admin::user_grant_server),
        )
        .route(
            "/admin/users/{id}/grants/{server_id}/revoke",
            post(admin::user_revoke_server),
        )
        .route(
            "/admin/users/{id}/delete-confirm",
            get(admin::user_delete_confirm),
        )
        .route("/admin/users/{id}/delete", post(admin::user_delete))
        .route(
            "/admin/servers/{id}/grants/_grant-all",
            post(admin::server_grant_all_users),
        )
        .route(
            "/admin/servers/{id}/grants/_revoke-all",
            post(admin::server_revoke_all_users),
        )
        .route(
            "/admin/users/{id}/disable",
            post(admin::user_set_disabled_true),
        )
        .route(
            "/admin/users/{id}/enable",
            post(admin::user_set_disabled_false),
        )
        .route("/admin/search", get(admin::search))
        .route("/admin/audit", get(admin::audit))
        .route("/admin/audit/", get(admin::audit))
        .route("/admin/audit.csv", get(admin::audit_csv))
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
        .route("/admin/settings/appearance", get(admin::settings))
        .route("/admin/settings/backups", get(admin::settings_backups))
        .route(
            "/admin/settings/notifications",
            get(admin::settings_notifications),
        )
        .route("/admin/settings/system", get(admin::settings_system))
        .route("/admin/boosty", get(admin::boosty_page))
        .route("/admin/boosty/settings", post(admin::boosty_settings_save))
        .route("/admin/boosty/sync", post(admin::boosty_sync_now))
        .route("/admin/boosty/link", post(admin::boosty_link))
        .route("/admin/boosty/unlink/{user}", post(admin::boosty_unlink))
        .route("/admin/boosty/disable/{user}", post(admin::boosty_disable))
        .route(
            "/admin/settings/timezone",
            post(admin::settings_timezone_set),
        )
        .route(
            "/admin/settings/public-url",
            post(admin::settings_public_url_set),
        )
        .route(
            "/admin/settings/geoip/update-now",
            get(admin::settings_geoip_update_now_sse),
        )
        .route("/admin/settings/telegram", post(admin::settings_telegram))
        .route(
            "/admin/settings/notification-language",
            post(admin::settings_notification_language),
        )
        .route(
            "/admin/settings/digest-now",
            post(admin::settings_digest_now),
        )
        .route(
            "/admin/settings/telegram/test",
            post(admin::settings_telegram_test),
        )
        .route(
            "/admin/servers/{id}/push-deploy-key",
            post(admin::server_push_deploy_key),
        )
        .route("/admin/backup/snapshot", post(admin::backup_snapshot_now))
        .route("/admin/backup/download/{name}", get(admin::backup_download))
        .route("/admin/backup/self-test", post(admin::backup_self_test))
        .route("/admin/tweak/{kind}", post(admin::set_tweak))
        .route("/admin/logout", post(admin::logout))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin::html_error_pages,
        ))
        .nest_service(
            "/admin/assets",
            tower::ServiceBuilder::new()
                .layer(axum::middleware::from_fn(
                    crate::handlers::admin::asset_cache_control,
                ))
                .service(ServeDir::new(assets_dir)),
        )
        .with_state(state);

    let with_csrf = with_admin.route_layer(axum::middleware::from_fn(
        crate::handlers::csrf::require_same_origin,
    ));

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
                 object-src 'none'; \
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
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("same-origin"),
            ),
        )
        .route_layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::HeaderName::from_static("permissions-policy"),
                axum::http::HeaderValue::from_static(
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                 magnetometer=(), microphone=(), payment=(), usb=()",
                ),
            ),
        );

    match auth {
        Ok(Some(auth)) => with_security_headers.route_layer(axum::middleware::from_fn_with_state(
            auth,
            crate::handlers::auth::require_basic_auth,
        )),
        Ok(None) => with_security_headers,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_admin_assets_accepts_complete_directory_and_rejects_directory_as_file() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["admin.js", "admin.css", "icons.svg", "favicon.svg"] {
            std::fs::write(dir.path().join(name), "test asset").unwrap();
        }
        validate_admin_assets(dir.path()).unwrap();

        let js = dir.path().join("admin.js");
        std::fs::remove_file(&js).unwrap();
        std::fs::create_dir(&js).unwrap();
        let err = validate_admin_assets(dir.path()).unwrap_err().to_string();
        assert!(err.contains("admin.js"), "{err}");
    }
}
