use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::Markup;

use super::render::server_detail_render;
use super::types::{ServerDetailQuery, ServerTab};
use crate::AppState;

// Thin axum handlers — one per tab route in app.rs. Bare
// `/admin/servers/{id}` (+ trailing slash) + `/status` both land here.
pub(crate) async fn server_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Status).await
}

pub(crate) async fn server_detail_activity(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Activity).await
}

pub(crate) async fn server_detail_protocols_tab(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Protocols).await
}

pub(crate) async fn server_detail_grants_tab(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Grants).await
}

pub(crate) async fn server_detail_setup(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Setup).await
}
