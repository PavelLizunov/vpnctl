//! Axum route handlers for the user-detail admin page and its sub-tabs.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::Markup;

use super::render::user_detail_render;
use super::types::{UserDetailQuery, UserTab};
use crate::AppState;

// Thin axum handlers — one per tab route in app.rs. Bare
// `/admin/users/{id}` (+ trailing slash) + `/overview` both land here.
pub(crate) async fn user_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Overview).await
}

pub(crate) async fn user_detail_delivery(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Delivery).await
}

pub(crate) async fn user_detail_access(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Access).await
}

pub(crate) async fn user_detail_activity(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Activity).await
}

pub(crate) async fn user_detail_traffic(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Traffic).await
}
