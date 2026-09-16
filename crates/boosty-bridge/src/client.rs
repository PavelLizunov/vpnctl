//! Boosty API client construction and HTTP configuration.

use std::time::Duration;

use boosty_api::api_client::ApiClient;
use vpnctl_inventory::BoostySettings;

use crate::types::BridgeError;

/// Boosty API base URL.
pub(crate) const BOOSTY_BASE_URL: &str = "https://api.boosty.to";

/// Connection / total-request timeouts for the HTTP client. Token refresh
/// holds the client's internal auth mutex across the network call (see
/// boosty_api docs), so a client WITHOUT timeouts turns one hung connection
/// into a permanently stuck poller and a hanging /admin/boosty page.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn build_http_client() -> Result<reqwest::Client, BridgeError> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| BridgeError::Config(format!("building HTTP client failed: {e}")))
}

/// Build an authenticated Boosty [`ApiClient`] from bridge settings.
///
/// Uses Bearer-first flow: if an `access_token` is present, it is used directly
/// to avoid immediate, unnecessary token refresh requests that fail with `invalid_grant`
/// if the browser session rotated the refresh token. Falls back to refresh-token flow
/// if only refresh credentials are set.
///
/// `base_url` is the API root (production callers pass [`BOOSTY_BASE_URL`]
/// via [`sync_from_settings`](crate::sync_from_settings); tests point it at a mock server).
pub async fn build_client(
    settings: &BoostySettings,
    base_url: &str,
) -> Result<ApiClient, BridgeError> {
    if let Some(token) = settings.access_token.as_deref()
        && !token.is_empty()
    {
        return build_bearer_client(token, base_url).await;
    }

    if let (Some(refresh), Some(device)) = (
        settings.refresh_token.as_deref(),
        settings.device_id.as_deref(),
    ) && !refresh.is_empty()
        && !device.is_empty()
    {
        return build_refresh_client(refresh, device, base_url).await;
    }

    Err(BridgeError::Config(
        "no Boosty credentials set (need an access token, or a refresh token + device id)".into(),
    ))
}

/// Build a Bearer-authenticated [`ApiClient`].
pub async fn build_bearer_client(
    access_token: &str,
    base_url: &str,
) -> Result<ApiClient, BridgeError> {
    let http = build_http_client()?;
    let client = ApiClient::new(http, base_url);
    client.set_bearer_token(access_token).await?;
    Ok(client)
}

/// Build a refresh-flow authenticated [`ApiClient`].
pub async fn build_refresh_client(
    refresh_token: &str,
    device_id: &str,
    base_url: &str,
) -> Result<ApiClient, BridgeError> {
    let http = build_http_client()?;
    let client = ApiClient::new(http, base_url);
    client
        .set_refresh_token_and_device_id(refresh_token, device_id)
        .await?;
    Ok(client)
}
