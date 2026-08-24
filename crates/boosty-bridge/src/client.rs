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

/// Build an authenticated Boosty [`ApiClient`] from bridge settings.
///
/// Prefers the refresh flow (refresh token + device id): access tokens
/// expire within ~an hour, so with both credentials configured a static
/// token would kill the bridge on its first expiry. Falls back to the
/// static bearer token; errors if neither is configured.
///
/// `base_url` is the API root (production callers pass [`BOOSTY_BASE_URL`]
/// via [`sync_from_settings`](crate::sync_from_settings); tests point it at a mock server).
pub async fn build_client(
    settings: &BoostySettings,
    base_url: &str,
) -> Result<ApiClient, BridgeError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| BridgeError::Config(format!("building HTTP client failed: {e}")))?;
    let client = ApiClient::new(http, base_url);

    if let (Some(refresh), Some(device)) = (
        settings.refresh_token.as_deref(),
        settings.device_id.as_deref(),
    ) && !refresh.is_empty()
        && !device.is_empty()
    {
        client
            .set_refresh_token_and_device_id(refresh, device)
            .await?;
        return Ok(client);
    }

    if let Some(token) = settings.access_token.as_deref()
        && !token.is_empty()
    {
        client.set_bearer_token(token).await?;
        return Ok(client);
    }

    Err(BridgeError::Config(
        "no Boosty credentials set (need a refresh token + device id, or an access token)".into(),
    ))
}
