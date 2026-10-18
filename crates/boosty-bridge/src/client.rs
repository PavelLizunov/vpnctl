use std::time::Duration;

use boosty_api::api_client::ApiClient;
use vpnctl_inventory::BoostySettings;

use crate::types::BridgeError;

pub(crate) const BOOSTY_BASE_URL: &str = "https://api.boosty.to";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn build_http_client() -> Result<reqwest::Client, BridgeError> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| BridgeError::Config(format!("building HTTP client failed: {e}")))
}

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

pub async fn build_bearer_client(
    access_token: &str,
    base_url: &str,
) -> Result<ApiClient, BridgeError> {
    let http = build_http_client()?;
    let client = ApiClient::new(http, base_url);
    client.set_bearer_token(access_token).await?;
    Ok(client)
}

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
