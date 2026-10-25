use std::time::Duration;

use boosty_api::api_client::ApiClient;
use boosty_api::error::AuthError;
use vpnctl_inventory::{BoostySettings, SqliteInventory};

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

pub(crate) async fn build_persisted_refresh_client(
    inv: &SqliteInventory,
    refresh_token: &str,
    device_id: &str,
    base_url: &str,
) -> Result<ApiClient, BridgeError> {
    #[derive(serde::Deserialize)]
    struct RefreshedTokens {
        access_token: String,
        refresh_token: String,
    }

    let response = build_http_client()?
        .post(format!("{base_url}/oauth/token/"))
        .form(&[
            ("device_id", device_id),
            ("device_os", "web"),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .map_err(AuthError::HttpRequest)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(AuthError::HttpStatus {
            status: response.status(),
            body: String::new(),
        }
        .into());
    }
    let tokens: RefreshedTokens = response.json().await.map_err(AuthError::HttpRequest)?;
    if tokens.refresh_token != refresh_token
        && !inv
            .rotate_boosty_refresh_token(refresh_token, &tokens.refresh_token)
            .await?
    {
        tracing::info!(
            target = "boosty_bridge",
            "kept the Boosty refresh credential changed during this sync"
        );
    }
    // A bearer client cannot rotate credentials invisibly during roster pagination.
    build_bearer_client(&tokens.access_token, base_url).await
}
