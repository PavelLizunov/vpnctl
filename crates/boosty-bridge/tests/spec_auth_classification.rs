use boosty_api::error::{ApiError, AuthError};
use reqwest::StatusCode;
use vpnctl_boosty_bridge::BridgeError;

#[test]
fn direct_auth_error_is_an_auth_failure() {
    let error = BridgeError::Auth(AuthError::InvalidTokenFormat);

    assert!(error.is_auth_failure());
}

#[test]
fn nested_invalid_grant_refresh_error_is_an_auth_failure() {
    let error = BridgeError::Api(ApiError::Auth(AuthError::HttpStatus {
        status: StatusCode::BAD_REQUEST,
        body: r#"{"error":"invalid_grant"}"#.into(),
    }));

    assert!(error.is_auth_failure());
}

#[test]
fn unauthorized_api_error_is_an_auth_failure() {
    let error = BridgeError::Api(ApiError::Unauthorized);

    assert!(error.is_auth_failure());
}

#[test]
fn nested_refresh_http_500_is_not_an_auth_failure() {
    let error = BridgeError::Api(ApiError::Auth(AuthError::HttpStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "temporary upstream failure".into(),
    }));

    assert!(!error.is_auth_failure());
}

#[test]
fn nested_refresh_parse_error_is_not_an_auth_failure() {
    let error = BridgeError::Api(ApiError::Auth(AuthError::ParseError(
        serde_json::Error::io(std::io::Error::other("invalid response")),
    )));

    assert!(!error.is_auth_failure());
}

#[test]
fn non_auth_api_error_is_not_an_auth_failure() {
    let error = BridgeError::Api(ApiError::Other("temporary upstream failure".into()));

    assert!(!error.is_auth_failure());
}

#[test]
fn config_error_is_not_an_auth_failure() {
    let error = BridgeError::Config("missing blog URL".into());

    assert!(!error.is_auth_failure());
}
