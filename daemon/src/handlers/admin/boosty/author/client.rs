use std::time::Duration;

use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct AuthorClient {
    base: Url,
    http: Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorIssue {
    Unavailable,
    Rejected(StatusCode),
    NotDispatched(StatusCode),
}

#[derive(Deserialize)]
struct Rejection {
    error: RejectionDetails,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RejectionDetails {
    #[serde(default)]
    not_dispatched: bool,
}

impl AuthorClient {
    pub(super) fn from_roster_url(roster_url: &str) -> Result<Self, AuthorIssue> {
        Self::with_timeout(roster_url, Duration::from_secs(4))
    }

    pub(super) fn with_timeout(roster_url: &str, timeout: Duration) -> Result<Self, AuthorIssue> {
        let mut base = Url::parse(roster_url).map_err(|_| AuthorIssue::Unavailable)?;
        if base.scheme() != "http"
            || base.host_str() != Some("127.0.0.1")
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(AuthorIssue::Unavailable);
        }
        base.set_query(None);
        base.set_fragment(None);
        let http = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(1))
            .timeout(timeout)
            .build()
            .map_err(|_| AuthorIssue::Unavailable)?;
        Ok(Self { base, http })
    }

    pub(super) async fn get<T: DeserializeOwned>(
        &self,
        path: &[&str],
        query: &impl Serialize,
    ) -> Result<T, AuthorIssue> {
        Self::send(self.http.get(self.url(path, true)?).query(query)).await
    }

    pub(super) async fn post<T: DeserializeOwned>(
        &self,
        path: &[&str],
        body: &impl Serialize,
    ) -> Result<T, AuthorIssue> {
        let body = serde_json::to_vec(body).map_err(|_| AuthorIssue::Unavailable)?;
        Self::send(
            self.http
                .post(self.url(path, false)?)
                .header("X-Boosty-Request", "1")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body),
        )
        .await
    }

    fn url(&self, path: &[&str], versioned: bool) -> Result<Url, AuthorIssue> {
        let mut url = self.base.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| AuthorIssue::Unavailable)?;
            segments.clear().push("api");
            if versioned {
                segments.push("v1");
            }
            segments.extend(path.iter().copied());
        }
        Ok(url)
    }

    async fn send<T: DeserializeOwned>(request: RequestBuilder) -> Result<T, AuthorIssue> {
        let mut response = request.send().await.map_err(|_| AuthorIssue::Unavailable)?;
        let status = response.status();
        if status != StatusCode::OK && !status.is_client_error() && !status.is_server_error() {
            return Err(AuthorIssue::Rejected(status));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthorIssue::Unavailable)?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(AuthorIssue::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        if status != StatusCode::OK {
            return Err(
                if serde_json::from_slice::<Rejection>(&body)
                    .is_ok_and(|rejection| rejection.error.not_dispatched)
                {
                    AuthorIssue::NotDispatched(status)
                } else {
                    AuthorIssue::Rejected(status)
                },
            );
        }
        serde_json::from_slice(&body).map_err(|_| AuthorIssue::Unavailable)
    }
}
