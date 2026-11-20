use std::time::Duration;

use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct AuthorClient {
    base: Url,
    http: Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorIssue {
    Unavailable,
    Rejected(StatusCode),
}

impl AuthorClient {
    pub(super) fn from_roster_url(roster_url: &str) -> Result<Self, AuthorIssue> {
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
            .timeout(Duration::from_secs(4))
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
        if response.status() != StatusCode::OK {
            return Err(AuthorIssue::Rejected(response.status()));
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
        serde_json::from_slice(&body).map_err(|_| AuthorIssue::Unavailable)
    }
}
