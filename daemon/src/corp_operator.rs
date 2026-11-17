//! Authenticated operator controls for independent corporate subscriptions.
use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use tower::ServiceExt;

use crate::{AppState, handlers::auth::BasicAuth};
mod actions;
mod credentials;
mod views;

type Failure = Box<Response>;
type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone)]
pub struct OperatorConfig {
    auth: Option<BasicAuth>,
    origin: Option<String>,
    authority: Option<String>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl std::fmt::Debug for OperatorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorConfig([redacted])")
    }
}

impl OperatorConfig {
    pub fn from_parts(
        user: Option<String>,
        password: Option<String>,
        origin: Option<String>,
        install_secret: &str,
    ) -> Self {
        let origin = origin.filter(|raw| {
            let Ok(url) = url::Url::parse(raw) else {
                return false;
            };
            url.scheme() == "https"
                && url.host_str().is_some_and(|host| !host.is_empty())
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.origin().ascii_serialization() == *raw
                && raw != "https://admin.corp.ninitux.com"
        });
        let authority = origin.as_ref().map(|value| value[8..].to_owned());
        Self {
            auth: BasicAuth::from_parts(user, password, install_secret)
                .ok()
                .flatten(),
            origin,
            authority,
            clock: Arc::new(|| chrono::Utc::now().timestamp()),
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }
}

#[derive(Clone)]
struct OperatorState {
    app: AppState,
    config: OperatorConfig,
}

pub(crate) fn isolate(legacy: Router, app: AppState, config: OperatorConfig) -> Router {
    let canonical_origin = config.origin.clone();
    let canonical_authority = config.authority.clone();
    let operator = Router::new()
        .fallback(handle)
        .with_state(OperatorState { app, config })
        .layer(tower_http::limit::RequestBodyLimitLayer::new(8192))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ));
    Router::new().fallback_service(tower::service_fn(move |request: Request| {
        let legacy = legacy.clone();
        let operator = operator.clone();
        let canonical_origin = canonical_origin.clone();
        let canonical_authority = canonical_authority.clone();
        async move {
            let path = request.uri().path();
            if (path == "/admin" || path.starts_with("/admin/"))
                && let (Some(origin), Some(authority)) = (canonical_origin.as_deref(), canonical_authority.as_deref())
                && authority.ends_with(".ts.net")
                && let Some(short) = authority.split('.').next()
                && let Some(host) = request.headers().get("host").and_then(|value| value.to_str().ok())
                && (host.eq_ignore_ascii_case(short) || host.eq_ignore_ascii_case(&format!("{short}:80")) || host.eq_ignore_ascii_case(&format!("{authority}:80"))) {
                if request.headers().get_all("host").iter().count() != 1
                    || request.uri().authority().is_some_and(|value| !value.as_str().eq_ignore_ascii_case(host)) {
                    return Ok::<_, Infallible>(crate::corp_portal::secure(error(StatusCode::BAD_REQUEST, "Некорректный адрес запроса.")));
                }
                if request.method() == Method::GET || request.method() == Method::HEAD {
                    let target = format!("{origin}{}", request.uri().path_and_query().map_or("/admin/", |value| value.as_str()));
                    return Ok(crate::corp_portal::secure(axum::response::Redirect::permanent(&target).into_response()));
                }
                return Ok(crate::corp_portal::secure(error(StatusCode::FORBIDDEN, "Откройте панель через её защищённый HTTPS-адрес и повторите действие.")));
            }
            if path != "/admin/corp" && !path.starts_with("/admin/corp/") {
                return legacy.oneshot(request).await;
            }
            let response = operator.oneshot(request).await?;
            let response = match response.status() {
                StatusCode::PAYLOAD_TOO_LARGE => error(StatusCode::PAYLOAD_TOO_LARGE, "Слишком большой запрос."),
                StatusCode::REQUEST_TIMEOUT => error(StatusCode::REQUEST_TIMEOUT, "Ответ не получен вовремя. Обновите состояние перед новой операцией. Если пароль потерян, выполните новую ротацию."),
                _ => response,
            };
            Ok::<_, Infallible>(crate::corp_portal::secure(response))
        }
    }))
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, axum::response::Html(views::document("Операция не выполнена", &format!("<p>{}</p><p><a href=\"/admin/corp\">Загрузить текущее состояние</a></p><p>Перед повторной операцией проверьте состояние. Потерянный пароль можно заменить новой ротацией.</p>", views::escape(message))))).into_response()
}
fn fail(status: StatusCode) -> Failure {
    let message = match status {
        StatusCode::CONFLICT => {
            "Состояние изменилось или операция недоступна. Обновите страницу и проверьте результат перед повторной операцией."
        }
        StatusCode::NOT_FOUND => "Объект не найден.",
        StatusCode::UNAUTHORIZED => "Требуется вход оператора.",
        StatusCode::FORBIDDEN => {
            "Не удалось проверить источник запроса или защитный код. Обновите страницу."
        }
        StatusCode::UNPROCESSABLE_ENTITY => "Некорректные поля запроса.",
        StatusCode::BAD_REQUEST => "Некорректный адрес или неоднозначные заголовки запроса.",
        _ => "Операция временно недоступна. Обновите состояние перед повторной попыткой.",
    };
    let mut response = error(status, message);
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            "www-authenticate",
            HeaderValue::from_static("Basic realm=\"vpnctl admin\", charset=\"UTF-8\""),
        );
    }
    Box::new(response)
}
fn unavailable() -> Failure {
    fail(StatusCode::SERVICE_UNAVAILABLE)
}

async fn handle(
    axum::extract::State(state): axum::extract::State<OperatorState>,
    request: Request,
) -> Response {
    let result = process(&state, request).await;
    match result {
        Ok(mut response) => {
            if let Some(auth) = &state.config.auth
                && let Ok(cookie) = HeaderValue::from_str(&auth.operator_session_cookie())
            {
                response.headers_mut().append("set-cookie", cookie);
            }
            response
        }
        Err(error) => *error,
    }
}

async fn process(state: &OperatorState, request: Request) -> Result<Response> {
    let headers = request.headers();
    for name in [
        "host",
        "authorization",
        "cookie",
        "origin",
        "content-type",
        "sec-fetch-site",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(fail(StatusCode::BAD_REQUEST));
        }
        if headers
            .get(name)
            .is_some_and(|value| value.to_str().is_err())
        {
            return Err(fail(StatusCode::BAD_REQUEST));
        }
    }
    if let Some(cookie) = headers.get("cookie").and_then(|value| value.to_str().ok()) {
        let count = cookie
            .split(';')
            .filter(|part| {
                part.trim()
                    .split_once('=')
                    .is_some_and(|(name, _)| name == "vpnctl_admin_session")
            })
            .count();
        if count > 1 {
            return Err(fail(StatusCode::BAD_REQUEST));
        }
    }
    let auth = state.config.auth.as_ref().ok_or_else(unavailable)?;
    let origin = state.config.origin.as_deref().ok_or_else(unavailable)?;
    let authority = state.config.authority.as_deref().ok_or_else(unavailable)?;
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST))?;
    if !host.eq_ignore_ascii_case(authority)
        || request
            .uri()
            .authority()
            .is_some_and(|value| !value.as_str().eq_ignore_ascii_case(authority))
        || request
            .uri()
            .scheme_str()
            .is_some_and(|scheme| scheme != "https")
    {
        return Err(fail(StatusCode::BAD_REQUEST));
    }
    if !auth.authenticate_operator(headers).await {
        return Err(fail(StatusCode::UNAUTHORIZED));
    }
    if request.uri().query().is_some() {
        return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
    }
    if headers
        .get("sec-fetch-site")
        .is_some_and(|v| v == "cross-site")
    {
        return Err(fail(StatusCode::FORBIDDEN));
    }
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    if method == Method::GET {
        return match path.as_str() {
            "/admin/corp" => views::page(state).await,
            "/admin/corp/companies" => views::company_list(state).await,
            path if path.starts_with("/admin/corp/company/") => {
                let id = path.trim_start_matches("/admin/corp/company/");
                if id.is_empty()
                    || id.len() > 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                {
                    return Err(fail(StatusCode::NOT_FOUND));
                }
                views::page_for(state, id).await
            }
            "/admin/corp/assets/operator.css" => Ok((
                [("content-type", "text/css; charset=utf-8")],
                include_str!("../assets/corp-operator.css"),
            )
                .into_response()),
            _ if actions::known_path(&path) => Err(fail(StatusCode::METHOD_NOT_ALLOWED)),
            _ => Err(fail(StatusCode::NOT_FOUND)),
        };
    }
    if !actions::known_path(&path) {
        return Err(fail(StatusCode::NOT_FOUND));
    }
    if method != Method::POST || path == "/admin/corp" || path == "/admin/corp/assets/operator.css"
    {
        return Err(fail(StatusCode::METHOD_NOT_ALLOWED));
    }
    if headers.get("origin").and_then(|v| v.to_str().ok()) != Some(origin) {
        return Err(fail(StatusCode::FORBIDDEN));
    }
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type != "application/x-www-form-urlencoded"
        && content_type != "application/x-www-form-urlencoded; charset=UTF-8"
    {
        return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let bytes = axum::body::to_bytes(request.into_body(), 8192)
        .await
        .map_err(|_| fail(StatusCode::PAYLOAD_TOO_LARGE))?;
    let form = actions::Form::parse(&bytes)?;
    if !auth.verify_operator_csrf(origin, form.get("csrf")?, (state.config.clock)()) {
        return Err(fail(StatusCode::FORBIDDEN));
    }
    actions::perform(state, &path, &form).await
}
