mod telephony;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use vpnctl_inventory::{
    CorpPublication, CorpRecord, CorpRevision, CorpSession, CorpSessionInput, CorpStoreError,
};
use zeroize::Zeroizing;

use super::eligibility::eligible_servers;
use super::security::{self, equal_secret, now, single_header};
use super::{COOKIE, MAX_BODY, PortalState, SESSION_SECONDS, views};
use crate::AppState;
use crate::corp_policy::{
    PolicyPayload, PolicyRule, PolicySigningKey, normalize_site, seed_rules, validate_rules,
    verify_envelope,
};

type PortalResult<T> = Result<T, Box<Response>>;

pub(super) fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Не удалось получить правила. Попробуйте позже.",
    )
}
fn unauthorized() -> Response {
    error(StatusCode::UNAUTHORIZED, "Войдите снова, чтобы продолжить.")
}
fn invalid() -> Response {
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Проверьте адреса, маршруты и заметки.",
    )
}
fn conflict() -> Response {
    error(
        StatusCode::CONFLICT,
        "Правила или доступ изменились. Обновите список перед сохранением.",
    )
}

fn api_gate_error(response: Response) -> Response {
    match response.status() {
        StatusCode::FORBIDDEN => error(
            StatusCode::FORBIDDEN,
            "Подключите корпоративный VPN и обновите страницу.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => unavailable(),
        _ => response,
    }
}

fn store_error(error_value: &CorpStoreError) -> Response {
    match error_value {
        CorpStoreError::Conflict => conflict(),
        CorpStoreError::InvalidInput(_) => invalid(),
        _ => unavailable(),
    }
}

pub(super) async fn handle(State(state): State<PortalState>, request: Request) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if path == "/api/v1/corp/egress-observation" {
        return observation(&state.app, request).await;
    }
    if method == Method::GET {
        match path.as_str() {
            "/assets/corp.css" => {
                return (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    views::CSS,
                )
                    .into_response();
            }
            "/assets/corp-diagnostics.js" => {
                return (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    views::DIAGNOSTICS_JS,
                )
                    .into_response();
            }
            "/assets/corp-phone.js" => {
                return (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    views::PHONE_JS,
                )
                    .into_response();
            }
            "/assets/corp.js" => {
                return (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    views::JS,
                )
                    .into_response();
            }
            "/api/v1/corp/policy" => return reader(&state.app, request.headers(), false).await,
            "/api/v1/corp/policy/telephony" => {
                if request.uri().query().is_some() {
                    return invalid();
                }
                return reader(&state.app, request.headers(), true).await;
            }
            _ => {}
        }
    }
    let diagnostics_route = path == "/api/corp/reports" || path.starts_with("/api/corp/reports/");
    let phone_route = path == "/api/v1/corp/portal/telephony"
        || path.starts_with("/api/v1/corp/portal/telephony/");
    if !phone_route
        && !diagnostics_route
        && !matches!(
            path.as_str(),
            "/" | "/diagnostics"
                | "/login"
                | "/logout"
                | "/api/corp/state"
                | "/api/corp/normalize"
                | "/api/corp/rules"
                | "/api/corp/history"
                | "/api/corp/restore"
        )
    {
        return error(StatusCode::NOT_FOUND, "Страница не найдена.");
    }
    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip());
    if matches!(path.as_str(), "/" | "/diagnostics") && method == Method::GET {
        let record = match browser_access(&state.app, &headers, peer).await {
            Ok((record, _)) => record,
            Err(response) => return *response,
        };
        return if let Ok((_, current_session)) = session(&state.app, &headers, &record).await {
            Html(if path == "/diagnostics" {
                views::diagnostics(&current_session.csrf_token)
            } else {
                views::editor()
            })
            .into_response()
        } else {
            Html(views::login(None)).into_response()
        };
    }
    if path == "/login" && method == Method::POST {
        return login(&state, request, peer).await;
    }
    let context = match authorized(&state.app, &headers, peer).await {
        Ok(context) => context,
        Err(response) => return api_gate_error(*response),
    };
    if method == Method::POST {
        if !security::same_origin(&headers)
            || !single_header(&headers, "x-corp-csrf")
                .is_some_and(|value| equal_secret(value, &context.session.csrf_token))
        {
            return error(
                StatusCode::FORBIDDEN,
                "Не удалось проверить запрос. Обновите страницу.",
            );
        }
        if phone_route {
            return telephony::handle(&state.app, request, peer, context).await;
        }
        if diagnostics_route {
            return diagnostics_request(&state.app, request).await;
        }
        match path.as_str() {
            "/logout" => {
                if let Err(error_value) = state
                    .app
                    .inv
                    .revoke_corp_session(&context.session_hash, "corp.browser")
                    .await
                {
                    return store_error(&error_value);
                }
                return redirect(&format!(
                    "{COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
                ));
            }
            "/api/corp/normalize" => {
                let input: Normalize = match parse_json(request).await {
                    Ok(input) => input,
                    Err(response) => return *response,
                };
                let domain = match normalize_site(&input.site) {
                    Ok(domain) => domain,
                    Err(_) => return invalid(),
                };
                if validate_rules(&[PolicyRule {
                    domain: domain.clone(),
                    action: "direct".into(),
                    comment: String::new(),
                }])
                .is_err()
                {
                    return invalid();
                }
                return Json(json!({"domain": domain})).into_response();
            }
            "/api/corp/rules" => {
                let input: Publish = match parse_json(request).await {
                    Ok(input) => input,
                    Err(response) => return *response,
                };
                return publish(&state.app, &headers, peer, context.record, input).await;
            }
            "/api/corp/restore" => {
                let input: Restore = match parse_json(request).await {
                    Ok(input) => input,
                    Err(response) => return *response,
                };
                let prior = match state.app.inv.corp_revision(input.revision).await {
                    Ok(Some(prior)) => prior,
                    Ok(None) => return error(StatusCode::NOT_FOUND, "Эта версия уже недоступна."),
                    Err(error_value) => return store_error(&error_value),
                };
                let payload = match stored_payload(&prior, &context.record) {
                    Ok(payload) => payload,
                    Err(response) => return *response,
                };
                return publish(
                    &state.app,
                    &headers,
                    peer,
                    context.record,
                    Publish {
                        expected_revision: input.expected_revision,
                        apply: input.apply,
                        confirm_interrupt: input.confirm_interrupt,
                        rules: payload.rules,
                    },
                )
                .await;
            }
            _ => {}
        }
    } else if method == Method::GET {
        if phone_route {
            return telephony::handle(&state.app, request, peer, context).await;
        }
        if diagnostics_route {
            return diagnostics_request(&state.app, request).await;
        }
        match path.as_str() {
            "/api/corp/state" => {
                let (revision, rules) = match current_rules(&state.app, &context.record).await {
                    Ok(value) => value,
                    Err(response) => return *response,
                };
                return Json(json!({"revision": revision, "rules": rules, "csrf": context.session.csrf_token})).into_response();
            }
            "/api/corp/history" => {
                let rows = match state.app.inv.corp_history(100).await {
                    Ok(rows) => rows,
                    Err(error_value) => return store_error(&error_value),
                };
                let mut history = Vec::with_capacity(rows.len());
                for row in rows {
                    let payload = match stored_payload(&row, &context.record) {
                        Ok(payload) => payload,
                        Err(response) => return *response,
                    };
                    history.push(json!({"revision": row.revision, "published_at": row.published_at, "apply": payload.apply, "rule_count": payload.rules.len()}));
                }
                return Json(history).into_response();
            }
            _ => {}
        }
    }
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "Этот способ запроса не поддерживается.",
    )
}

async fn active_record(app: &AppState) -> PortalResult<CorpRecord> {
    let record = app
        .inv
        .corp_record()
        .await
        .map_err(|error_value| store_error(&error_value))?
        .ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, Html(views::unavailable())).into_response()
        })?;
    if !record.status.enabled
        || app
            .inv
            .get_user(&record.status.user_id)
            .await
            .map_err(|_| unavailable())?
            .is_none_or(|user| user.disabled)
    {
        return Err(Box::new(
            (StatusCode::SERVICE_UNAVAILABLE, Html(views::unavailable())).into_response(),
        ));
    }
    Ok(record)
}

async fn browser_access(
    app: &AppState,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> PortalResult<(CorpRecord, IpAddr)> {
    let record = active_record(app).await?;
    let trusted =
        peer.is_some_and(|ip| crate::real_ip::is_trusted_proxy(security::canonical_ip(ip)));
    let ip = security::resolve_client_ip(headers, peer, trusted);
    let denied = || (StatusCode::FORBIDDEN, Html(views::vpn_required(ip))).into_response();
    let ip = ip.ok_or_else(denied)?;
    let eligible = eligible_servers(app, &record.status.user_id)
        .await
        .map_err(|_| unavailable())?;
    let exits = app
        .inv
        .corp_verified_egress()
        .await
        .map_err(|error_value| store_error(&error_value))?;
    let current_time = now();
    if !exits.iter().any(|exit| {
        exit.ip == ip
            && exit.verified_at <= current_time
            && current_time - exit.verified_at <= 86_400
            && eligible.iter().any(|server| {
                server.server_id == exit.server_id
                    && server.configuration_fingerprint == exit.configuration_fingerprint
            })
    }) {
        return Err(Box::new(denied()));
    }
    Ok((record, ip))
}

async fn session(
    app: &AppState,
    headers: &HeaderMap,
    record: &CorpRecord,
) -> PortalResult<(String, CorpSession)> {
    let hash = security::session_hash(headers).ok_or_else(unauthorized)?;
    let session = app
        .inv
        .corp_session(&hash, now())
        .await
        .map_err(|error_value| store_error(&error_value))?
        .ok_or_else(unauthorized)?;
    if session.auth_generation != record.status.auth_generation
        || session.config_version != record.status.config_version
    {
        return Err(Box::new(unauthorized()));
    }
    Ok((hash, session))
}

struct BrowserContext {
    record: CorpRecord,
    session: CorpSession,
    session_hash: String,
}

async fn authorized(
    app: &AppState,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> PortalResult<BrowserContext> {
    let (record, _) = browser_access(app, headers, peer).await?;
    let (session_hash, session) = session(app, headers, &record).await?;
    Ok(BrowserContext {
        record,
        session,
        session_hash,
    })
}

async fn login(state: &PortalState, request: Request, peer: Option<IpAddr>) -> Response {
    let headers = request.headers().clone();
    let (record, ip) = match browser_access(&state.app, &headers, peer).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if !security::same_origin(&headers) {
        return error(StatusCode::FORBIDDEN, "Откройте страницу входа заново.");
    }
    if !content_type(&headers, "application/x-www-form-urlencoded") {
        return invalid();
    }
    if !state.logins.try_acquire(Some(ip), Instant::now()) {
        let mut response = error(
            StatusCode::TOO_MANY_REQUESTS,
            "Слишком много попыток. Подождите минуту.",
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return response;
    }
    let body = match to_bytes(request.into_body(), 4096).await {
        Ok(bytes) => bytes,
        Err(_) => return invalid(),
    };
    let form = url::form_urlencoded::parse(&body).collect::<Vec<_>>();
    if form.len() != 1 || form[0].0 != "password" || !(1..=512).contains(&form[0].1.len()) {
        return invalid();
    }
    let password = Zeroizing::new(form[0].1.to_string());
    if !security::verify_password(
        password,
        Zeroizing::new(record.credentials.password_phc.clone()),
    )
    .await
    {
        return (
            StatusCode::UNAUTHORIZED,
            Html(views::login(Some("Неверный пароль. Попробуйте ещё раз."))),
        )
            .into_response();
    }
    let (fresh, _) = match browser_access(&state.app, &headers, peer).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if fresh.status.auth_generation != record.status.auth_generation {
        return unauthorized();
    }
    let (Some(token), Some(csrf)) = (security::random_token(), security::random_token()) else {
        return unavailable();
    };
    let current_time = now();
    let input = CorpSessionInput {
        token_hash: security::token_hash(&token),
        csrf_token: csrf.to_string(),
        expires_at: current_time.saturating_add(SESSION_SECONDS),
    };
    if let Err(error_value) = state
        .app
        .inv
        .issue_corp_session(
            record.status.auth_generation,
            &input,
            current_time,
            "corp.browser",
        )
        .await
    {
        return store_error(&error_value);
    }
    state.logins.clear(Some(ip));
    redirect(&format!(
        "{COOKIE}={}; Path=/; Max-Age={SESSION_SECONDS}; Secure; HttpOnly; SameSite=Strict",
        token.as_str()
    ))
}

fn redirect(cookie: &str) -> Response {
    let Ok(cookie) = HeaderValue::from_str(cookie) else {
        return unavailable();
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/"));
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

fn content_type(headers: &HeaderMap, expected: &str) -> bool {
    single_header(headers, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
    })
}

async fn parse_json<T: DeserializeOwned>(request: Request) -> PortalResult<T> {
    if !content_type(request.headers(), "application/json") {
        return Err(Box::new(invalid()));
    }
    let bytes = to_bytes(request.into_body(), MAX_BODY).await.map_err(|_| {
        error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Слишком большой список правил.",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| Box::new(invalid()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Normalize {
    site: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Publish {
    expected_revision: u64,
    apply: String,
    confirm_interrupt: bool,
    rules: Vec<PolicyRule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    expected_revision: u64,
    revision: u64,
    apply: String,
    confirm_interrupt: bool,
}

async fn current_rules(
    app: &AppState,
    record: &CorpRecord,
) -> PortalResult<(u64, Vec<PolicyRule>)> {
    let current = app
        .inv
        .corp_current_policy(record.status.config_version)
        .await
        .map_err(|error_value| store_error(&error_value))?;
    let Some(current) = current else {
        return seed_rules()
            .map(|rules| (0, rules))
            .map_err(|_| Box::new(unavailable()));
    };
    let keys = record
        .credentials
        .signing_keys
        .iter()
        .map(|key| (key.id.clone(), key.spki.clone()))
        .collect::<BTreeMap<_, _>>();
    let signed = verify_envelope(&current.envelope, &record.status.policy_id, &keys)
        .map_err(|_| unavailable())?;
    if signed.payload_bytes != current.payload
        || signed.payload_sha256.to_ascii_lowercase() != current.payload_sha256
        || signed.payload.revision != current.revision
    {
        return Err(Box::new(unavailable()));
    }
    Ok((signed.payload.revision, signed.payload.rules))
}

fn stored_payload(revision: &CorpRevision, record: &CorpRecord) -> PortalResult<PolicyPayload> {
    let payload: PolicyPayload =
        serde_json::from_slice(&revision.payload).map_err(|_| unavailable())?;
    if payload.schema != 1
        || payload.policy_id != record.status.policy_id
        || payload.key_id != revision.key_id
        || payload.revision != revision.revision
        || i64::try_from(payload.published_at).ok() != Some(revision.published_at)
        || !matches!(payload.apply.as_str(), "now" | "next_connection")
        || format!("{:x}", Sha256::digest(&revision.payload)) != revision.payload_sha256
        || validate_rules(&payload.rules).is_err()
    {
        return Err(Box::new(unavailable()));
    }
    Ok(payload)
}

async fn publish(
    app: &AppState,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    record: CorpRecord,
    input: Publish,
) -> Response {
    publish_feed(
        app,
        headers,
        peer,
        record,
        FeedPublish {
            expected_revision: input.expected_revision,
            apply: input.apply,
            confirm_interrupt: input.confirm_interrupt,
            rules: PublicationRules::Sites(input.rules),
        },
    )
    .await
}

enum PublicationRules {
    Sites(Vec<PolicyRule>),
    Phone(Vec<crate::corp_policy::PhoneRule>),
}
struct FeedPublish {
    expected_revision: u64,
    apply: String,
    confirm_interrupt: bool,
    rules: PublicationRules,
}

async fn publish_feed(
    app: &AppState,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    record: CorpRecord,
    input: FeedPublish,
) -> Response {
    if let PublicationRules::Phone(rules) = &input.rules {
        if let Err(response) = telephony::runtime_routes(rules) {
            return *response;
        }
    }
    let valid_rules = match &input.rules {
        PublicationRules::Sites(rules) => validate_rules(rules),
        PublicationRules::Phone(rules) => crate::corp_policy::validate_phone_rules(rules),
    };
    if !matches!(input.apply.as_str(), "next_connection" | "now")
        || (input.apply == "now" && !input.confirm_interrupt)
        || valid_rules.is_err()
    {
        return invalid();
    }
    let phone = matches!(&input.rules, PublicationRules::Phone(_));
    let current_revision = if phone {
        match app
            .inv
            .corp_current_phone_policy(record.status.config_version)
            .await
        {
            Ok(current) => current.map_or(0, |row| row.revision),
            Err(error_value) => return store_error(&error_value),
        }
    } else {
        record.status.revision
    };
    if input.expected_revision != current_revision
        || current_revision >= vpnctl_inventory::CORP_MAX_REVISION
    {
        return conflict();
    }
    let Some(key) = record
        .credentials
        .signing_keys
        .iter()
        .find(|key| key.id == record.status.active_key_id)
    else {
        return unavailable();
    };
    let der = match STANDARD.decode(&key.pkcs8) {
        Ok(der) => Zeroizing::new(der),
        Err(_) => return unavailable(),
    };
    let signer = match PolicySigningKey::from_pkcs8_der(&der) {
        Ok(signer) => signer,
        Err(_) => return unavailable(),
    };
    if signer.spki_base64().ok().as_deref() != Some(key.spki.as_str()) {
        return unavailable();
    }
    let published_at = now();
    let Ok(timestamp) = u64::try_from(published_at) else {
        return unavailable();
    };
    let signed = match input.rules {
        PublicationRules::Sites(rules) => signer
            .sign(&PolicyPayload {
                schema: 1,
                policy_id: record.status.policy_id.clone(),
                key_id: key.id.clone(),
                revision: current_revision + 1,
                published_at: timestamp,
                apply: input.apply,
                rules,
            })
            .map(|signed| (signed.payload_sha256, signed.payload_bytes, signed.envelope)),
        PublicationRules::Phone(rules) => signer
            .sign_phone(&crate::corp_policy::PhonePayload {
                schema: 1,
                kind: "telephony".into(),
                policy_id: record.status.policy_id.clone(),
                key_id: key.id.clone(),
                revision: current_revision + 1,
                published_at: timestamp,
                apply: input.apply,
                rules,
            })
            .map(|signed| (signed.payload_sha256, signed.payload_bytes, signed.envelope)),
    };
    let (payload_sha256, payload, envelope) = match signed {
        Ok(signed) => signed,
        Err(_) => return invalid(),
    };
    let fresh = match authorized(app, headers, peer).await {
        Ok(fresh) => fresh,
        Err(response) => return api_gate_error(*response),
    };
    if fresh.record.status.config_version != record.status.config_version {
        return conflict();
    }
    let publication = CorpPublication {
        expected_revision: current_revision,
        expected_config_version: record.status.config_version,
        key_id: key.id.clone(),
        published_at,
        payload_sha256: payload_sha256.to_ascii_lowercase(),
        payload,
        envelope,
    };
    let result = if phone {
        app.inv
            .publish_corp_phone_policy(&publication, "corp.browser")
            .await
    } else {
        app.inv
            .publish_corp_policy(&publication, "corp.browser")
            .await
    };
    match result {
        Ok(revision) => {
            Json(json!({"revision":revision.revision,"published_at":revision.published_at}))
                .into_response()
        }
        Err(error_value) => store_error(&error_value),
    }
}

async fn reader(app: &AppState, headers: &HeaderMap, phone: bool) -> Response {
    let record = match active_record(app).await {
        Ok(record) => record,
        Err(response) => return api_gate_error(*response),
    };
    let Some(token) = single_header(headers, "authorization")
        .filter(|value| value.len() <= 1024)
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return unauthorized();
    };
    if !(32..=512).contains(&token.len()) {
        return unauthorized();
    }
    let mut matches = false;
    for reader in &record.credentials.reader_tokens {
        matches |= equal_secret(token, &reader.token);
    }
    if !matches {
        return unauthorized();
    }
    let current = if phone {
        app.inv
            .corp_current_phone_policy(record.status.config_version)
            .await
    } else {
        app.inv
            .corp_current_policy(record.status.config_version)
            .await
    };
    match current {
        Ok(Some(revision)) => (
            [(header::CONTENT_TYPE, "application/json")],
            revision.envelope,
        )
            .into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "Правила ещё не опубликованы."),
        Err(error_value) => store_error(&error_value),
    }
}

async fn observation(app: &AppState, request: Request) -> Response {
    if request.method() != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if request.uri().query().is_some() {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip());
    let trusted =
        peer.is_some_and(|ip| crate::real_ip::is_trusted_proxy(security::canonical_ip(ip)));
    let Some(ip) = security::resolve_client_ip(request.headers(), peer, trusted) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some(token) = single_header(request.headers(), "authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| Zeroizing::new(v.to_owned()))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match to_bytes(request.into_body(), 1024).await {
        Ok(body) if body.is_empty() => {}
        Ok(_) => return StatusCode::UNPROCESSABLE_ENTITY.into_response(),
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    }
    if app.corp_egress.observe(&token, ip).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(value) = HeaderValue::from_str(&token) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    (StatusCode::NO_CONTENT, [("x-corp-probe", value)]).into_response()
}

async fn diagnostics_request(app: &AppState, request: Request) -> Response {
    use super::diagnostics::{BridgeError, valid_id};
    let bad_request = || error(StatusCode::BAD_REQUEST, "Некорректный запрос отчёта.");
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let tail = path.strip_prefix("/api/corp/reports").unwrap_or_default();
    let result = if tail.is_empty() && method == Method::GET {
        let mut query = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (key, value) in
            url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        {
            if !seen.insert(key.to_string()) {
                return bad_request();
            }
            match key.as_ref() {
                "limit" if value.parse::<u16>().is_ok_and(|v| (1..=100).contains(&v)) => {}
                "cursor" if valid_id(&value) => {}
                _ => return bad_request(),
            }
            query.push((key.into_owned(), value.into_owned()));
        }
        let Some(client) = &app.corp_diagnostics else {
            return diagnostics_unavailable();
        };
        client
            .list(&query)
            .await
            .map(|body| Json(body).into_response())
    } else {
        let parts = tail
            .strip_prefix('/')
            .unwrap_or_default()
            .split('/')
            .collect::<Vec<_>>();
        if parts.is_empty() || !valid_id(parts[0]) || request.uri().query().is_some() {
            return bad_request();
        }
        let id = parts[0];
        if parts.len() == 1 && method == Method::GET {
            let Some(client) = &app.corp_diagnostics else {
                return diagnostics_unavailable();
            };
            client
                .detail(id)
                .await
                .map(|body| Json(body).into_response())
        } else if parts.len() == 2 && parts[1] == "retry" && method == Method::POST {
            let body: serde_json::Value = match parse_json(request).await {
                Ok(body) => body,
                Err(response) => return *response,
            };
            if !body.as_object().is_some_and(|object| object.is_empty()) {
                return bad_request();
            }
            let Some(client) = &app.corp_diagnostics else {
                return diagnostics_unavailable();
            };
            client
                .retry(id)
                .await
                .map(|body| (StatusCode::ACCEPTED, Json(body)).into_response())
        } else {
            return error(
                StatusCode::METHOD_NOT_ALLOWED,
                "Этот способ запроса не поддерживается.",
            );
        }
    };
    match result {
        Ok(response) => response,
        Err(BridgeError::NotFound) => error(StatusCode::NOT_FOUND, "Отчёт недоступен."),
        Err(BridgeError::Invalid) => bad_request(),
        Err(BridgeError::Conflict) => error(
            StatusCode::CONFLICT,
            "Анализ уже выполняется. Обновите отчёт позже.",
        ),
        Err(BridgeError::Unavailable) => diagnostics_unavailable(),
    }
}
fn diagnostics_unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Диагностика сейчас недоступна. Попробуйте позже. Правила продолжают работать.",
    )
}
