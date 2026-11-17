use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use std::collections::{BTreeMap, BTreeSet};
use vpnctl_core::{ServerId, UserId};
use vpnctl_inventory::{CorpCredentials, CorpSetup, CorpStoreError};
use zeroize::Zeroizing;

use super::{OperatorState, Result, credentials, fail, unavailable, views};

pub(super) struct Form(BTreeMap<String, Zeroizing<String>>);
impl Form {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes
            .split(|byte| *byte == b'&')
            .any(|field| field.is_empty() || !field.contains(&b'='))
        {
            return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
        }
        if std::str::from_utf8(bytes).is_err() {
            return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
        }
        // url's parser is intentionally forgiving; reject malformed percent/UTF-8 first.
        let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
        let mut position = 0;
        while position < bytes.len() {
            if bytes[position] == b'%' {
                let pair = bytes
                    .get(position + 1..position + 3)
                    .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY))?;
                let hex = std::str::from_utf8(pair)
                    .map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY))?;
                decoded.push(
                    u8::from_str_radix(hex, 16)
                        .map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY))?,
                );
                position += 3;
            } else {
                decoded.push(bytes[position]);
                position += 1;
            }
        }
        std::str::from_utf8(&decoded).map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY))?;
        let mut fields = BTreeMap::new();
        for (key, value) in url::form_urlencoded::parse(bytes) {
            if fields
                .insert(key.into_owned(), Zeroizing::new(value.into_owned()))
                .is_some()
            {
                return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
            }
        }
        Ok(Self(fields))
    }
    pub(super) fn get(&self, name: &str) -> Result<&str> {
        self.0
            .get(name)
            .map(|value| value.as_str())
            .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY))
    }
    fn exact(&self, fields: &[&str]) -> Result<()> {
        let expected: BTreeSet<_> = fields
            .iter()
            .copied()
            .chain(std::iter::once("csrf"))
            .collect();
        let company_present = self.0.contains_key("company_id");
        if self.0.len() != expected.len() + usize::from(company_present)
            || self
                .0
                .keys()
                .any(|key| key != "company_id" && !expected.contains(key.as_str()))
        {
            return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
        }
        Ok(())
    }
    fn confirmed(&self, name: &str) -> Result<()> {
        if self.get(name)? != "true" {
            return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
        }
        Ok(())
    }
    fn version(&self) -> Result<u64> {
        let text = self.get("expected_config_version")?;
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
        }
        let value = text
            .parse::<u64>()
            .map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY))?;
        if value.to_string() != text {
            return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
        }
        Ok(value)
    }
    fn id(&self, name: &str) -> Result<&str> {
        let value = self.get(name)?;
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(fail(StatusCode::UNPROCESSABLE_ENTITY));
        }
        Ok(value)
    }
}

pub(super) fn known_path(path: &str) -> bool {
    matches!(
        path,
        "/admin/corp"
            | "/admin/corp/assets/operator.css"
            | "/admin/corp/setup"
            | "/admin/corp/enabled"
            | "/admin/corp/password/rotate"
            | "/admin/corp/readers/add"
            | "/admin/corp/readers/remove"
            | "/admin/corp/signers/add"
            | "/admin/corp/signers/activate"
            | "/admin/corp/signers/remove"
            | "/admin/corp/sessions/revoke"
            | "/admin/corp/export"
            | "/admin/corp/probe"
            | "/admin/corp/companies"
            | "/admin/corp/support/export"
    )
}
fn store(error: &CorpStoreError) -> super::Failure {
    match error {
        CorpStoreError::Conflict => fail(StatusCode::CONFLICT),
        _ => unavailable(),
    }
}
fn probe_error(error: crate::corp_egress::ProbeError) -> super::Failure {
    use crate::corp_egress::ProbeError;
    match error {
        ProbeError::Busy | ProbeError::Conflict => fail(StatusCode::CONFLICT),
        ProbeError::NotFound => fail(StatusCode::NOT_FOUND),
        ProbeError::Unavailable | ProbeError::Failed | ProbeError::CleanupFailed => unavailable(),
    }
}

pub(super) async fn perform(state: &OperatorState, path: &str, form: &Form) -> Result<Response> {
    let action = path
        .strip_prefix("/admin/corp/")
        .ok_or_else(|| fail(StatusCode::NOT_FOUND))?;
    let fields: &[&str] = match action {
        "setup" => &["user_id", "confirm_binding"],
        "enabled" => &["expected_config_version", "enabled", "confirm"],
        "password/rotate" | "sessions/revoke" => &["expected_config_version", "confirm"],
        "readers/add" | "signers/add" => &["expected_config_version"],
        "readers/remove" => &["expected_config_version", "reader_id", "confirm"],
        "signers/activate" | "signers/remove" => &["expected_config_version", "key_id", "confirm"],
        "export" => &["expected_config_version", "reader_id"],
        "support/export" => &["expected_config_version"],
        "probe" => &["expected_config_version", "server_id"],
        _ => return Err(fail(StatusCode::NOT_FOUND)),
    };
    form.exact(fields)?;
    if fields.contains(&"confirm") {
        form.confirmed("confirm")?;
    }
    if action == "setup" {
        return setup(state, form).await;
    }
    let company_id = if form.0.contains_key("company_id") {
        form.id("company_id")?
    } else {
        "legacy"
    };
    let destination = views::company_url(company_id);
    let scoped = state.app.inv.corp_for(company_id);
    let version = form.version()?;
    let mut record = scoped
        .corp_record()
        .await
        .map_err(|error| store(&error))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND))?;
    if record.status.config_version != version {
        return Err(fail(StatusCode::CONFLICT));
    }
    let mut reveal = None;
    let mut enabled = record.status.enabled;
    match action {
        "enabled" => match form.get("enabled")? {
            "true" => enabled = true,
            "false" => enabled = false,
            _ => return Err(fail(StatusCode::UNPROCESSABLE_ENTITY)),
        },
        "password/rotate" => {
            let (password, hash) = credentials::password().await?;
            record.credentials.password_phc = hash.to_string();
            reveal = Some(password);
        }
        "readers/add" => {
            if record.credentials.reader_tokens.len() >= 2 {
                return Err(fail(StatusCode::CONFLICT));
            }
            record
                .credentials
                .reader_tokens
                .push(credentials::reader()?);
        }
        "readers/remove" => {
            let id = form.id("reader_id")?;
            if !record
                .credentials
                .reader_tokens
                .iter()
                .any(|reader| reader.id == id)
            {
                return Err(fail(StatusCode::NOT_FOUND));
            }
            if record.credentials.reader_tokens.len() <= 1 {
                return Err(fail(StatusCode::CONFLICT));
            }
            record
                .credentials
                .reader_tokens
                .retain(|reader| reader.id != id);
        }
        "signers/add" => {
            if record.credentials.signing_keys.len() >= 4 {
                return Err(fail(StatusCode::CONFLICT));
            }
            record.credentials.signing_keys.push(credentials::signer()?);
        }
        "signers/activate" => {
            let id = form.id("key_id")?;
            if !record
                .credentials
                .signing_keys
                .iter()
                .any(|key| key.id == id)
            {
                return Err(fail(StatusCode::NOT_FOUND));
            }
            record.credentials.active_key_id = id.to_owned();
        }
        "signers/remove" => {
            let id = form.id("key_id")?;
            if !record
                .credentials
                .signing_keys
                .iter()
                .any(|key| key.id == id)
            {
                return Err(fail(StatusCode::NOT_FOUND));
            }
            if record.credentials.active_key_id == id {
                return Err(fail(StatusCode::CONFLICT));
            }
            // Revisions are immutable and publication CAS is tied to this config version.
            // Verify retained envelopes as well as metadata before retiring trust.
            let keys = record
                .credentials
                .signing_keys
                .iter()
                .map(|key| (key.id.clone(), key.spki.clone()))
                .collect();
            for revision in scoped
                .corp_history(100)
                .await
                .map_err(|error| store(&error))?
            {
                let signed = crate::corp_policy::verify_envelope(
                    &revision.envelope,
                    &record.status.policy_id,
                    &keys,
                )
                .map_err(|_| unavailable())?;
                if revision.key_id == id || signed.payload.key_id == id {
                    return Err(fail(StatusCode::CONFLICT));
                }
            }
            for revision in scoped
                .corp_phone_history(100)
                .await
                .map_err(|error| store(&error))?
            {
                let signed = crate::corp_policy::verify_phone_envelope(
                    &revision.envelope,
                    &record.status.policy_id,
                    &keys,
                )
                .map_err(|_| unavailable())?;
                if revision.key_id == id || signed.payload.key_id == id {
                    return Err(fail(StatusCode::CONFLICT));
                }
            }
            record.credentials.signing_keys.retain(|key| key.id != id);
        }
        "sessions/revoke" => {
            scoped
                .revoke_corp_sessions(version, "operator-corp-session-revoke")
                .await
                .map_err(|error| store(&error))?;
            return Ok(Redirect::to(&destination).into_response());
        }
        "export" => {
            return export(state, company_id, &record, form.id("reader_id")?, version).await;
        }
        "support/export" => {
            let client = state
                .app
                .corp_diagnostics
                .as_ref()
                .ok_or_else(unavailable)?;
            let support = client
                .provision(&record.status.policy_id, &record.status.user_id.0)
                .await
                .map_err(|_| unavailable())?;
            let current = scoped
                .corp_record()
                .await
                .map_err(|error| store(&error))?
                .ok_or_else(unavailable)?;
            if current.status.config_version != version {
                return Err(fail(StatusCode::CONFLICT));
            }
            let bytes = serde_json::to_vec(&support.support).map_err(|_| unavailable())?;
            return Ok((
                [
                    ("content-type", "application/json"),
                    (
                        "content-disposition",
                        "attachment; filename=\"business.support.json\"",
                    ),
                ],
                bytes,
            )
                .into_response());
        }
        "probe" => {
            let server = ServerId(form.id("server_id")?.to_owned());
            let ticket = state
                .app
                .corp_egress
                .queue_probe_for(state.app.clone(), company_id, version, server)
                .await
                .map_err(probe_error)?;
            // The controller owns the accepted job through cleanup, independently of this response.
            drop(ticket);
            return Ok(Redirect::to(&destination).into_response());
        }
        _ => return Err(fail(StatusCode::NOT_FOUND)),
    }
    // Removing authority must work even if existing cryptographic material is corrupt.
    if action != "enabled" || enabled {
        credentials::validate(&record.credentials)?;
    }
    if action == "enabled"
        && enabled
        && !state
            .app
            .corp_egress
            .ready_to_enable_for(&state.app, company_id, version)
            .await
            .map_err(probe_error)?
    {
        return Err(unavailable());
    }
    scoped
        .update_corp_security(
            version,
            enabled,
            &record.credentials,
            if action == "enabled" && enabled {
                "operator-corp-enable"
            } else {
                actor(action)
            },
        )
        .await
        .map_err(|error| store(&error))?;
    match reveal {
        Some(password) => Ok(views::reveal(
            &password,
            company_id,
            &record.status.user_id.0,
        )),
        None => Ok(Redirect::to(&destination).into_response()),
    }
}
fn actor(action: &str) -> &'static str {
    match action {
        "enabled" => "operator-corp-disable",
        "password/rotate" => "operator-corp-password-rotate",
        "readers/add" => "operator-corp-reader-add",
        "readers/remove" => "operator-corp-reader-remove",
        "signers/add" => "operator-corp-signer-add",
        "signers/activate" => "operator-corp-signer-activate",
        _ => "operator-corp-signer-remove",
    }
}
async fn setup(state: &OperatorState, form: &Form) -> Result<Response> {
    form.confirmed("confirm_binding")?;
    let user_id = UserId(form.id("user_id")?.to_owned());
    let companies = state
        .app
        .inv
        .corp_companies()
        .await
        .map_err(|error| store(&error))?;
    if companies
        .iter()
        .any(|company| company.status.user_id == user_id)
    {
        return Err(fail(StatusCode::CONFLICT));
    }
    let company_id = if companies.is_empty() {
        "legacy".to_owned()
    } else {
        credentials::identifier()?
    };
    let user = state
        .app
        .inv
        .get_user(&user_id)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND))?;
    if user.disabled {
        return Err(unavailable());
    }
    let (password, hash) = credentials::password().await?;
    let signer = credentials::signer()?;
    let credentials = CorpCredentials {
        password_phc: hash.to_string(),
        reader_tokens: vec![credentials::reader()?],
        active_key_id: signer.id.clone(),
        signing_keys: vec![signer],
    };
    credentials::validate(&credentials)?;
    let policy_id = credentials::identifier()?;
    state
        .app
        .inv
        .corp_for(&company_id)
        .create_corp(
            &CorpSetup {
                user_id: user_id.clone(),
                policy_id: policy_id.clone(),
                credentials,
            },
            "operator-corp-setup",
        )
        .await
        .map_err(|error| store(&error))?;
    let support_ready = match &state.app.corp_diagnostics {
        Some(client) => client.provision(&policy_id, &user_id.0).await.is_ok(),
        None => false,
    };
    Ok(views::reveal_setup(
        &password,
        &company_id,
        &user_id.0,
        support_ready,
    ))
}
async fn export(
    state: &OperatorState,
    company_id: &str,
    record: &vpnctl_inventory::CorpRecord,
    reader_id: &str,
    version: u64,
) -> Result<Response> {
    let reader = record
        .credentials
        .reader_tokens
        .iter()
        .find(|reader| reader.id == reader_id)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND))?;
    credentials::validate(&record.credentials)?;
    let keys: Vec<_> = record
        .credentials
        .signing_keys
        .iter()
        .map(|key| serde_json::json!({"id": key.id, "spki": key.spki}))
        .collect();
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"{\"policy_id\":");
    serde_json::to_writer(&mut *bytes, &record.status.policy_id).map_err(|_| unavailable())?;
    bytes.extend_from_slice(
        b",\"endpoint\":\"https://admin.corp.ninitux.com/api/v1/corp/policy\",\"read_token\":",
    );
    serde_json::to_writer(&mut *bytes, &reader.token).map_err(|_| unavailable())?;
    bytes.extend_from_slice(b",\"keys\":");
    serde_json::to_writer(&mut *bytes, &keys).map_err(|_| unavailable())?;
    bytes.push(b'}');
    let current = state
        .app
        .inv
        .corp_for(company_id)
        .corp_record()
        .await
        .map_err(|error| store(&error))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND))?;
    if current.status.config_version != version {
        return Err(fail(StatusCode::CONFLICT));
    }
    let mut response = ([("content-type", "application/json")], bytes.to_vec()).into_response();
    response.headers_mut().insert(
        "content-disposition",
        HeaderValue::from_static("attachment; filename=\"business.policy.json\""),
    );
    Ok(response)
}
