use super::*;
use crate::corp_policy::{
    PhonePayload, PhoneRule, normalize_phone_value, seed_phone_rules, verify_phone_envelope,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalizePhone {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishPhone {
    expected_revision: u64,
    apply: String,
    confirm_interrupt: bool,
    rules: Vec<PhoneRule>,
}

pub(super) async fn handle(
    app: &AppState,
    request: Request,
    peer: Option<IpAddr>,
    context: BrowserContext,
) -> Response {
    let path = request
        .uri()
        .path()
        .strip_prefix("/api/v1/corp/portal/telephony")
        .unwrap_or_default()
        .to_owned();
    let method = request.method().clone();
    if request.uri().query().is_some() {
        return invalid();
    }
    if method == Method::GET && matches!(path.as_str(), "" | "/state") {
        let current = match app
            .inv
            .corp_current_phone_policy(context.record.status.config_version)
            .await
        {
            Ok(current) => current,
            Err(error_value) => return store_error(&error_value),
        };
        let (revision, rules) = if let Some(current) = current {
            match stored(&current, &context.record) {
                Ok(payload) => (current.revision, payload.rules),
                Err(response) => return *response,
            }
        } else {
            match seed_phone_rules() {
                Ok(rules) => (0, rules),
                Err(_) => return unavailable(),
            }
        };
        return Json(json!({"revision":revision,"rules":rules,"csrf":context.session.csrf_token}))
            .into_response();
    }
    if method == Method::GET && path == "/history" {
        let rows = match app.inv.corp_phone_history(100).await {
            Ok(rows) => rows,
            Err(error_value) => return store_error(&error_value),
        };
        let mut history = Vec::with_capacity(rows.len());
        for row in rows {
            let payload = match stored(&row, &context.record) {
                Ok(payload) => payload,
                Err(response) => return *response,
            };
            history.push(json!({"revision":row.revision,"published_at":row.published_at,"apply":payload.apply,"rule_count":payload.rules.len()}));
        }
        return Json(history).into_response();
    }
    let headers = request.headers().clone();
    if method == Method::POST && path == "/normalize" {
        let input: NormalizePhone = match parse_json(request).await {
            Ok(input) => input,
            Err(response) => return *response,
        };
        return match normalize_phone_value(&input.kind, &input.value) {
            Ok(value) => Json(json!({"type":input.kind,"value":value})).into_response(),
            Err(_) => invalid(),
        };
    }
    let input = if method == Method::POST && path == "/rules" {
        let input: PublishPhone = match parse_json(request).await {
            Ok(input) => input,
            Err(response) => return *response,
        };
        FeedPublish {
            expected_revision: input.expected_revision,
            apply: input.apply,
            confirm_interrupt: input.confirm_interrupt,
            rules: PublicationRules::Phone(input.rules),
        }
    } else if method == Method::POST && path == "/restore" {
        let input: Restore = match parse_json(request).await {
            Ok(input) => input,
            Err(response) => return *response,
        };
        let row = match app.inv.corp_phone_revision(input.revision).await {
            Ok(Some(row)) => row,
            Ok(None) => return error(StatusCode::NOT_FOUND, "Эта версия уже недоступна."),
            Err(error_value) => return store_error(&error_value),
        };
        let payload = match stored(&row, &context.record) {
            Ok(payload) => payload,
            Err(response) => return *response,
        };
        FeedPublish {
            expected_revision: input.expected_revision,
            apply: input.apply,
            confirm_interrupt: input.confirm_interrupt,
            rules: PublicationRules::Phone(payload.rules),
        }
    } else {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Этот способ запроса не поддерживается.",
        );
    };
    publish_feed(app, &headers, peer, context.record, input).await
}

fn stored(row: &CorpRevision, record: &CorpRecord) -> PortalResult<PhonePayload> {
    let keys = record
        .credentials
        .signing_keys
        .iter()
        .map(|key| (key.id.clone(), key.spki.clone()))
        .collect();
    let signed = verify_phone_envelope(&row.envelope, &record.status.policy_id, &keys)
        .map_err(|_| unavailable())?;
    let payload = signed.payload;
    if signed.payload_bytes != row.payload
        || signed.payload_sha256.to_ascii_lowercase() != row.payload_sha256
        || payload.key_id != row.key_id
        || payload.revision != row.revision
        || i64::try_from(payload.published_at).ok() != Some(row.published_at)
    {
        return Err(Box::new(unavailable()));
    }
    Ok(payload)
}

pub(super) fn runtime_routes(rules: &[PhoneRule]) -> PortalResult<()> {
    use ipnet::IpNet;
    use std::net::Ipv4Addr;
    for rule in rules.iter().filter(|rule| rule.kind == "ip_cidr") {
        let network: IpNet = rule.value.parse().map_err(|_| Box::new(invalid()))?;
        let IpNet::V4(network) = network else {
            return Err(Box::new(error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Corp пока поддерживает только IPv4-адреса телефонии",
            )));
        };
        if rule.action == "proxy"
            && [
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(169, 254, 0, 0), 16),
                (Ipv4Addr::new(127, 0, 0, 0), 8),
            ]
            .into_iter()
            .any(|(address, prefix)| {
                ipnet::Ipv4Net::new(address, prefix).is_ok_and(|excluded| {
                    excluded.contains(&network.addr()) || network.contains(&excluded.addr())
                })
            })
        {
            return Err(Box::new(error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Этот диапазон пересекается с локальной сетью, которая должна работать без VPN. Выберите более узкий внешний IPv4-адрес или маршрут напрямую.",
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::corp_policy::PolicySigningKey;
    use vpnctl_core::UserId;
    use vpnctl_inventory::{CorpCredentials, CorpSigningKey, CorpStatus};

    #[test]
    fn archived_phone_requires_verified_envelope_and_matching_stored_metadata() {
        let key = PolicySigningKey::generate().unwrap();
        let signed = key
            .sign_phone(&PhonePayload {
                schema: 1,
                kind: "telephony".into(),
                policy_id: "test-policy".into(),
                key_id: "test-key".into(),
                revision: 1,
                published_at: 1,
                apply: "next_connection".into(),
                rules: vec![],
            })
            .unwrap();
        let record = CorpRecord {
            status: CorpStatus {
                user_id: UserId("test".into()),
                policy_id: "test-policy".into(),
                enabled: true,
                auth_generation: 1,
                config_version: 1,
                revision: 0,
                active_key_id: "test-key".into(),
            },
            credentials: CorpCredentials {
                password_phc: String::new(),
                reader_tokens: vec![],
                signing_keys: vec![CorpSigningKey {
                    id: "test-key".into(),
                    pkcs8: String::new(),
                    spki: key.spki_base64().unwrap(),
                }],
                active_key_id: "test-key".into(),
            },
        };
        let mut row = CorpRevision {
            revision: 1,
            key_id: "test-key".into(),
            published_at: 1,
            payload_sha256: signed.payload_sha256.to_ascii_lowercase(),
            payload: signed.payload_bytes,
            envelope: signed.envelope,
        };
        assert!(stored(&row, &record).is_ok());
        let envelope = row.envelope.clone();
        row.envelope = b"{}".to_vec();
        assert!(stored(&row, &record).is_err());
        row.envelope = envelope;
        row.revision = 2;
        assert!(stored(&row, &record).is_err());
        row.revision = 1;
        row.payload.push(b' ');
        assert!(stored(&row, &record).is_err());
    }
}
