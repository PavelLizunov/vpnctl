use serde_json::Value;

use super::types::{BashInventoryEnv, BashSingboxData, BashTuicUser, BashVlessUser};

/// Parse a bash `inventory/<IP>.env` file. Format is a tiny K=V dialect
/// — `KEY=value`, `# comments`, blank lines. Only the 5 keys vpnctl
/// migration needs are recognised; unknown keys are tolerated (operator
/// might have added their own annotations).
pub fn parse_bash_inventory_env(s: &str) -> Result<BashInventoryEnv, String> {
    let mut server_ip: Option<String> = None;
    let mut ssh_port: u16 = 22;
    let mut reality_public: Option<String> = None;
    let mut short_id: Option<String> = None;
    let mut users: Vec<String> = Vec::new();
    for (lineno, raw_line) in s.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {} not KEY=VALUE: {raw_line:?}", lineno + 1));
        };
        match k.trim() {
            "SERVER_IP" => server_ip = Some(v.trim().to_string()),
            "SSH_PORT" => {
                ssh_port = v
                    .trim()
                    .parse()
                    .map_err(|e| format!("line {} SSH_PORT not u16: {e}", lineno + 1))?;
            }
            "REALITY_PUBLIC" => reality_public = Some(v.trim().to_string()),
            "SHORT_ID" => short_id = Some(v.trim().to_string()),
            "USERS" => {
                users = v
                    .split(',')
                    .map(|u| u.trim().to_string())
                    .filter(|u| !u.is_empty())
                    .collect();
            }
            _ => {}
        }
    }
    Ok(BashInventoryEnv {
        server_ip: server_ip.ok_or("missing SERVER_IP")?,
        ssh_port,
        reality_public: reality_public.ok_or("missing REALITY_PUBLIC")?,
        short_id: short_id.ok_or("missing SHORT_ID")?,
        users,
    })
}

/// Extract VLESS + TUIC users from a parsed sing-box `config.json` +
/// the REALITY private key from `keys.env` text. The TWO files are
/// read together because the migration plan needs both to make
/// decisions (e.g. emit `vless.private_key` only if we know the
/// public half came from this server).
///
/// `keys_env_text` is the raw `keys.env` file (KEY=VALUE lines, same
/// dialect as `inventory/<IP>.env`).
pub fn parse_bash_singbox(
    config_json: &str,
    keys_env_text: &str,
) -> Result<BashSingboxData, String> {
    let cfg: Value = serde_json::from_str(config_json)
        .map_err(|e| format!("config.json not valid JSON: {e}"))?;
    let inbounds = cfg
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or("config.json has no `inbounds` array")?;

    // Find FIRST `vless-reality-*` inbound (modern bash adds a
    // secondary `vless-reality-2083` for NAT-edge clients — we
    // ignore it; the planner emits a warning if it sees one).
    let primary_vless = inbounds
        .iter()
        .filter(|i| {
            i.get("type").and_then(Value::as_str) == Some("vless")
                && i.get("tag")
                    .and_then(Value::as_str)
                    .map(|t| t.starts_with("vless-reality"))
                    .unwrap_or(false)
        })
        .min_by_key(|i| {
            i.get("listen_port")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX)
        });
    let mut vless_users = Vec::new();
    if let Some(ib) = primary_vless
        && let Some(users) = ib.get("users").and_then(Value::as_array)
    {
        for u in users {
            let name = u
                .get("name")
                .and_then(Value::as_str)
                .ok_or("vless user missing name")?;
            let uuid = u
                .get("uuid")
                .and_then(Value::as_str)
                .ok_or("vless user missing uuid")?;
            let flow = u.get("flow").and_then(Value::as_str).map(str::to_string);
            vless_users.push(BashVlessUser {
                name: name.to_string(),
                uuid: uuid.to_string(),
                flow,
            });
        }
    }

    // TUIC inbound. The tag is `tuic-in` in every modern deploy.
    let tuic_inbound = inbounds
        .iter()
        .find(|i| i.get("type").and_then(Value::as_str) == Some("tuic"));
    let mut tuic_users = Vec::new();
    if let Some(ib) = tuic_inbound
        && let Some(users) = ib.get("users").and_then(Value::as_array)
    {
        for u in users {
            let name = u
                .get("name")
                .and_then(Value::as_str)
                .ok_or("tuic user missing name")?;
            let uuid = u
                .get("uuid")
                .and_then(Value::as_str)
                .ok_or("tuic user missing uuid")?;
            let password = u
                .get("password")
                .and_then(Value::as_str)
                .ok_or("tuic user missing password")?;
            tuic_users.push(BashTuicUser {
                name: name.to_string(),
                uuid: uuid.to_string(),
                password: password.to_string(),
            });
        }
    }

    // Pull REALITY_PRIVATE out of keys.env. Same dialect as the
    // inventory env file — KEY=VAL lines with comments.
    let mut reality_private: Option<String> = None;
    for raw in keys_env_text.lines() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=')
            && k.trim() == "REALITY_PRIVATE"
        {
            reality_private = Some(v.trim().to_string());
            break;
        }
    }
    Ok(BashSingboxData {
        vless_users,
        tuic_users,
        reality_private,
    })
}
