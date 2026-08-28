use serde::Serialize;
use serde_json::{Value, json};
use vpnctl_core::{User, UserId};

use super::handler::SubError;
use super::singbox::render_singbox_for_mihomo;
use crate::app::AppState;

#[derive(Serialize)]
struct MihomoConfig {
    proxies: Vec<Value>,
    #[serde(rename = "proxy-groups")]
    proxy_groups: Vec<ProxyGroup>,
    rules: Vec<String>,
}

#[derive(Serialize)]
struct ProxyGroup {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    proxies: Vec<String>,
}

struct CandidateProxy {
    tag: String,
    detour: Option<String>,
    val: Value,
}

pub(super) async fn render_mihomo(
    state: &AppState,
    user: &User,
) -> Result<(UserId, String), SubError> {
    let (user_id, singbox_cfg) = render_singbox_for_mihomo(state, user).await?;

    let mut candidates: Vec<CandidateProxy> = Vec::new();

    if let Some(outbounds) = singbox_cfg.get("outbounds").and_then(Value::as_array) {
        for outbound in outbounds {
            let Some(out_type) = outbound.get("type").and_then(Value::as_str) else {
                continue;
            };

            match out_type {
                "vless" => {
                    let is_reality = outbound
                        .get("tls")
                        .and_then(|t| t.get("reality"))
                        .and_then(|r| r.get("enabled"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);

                    if !is_reality {
                        continue;
                    }

                    let Some(tag) = outbound.get("tag").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(server) = outbound.get("server").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(port) = outbound.get("server_port").and_then(Value::as_u64) else {
                        continue;
                    };
                    let Some(uuid) = outbound.get("uuid").and_then(Value::as_str) else {
                        continue;
                    };

                    let reality_obj = outbound.get("tls").and_then(|t| t.get("reality"));

                    let Some(public_key) = reality_obj
                        .and_then(|r| r.get("public_key"))
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let Some(short_id) = reality_obj
                        .and_then(|r| r.get("short_id"))
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };

                    let flow = outbound.get("flow").and_then(Value::as_str);
                    let servername = outbound
                        .get("tls")
                        .and_then(|t| t.get("server_name"))
                        .and_then(Value::as_str);
                    let fingerprint = outbound
                        .get("tls")
                        .and_then(|t| t.get("utls"))
                        .and_then(|u| u.get("fingerprint"))
                        .and_then(Value::as_str);
                    let packet_encoding = outbound.get("packet_encoding").and_then(Value::as_str);
                    let detour = outbound.get("detour").and_then(Value::as_str);

                    let mut map = serde_json::Map::new();
                    map.insert("name".to_string(), json!(tag));
                    map.insert("type".to_string(), json!("vless"));
                    map.insert("server".to_string(), json!(server));
                    map.insert("port".to_string(), json!(port));
                    map.insert("uuid".to_string(), json!(uuid));
                    map.insert("network".to_string(), json!("tcp"));
                    map.insert("udp".to_string(), json!(true));
                    map.insert("tls".to_string(), json!(true));

                    if let Some(sn) = servername {
                        map.insert("servername".to_string(), json!(sn));
                    }
                    if let Some(fl) = flow {
                        map.insert("flow".to_string(), json!(fl));
                    }
                    if let Some(fp) = fingerprint {
                        // sing-box calls its randomized uTLS mode `randomized`;
                        // Mihomo's equivalent documented value is `random`.
                        let fp = if fp == "randomized" { "random" } else { fp };
                        map.insert("client-fingerprint".to_string(), json!(fp));
                    }
                    map.insert(
                        "reality-opts".to_string(),
                        json!({
                            "public-key": public_key,
                            "short-id": short_id,
                        }),
                    );
                    if let Some(pe) = packet_encoding {
                        map.insert("packet-encoding".to_string(), json!(pe));
                    }

                    candidates.push(CandidateProxy {
                        tag: tag.to_string(),
                        detour: detour.map(str::to_string),
                        val: Value::Object(map),
                    });
                }
                "hysteria2" => {
                    let Some(tag) = outbound.get("tag").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(server) = outbound.get("server").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(port) = outbound.get("server_port").and_then(Value::as_u64) else {
                        continue;
                    };
                    let Some(password) = outbound.get("password").and_then(Value::as_str) else {
                        continue;
                    };

                    let tls_obj = outbound.get("tls");
                    let skip_cert_verify = tls_obj
                        .and_then(|t| t.get("insecure"))
                        .and_then(Value::as_bool);
                    let sni = tls_obj
                        .and_then(|t| t.get("server_name"))
                        .and_then(Value::as_str);
                    let alpn = tls_obj
                        .and_then(|t| t.get("alpn"))
                        .and_then(Value::as_array);

                    let obfs_obj = outbound.get("obfs");
                    let obfs_type = obfs_obj.and_then(|o| o.get("type")).and_then(Value::as_str);
                    let obfs_password = obfs_obj
                        .and_then(|o| o.get("password"))
                        .and_then(Value::as_str);

                    let detour = outbound.get("detour").and_then(Value::as_str);

                    let mut map = serde_json::Map::new();
                    map.insert("name".to_string(), json!(tag));
                    map.insert("type".to_string(), json!("hysteria2"));
                    map.insert("server".to_string(), json!(server));
                    map.insert("port".to_string(), json!(port));
                    map.insert("password".to_string(), json!(password));
                    map.insert("udp".to_string(), json!(true));

                    if let Some(scv) = skip_cert_verify {
                        map.insert("skip-cert-verify".to_string(), json!(scv));
                    }
                    if let Some(sn) = sni {
                        map.insert("sni".to_string(), json!(sn));
                    }
                    if let Some(al) = alpn {
                        map.insert("alpn".to_string(), json!(al));
                    }
                    if let Some(ot) = obfs_type {
                        map.insert("obfs".to_string(), json!(ot));
                    }
                    if let Some(op) = obfs_password {
                        map.insert("obfs-password".to_string(), json!(op));
                    }

                    candidates.push(CandidateProxy {
                        tag: tag.to_string(),
                        detour: detour.map(str::to_string),
                        val: Value::Object(map),
                    });
                }
                _ => {}
            }
        }
    }

    let candidate_map: std::collections::HashMap<&str, &CandidateProxy> =
        candidates.iter().map(|c| (c.tag.as_str(), c)).collect();

    let mut final_proxies: Vec<Value> = Vec::new();
    let mut proxy_names: Vec<String> = Vec::new();

    for candidate in &candidates {
        if let Some(upstream_name) = &candidate.detour {
            if let Some(upstream) = candidate_map.get(upstream_name.as_str()) {
                if upstream_name != &candidate.tag && upstream.detour.is_none() {
                    let mut proxy_val = candidate.val.clone();
                    if let Some(obj) = proxy_val.as_object_mut() {
                        obj.insert("dialer-proxy".to_string(), json!(upstream_name));
                    }
                    proxy_names.push(candidate.tag.clone());
                    final_proxies.push(proxy_val);
                } else {
                    tracing::debug!(
                        target = "vpnctld::sub",
                        tag = %candidate.tag,
                        upstream = %upstream_name,
                        "chained target upstream invalid (self or has own detour); omitting target"
                    );
                }
            } else {
                tracing::debug!(
                    target = "vpnctld::sub",
                    tag = %candidate.tag,
                    upstream = %upstream_name,
                    "chained target upstream not found among proxies; omitting target"
                );
            }
        } else {
            proxy_names.push(candidate.tag.clone());
            final_proxies.push(candidate.val.clone());
        }
    }

    let proxy_group_proxies = if proxy_names.is_empty() {
        vec!["DIRECT".to_string()]
    } else {
        proxy_names
    };

    let config = MihomoConfig {
        proxies: final_proxies,
        proxy_groups: vec![ProxyGroup {
            name: "VPN".to_string(),
            group_type: "select".to_string(),
            proxies: proxy_group_proxies,
        }],
        rules: vec!["MATCH,VPN".to_string()],
    };

    let yaml = serde_saphyr::to_string(&config)
        .map_err(|_| SubError::Internal("yaml serialization failed".to_string()))?;

    Ok((user_id, yaml))
}
