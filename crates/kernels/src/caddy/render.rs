use serde::Deserialize;
use vpnctl_core::{CoreError, Protocol, RenderCtx, Result, User};

pub(crate) const VLESSWS_BACKEND_PORT: u16 = 11443;

pub(crate) const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile";
pub(crate) const VLESSWS_SINGBOX_CONFIG: &str = "/etc/caddy/vlessws-singbox.json";
pub(crate) const VLESSWS_UNIT: &str = "caddy-vlessws";
pub(crate) const VLESSWS_DEPLOY_ENV: &str = "/etc/caddy/.vlessws-deploy.env";

pub(crate) const BUNDLE_DELIMITER: &str = "====FILE: ";
pub(crate) const BUNDLE_DELIMITER_END: &str = "====";

#[derive(Debug, Deserialize)]
pub(crate) struct NaiveEnvelope {
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) acme_email: String,
    pub(crate) auth: Vec<NaiveAuth>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NaiveAuth {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VlessWsEnvelope {
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) acme_email: String,
    pub(crate) front_port: u16,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) users: Vec<VlessWsUser>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VlessWsUser {
    pub(crate) uuid: String,
    #[serde(default)]
    pub(crate) name: String,
}

pub(crate) fn render_vlessws_bundle(
    ctx: &RenderCtx<'_>,
    users: &[User],
    proto: &dyn Protocol,
) -> Result<Vec<u8>> {
    let env_json = proto.server_inbound(ctx, users)?;
    let env: VlessWsEnvelope = serde_json::from_value(env_json)
        .map_err(|e| CoreError::Render(format!("vless-ws envelope parse: {e}")))?;

    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if env.domain.trim().is_empty() || env.domain.contains(ILLEGAL) {
        return Err(CoreError::Render(format!(
            "vless-ws domain is empty or contains illegal characters: {:?}",
            env.domain
        )));
    }
    if env.acme_email.contains(ILLEGAL) {
        return Err(CoreError::Render(format!(
            "vless-ws acme_email contains illegal characters: {:?}",
            env.acme_email
        )));
    }
    if !env.path.starts_with('/')
        || env.path.len() < 2
        || !env.path[1..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(CoreError::Render(format!(
            "vless-ws path must be `/<[A-Za-z0-9_-]+>`: {:?}",
            env.path
        )));
    }

    let has_users = !env.users.is_empty();

    let mut cf = String::with_capacity(1024);
    cf.push_str("# Rendered by vpnctl. Do not hand-edit \u{2014} your changes will be\n");
    cf.push_str("# overwritten on next `vpnctl deploy`.\n");
    cf.push_str("{\n");
    if !env.acme_email.trim().is_empty() {
        cf.push_str(&format!("\temail {}\n", env.acme_email));
    }
    cf.push_str("\tservers {\n\t\tprotocols h1 h2\n\t}\n");
    cf.push_str("\tlog {\n\t\texclude http.log.error\n\t}\n");
    cf.push_str("}\n\n");

    cf.push_str(&format!("{}:{} {{\n", env.domain, env.front_port));
    if !env.acme_email.trim().is_empty() {
        cf.push_str(&format!("\ttls {}\n", env.acme_email));
    }
    cf.push_str("\tencode\n");
    cf.push_str("\theader -Server\n");
    if has_users {
        cf.push_str(&format!("\t@vlessws path {}\n", env.path));
        cf.push_str(&format!(
            "\treverse_proxy @vlessws 127.0.0.1:{VLESSWS_BACKEND_PORT}\n"
        ));
    }
    cf.push_str("\tfile_server {\n\t\troot /var/www/naive-site\n\t}\n");
    cf.push_str("}\n");

    let inbounds = if has_users {
        let users_json: Vec<serde_json::Value> = env
            .users
            .iter()
            .map(|u| serde_json::json!({ "uuid": u.uuid, "name": u.name }))
            .collect();
        serde_json::json!([{
            "type": "vless",
            "tag": "vlessws-in",
            "listen": "127.0.0.1",
            "listen_port": VLESSWS_BACKEND_PORT,
            "users": users_json,
            "transport": { "type": "ws", "path": env.path }
        }])
    } else {
        serde_json::json!([])
    };
    let sb = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": inbounds,
        "outbounds": [ { "type": "direct", "tag": "direct" } ]
    });
    let sb_json = serde_json::to_string_pretty(&sb)
        .map_err(|e| CoreError::Render(format!("vless-ws sing-box config marshal: {e}")))?;

    let meta = format!("VLESSWS_FRONT_PORT={}\n", env.front_port);

    let mut bundle = String::with_capacity(cf.len() + sb_json.len() + meta.len() + 256);
    for (path, body) in [
        (CADDYFILE_PATH, cf.as_str()),
        (VLESSWS_SINGBOX_CONFIG, sb_json.as_str()),
        (VLESSWS_DEPLOY_ENV, meta.as_str()),
    ] {
        bundle.push_str(BUNDLE_DELIMITER);
        bundle.push_str(path);
        bundle.push_str(BUNDLE_DELIMITER_END);
        bundle.push('\n');
        bundle.push_str(body);
        if !body.ends_with('\n') {
            bundle.push('\n');
        }
    }
    Ok(bundle.into_bytes())
}

pub(crate) fn render_naive_config(
    ctx: &RenderCtx<'_>,
    users: &[User],
    naive: &dyn Protocol,
) -> Result<Vec<u8>> {
    let envelope_json = naive.server_inbound(ctx, users)?;
    let env: NaiveEnvelope = serde_json::from_value(envelope_json)
        .map_err(|e| CoreError::Render(format!("naive envelope parse: {e}")))?;

    if env.domain.trim().is_empty() {
        return Err(CoreError::Render(
            "naive requires a non-empty `naive.domain` secret".into(),
        ));
    }
    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if env.domain.contains(ILLEGAL) {
        return Err(CoreError::Render(format!(
            "naive.domain contains illegal characters: {:?}",
            env.domain
        )));
    }
    if env.acme_email.contains(ILLEGAL) {
        return Err(CoreError::Render(format!(
            "naive.acme_email contains illegal characters: {:?}",
            env.acme_email
        )));
    }
    for a in &env.auth {
        if a.username.contains(ILLEGAL) || a.password.contains(ILLEGAL) {
            return Err(CoreError::Render(format!(
                "naive basic_auth for '{}' contains illegal characters",
                a.username
            )));
        }
    }

    let mut out = String::with_capacity(1024);
    out.push_str("# Rendered by vpnctl. Do not hand-edit \u{2014} your changes will be\n");
    out.push_str("# overwritten on next `vpnctl deploy`.\n");
    out.push_str("{\n");
    out.push_str("\torder forward_proxy before file_server\n");
    if !env.acme_email.trim().is_empty() {
        out.push_str(&format!("\temail {}\n", env.acme_email));
    }
    out.push_str("\tlog {\n\t\texclude http.log.error\n\t}\n");
    out.push_str("}\n\n");

    out.push_str(&format!(":443, {} {{\n", env.domain));
    if !env.acme_email.trim().is_empty() {
        out.push_str(&format!("\ttls {}\n", env.acme_email));
    }
    out.push_str("\tencode\n");
    out.push_str("\theader -Server\n");

    if env.auth.is_empty() {
        out.push_str("\tfile_server {\n\t\troot /var/www/naive-site\n\t}\n");
    } else {
        out.push_str("\tforward_proxy {\n");
        for a in &env.auth {
            out.push_str(&format!("\t\tbasic_auth {} {}\n", a.username, a.password));
        }
        out.push_str("\t\thide_ip\n");
        out.push_str("\t\thide_via\n");
        out.push_str("\t\tprobe_resistance\n");
        out.push_str("\t}\n");
        out.push_str("\tfile_server {\n\t\troot /var/www/naive-site\n\t}\n");
    }
    out.push_str("}\n");

    Ok(out.into_bytes())
}

pub(crate) fn caddy_state_machine_prologue(
    caddyfile: &str,
    sb_config: &str,
    deploy_env: &str,
    vlessws_unit: &str,
) -> String {
    format!(
        r#"
            # Snapshot live configs and deploy env before swapping.
            # Snapshot cp failures must abort immediately under set -e before
            # the swap (no || true / error swallowing on existing configs).
            HAD_CADDYFILE_PREV=0
            if [ -f {caddyfile} ]; then
                cp -a {caddyfile} {caddyfile}.bak
                HAD_CADDYFILE_PREV=1
            fi

            HAD_SB_PREV=0
            if [ -f {sb_config} ]; then
                cp -a {sb_config} {sb_config}.bak
                HAD_SB_PREV=1
            fi

            HAD_DEPLOY_ENV_PREV=0
            if [ -f {deploy_env} ]; then
                cp -a {deploy_env} {deploy_env}.bak
                HAD_DEPLOY_ENV_PREV=1
            fi

            # Record pre-deploy enablement and active states before mutations.
            HAD_CADDY_ENABLED=0
            if systemctl is-enabled --quiet caddy 2>/dev/null; then
                HAD_CADDY_ENABLED=1
            fi
            HAD_CADDY_ACTIVE=0
            if systemctl is-active --quiet caddy 2>/dev/null; then
                HAD_CADDY_ACTIVE=1
            fi

            HAD_VLESSWS_ENABLED=0
            if systemctl is-enabled --quiet {vlessws_unit} 2>/dev/null; then
                HAD_VLESSWS_ENABLED=1
            fi
            HAD_VLESSWS_ACTIVE=0
            if systemctl is-active --quiet {vlessws_unit} 2>/dev/null; then
                HAD_VLESSWS_ACTIVE=1
            fi

            # Common non-recursive recovery state machine for post-first-swap failures.
            _in_recover=0
            recover() {{
                set +e
                [ "$_in_recover" = 1 ] && return 1
                _in_recover=1
                _failed="${{1:-}}"
                if [ -n "$_failed" ]; then
                    echo "$_failed did not become active. Last 20 log lines:" >&2
                    journalctl -u "$_failed" --no-pager -n 20 >&2 || true
                fi
                if [ "$HAD_CADDYFILE_PREV" = 1 ] && [ -f {caddyfile}.bak ]; then
                    echo "rolling back Caddyfile to previous config" >&2
                    mv {caddyfile}.bak {caddyfile} || true
                else
                    echo "no previous Caddyfile — removing failed deploy" >&2
                    rm -f {caddyfile} || true
                    rm -f {caddyfile}.bak || true
                fi
                if [ "$HAD_SB_PREV" = 1 ] && [ -f {sb_config}.bak ]; then
                    echo "rolling back backend config to previous config" >&2
                    mv {sb_config}.bak {sb_config} || true
                else
                    echo "no previous backend config — removing failed deploy" >&2
                    rm -f {sb_config} || true
                    rm -f {sb_config}.bak || true
                fi
                if [ "$HAD_DEPLOY_ENV_PREV" = 1 ] && [ -f {deploy_env}.bak ]; then
                    mv {deploy_env}.bak {deploy_env} || true
                else
                    rm -f {deploy_env} || true
                    rm -f {deploy_env}.bak || true
                fi
                if [ "$HAD_VLESSWS_ENABLED" = 1 ]; then
                    systemctl enable {vlessws_unit} >/dev/null 2>&1 || true
                else
                    systemctl disable {vlessws_unit} >/dev/null 2>&1 || true
                fi
                if [ "$HAD_VLESSWS_ACTIVE" = 1 ]; then
                    systemctl restart {vlessws_unit} || true
                else
                    systemctl stop {vlessws_unit} || true
                fi
                if [ "$HAD_CADDY_ENABLED" = 1 ]; then
                    systemctl enable caddy >/dev/null 2>&1 || true
                else
                    systemctl disable caddy >/dev/null 2>&1 || true
                fi
                if [ "$HAD_CADDY_ACTIVE" = 1 ]; then
                    systemctl reload-or-restart caddy || true
                else
                    systemctl stop caddy || true
                fi
                exit 1
            }}
        "#,
        caddyfile = caddyfile,
        sb_config = sb_config,
        deploy_env = deploy_env,
        vlessws_unit = vlessws_unit,
    )
}

pub(crate) fn vlessws_apply_script() -> String {
    let prologue = caddy_state_machine_prologue(
        CADDYFILE_PATH,
        VLESSWS_SINGBOX_CONFIG,
        VLESSWS_DEPLOY_ENV,
        VLESSWS_UNIT,
    );
    format!(
        r#"
            set -eu
            BUNDLE=/etc/caddy/.vlessws-bundle.new
            test -f "$BUNDLE"

            # Unpack the bundle. awk splits on
            # the marker line and writes each member to `<path>.new`.
            awk '
                BEGIN {{ outfile = ""; }}
                /^====FILE: .*====$/ {{
                    if (outfile != "") {{ close(outfile); }}
                    path = $0
                    sub(/^====FILE: /, "", path)
                    sub(/====$/, "", path)
                    outfile = path ".new"
                    next
                }}
                {{
                    if (outfile != "") {{ print > outfile }}
                }}
            ' "$BUNDLE"

            # Validate the NEW Caddyfile BEFORE swapping (a bad Caddyfile
            # must never take down the running edge).
            /usr/local/bin/caddy validate --config {caddyfile}.new
{prologue}
            # Atomic swaps + perms. Every post-first-swap fallible filesystem command routes via || recover "".
            mv {caddyfile}.new {caddyfile} || recover ""
            chown caddy:caddy {caddyfile} || recover ""
            chmod 0644 {caddyfile} || recover ""
            mv {sb_config}.new {sb_config} || recover ""
            chown root:root {sb_config} || recover ""
            chmod 0644 {sb_config} || recover ""
            mv {deploy_env}.new {deploy_env} || recover ""
            chmod 0644 {deploy_env} || recover ""
            rm -f "$BUNDLE" || recover ""

            # Firewall: open ACME :80 + the operator-chosen front port
            # (best-effort; a host without ufw is a clean no-op). The front
            # port comes from the rendered meta member.
            if command -v ufw >/dev/null 2>&1; then
                ufw allow 80/tcp >/dev/null 2>&1 || true
                . {deploy_env} 2>/dev/null || true
                if [ -n "${{VLESSWS_FRONT_PORT:-}}" ]; then
                    ufw allow "${{VLESSWS_FRONT_PORT}}/tcp" >/dev/null 2>&1 || true
                fi
            fi

            # Restart the BACKEND (loopback sing-box) FIRST so caddy's
            # reverse_proxy upstream is reachable when caddy reloads.
            systemctl enable {vlessws_unit} >/dev/null 2>&1 || recover "{vlessws_unit}"
            systemctl restart {vlessws_unit} || recover "{vlessws_unit}"

            systemctl enable caddy >/dev/null 2>&1 || recover "caddy"
            systemctl reload-or-restart caddy || recover "caddy"

            # Poll BOTH units. caddy's first ACME issue can take ~20 s, so 15x2 s.
            for s in {vlessws_unit} caddy; do
                ok=0
                for i in $(seq 1 15); do
                    state=$(systemctl is-active "$s" 2>/dev/null || true)
                    if [ "$state" = "active" ]; then
                        ok=1
                        break
                    fi
                    sleep 2
                done
                if [ "$ok" != 1 ]; then
                    recover "$s"
                fi
            done

            # Both units up — drop transient snapshots best-effort (never fatal / never recover).
            rm -f {caddyfile}.bak || true
            rm -f {sb_config}.bak || true
            rm -f {deploy_env}.bak || true
        "#,
        caddyfile = CADDYFILE_PATH,
        sb_config = VLESSWS_SINGBOX_CONFIG,
        deploy_env = VLESSWS_DEPLOY_ENV,
        vlessws_unit = VLESSWS_UNIT,
        prologue = prologue,
    )
}

pub(crate) fn naive_apply_script() -> String {
    let prologue = caddy_state_machine_prologue(
        CADDYFILE_PATH,
        VLESSWS_SINGBOX_CONFIG,
        VLESSWS_DEPLOY_ENV,
        VLESSWS_UNIT,
    );
    format!(
        r#"
            set -eu

            # Validate the NEW Caddyfile BEFORE swapping.
            /usr/local/bin/caddy validate --config {caddyfile}.new
{prologue}
            # Atomic swap + perms. Every post-first-swap fallible filesystem command routes via || recover "".
            mv {caddyfile}.new {caddyfile} || recover ""
            chown caddy:caddy {caddyfile} || recover ""
            chmod 0644 {caddyfile} || recover ""

            # Enable and reload-or-restart caddy.
            systemctl enable caddy >/dev/null 2>&1 || recover "caddy"
            systemctl reload-or-restart caddy || recover "caddy"

            # Poll caddy active state.
            ok=0
            for i in $(seq 1 15); do
                state=$(systemctl is-active caddy 2>/dev/null || true)
                if [ "$state" = "active" ]; then
                    ok=1
                    break
                fi
                sleep 2
            done
            if [ "$ok" != 1 ]; then
                recover "caddy"
            fi

            # Retire stale VLESS-WS backend only after Caddy is active.
            # Stop, disable, and live artifact deletion are checked and route to recover while snapshots exist.
            if [ "$HAD_VLESSWS_ACTIVE" = 1 ] || [ "$HAD_VLESSWS_ENABLED" = 1 ] || [ -f {sb_config} ] || [ -f {sb_config}.bak ] || systemctl is-active --quiet {vlessws_unit} 2>/dev/null || systemctl is-enabled --quiet {vlessws_unit} 2>/dev/null; then
                systemctl stop {vlessws_unit} || recover "{vlessws_unit}"
                systemctl disable {vlessws_unit} || recover "{vlessws_unit}"
            fi
            rm -f {sb_config} || recover ""
            rm -f {deploy_env} || recover ""
            rm -f {sb_config}.bak || true
            rm -f {deploy_env}.bak || true
            rm -f {caddyfile}.bak || true
        "#,
        caddyfile = CADDYFILE_PATH,
        sb_config = VLESSWS_SINGBOX_CONFIG,
        deploy_env = VLESSWS_DEPLOY_ENV,
        vlessws_unit = VLESSWS_UNIT,
        prologue = prologue,
    )
}
