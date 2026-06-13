use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Shadowsocks 2022 (AEAD-2022) — TCP-based proxy with a different
/// wire fingerprint than VLESS/TUIC/Hysteria. Useful as a **fallback
/// when REALITY gets actively detected on a given network**: clients
/// can fail-over to ss-2022 on the same node and likely keep working
/// while the operator rotates the REALITY material.
///
/// # Single-user mode (v0.4 limitation)
///
/// AEAD-2022 ciphers REQUIRE the user-key to be exactly the cipher's
/// key length (16 bytes for `2022-blake3-aes-128-gcm`, 32 for the
/// other two). Our `User.tuic_password` is 24 bytes random base64 —
/// doesn't fit either size, so we can't reuse it for per-user
/// authentication.
///
/// For v0.4 we ship **single-user mode**: one server-wide PSK in
/// `ss2022.psk`, all clients on the node use that same key. Same
/// security model as a Wi-Fi password: rotation invalidates every
/// client at once, no per-user revocation. Acceptable for a
/// single-tenant homelab where Pavel is the sole operator and
/// per-user attribution lives at the VLESS/TUIC layer anyway.
///
/// Multi-user mode would need a new `User.shadowsocks_2022_psk`
/// column with a length-correct minted secret. Deferred.
///
/// # Method choice
///
/// Default: `2022-blake3-aes-128-gcm` (16-byte key). On AArch64 with
/// AES-NI it's the fastest. Operators can override via
/// `ss2022.method` for AES-256 or ChaCha20-Poly1305 paranoia /
/// non-AES-accelerated hardware.
///
/// # Listen port
///
/// TCP/8388 — standard Shadowsocks port. UDP relay is enabled
/// alongside (sing-box default for the `shadowsocks` inbound).
///
/// **Stateless**, like every other Protocol in this crate.
#[derive(Debug, Default)]
pub struct Shadowsocks2022;

impl Shadowsocks2022 {
    pub fn new() -> Self {
        Self
    }
}

/// Default AEAD-2022 cipher. Most common choice; matches widely-deployed
/// 16-byte key length so the example PSK hex/base64 in operator docs
/// stays simple.
const DEFAULT_METHOD: &str = "2022-blake3-aes-128-gcm";

const VALID_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// Listen port. Public so tests + UI handlers can format share-links
/// without duplicating the constant.
pub const SS_2022_PORT: u16 = 8388;

/// Percent-encode set for the **password** segment of a SIP002 SS URI.
/// Per-spec, AEAD-2022 URIs use plain `method:password` userinfo
/// with percent encoding (NOT base64url like older AEAD ciphers).
/// This set escapes everything that has special meaning in the
/// userinfo / authority / path of a URI **plus `:`** — `:` is the
/// `method:password` separator, and a literal `:` in a rotated PSK
/// would otherwise break parsers that split on the first colon.
const PASSWORD: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'@')
    .add(b'/')
    .add(b'\\')
    .add(b'[')
    .add(b']')
    .add(b':');

/// Fragment-only escape set for the `#tag` portion. `:` and `+`
/// don't need escaping inside a fragment.
const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

impl Protocol for Shadowsocks2022 {
    fn id(&self) -> ProtocolId {
        ProtocolId("shadowsocks-2022".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", SS_2022_PORT), ("udp", SS_2022_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Shadowsocks-2022 emits AEAD-encrypted random bytes from
        // byte 0 — there is NO TLS handshake, NO HTTP envelope, no
        // observable protocol structure. DPI engines flag the stream
        // by Shannon-entropy-from-first-byte heuristics (a real TCP
        // app protocol opens with a header band; SS opens with
        // uniform random). TSPU (RU) blocks SS-on-port-N on first
        // 10kB of traffic since 2024; GFW (CN) drops it on ASN
        // reputation alone. Active probing returns nothing
        // (replay-protected AEAD), so the probe cannot CONFIRM SS
        // — but the entropy fingerprint is already enough to drop.
        vpnctl_core::DpiRisk::Weak
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // Server-wide PSK shared by every client on the node. 16 raw
        // bytes = 128-bit for the default `2022-blake3-aes-128-gcm`
        // cipher; STANDARD base64 (24 chars, padded) because sing-box
        // base64-DECODES `password` with Go's `base64.StdEncoding` —
        // hence `Base64Key`, NOT `Password` (a url-safe/unpadded string
        // would fail to decode and reject the whole node config).
        //
        // THIS is the spec whose absence broke the `kg` deploy
        // 2026-05-30 (`MissingSecret { key: "ss2022.psk" }`): the
        // wizard minter hardcoded vless/wireguard/hysteria2 only.
        vec![vpnctl_core::ServerSecretSpec::Base64Key {
            key: "ss2022.psk",
            key_bytes: 16,
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, _users: &[User]) -> Result<serde_json::Value> {
        // PSK is REQUIRED — without it the inbound can't decrypt.
        // We refuse rather than render a broken config; the caller
        // (deploy command) surfaces this as a clear "missing secret"
        // error before SSH'ing to the node.
        let psk = ctx.require("ss2022.psk")?;

        // Method validation — sing-box silently fails on a typo'd
        // method string, leaving operators chasing "why isn't anyone
        // connecting" through journalctl. Reject up front.
        let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
        if !VALID_METHODS.contains(&method) {
            return Err(CoreError::Render(format!(
                "shadowsocks-2022 method '{method}' not supported (valid: {:?})",
                VALID_METHODS
            )));
        }

        Ok(json!({
            "type": "shadowsocks",
            "tag": "ss22-in",
            "listen": "::",
            "listen_port": SS_2022_PORT,
            "method": method,
            "password": psk,
            // sing-box defaults to TCP+UDP relay; explicit network
            // declaration would lock UDP off if we typed it wrong.
            // Leaving it implicit matches both the bash project's
            // existing ss inbounds and sing-box's documented default.
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, _user: &User) -> Result<serde_json::Value> {
        // Single-user mode: every client uses the server PSK as their
        // password. No per-user differentiation here; per-user
        // attribution (when needed) comes from VLESS/TUIC inbounds
        // on the same node.
        let psk = ctx.require("ss2022.psk")?;
        let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
        if !VALID_METHODS.contains(&method) {
            return Err(CoreError::Render(format!(
                "shadowsocks-2022 method '{method}' not supported (valid: {:?})",
                VALID_METHODS
            )));
        }
        Ok(json!({
            "type": "shadowsocks",
            "tag": "ss22-out",
            "server": ctx.server.address,
            "server_port": SS_2022_PORT,
            "method": method,
            "password": psk,
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let psk = ctx.require("ss2022.psk")?;
        let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
        if !VALID_METHODS.contains(&method) {
            return Err(CoreError::Render(format!(
                "shadowsocks-2022 method '{method}' not supported (valid: {:?})",
                VALID_METHODS
            )));
        }
        // SIP002 URI scheme:
        //   ss://<method>:<password-pct-encoded>@<host>:<port>/#<tag>
        // For AEAD-2022, userinfo is the LITERAL `method:password`
        // string with percent encoding (NOT base64url-encoded like
        // older AEAD ciphers). Confirmed by SIP002 spec at
        // https://shadowsocks.org/doc/sip002.html — clients that
        // base64-decode the userinfo on AEAD-2022 are explicitly
        // wrong per spec.
        //
        // Important: encode `method` and `password` SEPARATELY then
        // join with a literal `:`. The PASSWORD set escapes `:` so
        // a rotated PSK that happens to contain `:` doesn't split
        // the userinfo in the wrong place. Method strings are
        // alphanumeric+hyphen so they need no encoding, but we
        // still run them through the same set defensively (no-op
        // for valid methods).
        let pw_enc = utf8_percent_encode(psk, PASSWORD);
        let method_enc = utf8_percent_encode(method, PASSWORD);
        let tag_enc = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "ss://{method_enc}:{pw_enc}@{addr}:{port}/#{tag_enc}",
            method_enc = method_enc,
            pw_enc = pw_enc,
            addr = host_for_url(&ctx.server.address),
            port = SS_2022_PORT,
            tag_enc = tag_enc,
        ))
    }
}
