use std::collections::HashMap;
use std::fmt;

use crate::error::Result;
use crate::id::ProtocolId;
use crate::models::{RenderCtx, User};

/// Протоколы — **stateless**. Ключи и прочие секреты приходят через
/// `RenderCtx::secrets`. Это позволяет инстанциировать `Protocol` один раз в
/// `Registry` (без знания ключей), а ключи на каждый деплой брать из
/// inventory.
pub trait Protocol: fmt::Debug + Send + Sync {
    fn id(&self) -> ProtocolId;

    /// Кусочек серверного inbound — например `{ "type": "vless", ... }`
    /// для sing-box. Ядро потом склеит inbound'ы вместе.
    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value>;

    /// Полный клиентский конфиг (sing-box / wireguard / etc).
    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value>;

    /// Share-link (`vless://...`, `tuic://...`, `wg://...`, и т.д.).
    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String>;

    /// What `(proto, port)` tuples this protocol's `server_inbound`
    /// is expected to listen on. Default empty so existing protocols
    /// without listening-side semantics (or where the port is
    /// runtime-configurable via secrets) don't have to opt in.
    ///
    /// **Used by:** `daemon::handlers::admin::server_detail` drift
    /// detection — compares this declaration against the live
    /// `node_probe` output and highlights mismatch.
    ///
    /// Implementations return `&'static [(&'static str, u16)]`
    /// (compile-time constants); no runtime cost. Adding a new
    /// protocol that wants drift coverage is one method override
    /// here — no daemon edits needed. (Caught by review-agent
    /// against the prior burst: hardcoding the map in admin.rs
    /// violated the kernel/protocol orthogonality invariant.)
    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[]
    }

    /// Effective `(proto, port)` tuples this protocol's inbound will bind
    /// on a SPECIFIC server, taking that server's secrets into account.
    /// Defaults to the static [`listen_ports`](Self::listen_ports);
    /// protocols whose port is runtime-configurable via a per-server secret
    /// (today: VLESS+REALITY's `vless.listen_port` co-tenant override)
    /// override this so the firewall step, the cross-protocol port-conflict
    /// guard and the admin drift table all see the REAL port instead of the
    /// compile-time default. Consumers that have server context MUST call
    /// this rather than `listen_ports`.
    fn effective_listen_ports(
        &self,
        _secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        self.listen_ports().to_vec()
    }

    /// Does this protocol's `client_config` belong in the legacy sing-box
    /// JSON response? Default `true`; protocols delivered only through
    /// dedicated artefacts (for example WireGuard) override this to `false`.
    fn appears_in_sing_box_sub(&self) -> bool {
        true
    }

    /// Does the same outbound work in stock sing-box? Defaults to the legacy
    /// decision so native protocols need no second override. Fork-only
    /// transports override this method while remaining available to legacy
    /// sing-box-lx/VPNRouter consumers.
    fn appears_in_stock_sing_box_sub(&self) -> bool {
        self.appears_in_sing_box_sub()
    }

    /// How well this protocol resists DPI / active-probing in
    /// censorship environments (RU/IR/CN ASNs in 2026). Used by the
    /// admin UI to render a coloured risk chip next to each enabled
    /// protocol, downscale the font of `Weak` rows, and surface an
    /// explainer tooltip — operator decides whether to keep the
    /// protocol on, `hide` it (NM-10), or hard-disable it.
    ///
    /// Default is `Moderate` — every protocol's `server_inbound` is
    /// some flavour of obfuscated TLS / QUIC, so a moderate default
    /// reflects "not trivially fingerprintable, but not certified
    /// best-of-breed either". Implementations that have a clearer
    /// position (REALITY's `dest:` active-probe forwarding; raw
    /// WireGuard's fixed 4-byte handshake type tag; Shadowsocks-2022's
    /// high-entropy first byte) override.
    ///
    /// NM-12 (Pavel 2026-05-20): «давай начнём с того что ты уберёшь
    /// чтото плохие протоколы и пометишь их в ui как плохие и можешь
    /// даже шрифт меньше сделать у них». This is the trait-level
    /// substrate for that UI work — the admin templates read
    /// `Registry::protocol(pid).map(|p| p.dpi_risk())` and render
    /// accordingly. Adding a new protocol that wants risk coverage is
    /// one method override here; no admin / inventory edits needed.
    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Moderate
    }

    /// Server-side secrets this protocol needs minted before
    /// `server_inbound` can render. Default empty — protocols whose
    /// secrets are per-user (Trojan / AnyTLS user passwords) or
    /// generated node-side at deploy time (TUIC / Hysteria2 self-signed
    /// cert) need no pre-mint.
    ///
    /// **Used by:** `daemon::wizard_bootstrap::bootstrap_server_secrets`,
    /// which iterates a server's enabled protocols, collects these
    /// specs, and generates + persists any declared key that's absent —
    /// idempotently (a present key is never regenerated, so existing
    /// clients keep working). Adding a secret-bearing protocol is one
    /// override here; no daemon edits.
    ///
    /// Closes the orthogonality TODO that let `shadowsocks-2022` ship
    /// without its `ss2022.psk` ever getting minted by the wizard — the
    /// `kg` deploy 2026-05-30 failed at render with
    /// `MissingSecret { key: "ss2022.psk" }` because the minter
    /// hardcoded only vless / wireguard / hysteria2.
    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        Vec::new()
    }
}

/// A server-side secret a [`Protocol`] declares it needs minted before
/// its inbound can render. The bootstrap secret-minter
/// (`daemon::wizard_bootstrap::bootstrap_server_secrets`) generates +
/// persists any declared key that's absent.
///
/// Declarative (the protocol says WHAT, the minter does HOW) on
/// purpose: the crypto primitives stay centralised in the daemon
/// (which already depends on `vpnctl-crypto`), so the `protocols`
/// crate needs no crypto dependency and the byte-shape of every
/// generated secret has one source of truth. Adding a protocol that
/// needs an EXISTING kind is a one-line spec in its own file with zero
/// daemon edits (the orthogonality invariant); a genuinely new KIND
/// (rare) adds one match arm in the minter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSecretSpec {
    /// One random URL-safe-base64 password carrying `entropy_bytes` of
    /// entropy (minted via `vpnctl_crypto::gen_password`). For secrets
    /// consumed as an OPAQUE STRING (e.g. Hysteria2 Salamander obfs
    /// password) — NOT base64-decoded by the node daemon.
    Password {
        key: &'static str,
        entropy_bytes: usize,
    },
    /// Random raw key of `key_bytes`, encoded as STANDARD (padded)
    /// base64 (minted via `vpnctl_crypto::gen_base64_key`). For secrets
    /// the node daemon base64-DECODES back to raw key material — e.g. a
    /// Shadowsocks-2022 PSK (sing-box uses Go `base64.StdEncoding`, so a
    /// url-safe / unpadded string would fail to decode and reject the
    /// whole node config). Distinct from `Password` precisely because
    /// the encoding contract differs.
    Base64Key { key: &'static str, key_bytes: usize },
    /// x25519 keypair (REALITY) persisted as two keys
    /// (`vpnctl_crypto::gen_x25519_keypair`).
    X25519Keypair {
        private_key: &'static str,
        public_key: &'static str,
    },
    /// WireGuard (Curve25519) server keypair persisted as two keys
    /// (`vpnctl_crypto::gen_wireguard_keypair`).
    WireguardKeypair {
        private_key: &'static str,
        public_key: &'static str,
    },
    /// REALITY `short_id` — random 8-byte hex
    /// (`vpnctl_crypto::gen_short_id`).
    ShortId { key: &'static str },
}

/// DPI / active-probing resilience tier. Stored only in the registry
/// (compile-time const per protocol impl); never persisted.
///
/// - `Strong` — well-camouflaged: REALITY (TLS handshake to a real
///   upstream, active-probe defence via `dest:` forwarding), Naive
///   (Caddy with probe-resistant forwardproxy).
/// - `Moderate` — recognisable on careful active probing but not
///   trivially fingerprintable: TUIC v5, Hysteria2, AnyTLS, Trojan.
/// - `Weak` — known DPI-fingerprintable in 2026 RU/IR/CN:
///   Shadowsocks-2022 (high-entropy random from byte 0), raw
///   WireGuard (fixed `0x01 0x00 0x00 0x00` handshake initiation tag
///   trivially matched by TSPU / GFW).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiRisk {
    Strong,
    Moderate,
    Weak,
}

impl DpiRisk {
    /// Short label for the admin UI chip (≤10 chars to fit the
    /// existing row layout).
    pub fn label(self) -> &'static str {
        match self {
            DpiRisk::Strong => "DPI: strong",
            DpiRisk::Moderate => "DPI: moderate",
            DpiRisk::Weak => "DPI: weak",
        }
    }

    /// One-sentence explainer for the UI tooltip — surfaces the
    /// specific fingerprint or defence so the operator knows why
    /// the protocol earned its tier.
    pub fn tooltip(self) -> &'static str {
        match self {
            DpiRisk::Strong => {
                "Active-probe-resistant: TLS handshake to a real upstream / no fixed wire signature. Recommended."
            }
            DpiRisk::Moderate => {
                "Recognisable on careful active probing (QUIC version, AEAD-on-port-N) but not trivially blocked. Useful as a fallback."
            }
            DpiRisk::Weak => {
                "Trivially fingerprintable in RU/IR/CN 2026 (Shadowsocks high-entropy first byte, raw WireGuard 0x01 handshake tag, Trojan-without-fallback self-signed cert, Hysteria2 on legacy servers that lack the Salamander obfs secret — re-deploy mints it). Consider hiding via NM-10."
            }
        }
    }

    /// CSS variable name for the chip's border + text colour. Single
    /// source of truth — the admin UI's chip rendering calls these
    /// instead of repeating the `match` arms inline. Adding a future
    /// tier (e.g. `Critical`) is a one-spot edit. Review-agent NM-12
    /// flagged the original 4× duplication.
    ///
    /// The `var(--name, #hex)` fallback is the literal colour because
    /// `admin.css` doesn't (yet) define `--acc-good` / `--acc-bad` in
    /// `:root` — a theme that wants to override the palette can add
    /// them and these chips re-tint automatically.
    pub fn border_css(self) -> &'static str {
        match self {
            DpiRisk::Strong => "var(--acc-good, #2c5f2d)",
            DpiRisk::Moderate => "var(--rule)",
            DpiRisk::Weak => "var(--acc-bad, #97233f)",
        }
    }

    /// Text colour for the chip. Strong + Weak use the same value as
    /// their border (high-contrast "ok"/"bad" badge); Moderate uses
    /// `--mute` so the chip recedes into the dotted rule.
    pub fn text_css(self) -> &'static str {
        match self {
            DpiRisk::Strong => "var(--acc-good, #2c5f2d)",
            DpiRisk::Moderate => "var(--mute)",
            DpiRisk::Weak => "var(--acc-bad, #97233f)",
        }
    }
}
