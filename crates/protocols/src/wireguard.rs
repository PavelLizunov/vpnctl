//! WireGuard protocol — wire format clients consume. The Kernel that
//! actually runs WireGuard on the node (today: AmneziaWG with anti-DPI
//! obfuscation; future: vanilla `wg-quick`) reads this module's
//! `server_inbound()` envelope and transforms it into its native
//! config format (INI for wg-quick / amneziawg-tools, JSON for
//! sing-box's hypothetical `wireguard` inbound).
//!
//! # Envelope schema (the trait-impedance fix)
//!
//! `Protocol::server_inbound` returns `serde_json::Value`. AmneziaWG
//! renders INI, not JSON — so we'd hit a trait-impedance problem if
//! the Protocol returned a sing-box-flavoured JSON config. Instead,
//! this module returns a STABLE ENVELOPE that any Kernel can
//! deserialise into a typed struct and transform.
//!
//! Envelope shape (JSON, byte-stable across runs — uses BTreeMap
//! ordering for the `peers` field if applicable; users vec is iterated
//! in caller-provided order which is `inv.users_for_server`'s
//! lex-sorted-by-id order):
//!
//! ```json
//! {
//!   "type": "wireguard",
//!   "tag": "wg-in",
//!   "listen_port": 51820,
//!   "private_key": "<base64 server private key>",
//!   "address_cidr": "10.66.0.1/24",
//!   "peers": [
//!     { "name": "alex", "public_key": "<base64 user pubkey>", "allowed_ips": "10.66.0.2/32" }
//!   ]
//! }
//! ```
//!
//! Per-peer `allowed_ips` is computed deterministically from the
//! peer's index in the `users` slice: `10.66.0.<2 + index>/32`. This
//! is stable across re-renders provided callers pass users in the
//! same order each time (which `inv.users_for_server` does — it
//! `ORDER BY id`s).
//!
//! # Per-user contract
//!
//! Users with `wireguard_pubkey == None` are SKIPPED (not an error)
//! in `server_inbound` so a partially-provisioned node still deploys.
//! Same user → `share_link` is a HARD ERROR (the operator is asking
//! for something that can't possibly work). Same split as Hysteria2's
//! `tuic_password` handling.
//!
//! Pubkey validation: 44 chars, base64 (`[A-Za-z0-9+/]{43}=`). Reject
//! malformed early so a typo doesn't reach `awg setconf` and crash
//! the kernel module.
//!
//! # Client config
//!
//! `client_config` returns an envelope SUITABLE for transformation
//! into a client `.conf` file. The CLIENT private key is emitted as
//! a placeholder (`"<PASTE YOUR PRIVATE KEY HERE>"`) — vpnctl never
//! sees it. The operator (or AmneziaVPN's import flow) substitutes
//! it. Standard self-hosted-WireGuard UX.
//!
//! # Share link
//!
//! `wireguard://?conf=<base64url(.conf bytes)>#<user-id>`. Not an
//! IETF-blessed URI; chosen for stability + universal QR encoding.
//! AmneziaVPN clients accept it. Vanilla WireGuard mobile apps don't,
//! but the user-detail page already shows the raw conf alongside the
//! QR (operator can paste manually).
//!
//! Stateless, like every other Protocol in this crate.

mod amnezia;
mod helpers;
mod protocol;
mod render;

#[cfg(test)]
mod tests;

pub use amnezia::{amnezia_share_link, awg_share_link};
pub use helpers::{CLIENT_PRIVKEY_PLACEHOLDER, WIREGUARD_PORT, is_valid_wg_pubkey};
pub use protocol::WireGuard;
pub use render::render_client_conf_public;
