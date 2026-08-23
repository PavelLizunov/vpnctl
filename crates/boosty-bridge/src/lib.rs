//! Boosty → vpnctl provisioning bridge.
//!
//! Reconciles VPN access with Boosty subscription state: an active
//! subscriber's linked user is enabled, a lapsed subscriber's linked user
//! is disabled (soft-mute — secrets/uuid/device_id/grants preserved, so
//! re-subscribing restores access byte-for-byte). Only users LINKED to a
//! Boosty subscriber are ever touched (see [`reconcile`]).
//!
//! The pure decision logic lives in [`reconcile`]; [`sync_once`] is the
//! I/O orchestration (fetch subscribers → reconcile → apply).

mod client;
mod reconcile;
mod roster;
mod sync;
mod types;

pub use client::build_client;
pub use reconcile::{Action, LinkedUser, SubscriberState, reconcile};
pub use sync::{
    sync_from_inventory, sync_from_settings, sync_from_settings_at, sync_once,
    sync_once_with_policy,
};
pub use types::{
    ApplyMode, BridgeError, NewSubscriberInfo, SubscriberSnapshot, SyncReport, sync_failure_summary,
};
