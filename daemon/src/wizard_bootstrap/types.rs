use std::path::PathBuf;

use serde::Serialize;

/// All the inputs the bootstrap needs. Built by the SSE handler from
/// the wizard session + the daemon's deploy key path.
#[derive(Clone, Debug)]
pub struct BootstrapPlan {
    /// Server id we're going to register the host as. Derived from
    /// `address` by `derive_server_id` so the operator doesn't have
    /// to invent a name (one-action ceiling).
    pub server_id: String,
    /// IPv4, IPv6 or hostname. Already validated by
    /// `crate::wizard::validate_address`.
    pub address: String,
    /// SSH login selected in step 1 (`root` by default).
    pub ssh_user: String,
    /// SSH port. Defaults to 22 — overridden when the step-1 form's
    /// optional port field is non-empty.
    pub ssh_port: u16,
    /// Root password — used ONCE to push the deploy pubkey, then
    /// every subsequent step uses key auth.
    pub root_password: String,
    /// Path to the daemon's deploy private key
    /// (`/var/lib/vpnctl/.ssh/id_ed25519` in production). The bootstrap
    /// reads `.pub` from this to push to `authorized_keys`.
    pub deploy_key_path: PathBuf,
    /// known_hosts file the daemon uses for subsequent connects.
    /// Defaults to `/var/lib/vpnctl/.ssh/known_hosts`. Tests override
    /// with a tempdir.
    pub known_hosts_path: PathBuf,
}

/// One event in the bootstrap progress stream. Serialised as JSON
/// into the SSE event payload.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootstrapEvent {
    /// Advisory progress. `phase` is a short machine-readable id
    /// (the browser groups consecutive events with the same phase);
    /// `message` is the human-readable text shown in the log pane.
    Step {
        phase: &'static str,
        message: String,
    },
    /// Terminal success. `server_id` is the registered id; `redirect`
    /// is the URL the browser should navigate to next (the server
    /// detail page).
    Ok { server_id: String, redirect: String },
    /// Terminal failure. `phase` is where it failed; `message` is
    /// the operator-readable reason. Stream ends after this — no more
    /// events.
    Error {
        phase: &'static str,
        message: String,
    },
}
