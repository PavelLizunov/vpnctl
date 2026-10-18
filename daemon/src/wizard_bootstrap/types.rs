use std::path::PathBuf;

use serde::Serialize;

#[derive(Clone, Debug)]
pub struct BootstrapPlan {
    pub server_id: String,
    pub address: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub root_password: String,
    pub deploy_key_path: PathBuf,
    pub known_hosts_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootstrapEvent {
    Step {
        phase: &'static str,
        message: String,
    },
    Ok {
        server_id: String,
        redirect: String,
    },
    Error {
        phase: &'static str,
        message: String,
    },
}
