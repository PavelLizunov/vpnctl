use std::collections::HashMap;

use vpnctl_core::{Server, ServerId, User, UserId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BashInventoryEnv {
    pub server_ip: String,
    pub ssh_port: u16,
    pub reality_public: String,
    pub short_id: String,
    pub users: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BashVlessUser {
    pub name: String,
    pub uuid: String,
    pub flow: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BashTuicUser {
    pub name: String,
    pub uuid: String,
    pub password: String,
}

#[derive(Clone, Debug, Default)]
pub struct BashSingboxData {
    pub vless_users: Vec<BashVlessUser>,
    pub tuic_users: Vec<BashTuicUser>,
    pub reality_private: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedUser {
    pub name: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct MigrationPlan {
    pub server: Server,
    pub server_secrets: HashMap<String, String>,
    pub users_to_import: Vec<User>,
    pub grants: Vec<(UserId, ServerId)>,
    pub skipped: Vec<SkippedUser>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MigrationOutcome {
    pub server_created: bool,
    pub server_already_existed: bool,
    pub server_address_updated: bool,
    pub secrets_set: usize,
    pub users_created: usize,
    pub users_overwritten: Vec<String>,
    pub users_skipped_existing: Vec<String>,
    pub grants_made: usize,
    pub other_server_grants_preserved: Vec<String>,
}
