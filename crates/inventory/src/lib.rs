//! Inventory — хранение состояния (servers/users/grants/audit).
//! В этом скелете — in-memory; в следующей итерации заменим на sqlx+sqlite.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vpnctl_core::{CoreError, Result, Server, ServerId, User, UserId};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct InMemoryInventory {
    servers: HashMap<String, Server>,
    users: HashMap<String, User>,
    /// `(user_id, server_id)` — кому на какие сервера дан доступ.
    grants: Vec<(String, String)>,
}

impl InMemoryInventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_server(&mut self, s: Server) -> Result<()> {
        if self.servers.contains_key(&s.id.0) {
            return Err(CoreError::Render(format!(
                "server {} already exists",
                s.id.0
            )));
        }
        self.servers.insert(s.id.0.clone(), s);
        Ok(())
    }

    pub fn add_user(&mut self, u: User) -> Result<()> {
        if self.users.contains_key(&u.id.0) {
            return Err(CoreError::Render(format!("user {} already exists", u.id.0)));
        }
        self.users.insert(u.id.0.clone(), u);
        Ok(())
    }

    pub fn grant(&mut self, user: &UserId, server: &ServerId) {
        let pair = (user.0.clone(), server.0.clone());
        if !self.grants.contains(&pair) {
            self.grants.push(pair);
        }
    }

    pub fn server(&self, id: &ServerId) -> Option<&Server> {
        self.servers.get(&id.0)
    }

    pub fn user(&self, id: &UserId) -> Option<&User> {
        self.users.get(&id.0)
    }

    pub fn users_for_server(&self, server: &ServerId) -> Vec<&User> {
        self.grants
            .iter()
            .filter(|(_, sid)| sid == &server.0)
            .filter_map(|(uid, _)| self.users.get(uid))
            .collect()
    }
}
