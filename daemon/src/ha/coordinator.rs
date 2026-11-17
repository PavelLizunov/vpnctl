#[derive(Debug, Clone)]
pub struct HaConfig {
    pub node_id: String,
    pub stop_budget_ms: u64,
    pub max_replica_age_ms: u64,
    pub schema_version: u64,
    pub build: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousLeader {
    pub node_id: String,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub holder: String,
    pub epoch: u64,
    pub expires_at_ms: u64,
    pub previous: Option<PreviousLeader>,
}

#[derive(Debug, Clone)]
pub struct ReplicaProof {
    pub verified_at_ms: u64,
    pub inventory_revision: u64,
    pub required_revision: u64,
    pub schema_version: u64,
    pub build: String,
    pub integrity_verified: bool,
    pub identities_verified: bool,
}

#[derive(Debug, Clone)]
pub struct FenceProof {
    pub previous_node_id: String,
    pub previous_epoch: u64,
    pub successor_epoch: u64,
    pub external_actions_fenced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Isolated,
    Follower,
    Candidate,
    Leader,
    Draining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    StopWorker,
}

#[derive(Debug)]
pub struct Coordinator {
    config: HaConfig,
    role: Role,
    lease: Option<Lease>,
    greatest_epoch: u64,
    retired_epoch: u64,
    worker_epoch: Option<u64>,
}

impl Coordinator {
    pub fn new(config: HaConfig) -> Result<Self, String> {
        if config.node_id.trim().is_empty() || config.build.trim().is_empty() {
            return Err("HA node identifier and build must be nonempty".into());
        }
        if config.stop_budget_ms == 0 || config.max_replica_age_ms == 0 {
            return Err("HA stop and replication age budgets must be positive".into());
        }
        Ok(Self {
            config,
            role: Role::Isolated,
            lease: None,
            greatest_epoch: 0,
            retired_epoch: 0,
            worker_epoch: None,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn observe(&mut self, lease: Option<Lease>, now_ms: u64) -> Action {
        self.tick(now_ms);
        let valid = lease.as_ref().is_some_and(|next| {
            self.structurally_valid(next, now_ms)
                && next.epoch > self.retired_epoch
                && (next.epoch > self.greatest_epoch
                    || next.epoch == self.greatest_epoch
                        && self.lease.as_ref().is_some_and(|old| {
                            old.holder == next.holder
                                && old.previous == next.previous
                                && next.expires_at_ms >= old.expires_at_ms
                        }))
        });
        if !valid {
            self.retire_current();
            self.lease = None;
        } else if let Some(next) = lease {
            if self.worker_epoch.is_some_and(|epoch| epoch != next.epoch)
                || self.worker_epoch.is_some() && next.holder != self.config.node_id
            {
                self.retire_current();
            }
            self.greatest_epoch = self.greatest_epoch.max(next.epoch);
            self.lease = Some(next);
        }
        self.refresh_role(now_ms);
        self.pending_action()
    }

    pub fn activate(
        &mut self,
        replica: &ReplicaProof,
        fence: Option<&FenceProof>,
        now_ms: u64,
    ) -> Result<(), String> {
        self.tick(now_ms);
        if self.role != Role::Candidate || self.worker_epoch.is_some() {
            return Err("HA controller is not a stopped candidate".into());
        }
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(|| "No quorum authority for activation".to_string())?;
        if !self.admission_valid(lease, now_ms) {
            return Err("Insufficient authority lifetime to safely fence the worker".into());
        }
        if replica.verified_at_ms > now_ms
            || now_ms - replica.verified_at_ms > self.config.max_replica_age_ms
        {
            return Err("Replica verification is stale or from the future".into());
        }
        if !replica.integrity_verified || !replica.identities_verified {
            return Err("Replica integrity and subscription identities must be verified".into());
        }
        if replica.inventory_revision < replica.required_revision {
            return Err("Replica has not reached the required inventory revision".into());
        }
        if replica.schema_version != self.config.schema_version
            || replica.build != self.config.build
        {
            return Err("Replica schema or controller build is incompatible".into());
        }
        if let Some(previous) = &lease.previous {
            let fenced = fence.is_some_and(|proof| {
                proof.external_actions_fenced
                    && proof.previous_node_id == previous.node_id
                    && proof.previous_epoch == previous.epoch
                    && proof.successor_epoch == lease.epoch
            });
            if !fenced {
                return Err("Previous controller external actions have not been fenced".into());
            }
        }
        self.worker_epoch = Some(lease.epoch);
        self.role = Role::Leader;
        Ok(())
    }

    pub fn tick(&mut self, now_ms: u64) -> Action {
        if self.lease.as_ref().is_some_and(|lease| {
            lease.expires_at_ms <= now_ms
                || lease.holder == self.config.node_id && !self.admission_valid(lease, now_ms)
        }) {
            self.retire_current();
            self.lease = None;
        }
        self.refresh_role(now_ms);
        self.pending_action()
    }

    pub fn worker_stopped(&mut self, now_ms: u64) {
        if let Some(epoch) = self.worker_epoch.take() {
            self.retired_epoch = self.retired_epoch.max(epoch);
        }
        self.tick(now_ms);
    }

    pub fn may_serve(&self, now_ms: u64) -> bool {
        self.role == Role::Leader
            && self.lease.as_ref().is_some_and(|lease| {
                self.worker_epoch == Some(lease.epoch) && self.admission_valid(lease, now_ms)
            })
    }

    fn structurally_valid(&self, lease: &Lease, now_ms: u64) -> bool {
        !lease.holder.trim().is_empty()
            && lease.epoch != 0
            && lease.expires_at_ms > now_ms
            && lease.previous.as_ref().is_none_or(|previous| {
                !previous.node_id.trim().is_empty()
                    && previous.epoch != 0
                    && previous.epoch < lease.epoch
            })
    }

    fn admission_valid(&self, lease: &Lease, now_ms: u64) -> bool {
        lease.holder == self.config.node_id
            && lease.epoch > self.retired_epoch
            && lease.expires_at_ms.saturating_sub(now_ms) > self.config.stop_budget_ms
    }

    fn retire_current(&mut self) {
        if let Some(lease) = &self.lease {
            self.retired_epoch = self.retired_epoch.max(lease.epoch);
        }
        if self.worker_epoch.is_some() {
            self.role = Role::Draining;
        }
    }

    fn refresh_role(&mut self, now_ms: u64) {
        self.role = if self.worker_epoch.is_some() {
            if self.role == Role::Draining {
                Role::Draining
            } else if self.lease.as_ref().is_some_and(|lease| {
                self.worker_epoch == Some(lease.epoch) && self.admission_valid(lease, now_ms)
            }) {
                Role::Leader
            } else {
                Role::Draining
            }
        } else {
            match &self.lease {
                Some(lease) if lease.epoch > self.retired_epoch && lease.expires_at_ms > now_ms => {
                    if lease.holder == self.config.node_id {
                        Role::Candidate
                    } else {
                        Role::Follower
                    }
                }
                _ => Role::Isolated,
            }
        };
    }

    fn pending_action(&self) -> Action {
        if self.role == Role::Draining {
            Action::StopWorker
        } else {
            Action::None
        }
    }
}
