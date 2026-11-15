//! Owned, serialized corporate exit observations. No production runner is installed.
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Semaphore, oneshot};
use tokio::time::Instant;
use vpnctl_core::ServerId;
use vpnctl_inventory::{CorpRecord, CorpStoreError, CorpVerifiedEgress};
use zeroize::Zeroizing;

use crate::AppState;
use crate::corp_portal::eligibility::{CorpProbePlan, eligible_servers, probe_plan};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    #[error("exit probing is unavailable")]
    Unavailable,
    #[error("exit probe target was not found")]
    NotFound,
    #[error("exit probing is busy")]
    Busy,
    #[error("exit probe configuration changed")]
    Conflict,
    #[error("exit probe failed")]
    Failed,
    #[error("exit probe cleanup failed")]
    CleanupFailed,
}

pub struct ProbeRequest {
    pub outbound: serde_json::Value,
    pub token: Zeroizing<String>,
}
impl std::fmt::Debug for ProbeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProbeRequest { .. }")
    }
}
#[async_trait::async_trait]
pub trait ProbeRunner: std::fmt::Debug + Send + Sync {
    fn available(&self) -> bool;
    async fn run(&self, request: ProbeRequest) -> Result<(), ProbeError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptState {
    Idle,
    Running,
    Verified,
    Failed,
    Conflict,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub state: AttemptState,
    pub finished_at: Option<i64>,
}

pub struct ProbeTicket {
    receiver: oneshot::Receiver<Result<(), ProbeError>>,
}
impl std::fmt::Debug for ProbeTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProbeTicket { .. }")
    }
}
impl ProbeTicket {
    pub async fn wait(self) -> Result<(), ProbeError> {
        self.receiver.await.unwrap_or(Err(ProbeError::Failed))
    }
}
struct Challenge {
    hash: [u8; 32],
    expires: Instant,
    observation: Option<IpAddr>,
}
#[derive(Default)]
struct Private {
    challenge: Option<Challenge>,
    attempts: HashMap<ServerId, Attempt>,
}
pub struct EgressController {
    runner: Arc<dyn ProbeRunner>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    permit: Arc<Semaphore>,
    poisoned: AtomicBool,
    private: Mutex<Private>,
    cursor: AtomicUsize,
    scan: Semaphore,
}
impl std::fmt::Debug for EgressController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EgressController { .. }")
    }
}
#[derive(Debug)]
struct Disabled;
#[async_trait::async_trait]
impl ProbeRunner for Disabled {
    fn available(&self) -> bool {
        false
    }
    async fn run(&self, _: ProbeRequest) -> Result<(), ProbeError> {
        Err(ProbeError::Unavailable)
    }
}
// Also runs during unwinding or task teardown; an incomplete helper cannot be reused.
struct JobGuard {
    controller: Arc<EgressController>,
    server: ServerId,
    complete: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl JobGuard {
    fn mark_complete(&mut self) {
        self.complete = true;
    }
}
impl Drop for JobGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.controller.poisoned.store(true, Ordering::SeqCst);
            if let Ok(mut private) = self.controller.private.lock() {
                private.challenge = None;
                private.attempts.insert(
                    self.server.clone(),
                    Attempt {
                        state: AttemptState::Failed,
                        finished_at: None,
                    },
                );
            }
        }
    }
}
impl EgressController {
    pub fn new(runner: Arc<dyn ProbeRunner>, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            runner,
            clock,
            permit: Arc::new(Semaphore::new(1)),
            poisoned: AtomicBool::new(false),
            private: Mutex::new(Private::default()),
            cursor: AtomicUsize::new(0),
            scan: Semaphore::new(1),
        }
    }
    pub fn disabled() -> Self {
        Self::new(
            Arc::new(Disabled),
            Arc::new(|| chrono::Utc::now().timestamp()),
        )
    }
    pub fn available(&self) -> bool {
        !self.poisoned.load(Ordering::SeqCst)
            && !self.private.is_poisoned()
            && self.runner.available()
    }
    pub fn attempt(&self, server: &ServerId) -> Attempt {
        self.private
            .lock()
            .ok()
            .and_then(|p| p.attempts.get(server).copied())
            .unwrap_or(Attempt {
                state: AttemptState::Idle,
                finished_at: None,
            })
    }
    pub fn observe(&self, token: &str, ip: IpAddr) -> Result<(), ProbeError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| ProbeError::Failed)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != token {
            return Err(ProbeError::Failed);
        }
        let ip = canonical(ip);
        let IpAddr::V4(v4) = ip else {
            return Err(ProbeError::Failed);
        };
        if v4.is_unspecified()
            || v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_multicast()
        {
            return Err(ProbeError::Failed);
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut p = self.private.lock().map_err(|_| ProbeError::Failed)?;
        let c = p.challenge.as_mut().ok_or(ProbeError::Failed)?;
        if Instant::now() >= c.expires
            || c.observation.is_some()
            || !bool::from(c.hash.ct_eq(&hash))
        {
            return Err(ProbeError::Failed);
        }
        c.observation = Some(ip);
        Ok(())
    }
    pub async fn queue_probe(
        self: &Arc<Self>,
        app: AppState,
        expected_config_version: u64,
        server: ServerId,
    ) -> Result<ProbeTicket, ProbeError> {
        if !self.available() {
            return Err(ProbeError::Unavailable);
        }
        let permit = Arc::clone(&self.permit)
            .try_acquire_owned()
            .map_err(|_| ProbeError::Busy)?;
        let record = binding(&app, expected_config_version).await?;
        let plan = probe_plan(&app, &record.status.user_id, &server)
            .await
            .map_err(|_| ProbeError::Unavailable)?
            .ok_or(ProbeError::NotFound)?;
        if plan.outbounds.is_empty() || plan.outbounds.len() > 8 {
            return Err(ProbeError::Failed);
        }
        if !self.available() {
            return Err(ProbeError::Unavailable);
        }
        {
            let mut p = self.private.lock().map_err(|_| ProbeError::Unavailable)?;
            if !p.attempts.contains_key(&server) && p.attempts.len() >= 512 {
                let oldest = p
                    .attempts
                    .iter()
                    .filter(|(_, a)| a.state != AttemptState::Running)
                    .min_by_key(|(_, a)| a.finished_at)
                    .map(|(id, _)| id.clone());
                if let Some(id) = oldest {
                    p.attempts.remove(&id);
                } else {
                    return Err(ProbeError::Busy);
                }
            }
            p.attempts.insert(
                server.clone(),
                Attempt {
                    state: AttemptState::Running,
                    finished_at: None,
                },
            );
        }
        let (sender, receiver) = oneshot::channel();
        let controller = Arc::clone(self);
        let mut guard = JobGuard {
            controller: Arc::clone(&controller),
            server: server.clone(),
            complete: false,
            _permit: permit,
        };
        drop(tokio::spawn(async move {
            let result = controller.execute(&app, &record, plan).await;
            if result == Err(ProbeError::CleanupFailed) {
                controller.poisoned.store(true, Ordering::SeqCst);
            }
            controller.finish(&server, result);
            guard.mark_complete();
            drop(guard);
            let _ = sender.send(result);
        }));
        Ok(ProbeTicket { receiver })
    }
    fn finish(&self, server: &ServerId, result: Result<(), ProbeError>) {
        if let Ok(mut p) = self.private.lock() {
            p.challenge = None;
            let state = match result {
                Ok(()) => AttemptState::Verified,
                Err(ProbeError::Conflict) => AttemptState::Conflict,
                Err(ProbeError::Unavailable) => AttemptState::Unavailable,
                _ => AttemptState::Failed,
            };
            p.attempts.insert(
                server.clone(),
                Attempt {
                    state,
                    finished_at: Some((self.clock)()),
                },
            );
        }
    }
    async fn execute(
        &self,
        app: &AppState,
        record: &CorpRecord,
        plan: CorpProbePlan,
    ) -> Result<(), ProbeError> {
        let started = Instant::now();
        let wall_start = (self.clock)();
        if !valid_time(wall_start) {
            return Err(ProbeError::Failed);
        }
        let mut ips = BTreeSet::new();
        for outbound in plan.outbounds {
            if started.elapsed() >= Duration::from_secs(60) {
                return Err(ProbeError::Failed);
            }
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| ProbeError::Failed)?;
            let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
            let hash = Sha256::digest(token.as_bytes()).into();
            self.private
                .lock()
                .map_err(|_| ProbeError::Failed)?
                .challenge = Some(Challenge {
                hash,
                expires: Instant::now() + Duration::from_secs(30),
                observation: None,
            });
            let result = self.runner.run(ProbeRequest { outbound, token }).await;
            let observed = self
                .private
                .lock()
                .map_err(|_| ProbeError::Failed)?
                .challenge
                .take()
                .and_then(|c| c.observation);
            result?;
            ips.insert(observed.ok_or(ProbeError::Failed)?);
        }
        let current = binding(app, record.status.config_version).await?;
        if current.status.user_id != record.status.user_id
            || current.status.policy_id != record.status.policy_id
        {
            return Err(ProbeError::Conflict);
        }
        let refreshed_plan = probe_plan(app, &current.status.user_id, &plan.server.server_id)
            .await
            .map_err(|_| ProbeError::Unavailable)?
            .ok_or(ProbeError::Conflict)?;
        if refreshed_plan.server.configuration_fingerprint != plan.server.configuration_fingerprint
        {
            return Err(ProbeError::Conflict);
        }
        let completed = (self.clock)();
        if !valid_time(completed) || completed < wall_start {
            return Err(ProbeError::Failed);
        }
        let previous = app.inv.corp_verified_egress().await.map_err(store_error)?;
        // Recheck the generation immediately before the durable storage CAS.
        binding(app, record.status.config_version).await?;
        let mut rows: Vec<_> = previous
            .iter()
            .filter(|r| r.server_id != plan.server.server_id)
            .cloned()
            .collect();
        rows.extend(ips.into_iter().map(|ip| CorpVerifiedEgress {
            server_id: plan.server.server_id.clone(),
            ip,
            configuration_fingerprint: plan.server.configuration_fingerprint.clone(),
            verified_at: completed,
        }));
        if identities(&previous) == identities(&rows) {
            app.inv
                .refresh_corp_egress(
                    record.status.config_version,
                    &previous,
                    &rows,
                    "corp.egress",
                )
                .await
                .map_err(store_error)?;
        } else {
            app.inv
                .replace_corp_egress(record.status.config_version, &rows, "corp.egress")
                .await
                .map_err(store_error)?;
        }
        Ok(())
    }
    pub async fn ready_to_enable(
        &self,
        app: &AppState,
        expected_config_version: u64,
    ) -> Result<bool, ProbeError> {
        if !self.available() {
            return Err(ProbeError::Unavailable);
        }
        let record = binding(app, expected_config_version).await?;
        let eligible = eligible_servers(app, &record.status.user_id)
            .await
            .map_err(|_| ProbeError::Unavailable)?;
        let rows = app.inv.corp_verified_egress().await.map_err(store_error)?;
        let now = (self.clock)();
        if !valid_time(now) {
            return Err(ProbeError::Failed);
        }
        if !self.available() {
            return Err(ProbeError::Unavailable);
        }
        Ok(rows.iter().any(|r| {
            fresh(r, now, 86400)
                && eligible.iter().any(|s| {
                    s.server_id == r.server_id
                        && s.configuration_fingerprint == r.configuration_fingerprint
                })
        }))
    }
    pub async fn refresh_due(self: &Arc<Self>, app: AppState) -> Result<(), ProbeError> {
        if !self.available() {
            return Err(ProbeError::Unavailable);
        }
        let _scan = self.scan.try_acquire().map_err(|_| ProbeError::Busy)?;
        let record = app
            .inv
            .corp_record()
            .await
            .map_err(store_error)?
            .ok_or(ProbeError::NotFound)?;
        let servers = eligible_servers(&app, &record.status.user_id)
            .await
            .map_err(|_| ProbeError::Unavailable)?;
        if servers.is_empty() {
            return Ok(());
        }
        let start = self.cursor.load(Ordering::SeqCst) % servers.len();
        for offset in 0..servers.len().min(4) {
            let index = (start + offset) % servers.len();
            self.cursor
                .store((index + 1) % servers.len(), Ordering::SeqCst);
            let server = &servers[index];
            let rows = app.inv.corp_verified_egress().await.map_err(store_error)?;
            let now = (self.clock)();
            if !valid_time(now) {
                return Err(ProbeError::Failed);
            }
            let matching: Vec<_> = rows
                .iter()
                .filter(|r| {
                    r.server_id == server.server_id
                        && r.configuration_fingerprint == server.configuration_fingerprint
                })
                .collect();
            if !matching.is_empty() && matching.iter().all(|r| fresh(r, now, 21599)) {
                continue;
            }
            let current = app
                .inv
                .corp_record()
                .await
                .map_err(store_error)?
                .ok_or(ProbeError::NotFound)?;
            match self
                .queue_probe(
                    app.clone(),
                    current.status.config_version,
                    server.server_id.clone(),
                )
                .await
            {
                Ok(ticket) => {
                    if ticket.wait().await == Err(ProbeError::CleanupFailed) {
                        return Err(ProbeError::Unavailable);
                    }
                }
                Err(ProbeError::Busy) => return Err(ProbeError::Busy),
                Err(ProbeError::Unavailable) => return Err(ProbeError::Unavailable),
                Err(_) => {}
            }
        }
        Ok(())
    }
}
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}
fn valid_time(now: i64) -> bool {
    (1..=253402300799).contains(&now)
}
fn fresh(r: &CorpVerifiedEgress, now: i64, max_age: i64) -> bool {
    r.verified_at > 0 && r.verified_at <= now && now - r.verified_at <= max_age
}
fn identities(rows: &[CorpVerifiedEgress]) -> BTreeSet<(String, IpAddr, String)> {
    rows.iter()
        .map(|r| {
            (
                r.server_id.0.clone(),
                canonical(r.ip),
                r.configuration_fingerprint.clone(),
            )
        })
        .collect()
}
fn store_error(error: CorpStoreError) -> ProbeError {
    match error {
        CorpStoreError::Conflict => ProbeError::Conflict,
        _ => ProbeError::Unavailable,
    }
}
async fn binding(app: &AppState, version: u64) -> Result<CorpRecord, ProbeError> {
    let record = app
        .inv
        .corp_record()
        .await
        .map_err(store_error)?
        .ok_or(ProbeError::NotFound)?;
    if record.status.config_version != version {
        return Err(ProbeError::Conflict);
    }
    if app
        .inv
        .get_user(&record.status.user_id)
        .await
        .map_err(|_| ProbeError::Unavailable)?
        .is_none_or(|u| u.disabled)
    {
        return Err(ProbeError::Unavailable);
    }
    Ok(record)
}
pub fn spawn_refresh(app: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(30),
            Duration::from_secs(600),
        );
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            let _ = app.corp_egress.refresh_due(app.clone()).await;
        }
    })
}
