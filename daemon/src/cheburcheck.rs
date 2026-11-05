//! Bounded external observations; independent from VPN and SSH health.
mod client;
mod events;
mod models;

pub use client::Client;
pub use events::{ProbeAccumulator, SseDecoder, SseEvent};
pub use models::{
    DynamicPhase, DynamicResult, Failure, FailureCode, ListResult, ProbeReport, Report,
};

const MAX_STATIC_BYTES: usize = 128 * 1024;
const MAX_SSE_BYTES: usize = 512 * 1024;
const MAX_EVENT_BYTES: usize = 32 * 1024;
const MAX_REPORTS: usize = 256;
const MAX_CONTEXT_BYTES: usize = 2048;
const MAX_TEXT_BYTES: usize = 512;
const MAX_VERDICT_BYTES: usize = 64;
