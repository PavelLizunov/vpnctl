use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::{
    DynamicPhase, DynamicResult, Failure, FailureCode, MAX_EVENT_BYTES, MAX_REPORTS, MAX_SSE_BYTES,
    MAX_TEXT_BYTES, MAX_VERDICT_BYTES, ProbeReport,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: String,
}

#[derive(Clone, Default)]
pub struct SseDecoder {
    line: Vec<u8>,
    event: String,
    data: String,
    has_data: bool,
    total_bytes: usize,
    failed: bool,
}

impl std::fmt::Debug for SseDecoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SseDecoder")
            .field("buffered_bytes", &self.buffered_bytes())
            .field("total_bytes", &self.total_bytes)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, Failure> {
        if self.failed {
            return Err(Failure::new(FailureCode::InvalidResponse));
        }
        let result = self.decode(chunk);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn decode(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, Failure> {
        self.total_bytes = self.total_bytes.saturating_add(chunk.len());
        if self.total_bytes > MAX_SSE_BYTES {
            return Err(Failure::new(FailureCode::ResponseLimit));
        }
        let mut events = Vec::new();
        for byte in chunk {
            if *byte == b'\n' {
                if let Some(event) = self.finish_line()? {
                    events.push(event);
                }
            } else {
                if self.buffered_bytes() >= MAX_EVENT_BYTES {
                    return Err(Failure::new(FailureCode::ResponseLimit));
                }
                self.line.push(*byte);
            }
        }
        Ok(events)
    }

    fn buffered_bytes(&self) -> usize {
        self.line
            .len()
            .saturating_add(self.event.len())
            .saturating_add(self.data.len())
    }

    fn finish_line(&mut self) -> Result<Option<SseEvent>, Failure> {
        let mut bytes = std::mem::take(&mut self.line);
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        let line =
            std::str::from_utf8(&bytes).map_err(|_| Failure::new(FailureCode::InvalidResponse))?;
        if line.is_empty() {
            let event = if !self.has_data {
                None
            } else {
                Some(SseEvent {
                    event: if self.event.is_empty() {
                        "message".into()
                    } else {
                        std::mem::take(&mut self.event)
                    },
                    data: std::mem::take(&mut self.data),
                })
            };
            self.event.clear();
            self.data.clear();
            self.has_data = false;
            return Ok(event);
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => self.event = value.to_owned(),
            "data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            _ => {}
        }
        Ok(None)
    }
}

#[derive(Clone, Default)]
pub struct ProbeAccumulator {
    result: DynamicResult,
    observer_ids: HashSet<String>,
    terminal: bool,
}

impl std::fmt::Debug for ProbeAccumulator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProbeAccumulator")
            .field("result", &self.result)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Started {
    online_probes: u32,
}

#[derive(Clone, Copy, Deserialize)]
struct Done {
    response_count: u32,
    online_probes: u32,
}

#[derive(Deserialize)]
struct Observer {
    probe_id: String,
    #[serde(default)]
    cached: bool,
    region: Option<String>,
    provider: Option<String>,
    asn: Option<String>,
    verdicts: Vec<String>,
    target_hop: Option<u16>,
    dpi_hop: Option<u16>,
}

impl ProbeAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: &str, data: &str) -> Result<bool, Failure> {
        if !matches!(event, "started" | "result" | "done") {
            return Ok(false);
        }
        let result = self.apply_known(event, data);
        if result.is_err() {
            self.terminal = true;
            self.result.phase = if self.result.reports.is_empty() {
                DynamicPhase::Unavailable
            } else {
                DynamicPhase::Partial
            };
        }
        result
    }

    pub fn snapshot(&self) -> DynamicResult {
        self.result.clone()
    }

    fn apply_known(&mut self, event: &str, data: &str) -> Result<bool, Failure> {
        if self.terminal {
            return Err(Failure::new(FailureCode::InvalidResponse));
        }
        if data.len() > MAX_EVENT_BYTES {
            return Err(Failure::new(FailureCode::ResponseLimit));
        }
        match event {
            "started" => {
                let value: Started = parse(data)?;
                if self
                    .result
                    .online_probes
                    .is_some_and(|count| count != value.online_probes)
                {
                    return Err(Failure::new(FailureCode::InvalidResponse));
                }
                self.result.online_probes = Some(value.online_probes);
                self.result.phase = DynamicPhase::Running;
                Ok(false)
            }
            "result" => self.add_observer(parse(data)?),
            "done" => self.finish(parse(data)?),
            _ => Ok(false),
        }
    }

    fn add_observer(&mut self, value: Observer) -> Result<bool, Failure> {
        let online = self
            .result
            .online_probes
            .ok_or_else(|| Failure::new(FailureCode::InvalidResponse))?;
        if value.probe_id.is_empty() || value.probe_id.len() > MAX_TEXT_BYTES {
            return Err(Failure::new(FailureCode::InvalidResponse));
        }
        if self.observer_ids.contains(&value.probe_id) {
            return Ok(false);
        }
        if self.result.reports.len() >= MAX_REPORTS {
            return Err(Failure::new(FailureCode::ResponseLimit));
        }
        if self.result.reports.len() as u64 >= u64::from(online) {
            return Err(Failure::new(FailureCode::InvalidResponse));
        }
        if [&value.region, &value.provider, &value.asn]
            .into_iter()
            .any(|field| {
                field
                    .as_ref()
                    .is_some_and(|text| text.len() > MAX_TEXT_BYTES)
            })
            || value.verdicts.len() > 16
            || value
                .verdicts
                .iter()
                .any(|text| text.is_empty() || text.len() > MAX_VERDICT_BYTES)
        {
            return Err(Failure::new(FailureCode::ResponseLimit));
        }
        self.observer_ids.insert(value.probe_id);
        self.result.reports.push(ProbeReport {
            region: value.region,
            provider: value.provider,
            asn: value.asn,
            cached: value.cached,
            verdicts: value.verdicts,
            target_hop: value.target_hop,
            dpi_hop: value.dpi_hop,
        });
        Ok(false)
    }

    fn finish(&mut self, value: Done) -> Result<bool, Failure> {
        let count = u32::try_from(self.result.reports.len())
            .map_err(|_| Failure::new(FailureCode::ResponseLimit))?;
        if self.result.online_probes != Some(value.online_probes)
            || value.response_count != count
            || count > value.online_probes
        {
            return Err(Failure::new(FailureCode::InvalidResponse));
        }
        self.terminal = true;
        if value.online_probes == 0 {
            self.result.phase = DynamicPhase::Unavailable;
            return Err(Failure::new(FailureCode::NoObservers));
        }
        self.result.phase = DynamicPhase::Done;
        Ok(true)
    }
}

fn parse<T: serde::de::DeserializeOwned>(data: &str) -> Result<T, Failure> {
    serde_json::from_str(data).map_err(|_| Failure::new(FailureCode::InvalidResponse))
}
