//! SSH-транспорт.
//!
//! Реальная implementaion поверх `russh` появится во второй итерации.
//! Сейчас здесь только `MockTransport`, чтобы остальные крейты могли
//! компилироваться и тестироваться без сети.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use vpnctl_core::{CoreError, Result, SshTransport};

/// Учебно-тестовый транспорт. Запоминает заливки, отдаёт сконфигурированные
/// ответы на `exec`. Полезен для unit-тестов ядер без поднятия SSH-сервера.
#[derive(Debug, Default)]
pub struct MockTransport {
    exec_responses: Mutex<HashMap<String, String>>,
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            exec_responses: Mutex::new(HashMap::new()),
            files: Mutex::new(HashMap::new()),
        }
    }

    pub fn expect(&self, cmd: &str, response: &str) {
        if let Ok(mut g) = self.exec_responses.lock() {
            g.insert(cmd.to_string(), response.to_string());
        }
    }

    pub fn uploaded(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().ok()?.get(path).cloned()
    }
}

#[async_trait]
impl SshTransport for MockTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        let g = self
            .exec_responses
            .lock()
            .map_err(|_| CoreError::Transport("mock lock poisoned".into()))?;
        Ok(g.get(cmd).cloned().unwrap_or_default())
    }

    async fn upload(&self, path: &str, content: &[u8]) -> Result<()> {
        let mut g = self
            .files
            .lock()
            .map_err(|_| CoreError::Transport("mock lock poisoned".into()))?;
        g.insert(path.to_string(), content.to_vec());
        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let g = self
            .files
            .lock()
            .map_err(|_| CoreError::Transport("mock lock poisoned".into()))?;
        g.get(path)
            .cloned()
            .ok_or_else(|| CoreError::Transport(format!("no such file: {path}")))
    }
}
