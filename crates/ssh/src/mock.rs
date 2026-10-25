use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use vpnctl_core::{CoreError, Result, SshTransport};

#[derive(Debug, Default)]
pub struct MockTransport {
    exec_responses: Mutex<HashMap<String, String>>,
    executed_commands: Mutex<Vec<String>>,
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn expect(&self, cmd: &str, response: &str) {
        if let Ok(mut g) = self.exec_responses.lock() {
            g.insert(cmd.to_string(), response.to_string());
        }
    }

    pub fn uploaded(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().ok()?.get(path).cloned()
    }

    pub fn executed_commands(&self) -> Result<Vec<String>> {
        self.executed_commands
            .lock()
            .map(|commands| commands.clone())
            .map_err(|_| CoreError::Transport("mock lock poisoned".into()))
    }
}

#[async_trait]
impl SshTransport for MockTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        self.executed_commands
            .lock()
            .map_err(|_| CoreError::Transport("mock lock poisoned".into()))?
            .push(cmd.to_string());
        let g = self
            .exec_responses
            .lock()
            .map_err(|_| CoreError::Transport("mock lock poisoned".into()))?;
        Ok(g.get(cmd).cloned().unwrap_or_default())
    }

    async fn exec_unprivileged(&self, cmd: &str) -> Result<String> {
        self.exec(cmd).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exec_returns_registered_response() -> Result<()> {
        let t = MockTransport::new();
        t.expect("uname -s", "Linux\n");
        assert_eq!(t.exec("uname -s").await?, "Linux\n");
        Ok(())
    }

    #[tokio::test]
    async fn executed_commands_records_calls_in_order_including_repeats() -> Result<()> {
        let t = MockTransport::new();
        t.expect("not executed", "unused response");
        assert!(t.executed_commands()?.is_empty());

        t.exec("id -u").await?;
        t.exec_unprivileged("whoami").await?;
        t.exec("id -u").await?;
        assert_eq!(t.executed_commands()?, ["id -u", "whoami", "id -u"]);
        Ok(())
    }

    #[tokio::test]
    async fn upload_then_read() -> Result<()> {
        let t = MockTransport::new();
        t.upload("/etc/sing-box/config.json", b"{}").await?;
        assert_eq!(t.read_file("/etc/sing-box/config.json").await?, b"{}");
        Ok(())
    }

    #[tokio::test]
    async fn read_missing_file_errors() {
        let t = MockTransport::new();
        let result = t.read_file("/nope").await;
        assert!(matches!(result, Err(CoreError::Transport(_))));
    }
}
