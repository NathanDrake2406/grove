use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LinesCodec};

// === Error Types ===

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connection failed: {0}")]
    Connection(std::io::Error),

    #[error("daemon not running (socket not found: {0})")]
    DaemonNotRunning(PathBuf),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

// === Response Type ===

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonResponse {
    pub ok: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

// === Client ===

pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Send a request to the daemon and return its response.
    ///
    /// Opens a new Unix socket connection, sends a single NDJSON line,
    /// reads a single NDJSON response line, and returns the parsed response.
    pub async fn request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<DaemonResponse, ClientError> {
        if !self.socket_path.exists() {
            return Err(ClientError::DaemonNotRunning(self.socket_path.clone()));
        }

        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(ClientError::Connection)?;

        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        let request = serde_json::json!({
            "method": method,
            "params": params,
        });
        let request_line = serde_json::to_string(&request)?;

        framed
            .send(request_line)
            .await
            .map_err(|e| ClientError::Protocol(format!("failed to send request: {e}")))?;

        let response_line = framed
            .next()
            .await
            .ok_or_else(|| ClientError::Protocol("connection closed before response".to_string()))?
            .map_err(|e| ClientError::Protocol(format!("failed to read response: {e}")))?;

        let response: DaemonResponse = serde_json::from_str(&response_line)?;
        Ok(response)
    }

    // === Convenience Methods ===

    pub async fn status(&self) -> Result<DaemonResponse, ClientError> {
        self.request("status", serde_json::json!({})).await
    }

    pub async fn shutdown(&self, token: Option<&str>) -> Result<DaemonResponse, ClientError> {
        let params = match token {
            Some(token) => serde_json::json!({ "token": token }),
            None => serde_json::json!({}),
        };
        self.request("shutdown", params).await
    }

    pub async fn list_workspaces(&self) -> Result<DaemonResponse, ClientError> {
        self.request("list_workspaces", serde_json::json!({})).await
    }

    pub async fn get_workspace(&self, workspace_id: &str) -> Result<DaemonResponse, ClientError> {
        self.request(
            "get_workspace",
            serde_json::json!({ "workspace_id": workspace_id }),
        )
        .await
    }

    pub async fn conflicts(
        &self,
        workspace_a: &str,
        workspace_b: &str,
    ) -> Result<DaemonResponse, ClientError> {
        self.request(
            "conflicts",
            serde_json::json!({
                "workspace_a": workspace_a,
                "workspace_b": workspace_b,
            }),
        )
        .await
    }

    pub async fn get_all_analyses(&self) -> Result<DaemonResponse, ClientError> {
        self.request("get_all_analyses", serde_json::json!({}))
            .await
    }

    pub async fn sync_worktrees(
        &self,
        worktrees: serde_json::Value,
    ) -> Result<DaemonResponse, ClientError> {
        self.request("sync_worktrees", serde_json::json!({ "worktrees": worktrees }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Serialization/Deserialization Tests ===

    #[test]
    fn deserialize_success_response() {
        let json = r#"{"ok": true, "data": {"workspace_count": 3}}"#;
        let response: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert_eq!(response.data.unwrap()["workspace_count"], 3);
        assert!(response.error.is_none());
    }

    #[test]
    fn deserialize_error_response() {
        let json = r#"{"ok": false, "error": "workspace not found"}"#;
        let response: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(!response.ok);
        assert!(response.data.is_none());
        assert_eq!(response.error.unwrap(), "workspace not found");
    }

    #[test]
    fn deserialize_success_with_null_data() {
        let json = r#"{"ok": true, "data": null}"#;
        let response: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert!(response.data.is_none());
    }

    #[test]
    fn deserialize_response_with_array_data() {
        let json = r#"{"ok": true, "data": [{"id": "abc"}, {"id": "def"}]}"#;
        let response: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        let data = response.data.unwrap();
        assert_eq!(data.as_array().unwrap().len(), 2);
    }

    #[test]
    fn deserialize_response_ignores_unknown_fields() {
        let json = r#"{"ok": true, "data": {"workspace_count": 3}, "extra": {"debug": true}}"#;
        let response: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert_eq!(response.data.unwrap()["workspace_count"], 3);
        assert!(response.error.is_none());
    }

    #[test]
    fn deserialize_response_rejects_missing_ok_field() {
        let json = r#"{"data": {"workspace_count": 3}}"#;
        let response: Result<DaemonResponse, _> = serde_json::from_str(json);
        assert!(response.is_err());
    }

    #[test]
    fn deserialize_response_rejects_non_boolean_ok() {
        let json = r#"{"ok": "true", "data": {"workspace_count": 3}}"#;
        let response: Result<DaemonResponse, _> = serde_json::from_str(json);
        assert!(response.is_err());
    }

    #[test]
    fn deserialize_response_rejects_truncated_json() {
        let json = r#"{"ok": true, "data": {"workspace_count": 3}"#;
        let response: Result<DaemonResponse, _> = serde_json::from_str(json);
        assert!(response.is_err());
    }

    #[test]
    fn deserialize_error_response_preserves_unicode() {
        let json = r#"{"ok": false, "error": "parse failed at λ.rs: 你好 🚫"}"#;
        let response: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("parse failed at λ.rs: 你好 🚫")
        );
    }

    #[test]
    fn request_json_serializes_correctly() {
        let request = serde_json::json!({
            "method": "conflicts",
            "params": {
                "workspace_a": "id-a",
                "workspace_b": "id-b",
            },
        });
        let line = serde_json::to_string(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["method"], "conflicts");
        assert_eq!(parsed["params"]["workspace_a"], "id-a");
        assert_eq!(parsed["params"]["workspace_b"], "id-b");
    }

    #[test]
    fn shutdown_request_json_serializes_correctly() {
        let request = serde_json::json!({
            "method": "shutdown",
            "params": {},
        });
        let line = serde_json::to_string(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["method"], "shutdown");
        assert_eq!(parsed["params"], serde_json::json!({}));
    }

    // === Connection Error Tests ===

    #[tokio::test]
    async fn connecting_to_nonexistent_socket_returns_daemon_not_running() {
        let client = DaemonClient::new("/tmp/grove-test-nonexistent-socket.sock");
        let result = client.status().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientError::DaemonNotRunning(path) => {
                assert_eq!(
                    path,
                    PathBuf::from("/tmp/grove-test-nonexistent-socket.sock")
                );
            }
            other => panic!("expected DaemonNotRunning, got: {other}"),
        }
    }

    #[test]
    fn client_stores_socket_path() {
        let client = DaemonClient::new("/tmp/test.sock");
        assert_eq!(client.socket_path(), Path::new("/tmp/test.sock"));
    }

    #[test]
    fn client_error_display_messages() {
        let err = ClientError::DaemonNotRunning(PathBuf::from("/tmp/test.sock"));
        assert_eq!(
            err.to_string(),
            "daemon not running (socket not found: /tmp/test.sock)"
        );

        let err = ClientError::Protocol("unexpected EOF".to_string());
        assert_eq!(err.to_string(), "protocol error: unexpected EOF");
    }
}
