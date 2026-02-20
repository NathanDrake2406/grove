use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use grove_lib::WorkspaceId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LinesCodec};
use tracing::{debug, error, info, warn};

use crate::state::{QueryRequest, QueryResponse, StateMessage};

// === Error Types ===

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("failed to bind socket at {path}: {source}")]
    Bind {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("connection error: {0}")]
    Connection(#[from] std::io::Error),

    #[error("json serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("state channel closed")]
    StateChannelClosed,

    #[error("response channel closed")]
    ResponseChannelClosed,

    #[error("codec error: {0}")]
    Codec(String),
}

// === Protocol Types ===

#[derive(Debug, Clone, Deserialize)]
pub struct SocketRequest {
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SocketResponse {
    pub fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

// === Request Parsing ===

fn parse_request(request: &SocketRequest) -> Result<QueryRequest, String> {
    match request.method.as_str() {
        "status" => Ok(QueryRequest::GetStatus),
        "list_workspaces" => Ok(QueryRequest::ListWorkspaces),
        "get_workspace" => {
            let workspace_id = request
                .params
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing required param: workspace_id".to_string())?;
            let workspace_id: WorkspaceId = workspace_id
                .parse()
                .map_err(|e| format!("invalid workspace_id: {e}"))?;
            Ok(QueryRequest::GetWorkspace { workspace_id })
        }
        "conflicts" => {
            let workspace_a = request
                .params
                .get("workspace_a")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing required param: workspace_a".to_string())?;
            let workspace_b = request
                .params
                .get("workspace_b")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing required param: workspace_b".to_string())?;
            let workspace_a: WorkspaceId = workspace_a
                .parse()
                .map_err(|e| format!("invalid workspace_a: {e}"))?;
            let workspace_b: WorkspaceId = workspace_b
                .parse()
                .map_err(|e| format!("invalid workspace_b: {e}"))?;
            Ok(QueryRequest::GetPairAnalysis {
                workspace_a,
                workspace_b,
            })
        }
        "get_all_analyses" => Ok(QueryRequest::GetAllAnalyses),
        other => Err(format!("unknown method: {other}")),
    }
}

// === Response Conversion ===

fn query_response_to_socket(response: QueryResponse) -> SocketResponse {
    match response {
        QueryResponse::Workspaces(workspaces) => {
            match serde_json::to_value(&workspaces) {
                Ok(data) => SocketResponse::success(data),
                Err(e) => SocketResponse::error(format!("serialization error: {e}")),
            }
        }
        QueryResponse::Workspace(maybe_ws) => match maybe_ws {
            Some(ws) => match serde_json::to_value(&ws) {
                Ok(data) => SocketResponse::success(data),
                Err(e) => SocketResponse::error(format!("serialization error: {e}")),
            },
            None => SocketResponse::error("workspace not found"),
        },
        QueryResponse::PairAnalysis(maybe_analysis) => match maybe_analysis {
            Some(analysis) => match serde_json::to_value(&analysis) {
                Ok(data) => SocketResponse::success(data),
                Err(e) => SocketResponse::error(format!("serialization error: {e}")),
            },
            None => SocketResponse::error("pair analysis not found"),
        },
        QueryResponse::AllAnalyses(analyses) => match serde_json::to_value(&analyses) {
            Ok(data) => SocketResponse::success(data),
            Err(e) => SocketResponse::error(format!("serialization error: {e}")),
        },
        QueryResponse::Status {
            workspace_count,
            analysis_count,
            base_commit,
        } => {
            let data = serde_json::json!({
                "workspace_count": workspace_count,
                "analysis_count": analysis_count,
                "base_commit": base_commit,
            });
            SocketResponse::success(data)
        }
    }
}

// === Socket Server ===

pub struct SocketServer {
    path: PathBuf,
    state_tx: mpsc::Sender<StateMessage>,
}

impl SocketServer {
    pub fn new(path: impl Into<PathBuf>, state_tx: mpsc::Sender<StateMessage>) -> Self {
        Self {
            path: path.into(),
            state_tx,
        }
    }

    /// Run the socket server, accepting connections until shutdown is signaled.
    pub async fn run(
        &self,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), SocketError> {
        // Clean up stale socket file if it exists
        Self::cleanup_socket(&self.path);

        let listener = UnixListener::bind(&self.path).map_err(|e| SocketError::Bind {
            path: self.path.clone(),
            source: e,
        })?;

        info!(path = %self.path.display(), "socket server listening");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            debug!("accepted new connection");
                            let state_tx = self.state_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, state_tx).await {
                                    warn!(error = %e, "connection handler error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "failed to accept connection");
                            // Continue accepting — transient errors shouldn't kill the server.
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("socket server received shutdown signal");
                    break;
                }
            }
        }

        Self::cleanup_socket(&self.path);
        info!("socket server stopped");
        Ok(())
    }

    fn cleanup_socket(path: &Path) {
        if path.exists() && let Err(e) = std::fs::remove_file(path) {
            warn!(path = %path.display(), error = %e, "failed to clean up stale socket");
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

// === Connection Handler ===

async fn handle_connection(
    stream: UnixStream,
    state_tx: mpsc::Sender<StateMessage>,
) -> Result<(), SocketError> {
    // LinesCodec with a 1 MiB max line length to prevent unbounded allocations
    let codec = LinesCodec::new_with_max_length(1_048_576);
    let mut framed = Framed::new(stream, codec);

    while let Some(line_result) = framed.next().await {
        let line = match line_result {
            Ok(line) => line,
            Err(e) => {
                let response = SocketResponse::error(format!("protocol error: {e}"));
                let response_json = serde_json::to_string(&response)?;
                if let Err(send_err) = framed.send(response_json).await {
                    debug!(error = %send_err, "failed to send error response");
                }
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = handle_request(&line, &state_tx).await;
        let response_json = serde_json::to_string(&response)?;

        if let Err(e) = framed.send(response_json).await {
            debug!(error = %e, "failed to send response, client likely disconnected");
            break;
        }
    }

    debug!("connection closed");
    Ok(())
}

async fn handle_request(
    line: &str,
    state_tx: &mpsc::Sender<StateMessage>,
) -> SocketResponse {
    // Parse the JSON request
    let request: SocketRequest = match serde_json::from_str(line) {
        Ok(req) => req,
        Err(e) => return SocketResponse::error(format!("invalid JSON: {e}")),
    };

    debug!(method = %request.method, "handling request");

    // Parse into a QueryRequest
    let query = match parse_request(&request) {
        Ok(q) => q,
        Err(e) => return SocketResponse::error(e),
    };

    // Send to state actor and await response
    let (reply_tx, reply_rx) = oneshot::channel();
    let message = StateMessage::Query {
        request: query,
        reply: reply_tx,
    };

    if state_tx.send(message).await.is_err() {
        return SocketResponse::error("daemon state unavailable");
    }

    match reply_rx.await {
        Ok(response) => query_response_to_socket(response),
        Err(_) => SocketResponse::error("state actor did not respond"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{GroveConfig, spawn_state_actor};
    use tokio::net::UnixStream;
    use uuid::Uuid;

    // === Unit tests for request parsing ===

    #[test]
    fn parse_status_request() {
        let req = SocketRequest {
            method: "status".to_string(),
            params: serde_json::json!({}),
        };
        let result = parse_request(&req);
        assert!(matches!(result, Ok(QueryRequest::GetStatus)));
    }

    #[test]
    fn parse_list_workspaces_request() {
        let req = SocketRequest {
            method: "list_workspaces".to_string(),
            params: serde_json::json!({}),
        };
        let result = parse_request(&req);
        assert!(matches!(result, Ok(QueryRequest::ListWorkspaces)));
    }

    #[test]
    fn parse_get_workspace_request() {
        let id = Uuid::new_v4();
        let req = SocketRequest {
            method: "get_workspace".to_string(),
            params: serde_json::json!({"workspace_id": id.to_string()}),
        };
        let result = parse_request(&req).unwrap();
        match result {
            QueryRequest::GetWorkspace { workspace_id } => {
                assert_eq!(workspace_id, id);
            }
            other => panic!("expected GetWorkspace, got: {other:?}"),
        }
    }

    #[test]
    fn parse_conflicts_request() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let req = SocketRequest {
            method: "conflicts".to_string(),
            params: serde_json::json!({
                "workspace_a": id_a.to_string(),
                "workspace_b": id_b.to_string(),
            }),
        };
        let result = parse_request(&req).unwrap();
        match result {
            QueryRequest::GetPairAnalysis {
                workspace_a,
                workspace_b,
            } => {
                assert_eq!(workspace_a, id_a);
                assert_eq!(workspace_b, id_b);
            }
            other => panic!("expected GetPairAnalysis, got: {other:?}"),
        }
    }

    #[test]
    fn parse_get_all_analyses_request() {
        let req = SocketRequest {
            method: "get_all_analyses".to_string(),
            params: serde_json::json!({}),
        };
        let result = parse_request(&req);
        assert!(matches!(result, Ok(QueryRequest::GetAllAnalyses)));
    }

    #[test]
    fn parse_unknown_method_returns_error() {
        let req = SocketRequest {
            method: "foobar".to_string(),
            params: serde_json::json!({}),
        };
        let result = parse_request(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown method: foobar"));
    }

    #[test]
    fn parse_get_workspace_missing_id_returns_error() {
        let req = SocketRequest {
            method: "get_workspace".to_string(),
            params: serde_json::json!({}),
        };
        let result = parse_request(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("workspace_id"));
    }

    #[test]
    fn parse_get_workspace_invalid_uuid_returns_error() {
        let req = SocketRequest {
            method: "get_workspace".to_string(),
            params: serde_json::json!({"workspace_id": "not-a-uuid"}),
        };
        let result = parse_request(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid workspace_id"));
    }

    // === Unit tests for response construction ===

    #[test]
    fn socket_response_success_serializes_correctly() {
        let resp = SocketResponse::success(serde_json::json!({"count": 5}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["data"]["count"], 5);
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn socket_response_error_serializes_correctly() {
        let resp = SocketResponse::error("something went wrong");
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"], "something went wrong");
        assert!(parsed.get("data").is_none());
    }

    // === Unit tests for JSON deserialization of SocketRequest ===

    #[test]
    fn deserialize_status_request_from_json() {
        let json = r#"{"method": "status", "params": {}}"#;
        let req: SocketRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "status");
    }

    #[test]
    fn deserialize_request_with_missing_params_uses_default() {
        let json = r#"{"method": "status"}"#;
        let req: SocketRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "status");
        assert!(req.params.is_null());
    }

    #[test]
    fn deserialize_invalid_json_returns_error() {
        let json = r#"not valid json"#;
        let result = serde_json::from_str::<SocketRequest>(json);
        assert!(result.is_err());
    }

    // === Integration tests: full round-trip with a real socket ===

    #[tokio::test]
    async fn round_trip_status_request() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await
        });

        // Wait briefly for the server to start listening
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect as a client
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        // Send status request
        framed
            .send(r#"{"method": "status", "params": {}}"#.to_string())
            .await
            .unwrap();

        // Read response
        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();

        assert_eq!(response["ok"], true);
        assert_eq!(response["data"]["workspace_count"], 0);
        assert_eq!(response["data"]["analysis_count"], 0);

        // Shut down
        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn round_trip_list_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        framed
            .send(r#"{"method": "list_workspaces", "params": {}}"#.to_string())
            .await
            .unwrap();

        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();

        assert_eq!(response["ok"], true);
        assert!(response["data"].as_array().unwrap().is_empty());

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn round_trip_invalid_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        framed
            .send("this is not valid json".to_string())
            .await
            .unwrap();

        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();

        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("invalid JSON"));

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn round_trip_unknown_method_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        framed
            .send(r#"{"method": "nonexistent", "params": {}}"#.to_string())
            .await
            .unwrap();

        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("unknown method"));

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn round_trip_multiple_requests_on_one_connection() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        // First request: status
        framed
            .send(r#"{"method": "status", "params": {}}"#.to_string())
            .await
            .unwrap();
        let resp1 = framed.next().await.unwrap().unwrap();
        let resp1: serde_json::Value = serde_json::from_str(&resp1).unwrap();
        assert_eq!(resp1["ok"], true);

        // Second request: list_workspaces
        framed
            .send(r#"{"method": "list_workspaces", "params": {}}"#.to_string())
            .await
            .unwrap();
        let resp2 = framed.next().await.unwrap().unwrap();
        let resp2: serde_json::Value = serde_json::from_str(&resp2).unwrap();
        assert_eq!(resp2["ok"], true);

        // Third request: get_all_analyses
        framed
            .send(r#"{"method": "get_all_analyses", "params": {}}"#.to_string())
            .await
            .unwrap();
        let resp3 = framed.next().await.unwrap().unwrap();
        let resp3: serde_json::Value = serde_json::from_str(&resp3).unwrap();
        assert_eq!(resp3["ok"], true);

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }
}
