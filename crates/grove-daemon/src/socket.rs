use std::path::{Path, PathBuf};
use std::time::Duration;

use grove_lib::WorkspaceId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::state::{QueryRequest, QueryResponse, StateMessage};

#[cfg(test)]
use futures::{SinkExt, StreamExt};
#[cfg(test)]
use tokio_util::codec::{Framed, LinesCodec};

const MAX_NDJSON_LINE_BYTES: usize = 1_048_576;
const DEFAULT_IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_STATE_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

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

#[derive(Debug)]
enum ParsedRequest {
    Query(QueryRequest),
    SyncWorktrees { desired: Vec<grove_lib::Workspace> },
}

fn parse_request(request: &SocketRequest) -> Result<ParsedRequest, String> {
    match request.method.as_str() {
        "status" => Ok(ParsedRequest::Query(QueryRequest::GetStatus)),
        "list_workspaces" => Ok(ParsedRequest::Query(QueryRequest::ListWorkspaces)),
        "get_workspace" => {
            let workspace_id = request
                .params
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing required param: workspace_id".to_string())?;
            let workspace_id: WorkspaceId = workspace_id
                .parse()
                .map_err(|e| format!("invalid workspace_id: {e}"))?;
            Ok(ParsedRequest::Query(QueryRequest::GetWorkspace {
                workspace_id,
            }))
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
            Ok(ParsedRequest::Query(QueryRequest::GetPairAnalysis {
                workspace_a,
                workspace_b,
            }))
        }
        "get_all_analyses" => Ok(ParsedRequest::Query(QueryRequest::GetAllAnalyses)),
        "sync_worktrees" => {
            let worktrees = request
                .params
                .get("worktrees")
                .ok_or_else(|| "missing required param: worktrees".to_string())?;

            #[derive(serde::Deserialize)]
            struct WorktreeParam {
                name: String,
                path: String,
                branch: String,
                #[allow(dead_code)]
                head: String,
            }

            let params: Vec<WorktreeParam> = serde_json::from_value(worktrees.clone())
                .map_err(|e| format!("invalid worktrees param: {e}"))?;

            let desired: Vec<grove_lib::Workspace> = params
                .into_iter()
                .map(|p| {
                    let path = std::path::PathBuf::from(&p.path);
                    let id = uuid::Uuid::new_v5(
                        &uuid::Uuid::NAMESPACE_URL,
                        path.to_string_lossy().as_bytes(),
                    );
                    grove_lib::Workspace {
                        id,
                        name: p.name,
                        branch: p.branch,
                        path,
                        base_ref: String::new(),
                        created_at: chrono::Utc::now(),
                        last_activity: chrono::Utc::now(),
                        metadata: grove_lib::WorkspaceMetadata::default(),
                    }
                })
                .collect();

            Ok(ParsedRequest::SyncWorktrees { desired })
        }
        other => Err(format!("unknown method: {other}")),
    }
}

// === Response Conversion ===

fn query_response_to_socket(response: QueryResponse) -> SocketResponse {
    match response {
        QueryResponse::Workspaces(workspaces) => match serde_json::to_value(&workspaces) {
            Ok(data) => SocketResponse::success(data),
            Err(e) => SocketResponse::error(format!("serialization error: {e}")),
        },
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
    shutdown_trigger: Option<broadcast::Sender<()>>,
    shutdown_token: Option<String>,
    idle_connection_timeout: Duration,
    state_reply_timeout: Duration,
}

impl SocketServer {
    pub fn new(path: impl Into<PathBuf>, state_tx: mpsc::Sender<StateMessage>) -> Self {
        Self {
            path: path.into(),
            state_tx,
            shutdown_trigger: None,
            shutdown_token: None,
            idle_connection_timeout: DEFAULT_IDLE_CONNECTION_TIMEOUT,
            state_reply_timeout: DEFAULT_STATE_REPLY_TIMEOUT,
        }
    }

    pub fn with_shutdown_trigger(mut self, shutdown_trigger: broadcast::Sender<()>) -> Self {
        self.shutdown_trigger = Some(shutdown_trigger);
        self
    }

    pub fn with_shutdown_token(mut self, shutdown_token: String) -> Self {
        self.shutdown_token = Some(shutdown_token);
        self
    }

    pub fn with_timeouts(
        mut self,
        idle_connection_timeout: Duration,
        state_reply_timeout: Duration,
    ) -> Self {
        self.idle_connection_timeout = idle_connection_timeout;
        self.state_reply_timeout = state_reply_timeout;
        self
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
            {
                warn!(
                    path = %self.path.display(),
                    error = %e,
                    "failed to set socket permissions to 0600"
                );
            }
        }

        info!(path = %self.path.display(), "socket server listening");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            debug!("accepted new connection");
                            let state_tx = self.state_tx.clone();
                            let shutdown_trigger = self.shutdown_trigger.clone();
                            let shutdown_token = self.shutdown_token.clone();
                            let idle_connection_timeout = self.idle_connection_timeout;
                            let state_reply_timeout = self.state_reply_timeout;
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_connection(
                                        stream,
                                        state_tx,
                                        shutdown_trigger,
                                        shutdown_token,
                                        idle_connection_timeout,
                                        state_reply_timeout,
                                    )
                                    .await
                                {
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
        if path.exists()
            && let Err(e) = std::fs::remove_file(path)
        {
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
    shutdown_trigger: Option<broadcast::Sender<()>>,
    shutdown_token: Option<String>,
    idle_connection_timeout: Duration,
    state_reply_timeout: Duration,
) -> Result<(), SocketError> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    loop {
        let frame = match timeout(
            idle_connection_timeout,
            read_next_line_frame(&mut reader, MAX_NDJSON_LINE_BYTES),
        )
        .await
        {
            Ok(frame_result) => frame_result?,
            Err(_) => {
                debug!(
                    timeout_ms = idle_connection_timeout.as_millis(),
                    "closing idle socket connection"
                );
                break;
            }
        };

        let line_bytes = match frame {
            ReadLineFrame::Line(line) => line,
            ReadLineFrame::ProtocolError(message) => {
                let response = SocketResponse::error(format!("protocol error: {message}"));
                if let Err(send_err) = write_response_line(&mut write_half, &response).await {
                    debug!(error = %send_err, "failed to send error response");
                    break;
                }
                continue;
            }
            ReadLineFrame::Eof => break,
        };

        let line = match std::str::from_utf8(trim_line_ending(&line_bytes)) {
            Ok(line) => line,
            Err(e) => {
                let response = SocketResponse::error(format!("protocol error: invalid UTF-8: {e}"));
                if let Err(send_err) = write_response_line(&mut write_half, &response).await {
                    debug!(error = %send_err, "failed to send UTF-8 protocol error response");
                    break;
                }
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let outcome = handle_request_with_options(
            line,
            &state_tx,
            shutdown_trigger.as_ref(),
            shutdown_token.as_deref(),
            state_reply_timeout,
        )
        .await;
        if let Err(e) = write_response_line(&mut write_half, &outcome.response).await {
            debug!(error = %e, "failed to send response, client likely disconnected");
            break;
        }
        if outcome.close_connection {
            break;
        }
    }

    debug!("connection closed");
    Ok(())
}

#[derive(Debug)]
enum ReadLineFrame {
    Line(Vec<u8>),
    ProtocolError(String),
    Eof,
}

async fn read_next_line_frame(
    reader: &mut (impl AsyncBufRead + Unpin),
    max_line_length: usize,
) -> Result<ReadLineFrame, std::io::Error> {
    let mut line = Vec::new();
    let mut dropping_oversized_line = false;

    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Ok(ReadLineFrame::Eof);
        }

        match buffer.iter().position(|byte| *byte == b'\n') {
            Some(newline_index) => {
                let to_take = newline_index + 1;
                let exceeds_max = line.len() + to_take > max_line_length + 1;
                if dropping_oversized_line || exceeds_max {
                    reader.consume(to_take);
                    return Ok(ReadLineFrame::ProtocolError(format!(
                        "line exceeds maximum length of {max_line_length} bytes"
                    )));
                }

                line.extend_from_slice(&buffer[..to_take]);
                reader.consume(to_take);
                return Ok(ReadLineFrame::Line(line));
            }
            None => {
                if dropping_oversized_line {
                    let to_consume = buffer.len();
                    reader.consume(to_consume);
                    continue;
                }

                if line.len() + buffer.len() > max_line_length + 1 {
                    let to_consume = buffer.len();
                    reader.consume(to_consume);
                    dropping_oversized_line = true;
                    continue;
                }

                line.extend_from_slice(buffer);
                let to_consume = buffer.len();
                reader.consume(to_consume);
            }
        }
    }
}

fn trim_line_ending(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

async fn write_response_line(
    writer: &mut OwnedWriteHalf,
    response: &SocketResponse,
) -> Result<(), SocketError> {
    let mut response_json = serde_json::to_vec(response)?;
    response_json.push(b'\n');
    writer.write_all(&response_json).await?;
    Ok(())
}

#[cfg(test)]
async fn handle_request(line: &str, state_tx: &mpsc::Sender<StateMessage>) -> SocketResponse {
    handle_request_with_options(line, state_tx, None, None, DEFAULT_STATE_REPLY_TIMEOUT)
        .await
        .response
}

struct RequestOutcome {
    response: SocketResponse,
    close_connection: bool,
}

async fn handle_request_with_options(
    line: &str,
    state_tx: &mpsc::Sender<StateMessage>,
    shutdown_trigger: Option<&broadcast::Sender<()>>,
    shutdown_token: Option<&str>,
    state_reply_timeout: Duration,
) -> RequestOutcome {
    // Parse the JSON request
    let request: SocketRequest = match serde_json::from_str(line) {
        Ok(req) => req,
        Err(e) => {
            return RequestOutcome {
                response: SocketResponse::error(format!("invalid JSON: {e}")),
                close_connection: false,
            };
        }
    };

    debug!(method = %request.method, "handling request");

    if request.method == "shutdown" {
        if let Some(expected_token) = shutdown_token {
            let provided_token = request.params.get("token").and_then(|v| v.as_str());
            if provided_token != Some(expected_token) {
                return RequestOutcome {
                    response: SocketResponse::error("unauthorized shutdown request"),
                    close_connection: false,
                };
            }
        }

        if let Some(trigger) = shutdown_trigger {
            if let Err(e) = trigger.send(()) {
                debug!(error = %e, "failed to broadcast shutdown signal");
            }
            return RequestOutcome {
                response: SocketResponse::success(serde_json::json!({
                    "status": "shutting_down"
                })),
                close_connection: true,
            };
        }

        return RequestOutcome {
            response: SocketResponse::error("shutdown unavailable"),
            close_connection: false,
        };
    }

    let parsed = match parse_request(&request) {
        Ok(p) => p,
        Err(e) => {
            return RequestOutcome {
                response: SocketResponse::error(e),
                close_connection: false,
            };
        }
    };

    let response = match parsed {
        ParsedRequest::Query(query) => {
            let (reply_tx, reply_rx) = oneshot::channel();
            let message = StateMessage::Query {
                request: query,
                reply: reply_tx,
            };

            if state_tx.send(message).await.is_err() {
                return RequestOutcome {
                    response: SocketResponse::error("daemon state unavailable"),
                    close_connection: false,
                };
            }

            match timeout(state_reply_timeout, reply_rx).await {
                Ok(Ok(response)) => query_response_to_socket(response),
                Ok(Err(_)) => SocketResponse::error("state actor did not respond"),
                Err(_) => SocketResponse::error("state actor response timed out"),
            }
        }
        ParsedRequest::SyncWorktrees { desired } => {
            let (reply_tx, reply_rx) = oneshot::channel();
            let message = StateMessage::SyncWorktrees {
                desired,
                reply: reply_tx,
            };

            if state_tx.send(message).await.is_err() {
                return RequestOutcome {
                    response: SocketResponse::error("daemon state unavailable"),
                    close_connection: false,
                };
            }

            match timeout(state_reply_timeout, reply_rx).await {
                Ok(Ok(Ok(sync_result))) => {
                    let added: Vec<String> =
                        sync_result.added.iter().map(|id| id.to_string()).collect();
                    let removed: Vec<String> =
                        sync_result.removed.iter().map(|id| id.to_string()).collect();
                    let unchanged: Vec<String> = sync_result
                        .unchanged
                        .iter()
                        .map(|id| id.to_string())
                        .collect();
                    let workspaces = match serde_json::to_value(&sync_result.workspaces) {
                        Ok(v) => v,
                        Err(e) => {
                            return RequestOutcome {
                                response: SocketResponse::error(format!(
                                    "serialization error: {e}"
                                )),
                                close_connection: false,
                            };
                        }
                    };
                    SocketResponse::success(serde_json::json!({
                        "added": added,
                        "removed": removed,
                        "unchanged": unchanged,
                        "workspaces": workspaces,
                    }))
                }
                Ok(Ok(Err(e))) => SocketResponse::error(e),
                Ok(Err(_)) => SocketResponse::error("state actor did not respond"),
                Err(_) => SocketResponse::error("state actor response timed out"),
            }
        }
    };

    RequestOutcome {
        response,
        close_connection: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{GroveConfig, spawn_state_actor};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use uuid::Uuid;

    fn short_temp_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("grv")
            .tempdir_in("/tmp")
            .unwrap()
    }

    fn unix_socket_bind_supported() -> bool {
        let dir = short_temp_dir();
        let socket_path = dir.path().join("bind-probe.sock");
        match std::os::unix::net::UnixListener::bind(&socket_path) {
            Ok(listener) => {
                drop(listener);
                let _ = std::fs::remove_file(&socket_path);
                true
            }
            Err(_) => false,
        }
    }

    async fn start_test_server() -> (
        tempfile::TempDir,
        PathBuf,
        mpsc::Sender<StateMessage>,
        tokio::task::JoinHandle<()>,
        tokio::sync::broadcast::Sender<()>,
        tokio::task::JoinHandle<Result<(), SocketError>>,
    ) {
        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let mut ready = false;
        for _ in 0..100 {
            match UnixStream::connect(&socket_path).await {
                Ok(stream) => {
                    drop(stream);
                    ready = true;
                    break;
                }
                Err(_) => {
                    if server_handle.is_finished() {
                        let result = server_handle
                            .await
                            .expect("server task join should succeed");
                        panic!("socket server exited before becoming ready: {result:?}");
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
        assert!(
            ready,
            "socket server did not become ready at {}",
            socket_path.display()
        );

        (
            dir,
            socket_path,
            state_tx,
            state_handle,
            shutdown_tx,
            server_handle,
        )
    }

    async fn start_test_server_with_shutdown_trigger() -> (
        tempfile::TempDir,
        PathBuf,
        mpsc::Sender<StateMessage>,
        tokio::task::JoinHandle<()>,
        tokio::sync::broadcast::Sender<()>,
        tokio::task::JoinHandle<Result<(), SocketError>>,
    ) {
        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let server = SocketServer::new(socket_path.clone(), state_tx.clone())
            .with_shutdown_trigger(shutdown_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let mut ready = false;
        for _ in 0..100 {
            match UnixStream::connect(&socket_path).await {
                Ok(stream) => {
                    drop(stream);
                    ready = true;
                    break;
                }
                Err(_) => {
                    if server_handle.is_finished() {
                        let result = server_handle
                            .await
                            .expect("server task join should succeed");
                        panic!("socket server exited before becoming ready: {result:?}");
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
        assert!(
            ready,
            "socket server did not become ready at {}",
            socket_path.display()
        );

        (
            dir,
            socket_path,
            state_tx,
            state_handle,
            shutdown_tx,
            server_handle,
        )
    }

    // === Unit tests for request parsing ===

    #[test]
    fn parse_status_request() {
        let req = SocketRequest {
            method: "status".to_string(),
            params: serde_json::json!({}),
        };
        let result = parse_request(&req);
        assert!(matches!(
            result,
            Ok(ParsedRequest::Query(QueryRequest::GetStatus))
        ));
    }

    #[test]
    fn parse_list_workspaces_request() {
        let req = SocketRequest {
            method: "list_workspaces".to_string(),
            params: serde_json::json!({}),
        };
        let result = parse_request(&req);
        assert!(matches!(
            result,
            Ok(ParsedRequest::Query(QueryRequest::ListWorkspaces))
        ));
    }

    #[test]
    fn parse_get_workspace_request() {
        let id = Uuid::new_v4();
        let req = SocketRequest {
            method: "get_workspace".to_string(),
            params: serde_json::json!({"workspace_id": id.to_string()}),
        };
        match parse_request(&req).unwrap() {
            ParsedRequest::Query(QueryRequest::GetWorkspace { workspace_id }) => {
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
        match parse_request(&req).unwrap() {
            ParsedRequest::Query(QueryRequest::GetPairAnalysis {
                workspace_a,
                workspace_b,
            }) => {
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
        assert!(matches!(
            result,
            Ok(ParsedRequest::Query(QueryRequest::GetAllAnalyses))
        ));
    }

    #[test]
    fn parse_sync_worktrees_request() {
        let req = SocketRequest {
            method: "sync_worktrees".to_string(),
            params: serde_json::json!({
                "worktrees": [
                    {"name": "main", "path": "/repo", "branch": "refs/heads/main", "head": "abc123"}
                ]
            }),
        };
        let result = parse_request(&req);
        assert!(matches!(result, Ok(ParsedRequest::SyncWorktrees { .. })));
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
        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

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
        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

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
        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

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
        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

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
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("unknown method")
        );

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn round_trip_multiple_requests_on_one_connection() {
        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

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

    #[tokio::test]
    async fn round_trip_shutdown_request_stops_server() {
        if !unix_socket_bind_supported() {
            return;
        }

        let (_dir, socket_path, state_tx, state_handle, _shutdown_tx, server_handle) =
            start_test_server_with_shutdown_trigger().await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        framed
            .send(r#"{"method":"shutdown","params":{}}"#.to_string())
            .await
            .unwrap();

        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["data"]["status"], "shutting_down");

        let join_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_handle)
            .await
            .expect("server should stop quickly after shutdown request");
        let run_result = join_result.expect("server task join should succeed");
        assert!(
            run_result.is_ok(),
            "server should stop cleanly after shutdown request: {run_result:?}"
        );

        state_tx.send(StateMessage::Shutdown).await.unwrap();
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn immediate_shutdown_signal_during_startup_exits_cleanly() {
        if !unix_socket_bind_supported() {
            return;
        }

        let dir = short_temp_dir();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        // Trigger shutdown immediately after spawn to hit startup/shutdown race windows.
        drop(shutdown_tx);

        let join_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_handle)
            .await
            .expect("server task should terminate quickly after shutdown");
        let run_result = join_result.expect("server task join should succeed");
        assert!(
            run_result.is_ok(),
            "server should exit cleanly: {run_result:?}"
        );

        state_tx.send(StateMessage::Shutdown).await.unwrap();
        state_handle.await.unwrap();
        assert!(!socket_path.exists(), "socket path should be cleaned up");
    }

    #[tokio::test]
    async fn server_can_restart_on_same_socket_path_after_shutdown() {
        if !unix_socket_bind_supported() {
            return;
        }

        let (dir, socket_path, state_tx_1, state_handle_1, shutdown_tx_1, server_handle_1) =
            start_test_server().await;

        drop(shutdown_tx_1);
        state_tx_1.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle_1.await;
        state_handle_1.await.unwrap();

        for _ in 0..100 {
            if !socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            !socket_path.exists(),
            "first server should remove socket path before restart"
        );

        let (state_tx_2, state_handle_2) = spawn_state_actor(GroveConfig::default(), None);
        let (shutdown_tx_2, shutdown_rx_2) = tokio::sync::broadcast::channel(1);
        let server_2 = SocketServer::new(socket_path.clone(), state_tx_2.clone());
        let server_handle_2 = tokio::spawn(async move { server_2.run(shutdown_rx_2).await });

        let mut ready = false;
        for _ in 0..100 {
            match UnixStream::connect(&socket_path).await {
                Ok(stream) => {
                    drop(stream);
                    ready = true;
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
        assert!(
            ready,
            "restarted server did not become ready at {}",
            socket_path.display()
        );

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);
        framed
            .send(r#"{"method":"status","params":{}}"#.to_string())
            .await
            .unwrap();
        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();
        assert_eq!(response["ok"], true);

        drop(shutdown_tx_2);
        state_tx_2.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle_2.await;
        state_handle_2.await.unwrap();

        drop(dir);
    }

    #[tokio::test]
    async fn fragmented_request_waits_for_newline_then_succeeds() {
        if !unix_socket_bind_supported() {
            return;
        }

        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        stream
            .write_all(br#"{"method":"status","params":"#)
            .await
            .unwrap();

        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        let pending_read = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            reader.read_line(&mut response_line),
        )
        .await;
        assert!(
            pending_read.is_err(),
            "server should not respond before newline-terminated NDJSON frame"
        );

        reader
            .get_mut()
            .write_all(
                br#"{}}
"#,
            )
            .await
            .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reader.read_line(&mut response_line),
        )
        .await
        .expect("response should arrive once newline is sent")
        .unwrap();

        let response: serde_json::Value = serde_json::from_str(response_line.trim()).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["data"]["workspace_count"], 0);

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_ndjson_sequence_between_valid_requests_preserves_order() {
        if !unix_socket_bind_supported() {
            return;
        }

        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        stream
            .write_all(
                br#"{"method":"status","params":{}}
{"method":"status"
{"method":"get_all_analyses","params":{}}
"#,
            )
            .await
            .unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        reader.read_line(&mut line).await.unwrap();
        let first: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(first["ok"], true);
        assert_eq!(first["data"]["workspace_count"], 0);

        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let second: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(second["ok"], false);
        assert!(second["error"].as_str().unwrap().contains("invalid JSON"));

        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let third: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(third["ok"], true);
        assert!(third["data"].as_array().unwrap().is_empty());

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_json_line_returns_protocol_error() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut huge_line = vec![b'a'; 1_100_000];
        huge_line.push(b'\n');
        match stream.write_all(&huge_line).await {
            Ok(()) => {
                let mut reader = BufReader::new(stream);
                let mut response_line = String::new();
                reader.read_line(&mut response_line).await.unwrap();

                let response: serde_json::Value =
                    serde_json::from_str(response_line.trim()).unwrap();
                assert_eq!(response["ok"], false);
                assert!(
                    response["error"]
                        .as_str()
                        .unwrap()
                        .contains("protocol error")
                );
            }
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
            }
        }

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn partial_json_line_returns_invalid_json_error() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);
        framed
            .send(r#"{"method":"status""#.to_string())
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
    async fn empty_line_is_ignored_and_connection_stays_usable() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        framed.send("".to_string()).await.unwrap();
        framed
            .send(r#"{"method":"status","params":{}}"#.to_string())
            .await
            .unwrap();

        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["data"]["workspace_count"], 0);

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn binary_garbage_line_returns_protocol_error() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        stream.write_all(&[0xff, 0xfe, 0xfd, b'\n']).await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(response_line.trim()).unwrap();
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("protocol error")
        );

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn valid_json_with_wrong_param_types_returns_error() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);

        framed
            .send(r#"{"method":"get_workspace","params":{"workspace_id":12345}}"#.to_string())
            .await
            .unwrap();

        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();
        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("workspace_id"));

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn json_missing_method_field_returns_invalid_json_error() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);
        framed.send(r#"{"params":{}}"#.to_string()).await.unwrap();

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
    async fn state_actor_unavailable_returns_error_response() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        state_tx.send(StateMessage::Shutdown).await.unwrap();
        state_handle.await.unwrap();

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let codec = LinesCodec::new_with_max_length(1_048_576);
        let mut framed = Framed::new(stream, codec);
        framed
            .send(r#"{"method":"status","params":{}}"#.to_string())
            .await
            .unwrap();

        let response_line = framed.next().await.unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("daemon state unavailable")
        );

        drop(shutdown_tx);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn protocol_error_does_not_poison_connection_for_followup_request() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(&[0xff, 0xfe, 0xfd, b'\n'])
            .await
            .unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let first: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(first["ok"], false);
        assert!(first["error"].as_str().unwrap().contains("protocol error"));

        line.clear();
        reader
            .get_mut()
            .write_all(br#"{"method":"status","params":{}}"#)
            .await
            .unwrap();
        reader.get_mut().write_all(b"\n").await.unwrap();
        reader.read_line(&mut line).await.unwrap();
        let second: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(second["ok"], true);
        assert_eq!(second["data"]["workspace_count"], 0);

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn max_length_boundary_line_returns_invalid_json_not_protocol_error() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut boundary_line = vec![b'a'; 1_048_576];
        boundary_line.push(b'\n');
        stream.write_all(&boundary_line).await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(response_line.trim()).unwrap();
        assert_eq!(response["ok"], false);
        let error = response["error"].as_str().unwrap();
        assert!(error.contains("invalid JSON"));
        assert!(!error.contains("protocol error"));

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_clients_with_mixed_valid_and_corrupt_requests() {
        let (_dir, socket_path, state_tx, state_handle, shutdown_tx, server_handle) =
            start_test_server().await;

        let mut tasks = Vec::new();
        for i in 0..32 {
            let socket_path = socket_path.clone();
            tasks.push(tokio::spawn(async move {
                let stream = UnixStream::connect(&socket_path).await.unwrap();
                let codec = LinesCodec::new_with_max_length(1_048_576);
                let mut framed = Framed::new(stream, codec);
                if i % 2 == 0 {
                    framed
                        .send(r#"{"method":"status","params":{}}"#.to_string())
                        .await
                        .unwrap();
                } else {
                    framed
                        .send(r#"{"method":"status""#.to_string())
                        .await
                        .unwrap();
                }

                let response_line = framed.next().await.unwrap().unwrap();
                let response: serde_json::Value = serde_json::from_str(&response_line).unwrap();
                (i, response["ok"].as_bool().unwrap())
            }));
        }

        for task in tasks {
            let (i, ok) = task.await.unwrap();
            if i % 2 == 0 {
                assert!(ok, "expected valid request from client {i} to succeed");
            } else {
                assert!(!ok, "expected invalid request from client {i} to fail");
            }
        }

        drop(shutdown_tx);
        state_tx.send(StateMessage::Shutdown).await.unwrap();
        let _ = server_handle.await;
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn handle_request_returns_error_when_state_drops_reply() {
        let (state_tx, mut state_rx) = mpsc::channel(1);
        let state_task = tokio::spawn(async move {
            if let Some(StateMessage::Query { reply, .. }) = state_rx.recv().await {
                drop(reply);
            } else {
                panic!("expected Query message");
            }
        });

        let response = handle_request(r#"{"method":"status","params":{}}"#, &state_tx).await;
        assert!(!response.ok);
        assert!(
            response
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("state actor did not respond")
        );

        state_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_request_returns_error_when_state_reply_times_out() {
        let (state_tx, mut state_rx) = mpsc::channel(1);
        let state_task = tokio::spawn(async move {
            if let Some(StateMessage::Query { .. }) = state_rx.recv().await {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            } else {
                panic!("expected Query message");
            }
        });

        let response = handle_request_with_options(
            r#"{"method":"status","params":{}}"#,
            &state_tx,
            None,
            None,
            Duration::from_millis(25),
        )
        .await
        .response;
        assert!(!response.ok);
        assert!(
            response
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("timed out")
        );

        state_task.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_request_requires_matching_token_when_configured() {
        let (state_tx, _state_rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);

        let unauthorized = handle_request_with_options(
            r#"{"method":"shutdown","params":{}}"#,
            &state_tx,
            Some(&shutdown_tx),
            Some("secret-token"),
            Duration::from_millis(25),
        )
        .await;
        assert!(!unauthorized.response.ok);
        assert_eq!(
            unauthorized.response.error.as_deref(),
            Some("unauthorized shutdown request")
        );
        assert!(!unauthorized.close_connection);

        let authorized = handle_request_with_options(
            r#"{"method":"shutdown","params":{"token":"secret-token"}}"#,
            &state_tx,
            Some(&shutdown_tx),
            Some("secret-token"),
            Duration::from_millis(25),
        )
        .await;
        assert!(authorized.response.ok);
        assert_eq!(
            authorized
                .response
                .data
                .as_ref()
                .and_then(|d| d.get("status")),
            Some(&serde_json::json!("shutting_down"))
        );
        assert!(authorized.close_connection);
    }

    #[tokio::test]
    async fn handle_request_sequence_survives_malformed_json_between_valid_requests() {
        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);

        let first = handle_request(r#"{"method":"status","params":{}}"#, &state_tx).await;
        assert!(first.ok);
        assert_eq!(first.data.unwrap()["workspace_count"], 0);

        let second = handle_request(r#"{"method":"status""#, &state_tx).await;
        assert!(!second.ok);
        assert!(
            second
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("invalid JSON")
        );

        let third = handle_request(r#"{"method":"get_all_analyses","params":{}}"#, &state_tx).await;
        assert!(third.ok);
        assert!(third.data.unwrap().as_array().unwrap().is_empty());

        state_tx.send(StateMessage::Shutdown).await.unwrap();
        state_handle.await.unwrap();
    }

    #[tokio::test]
    async fn handle_request_returns_state_unavailable_after_shutdown() {
        let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);

        let warmup = handle_request(r#"{"method":"status","params":{}}"#, &state_tx).await;
        assert!(warmup.ok);

        state_tx.send(StateMessage::Shutdown).await.unwrap();
        state_handle.await.unwrap();

        let after_shutdown = handle_request(r#"{"method":"status","params":{}}"#, &state_tx).await;
        assert!(!after_shutdown.ok);
        assert!(
            after_shutdown
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("daemon state unavailable")
        );
    }

    #[tokio::test]
    async fn read_next_line_frame_recovers_after_oversized_frame() {
        let (mut writer, reader_stream) = tokio::io::duplex(MAX_NDJSON_LINE_BYTES + 4096);
        let mut reader = BufReader::new(reader_stream);

        let mut oversized = vec![b'a'; MAX_NDJSON_LINE_BYTES + 64];
        oversized.push(b'\n');
        writer.write_all(&oversized).await.unwrap();
        writer
            .write_all(br#"{"method":"status","params":{}}"#)
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();

        let first = read_next_line_frame(&mut reader, MAX_NDJSON_LINE_BYTES)
            .await
            .unwrap();
        assert!(matches!(first, ReadLineFrame::ProtocolError(_)));

        let second = read_next_line_frame(&mut reader, MAX_NDJSON_LINE_BYTES)
            .await
            .unwrap();
        let second_line = match second {
            ReadLineFrame::Line(line) => line,
            other => panic!("expected follow-up line frame, got {other:?}"),
        };
        let second_text = std::str::from_utf8(trim_line_ending(&second_line)).unwrap();
        assert_eq!(second_text, r#"{"method":"status","params":{}}"#);
    }
}
