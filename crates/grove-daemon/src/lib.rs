pub mod db;
pub(crate) mod git;
pub mod lifecycle;
pub mod socket;
pub mod state;
pub mod watcher;
pub mod worker;

use std::path::Path;
use std::time::Duration;

use notify::{RecursiveMode, Watcher};
use thiserror::Error;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::Database;
use crate::lifecycle::DaemonPaths;
use crate::socket::SocketServer;
use crate::state::{GroveConfig, QueryRequest, QueryResponse, StateMessage};
use crate::watcher::{Debouncer, WatchEvent, WatcherConfig};
use crate::worker::spawn_worker_pool;

/// Errors that can occur during daemon operation.
#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("lifecycle error: {0}")]
    Lifecycle(#[from] lifecycle::LifecycleError),

    #[error("database error: {0}")]
    Database(#[from] db::DbError),

    #[error("socket error: {0}")]
    Socket(#[from] socket::SocketError),

    #[error("watcher error: {0}")]
    Watcher(#[from] notify::Error),
}

/// Initialize tracing with stderr output.
///
/// A file appender (writing to `log_path`) and an `EnvFilter` can be layered in
/// once `tracing-appender` and the `env-filter` feature are added as dependencies.
fn init_tracing(_log_path: &Path) {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(false)
        .with_writer(std::io::stderr)
        .init();
}

/// Run the daemon, blocking until a shutdown signal is received.
///
/// This is the main entry point for the daemon process. It:
/// 1. Creates runtime paths from `grove_dir`
/// 2. Writes a PID file (fails if daemon already running)
/// 3. Initializes tracing
/// 4. Opens the SQLite database
/// 5. Starts the state actor
/// 6. Starts worker pool + filesystem watcher pipeline
/// 7. Runs the socket server until SIGTERM/SIGINT
/// 8. Performs graceful shutdown and cleanup
pub async fn run(config: GroveConfig, grove_dir: &Path) -> Result<(), DaemonError> {
    let paths = DaemonPaths::from_grove_dir(grove_dir);

    // Ensure the grove directory exists
    std::fs::create_dir_all(grove_dir).map_err(lifecycle::LifecycleError::Io)?;

    // Write PID file — fails if another daemon is already running
    lifecycle::write_pid_file(&paths.pid_file)?;
    let shutdown_token = write_shutdown_token_file(&paths.shutdown_token_file)?;

    // From this point on, always clean up PID + socket files on exit
    let cleanup_result = run_inner(&config, &paths, &shutdown_token).await;

    // Always clean up, regardless of success or failure
    if let Err(e) = lifecycle::cleanup(&paths.pid_file, &paths.socket_file) {
        tracing::warn!(error = %e, "cleanup error during shutdown");
    }
    if let Err(e) = remove_shutdown_token_file(&paths.shutdown_token_file) {
        tracing::warn!(error = %e, "failed to remove shutdown token file");
    }

    cleanup_result
}

/// Inner run loop, separated so that `run()` can guarantee cleanup.
async fn run_inner(
    config: &GroveConfig,
    paths: &DaemonPaths,
    shutdown_token: &str,
) -> Result<(), DaemonError> {
    // Initialize tracing (stderr + eventually file)
    init_tracing(&paths.log_file);

    info!(
        pid = std::process::id(),
        grove_dir = %paths.pid_file.parent().unwrap_or(Path::new(".")).display(),
        "grove daemon starting"
    );

    // Open SQLite database
    let db = Database::open(&paths.db_file)?;
    info!(db_path = %paths.db_file.display(), "database opened");

    // Start state actor
    let (state_tx, state_handle) = state::spawn_state_actor(config.clone(), Some(db));
    info!("state actor started");

    let worker_pool = spawn_worker_pool(config.clone(), state_tx.clone());
    state_tx
        .send(StateMessage::AttachWorker {
            worker_tx: worker_pool.sender(),
        })
        .await
        .map_err(|_| socket::SocketError::StateChannelClosed)?;
    info!("worker pool started");

    let watcher_config = WatcherConfig {
        debounce_ms: config.watch_interval_ms,
        circuit_breaker_threshold: config.circuit_breaker_threshold,
        ignore_patterns: config.ignore_patterns.clone(),
        respect_gitignore: config.respect_gitignore,
    };

    // Create broadcast channel for coordinating shutdown across subsystems
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let watcher_shutdown_rx = shutdown_tx.subscribe();

    let watcher_handle = tokio::spawn(run_watcher_loop(
        state_tx.clone(),
        watcher_config,
        config.base_branch.clone(),
        Duration::from_millis(config.socket_state_reply_timeout_ms),
        watcher_shutdown_rx,
    ));

    // Create and run socket server
    let server = SocketServer::new(&paths.socket_file, state_tx.clone())
        .with_timeouts(
            Duration::from_millis(config.socket_idle_timeout_ms),
            Duration::from_millis(config.socket_state_reply_timeout_ms),
        )
        .with_shutdown_trigger(shutdown_tx.clone());
    let server = server.with_shutdown_token(shutdown_token.to_string());
    info!(socket = %paths.socket_file.display(), "socket server created");

    // Run socket server and shutdown signal concurrently. When a signal arrives,
    // ask the server to stop and wait until it exits before shutting down state.
    let server_run = server.run(shutdown_rx);
    tokio::pin!(server_run);

    let mut socket_error: Option<socket::SocketError> = None;
    tokio::select! {
        result = &mut server_run => {
            if let Err(e) = result {
                error!(error = %e, "socket server error");
                socket_error = Some(e);
            }
        }
        () = lifecycle::shutdown_signal() => {
            info!("shutdown signal received, initiating graceful shutdown");
            // Signal socket server to stop accepting connections
            let _ = shutdown_tx.send(());

            match server_run.await {
                Ok(()) => {}
                Err(e) => {
                    error!(error = %e, "socket server error");
                    socket_error = Some(e);
                }
            }
        }
    }

    // Ensure watcher loop exits even if server exited for another reason.
    let _ = shutdown_tx.send(());
    match watcher_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = %e, "watcher loop exited with error"),
        Err(e) => warn!(error = %e, "watcher loop task panicked"),
    }

    // Graceful shutdown: tell the state actor to drain and stop
    info!("sending shutdown to state actor");
    if let Err(e) = state_tx.send(StateMessage::Shutdown).await {
        warn!(error = %e, "failed to send shutdown to state actor (already stopped?)");
    }

    // Wait for the state actor to finish processing
    if let Err(e) = state_handle.await {
        warn!(error = %e, "state actor task panicked");
    }
    worker_pool.shutdown().await;

    info!("grove daemon stopped");
    if let Some(err) = socket_error {
        return Err(DaemonError::Socket(err));
    }

    Ok(())
}

async fn run_watcher_loop(
    state_tx: tokio::sync::mpsc::Sender<StateMessage>,
    watcher_config: WatcherConfig,
    base_branch: String,
    state_reply_timeout: Duration,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), notify::Error> {
    use std::collections::HashMap;

    let (event_tx, mut event_rx) =
        tokio::sync::mpsc::unbounded_channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(move |result| {
        let _ = event_tx.send(result);
    })?;

    let mut debouncer = Debouncer::new(watcher_config);
    let mut watched_workspaces: HashMap<grove_lib::WorkspaceId, std::path::PathBuf> =
        HashMap::new();
    refresh_watched_workspaces(
        &state_tx,
        state_reply_timeout,
        &mut watcher,
        &mut debouncer,
        &mut watched_workspaces,
    )
    .await;

    let mut flush_interval = tokio::time::interval(Duration::from_millis(100));
    let mut refresh_interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                break;
            }
            maybe_event = event_rx.recv() => {
                let Some(event_result) = maybe_event else {
                    break;
                };

                match event_result {
                    Ok(event) => {
                        let mut watch_events = debouncer.process_event(&event);
                        if !watch_events.is_empty() {
                            forward_watch_events(
                                &state_tx,
                                &watch_events,
                                &watched_workspaces,
                                &base_branch,
                                state_reply_timeout,
                            ).await;
                            watch_events.clear();
                        }
                    }
                    Err(e) => warn!(error = %e, "watcher event error"),
                }
            }
            _ = flush_interval.tick() => {
                let watch_events = debouncer.flush_debounced();
                if !watch_events.is_empty() {
                    forward_watch_events(
                        &state_tx,
                        &watch_events,
                        &watched_workspaces,
                        &base_branch,
                        state_reply_timeout,
                    )
                    .await;
                }
            }
            _ = refresh_interval.tick() => {
                refresh_watched_workspaces(
                    &state_tx,
                    state_reply_timeout,
                    &mut watcher,
                    &mut debouncer,
                    &mut watched_workspaces,
                ).await;
            }
        }
    }

    Ok(())
}

async fn forward_watch_events(
    state_tx: &tokio::sync::mpsc::Sender<StateMessage>,
    events: &[WatchEvent],
    watched_workspaces: &std::collections::HashMap<grove_lib::WorkspaceId, std::path::PathBuf>,
    base_branch: &str,
    state_reply_timeout: Duration,
) {
    for event in events {
        match event {
            WatchEvent::FilesChanged {
                workspace_id,
                paths,
            } => {
                for path in paths {
                    if let Err(e) = state_tx
                        .send(StateMessage::FileChanged {
                            workspace_id: *workspace_id,
                            path: path.clone(),
                        })
                        .await
                    {
                        warn!(error = %e, "failed to forward FilesChanged event");
                        return;
                    }
                }
            }
            WatchEvent::FullReindexNeeded { workspace_id } => {
                let fallback_path = watched_workspaces
                    .get(workspace_id)
                    .cloned()
                    .unwrap_or_default();
                if let Err(e) = state_tx
                    .send(StateMessage::FileChanged {
                        workspace_id: *workspace_id,
                        path: fallback_path,
                    })
                    .await
                {
                    warn!(error = %e, "failed to forward FullReindexNeeded event");
                    return;
                }
            }
            WatchEvent::BaseRefChanged { .. } => {
                if let Some(commit) =
                    resolve_base_branch_commit(state_tx, base_branch, state_reply_timeout).await
                    && let Err(e) = state_tx
                        .send(StateMessage::BaseRefChanged { new_commit: commit })
                        .await
                {
                    warn!(error = %e, "failed to forward BaseRefChanged event");
                    return;
                }
            }
        }
    }
}

async fn refresh_watched_workspaces(
    state_tx: &tokio::sync::mpsc::Sender<StateMessage>,
    state_reply_timeout: Duration,
    watcher: &mut notify::RecommendedWatcher,
    debouncer: &mut Debouncer,
    watched_workspaces: &mut std::collections::HashMap<grove_lib::WorkspaceId, std::path::PathBuf>,
) {
    use std::collections::HashSet;

    let workspaces = list_workspaces(state_tx, state_reply_timeout).await;
    let desired: std::collections::HashMap<grove_lib::WorkspaceId, std::path::PathBuf> = workspaces
        .into_iter()
        .map(|workspace| (workspace.id, workspace.path))
        .collect();

    let current_ids: HashSet<_> = watched_workspaces.keys().copied().collect();
    let desired_ids: HashSet<_> = desired.keys().copied().collect();

    for removed_id in current_ids.difference(&desired_ids) {
        if let Some(path) = watched_workspaces.remove(removed_id) {
            if let Err(e) = watcher.unwatch(&path) {
                warn!(path = %path.display(), error = %e, "failed to unwatch workspace");
            }
            debouncer.unregister_worktree(removed_id);
        }
    }

    for added_id in desired_ids.difference(&current_ids) {
        if let Some(path) = desired.get(added_id) {
            if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                warn!(path = %path.display(), error = %e, "failed to watch workspace");
                continue;
            }

            debouncer.register_worktree(*added_id, path.clone());
            watched_workspaces.insert(*added_id, path.clone());
            info!(workspace_id = %added_id, path = %path.display(), "watching workspace");
        }
    }
}

async fn list_workspaces(
    state_tx: &tokio::sync::mpsc::Sender<StateMessage>,
    reply_timeout: Duration,
) -> Vec<grove_lib::Workspace> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if let Err(e) = state_tx
        .send(StateMessage::Query {
            request: QueryRequest::ListWorkspaces,
            reply: reply_tx,
        })
        .await
    {
        warn!(error = %e, "failed to query state actor for workspace list");
        return Vec::new();
    }

    match tokio::time::timeout(reply_timeout, reply_rx).await {
        Ok(Ok(QueryResponse::Workspaces(workspaces))) => workspaces,
        Ok(Ok(other)) => {
            warn!(response = ?other, "unexpected response to workspace list query");
            Vec::new()
        }
        Ok(Err(_)) => {
            warn!("state actor closed workspace list reply channel");
            Vec::new()
        }
        Err(_) => {
            warn!(
                timeout_ms = reply_timeout.as_millis() as u64,
                "timed out waiting for workspace list response from state actor"
            );
            Vec::new()
        }
    }
}

async fn resolve_base_branch_commit(
    state_tx: &tokio::sync::mpsc::Sender<StateMessage>,
    base_branch: &str,
    state_reply_timeout: Duration,
) -> Option<String> {
    let workspaces = list_workspaces(state_tx, state_reply_timeout).await;
    let repo_path = workspaces.into_iter().next()?.path;
    let base_branch = base_branch.to_string();

    tokio::task::spawn_blocking(move || {
        let repo = gix::open(&repo_path).ok()?;
        let id = repo.rev_parse_single(base_branch.as_bytes()).ok()?;
        Some(id.to_hex().to_string())
    })
    .await
    .ok()?
}

fn write_shutdown_token_file(path: &Path) -> Result<String, lifecycle::LifecycleError> {
    let token = Uuid::new_v4().to_string();
    std::fs::write(path, &token).map_err(lifecycle::LifecycleError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(lifecycle::LifecycleError::Io)?;
    }
    Ok(token)
}

fn remove_shutdown_token_file(path: &Path) -> Result<(), lifecycle::LifecycleError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(lifecycle::LifecycleError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::lifecycle::DaemonPaths;
    use crate::socket::SocketServer;
    use crate::state::{GroveConfig, QueryRequest, StateMessage, spawn_state_actor};

    #[tokio::test]
    async fn daemon_components_wire_up() {
        let dir = tempfile::tempdir().unwrap();
        let grove_dir = dir.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let paths = DaemonPaths::from_grove_dir(&grove_dir);

        // DB opens successfully
        let db = Database::open(&paths.db_file).unwrap();

        // State actor starts
        let config = GroveConfig::default();
        let (tx, handle) = spawn_state_actor(config, Some(db));

        // Socket server constructs (don't run, just verify creation)
        let _server = SocketServer::new(&paths.socket_file, tx.clone());

        // Watcher debouncer constructs
        let _debouncer = Debouncer::new(WatcherConfig::default());

        // Shutdown cleanly
        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn pid_file_written_and_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let grove_dir = dir.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let paths = DaemonPaths::from_grove_dir(&grove_dir);

        // Write PID file
        lifecycle::write_pid_file(&paths.pid_file).unwrap();
        assert!(paths.pid_file.exists());

        // Verify it contains our PID
        let pid = lifecycle::read_pid_file(&paths.pid_file).unwrap().unwrap();
        assert_eq!(pid, std::process::id());

        // Cleanup removes it
        lifecycle::cleanup(&paths.pid_file, &paths.socket_file).unwrap();
        assert!(!paths.pid_file.exists());
    }

    #[tokio::test]
    async fn database_created_at_expected_path() {
        let dir = tempfile::tempdir().unwrap();
        let grove_dir = dir.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let paths = DaemonPaths::from_grove_dir(&grove_dir);

        let _db = Database::open(&paths.db_file).unwrap();
        assert!(paths.db_file.exists());
    }

    #[tokio::test]
    async fn watcher_config_derived_from_grove_config() {
        let config = GroveConfig {
            watch_interval_ms: 250,
            circuit_breaker_threshold: 50,
            ignore_patterns: vec!["custom_dir".to_string()],
            respect_gitignore: false,
            ..GroveConfig::default()
        };

        let watcher_config = WatcherConfig {
            debounce_ms: config.watch_interval_ms,
            circuit_breaker_threshold: config.circuit_breaker_threshold,
            ignore_patterns: config.ignore_patterns.clone(),
            respect_gitignore: config.respect_gitignore,
        };

        assert_eq!(watcher_config.debounce_ms, 250);
        assert_eq!(watcher_config.circuit_breaker_threshold, 50);
        assert_eq!(
            watcher_config.ignore_patterns,
            vec!["custom_dir".to_string()]
        );
        assert!(!watcher_config.respect_gitignore);
    }

    #[test]
    fn daemon_error_from_lifecycle_error() {
        let err = lifecycle::LifecycleError::AlreadyRunning(1234);
        let daemon_err: DaemonError = err.into();
        assert!(daemon_err.to_string().contains("1234"));
        assert!(daemon_err.to_string().contains("lifecycle"));
    }

    #[test]
    fn daemon_error_display() {
        let lifecycle_err: DaemonError = lifecycle::LifecycleError::InvalidPidFile.into();
        assert_eq!(
            lifecycle_err.to_string(),
            "lifecycle error: invalid PID file contents"
        );
    }

    #[tokio::test]
    async fn list_workspaces_returns_empty_when_query_reply_times_out() {
        let (state_tx, mut state_rx) = tokio::sync::mpsc::channel::<StateMessage>(1);
        let hold_reply = tokio::spawn(async move {
            if let Some(StateMessage::Query { request, reply }) = state_rx.recv().await {
                assert!(matches!(request, QueryRequest::ListWorkspaces));
                tokio::time::sleep(Duration::from_millis(50)).await;
                drop(reply);
            }
        });

        let result = list_workspaces(&state_tx, Duration::from_millis(5)).await;
        assert!(result.is_empty());
        hold_reply.await.unwrap();
    }

    #[tokio::test]
    async fn list_workspaces_returns_empty_when_query_reply_channel_closes() {
        let (state_tx, mut state_rx) = tokio::sync::mpsc::channel::<StateMessage>(1);
        let close_reply = tokio::spawn(async move {
            if let Some(StateMessage::Query { request, reply }) = state_rx.recv().await {
                assert!(matches!(request, QueryRequest::ListWorkspaces));
                drop(reply);
            }
        });

        let result = list_workspaces(&state_tx, Duration::from_millis(50)).await;
        assert!(result.is_empty());
        close_reply.await.unwrap();
    }
}
