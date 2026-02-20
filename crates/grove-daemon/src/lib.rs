pub mod db;
pub mod lifecycle;
pub mod socket;
pub mod state;
pub mod watcher;

use std::path::Path;

use thiserror::Error;
use tracing::info;

use crate::db::Database;
use crate::lifecycle::DaemonPaths;
use crate::socket::SocketServer;
use crate::state::{GroveConfig, StateMessage};
use crate::watcher::{Debouncer, WatcherConfig};

/// Errors that can occur during daemon operation.
#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("lifecycle error: {0}")]
    Lifecycle(#[from] lifecycle::LifecycleError),

    #[error("database error: {0}")]
    Database(#[from] db::DbError),

    #[error("socket error: {0}")]
    Socket(#[from] socket::SocketError),
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
/// 6. Constructs the watcher debouncer (not yet watching — needs worker pool)
/// 7. Runs the socket server until SIGTERM/SIGINT
/// 8. Performs graceful shutdown and cleanup
pub async fn run(config: GroveConfig, grove_dir: &Path) -> Result<(), DaemonError> {
    let paths = DaemonPaths::from_grove_dir(grove_dir);

    // Ensure the grove directory exists
    std::fs::create_dir_all(grove_dir)
        .map_err(lifecycle::LifecycleError::Io)?;

    // Write PID file — fails if another daemon is already running
    lifecycle::write_pid_file(&paths.pid_file)?;

    // From this point on, always clean up PID + socket files on exit
    let cleanup_result = run_inner(&config, &paths).await;

    // Always clean up, regardless of success or failure
    if let Err(e) = lifecycle::cleanup(&paths.pid_file, &paths.socket_file) {
        tracing::warn!(error = %e, "cleanup error during shutdown");
    }

    cleanup_result
}

/// Inner run loop, separated so that `run()` can guarantee cleanup.
async fn run_inner(config: &GroveConfig, paths: &DaemonPaths) -> Result<(), DaemonError> {
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

    // Create watcher debouncer (not started yet — needs worker pool integration)
    // TODO: Wire up filesystem watching once the worker pool is implemented.
    // The debouncer is ready; it needs a notify::RecommendedWatcher feeding events
    // into `debouncer.process_event()`, plus a worker pool to dispatch WatchEvents to.
    let watcher_config = WatcherConfig {
        debounce_ms: config.watch_interval_ms,
        circuit_breaker_threshold: config.circuit_breaker_threshold,
        ignore_patterns: config.ignore_patterns.clone(),
        respect_gitignore: config.respect_gitignore,
    };
    let _debouncer = Debouncer::new(watcher_config);

    // Create broadcast channel for coordinating shutdown across subsystems
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Create and run socket server
    let server = SocketServer::new(&paths.socket_file, state_tx.clone());
    info!(socket = %paths.socket_file.display(), "socket server created");

    // Run socket server and shutdown signal concurrently
    tokio::select! {
        result = server.run(shutdown_rx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "socket server error");
                return Err(DaemonError::Socket(e));
            }
        }
        () = lifecycle::shutdown_signal() => {
            info!("shutdown signal received, initiating graceful shutdown");
            // Signal socket server to stop accepting connections
            drop(shutdown_tx);
        }
    }

    // Graceful shutdown: tell the state actor to drain and stop
    info!("sending shutdown to state actor");
    if let Err(e) = state_tx.send(StateMessage::Shutdown).await {
        tracing::warn!(error = %e, "failed to send shutdown to state actor (already stopped?)");
    }

    // Wait for the state actor to finish processing
    if let Err(e) = state_handle.await {
        tracing::warn!(error = %e, "state actor task panicked");
    }

    info!("grove daemon stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::lifecycle::DaemonPaths;
    use crate::socket::SocketServer;
    use crate::state::{GroveConfig, StateMessage, spawn_state_actor};

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
        let pid = lifecycle::read_pid_file(&paths.pid_file)
            .unwrap()
            .unwrap();
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
        assert_eq!(watcher_config.ignore_patterns, vec!["custom_dir".to_string()]);
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
        let lifecycle_err: DaemonError =
            lifecycle::LifecycleError::InvalidPidFile.into();
        assert_eq!(
            lifecycle_err.to_string(),
            "lifecycle error: invalid PID file contents"
        );
    }
}
