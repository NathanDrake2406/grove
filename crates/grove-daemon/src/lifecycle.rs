use std::fs;
use std::path::{Path, PathBuf};

/// Errors that can occur during daemon lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon already running (pid: {0})")]
    AlreadyRunning(u32),
    #[error("invalid PID file contents")]
    InvalidPidFile,
}

/// Standard filesystem paths for daemon runtime files.
#[derive(Debug, Clone)]
pub struct DaemonPaths {
    pub pid_file: PathBuf,
    pub socket_file: PathBuf,
    pub db_file: PathBuf,
    pub log_file: PathBuf,
}

impl DaemonPaths {
    /// Constructs standard daemon paths from a `.grove/` directory.
    pub fn from_grove_dir(grove_dir: &Path) -> Self {
        Self {
            pid_file: grove_dir.join("daemon.pid"),
            socket_file: grove_dir.join("daemon.sock"),
            db_file: grove_dir.join("grove.db"),
            log_file: grove_dir.join("daemon.log"),
        }
    }
}

/// Writes the current process PID to the given file.
///
/// Fails with `LifecycleError::AlreadyRunning` if the file already exists
/// and the recorded process is still alive.
pub fn write_pid_file(path: &Path) -> Result<(), LifecycleError> {
    if let Some(existing_pid) = read_pid_file(path)? {
        if is_process_alive(existing_pid) {
            tracing::warn!(pid = existing_pid, path = %path.display(), "daemon already running");
            return Err(LifecycleError::AlreadyRunning(existing_pid));
        }
        tracing::info!(
            pid = existing_pid,
            path = %path.display(),
            "removing stale PID file from dead process"
        );
        remove_pid_file(path)?;
    }

    let pid = std::process::id();
    fs::write(path, pid.to_string())?;
    tracing::info!(pid, path = %path.display(), "wrote PID file");
    Ok(())
}

/// Reads the PID from the given file.
///
/// Returns `None` if the file does not exist.
pub fn read_pid_file(path: &Path) -> Result<Option<u32>, LifecycleError> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let pid = contents
                .trim()
                .parse::<u32>()
                .map_err(|_| LifecycleError::InvalidPidFile)?;
            Ok(Some(pid))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(LifecycleError::Io(e)),
    }
}

/// Removes the PID file at the given path.
///
/// Silently succeeds if the file does not exist.
pub fn remove_pid_file(path: &Path) -> Result<(), LifecycleError> {
    match fs::remove_file(path) {
        Ok(()) => {
            tracing::debug!(path = %path.display(), "removed PID file");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(LifecycleError::Io(e)),
    }
}

/// Checks whether a daemon is running by reading the PID file and
/// verifying the process is alive.
pub fn is_daemon_running(pid_path: &Path) -> bool {
    match read_pid_file(pid_path) {
        Ok(Some(pid)) => is_process_alive(pid),
        _ => false,
    }
}

/// Checks whether a process with the given PID is alive using `kill(pid, 0)`.
fn is_process_alive(pid: u32) -> bool {
    // SAFETY: kill with signal 0 does not send a signal; it only checks
    // whether the process exists and we have permission to signal it.
    // A return value of 0 means the process exists.
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    ret == 0
}

/// Returns a future that completes when SIGTERM or SIGINT is received.
///
/// This is used to trigger graceful shutdown of the daemon.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm =
        signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint =
        signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM, initiating graceful shutdown");
        }
        _ = sigint.recv() => {
            tracing::info!("received SIGINT, initiating graceful shutdown");
        }
    }
}

/// Removes the PID file and socket file, cleaning up daemon runtime artifacts.
///
/// Best-effort for the socket file: logs a warning on failure but does not
/// propagate the error. The PID file removal error is propagated.
pub fn cleanup(pid_path: &Path, socket_path: &Path) -> Result<(), LifecycleError> {
    remove_pid_file(pid_path)?;

    match fs::remove_file(socket_path) {
        Ok(()) => {
            tracing::debug!(path = %socket_path.display(), "removed socket file");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Socket file already gone — nothing to do.
        }
        Err(e) => {
            tracing::warn!(
                path = %socket_path.display(),
                error = %e,
                "failed to remove socket file"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    #[test]
    fn write_and_read_pid_file_round_trip() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");

        write_pid_file(&pid_path).expect("write_pid_file should succeed");

        let pid = read_pid_file(&pid_path)
            .expect("read_pid_file should succeed")
            .expect("PID file should exist");

        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn write_pid_file_fails_if_already_running() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");

        // Write current process PID — it is alive.
        let current_pid = std::process::id();
        fs::write(&pid_path, current_pid.to_string()).expect("write should succeed");

        let err = write_pid_file(&pid_path).expect_err("should fail with AlreadyRunning");
        match err {
            LifecycleError::AlreadyRunning(pid) => assert_eq!(pid, current_pid),
            other => panic!("expected AlreadyRunning, got: {other}"),
        }
    }

    #[test]
    fn stale_pid_file_gets_overwritten() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");

        // Write a PID that almost certainly doesn't correspond to a live process.
        // PID 4_000_000 is well above typical maximums on macOS/Linux.
        fs::write(&pid_path, "4000000").expect("write should succeed");

        // write_pid_file should detect the stale PID and overwrite.
        write_pid_file(&pid_path).expect("write_pid_file should overwrite stale PID");

        let pid = read_pid_file(&pid_path)
            .expect("read should succeed")
            .expect("PID file should exist");
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn cleanup_removes_both_files() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        let socket_path = dir.path().join("daemon.sock");

        fs::write(&pid_path, "12345").expect("write pid");
        fs::write(&socket_path, "socket-placeholder").expect("write socket");

        cleanup(&pid_path, &socket_path).expect("cleanup should succeed");

        assert!(!pid_path.exists(), "PID file should be removed");
        assert!(!socket_path.exists(), "socket file should be removed");
    }

    #[test]
    fn cleanup_succeeds_when_files_missing() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        let socket_path = dir.path().join("daemon.sock");

        // Neither file exists — cleanup should still succeed.
        cleanup(&pid_path, &socket_path).expect("cleanup should succeed even with missing files");
    }

    #[test]
    fn daemon_paths_from_grove_dir() {
        let grove_dir = Path::new("/tmp/test-workspace/.grove");
        let paths = DaemonPaths::from_grove_dir(grove_dir);

        assert_eq!(paths.pid_file, grove_dir.join("daemon.pid"));
        assert_eq!(paths.socket_file, grove_dir.join("daemon.sock"));
        assert_eq!(paths.db_file, grove_dir.join("grove.db"));
        assert_eq!(paths.log_file, grove_dir.join("daemon.log"));
    }

    #[test]
    fn is_daemon_running_true_for_current_process() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");

        fs::write(&pid_path, std::process::id().to_string()).expect("write pid");

        assert!(is_daemon_running(&pid_path));
    }

    #[test]
    fn is_daemon_running_false_for_nonexistent_pid() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");

        // PID 4_000_000 is extremely unlikely to be alive.
        fs::write(&pid_path, "4000000").expect("write pid");

        assert!(!is_daemon_running(&pid_path));
    }

    #[test]
    fn is_daemon_running_false_when_no_pid_file() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");

        assert!(!is_daemon_running(&pid_path));
    }

    #[test]
    fn read_pid_file_returns_none_when_missing() {
        let dir = temp_dir();
        let pid_path = dir.path().join("nonexistent.pid");

        let result = read_pid_file(&pid_path).expect("read should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn read_pid_file_errors_on_invalid_contents() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");

        fs::write(&pid_path, "not-a-number").expect("write should succeed");

        let err = read_pid_file(&pid_path).expect_err("should fail with InvalidPidFile");
        assert!(matches!(err, LifecycleError::InvalidPidFile));
    }

    #[test]
    fn remove_pid_file_succeeds_when_missing() {
        let dir = temp_dir();
        let pid_path = dir.path().join("nonexistent.pid");

        remove_pid_file(&pid_path).expect("remove should succeed for missing file");
    }

    #[test]
    fn read_pid_file_errors_on_negative_number() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "-42").expect("write should succeed");

        let err = read_pid_file(&pid_path).expect_err("negative pid should fail");
        assert!(matches!(err, LifecycleError::InvalidPidFile));
    }

    #[test]
    fn read_pid_file_errors_on_float() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "12.5").expect("write should succeed");

        let err = read_pid_file(&pid_path).expect_err("float pid should fail");
        assert!(matches!(err, LifecycleError::InvalidPidFile));
    }

    #[test]
    fn read_pid_file_errors_on_empty_string() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "").expect("write should succeed");

        let err = read_pid_file(&pid_path).expect_err("empty pid should fail");
        assert!(matches!(err, LifecycleError::InvalidPidFile));
    }

    #[test]
    fn read_pid_file_errors_on_overflowing_number() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "9999999999999999999999999").expect("write should succeed");

        let err = read_pid_file(&pid_path).expect_err("overflow pid should fail");
        assert!(matches!(err, LifecycleError::InvalidPidFile));
    }

    #[test]
    fn read_pid_file_trims_whitespace() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "  \n 12345 \t").expect("write should succeed");

        let pid = read_pid_file(&pid_path)
            .expect("read should succeed")
            .expect("pid should exist");
        assert_eq!(pid, 12345);
    }

    #[test]
    fn write_pid_file_detects_running_pid_with_whitespace_contents() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        let current_pid = std::process::id();
        fs::write(&pid_path, format!("  {current_pid}\n")).expect("write should succeed");

        let err = write_pid_file(&pid_path).expect_err("should fail with AlreadyRunning");
        assert!(matches!(err, LifecycleError::AlreadyRunning(pid) if pid == current_pid));
    }

    #[test]
    fn read_pid_file_errors_when_path_is_directory() {
        let dir = temp_dir();
        let pid_dir = dir.path().join("pid-dir");
        fs::create_dir(&pid_dir).expect("directory should be created");

        let err = read_pid_file(&pid_dir).expect_err("directory read should fail");
        assert!(matches!(err, LifecycleError::Io(_)));
    }

    #[test]
    fn remove_pid_file_errors_when_path_is_directory() {
        let dir = temp_dir();
        let pid_dir = dir.path().join("pid-dir");
        fs::create_dir(&pid_dir).expect("directory should be created");

        let err = remove_pid_file(&pid_dir).expect_err("remove_file on directory should fail");
        assert!(matches!(err, LifecycleError::Io(_)));
    }

    #[test]
    fn is_daemon_running_false_for_invalid_pid_contents() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "definitely-not-a-pid").expect("write should succeed");

        assert!(!is_daemon_running(&pid_path));
    }

    #[test]
    fn cleanup_still_removes_pid_when_socket_path_is_directory() {
        let dir = temp_dir();
        let pid_path = dir.path().join("daemon.pid");
        let socket_dir = dir.path().join("daemon.sock");
        fs::write(&pid_path, "12345").expect("pid write should succeed");
        fs::create_dir(&socket_dir).expect("socket dir should be created");

        cleanup(&pid_path, &socket_dir).expect("cleanup should ignore non-removable socket path");

        assert!(!pid_path.exists(), "PID file should still be removed");
        assert!(socket_dir.exists(), "socket directory should remain in place");
    }
}
