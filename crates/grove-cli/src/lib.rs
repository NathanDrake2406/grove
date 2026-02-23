pub mod bootstrap;
pub mod client;
pub mod commands;

use std::path::PathBuf;

use clap::Parser;

use crate::client::DaemonClient;

// === CLI Argument Parsing ===

#[derive(Parser, Debug)]
#[command(
    name = "grove",
    about = "Git worktree workspace manager with conflict intelligence"
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Show workspace status overview
    Status,

    /// Open the live interactive dashboard (TUI)
    Dashboard,

    /// List all workspaces
    List,

    /// Check if current worktree has conflicts (exit 1 if yes)
    Check,

    /// Show conflicts between two workspaces
    Conflicts {
        /// First workspace name or ID
        a: String,
        /// Second workspace name or ID
        b: String,
    },

    /// Manage the daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Generate shell integration (eval "$(grove init zsh)")
    Init {
        /// Shell type: zsh, bash, or fish
        shell: String,
    },
}

#[derive(clap::Subcommand, Debug, PartialEq, Eq)]
pub enum DaemonAction {
    /// Start the daemon
    Start,
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status,
}

// === Entrypoint ===

pub async fn run(args: CliArgs) -> Result<DaemonClient, Box<dyn std::error::Error>> {
    // Handle commands that don't require a grove workspace or daemon connection.
    match &args.command {
        Some(Commands::Init { shell }) => {
            commands::init::execute(shell)?;
            // No client needed/created for init
            std::process::exit(0);
        }
        Some(Commands::Daemon {
            action: DaemonAction::Start,
        }) => {
            handle_daemon_start();
            std::process::exit(0);
        }
        _ => {}
    }

    // Commands that manage the daemon directly — use existing find_grove_dir (no auto-spawn).
    match &args.command {
        Some(Commands::Daemon {
            action: DaemonAction::Stop,
        }) => {
            let grove_dir = find_grove_dir(std::env::current_dir()?)?;
            let socket_path = grove_dir.join("daemon.sock");
            let client = DaemonClient::new(&socket_path);
            handle_daemon_stop(&client, &grove_dir, args.json).await?;
            return Ok(client);
        }
        Some(Commands::Daemon {
            action: DaemonAction::Status,
        }) => {
            let grove_dir = find_grove_dir(std::env::current_dir()?)?;
            let socket_path = grove_dir.join("daemon.sock");
            let client = DaemonClient::new(&socket_path);
            commands::status::execute(&client, args.json).await?;
            return Ok(client);
        }
        _ => {}
    }

    // All other commands: bootstrap (auto-create .grove/, auto-spawn daemon, sync worktrees).
    let (client, _grove_dir) = bootstrap::bootstrap()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    match args.command {
        Some(Commands::Status) => {
            commands::status::execute(&client, args.json).await?;
        }
        Some(Commands::Dashboard) | None => {
            // Handled by the main binary to avoid cyclic dependency.
            // When `run` is called by the `grove` binary, it expects CLI commands to execute
            // except for Dashboard/TTY fallbacks, which the binary handles itself.
        }
        Some(Commands::List) => {
            commands::list::execute(&client, args.json).await?;
        }
        Some(Commands::Check) => {
            commands::check::execute(&client, args.json).await?;
        }
        Some(Commands::Conflicts { a, b }) => {
            commands::conflicts::execute(&client, &a, &b, args.json).await?;
        }
        // Already handled above; included for exhaustive matching.
        Some(Commands::Daemon { .. }) | Some(Commands::Init { .. }) => {
            unreachable!("handled above");
        }
    }

    Ok(client)
}

fn handle_daemon_start() {
    println!("Starting daemon...");
}

async fn handle_daemon_stop(
    client: &DaemonClient,
    grove_dir: &std::path::Path,
    json: bool,
) -> Result<(), commands::CommandError> {
    let shutdown_token = read_shutdown_token_file(grove_dir)?;
    let response = client.shutdown(shutdown_token.as_deref()).await?;

    if !response.ok {
        let message = response
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(commands::CommandError::DaemonError(message));
    }

    if json {
        let data = response
            .data
            .unwrap_or_else(|| serde_json::json!({ "status": "shutdown_requested" }));
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        println!("Daemon shutdown requested.");
    }

    Ok(())
}

fn read_shutdown_token_file(
    grove_dir: &std::path::Path,
) -> Result<Option<String>, commands::CommandError> {
    let token_path = grove_dir.join("daemon.shutdown.token");
    match std::fs::read_to_string(&token_path) {
        Ok(contents) => {
            let token = contents.trim().to_string();
            if token.is_empty() {
                Ok(None)
            } else {
                Ok(Some(token))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(commands::CommandError::DaemonError(format!(
            "failed to read shutdown token: {e}"
        ))),
    }
}

/// Walk up from the given directory looking for a `.grove/` directory.
fn find_grove_dir(start: PathBuf) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut dir = start;
    loop {
        let grove = dir.join(".grove");
        if grove.is_dir() {
            return Ok(grove);
        }
        if !dir.pop() {
            return Err("not in a grove workspace (no .grove/ directory found)".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::Value;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn spawn_shutdown_server(
        socket_path: PathBuf,
        expected_token: Option<String>,
        response: Value,
    ) -> tokio::task::JoinHandle<()> {
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("socket should bind");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept should succeed");
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let _ = reader
                .read_line(&mut line)
                .await
                .expect("request line should read");
            let request: Value = serde_json::from_str(&line).expect("request should be json");

            assert_eq!(request["method"], "shutdown");
            match expected_token {
                Some(token) => assert_eq!(request["params"]["token"], token),
                None => assert_eq!(request["params"], serde_json::json!({})),
            }

            let mut stream = reader.into_inner();
            stream
                .write_all(response.to_string().as_bytes())
                .await
                .expect("response should write");
            stream.write_all(b"\n").await.expect("newline should write");
        })
    }

    #[test]
    fn parse_no_args_defaults_to_status() {
        let args = CliArgs::try_parse_from(["grove"]).unwrap();
        assert!(args.command.is_none());
        assert!(!args.json);
    }

    #[test]
    fn parse_status_command() {
        let args = CliArgs::try_parse_from(["grove", "status"]).unwrap();
        assert!(matches!(args.command, Some(Commands::Status)));
    }

    #[test]
    fn parse_list_command() {
        let args = CliArgs::try_parse_from(["grove", "list"]).unwrap();
        assert!(matches!(args.command, Some(Commands::List)));
    }

    #[test]
    fn parse_conflicts_command() {
        let args = CliArgs::try_parse_from(["grove", "conflicts", "ws-a", "ws-b"]).unwrap();
        match args.command {
            Some(Commands::Conflicts { a, b }) => {
                assert_eq!(a, "ws-a");
                assert_eq!(b, "ws-b");
            }
            other => panic!("expected Conflicts, got: {other:?}"),
        }
    }

    #[test]
    fn parse_conflicts_requires_two_args() {
        let result = CliArgs::try_parse_from(["grove", "conflicts", "ws-a"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_daemon_start() {
        let args = CliArgs::try_parse_from(["grove", "daemon", "start"]).unwrap();
        match args.command {
            Some(Commands::Daemon { action }) => {
                assert_eq!(action, DaemonAction::Start);
            }
            other => panic!("expected Daemon Start, got: {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_stop() {
        let args = CliArgs::try_parse_from(["grove", "daemon", "stop"]).unwrap();
        match args.command {
            Some(Commands::Daemon { action }) => {
                assert_eq!(action, DaemonAction::Stop);
            }
            other => panic!("expected Daemon Stop, got: {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_status() {
        let args = CliArgs::try_parse_from(["grove", "daemon", "status"]).unwrap();
        match args.command {
            Some(Commands::Daemon { action }) => {
                assert_eq!(action, DaemonAction::Status);
            }
            other => panic!("expected Daemon Status, got: {other:?}"),
        }
    }

    #[test]
    fn parse_init_command() {
        let args = CliArgs::try_parse_from(["grove", "init", "zsh"]).unwrap();
        match args.command {
            Some(Commands::Init { shell }) => {
                assert_eq!(shell, "zsh");
            }
            other => panic!("expected Init, got: {other:?}"),
        }
    }

    #[test]
    fn parse_init_requires_shell_arg() {
        let result = CliArgs::try_parse_from(["grove", "init"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_flag_global() {
        let args = CliArgs::try_parse_from(["grove", "--json", "status"]).unwrap();
        assert!(args.json);
        assert!(matches!(args.command, Some(Commands::Status)));
    }

    #[test]
    fn parse_json_flag_after_subcommand() {
        let args = CliArgs::try_parse_from(["grove", "list", "--json"]).unwrap();
        assert!(args.json);
        assert!(matches!(args.command, Some(Commands::List)));
    }

    #[test]
    fn parse_unknown_command_fails() {
        let result = CliArgs::try_parse_from(["grove", "foobar"]);
        assert!(result.is_err());
    }

    #[test]
    fn find_grove_dir_fails_when_no_grove_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let result = find_grove_dir(tmp.path().to_path_buf());
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not in a grove workspace"));
    }

    #[test]
    fn find_grove_dir_succeeds_when_grove_directory_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".grove")).unwrap();

        let result = find_grove_dir(tmp.path().to_path_buf());

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tmp.path().join(".grove"));
    }

    #[test]
    fn find_grove_dir_walks_up_to_parent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".grove")).unwrap();
        let subdir = tmp.path().join("nested").join("deep");
        std::fs::create_dir_all(&subdir).unwrap();

        let result = find_grove_dir(subdir);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tmp.path().join(".grove"));
    }

    #[test]
    fn read_shutdown_token_file_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let token = read_shutdown_token_file(tmp.path()).unwrap();
        assert_eq!(token, None);
    }

    #[test]
    fn read_shutdown_token_file_trims_and_returns_token() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("daemon.shutdown.token"),
            "  secret-token \n",
        )
        .unwrap();

        let token = read_shutdown_token_file(tmp.path()).unwrap();
        assert_eq!(token.as_deref(), Some("secret-token"));
    }

    #[test]
    fn read_shutdown_token_file_treats_blank_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("daemon.shutdown.token"), "   \n").unwrap();

        let token = read_shutdown_token_file(tmp.path()).unwrap();
        assert_eq!(token, None);
    }

    #[test]
    fn read_shutdown_token_file_errors_on_non_readable_path() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("daemon.shutdown.token")).unwrap();

        let err = read_shutdown_token_file(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("failed to read shutdown token"));
    }

    #[tokio::test]
    async fn handle_daemon_stop_sends_token_and_accepts_json_success() {
        let tmp = tempfile::tempdir().unwrap();
        let grove_dir = tmp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();
        std::fs::write(grove_dir.join("daemon.shutdown.token"), "tok123").unwrap();

        let socket_path = grove_dir.join("daemon.sock");
        let server = spawn_shutdown_server(
            socket_path.clone(),
            Some("tok123".to_string()),
            serde_json::json!({
                "ok": true,
                "data": { "status": "shutdown_requested" }
            }),
        );

        let client = DaemonClient::new(&socket_path);
        handle_daemon_stop(&client, &grove_dir, true)
            .await
            .expect("daemon stop should succeed");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handle_daemon_stop_uses_empty_params_without_token() {
        let tmp = tempfile::tempdir().unwrap();
        let grove_dir = tmp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let socket_path = grove_dir.join("daemon.sock");
        let server = spawn_shutdown_server(
            socket_path.clone(),
            None,
            serde_json::json!({
                "ok": true,
                "data": null
            }),
        );

        let client = DaemonClient::new(&socket_path);
        handle_daemon_stop(&client, &grove_dir, false)
            .await
            .expect("daemon stop should succeed");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handle_daemon_stop_returns_error_when_daemon_rejects_shutdown() {
        let tmp = tempfile::tempdir().unwrap();
        let grove_dir = tmp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let socket_path = grove_dir.join("daemon.sock");
        let server = spawn_shutdown_server(
            socket_path.clone(),
            None,
            serde_json::json!({
                "ok": false,
                "error": "denied"
            }),
        );

        let client = DaemonClient::new(&socket_path);
        let err = handle_daemon_stop(&client, &grove_dir, false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("denied"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handle_daemon_stop_uses_unknown_error_fallback_when_missing_error_field() {
        let tmp = tempfile::tempdir().unwrap();
        let grove_dir = tmp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let socket_path = grove_dir.join("daemon.sock");
        let server = spawn_shutdown_server(
            socket_path.clone(),
            None,
            serde_json::json!({
                "ok": false,
                "error": null
            }),
        );

        let client = DaemonClient::new(&socket_path);
        let err = handle_daemon_stop(&client, &grove_dir, false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown error"));
        server.await.unwrap();
    }
}
