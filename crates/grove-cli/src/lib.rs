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

    /// List all workspaces
    List,

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

pub async fn run(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Handle commands that don't require a grove workspace or daemon connection.
    match &args.command {
        Some(Commands::Init { shell }) => {
            commands::init::execute(shell)?;
            return Ok(());
        }
        Some(Commands::Daemon {
            action: DaemonAction::Start,
        }) => {
            handle_daemon_start();
            return Ok(());
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
            return Ok(());
        }
        Some(Commands::Daemon {
            action: DaemonAction::Status,
        }) => {
            let grove_dir = find_grove_dir(std::env::current_dir()?)?;
            let socket_path = grove_dir.join("daemon.sock");
            let client = DaemonClient::new(&socket_path);
            commands::status::execute(&client, args.json).await?;
            return Ok(());
        }
        _ => {}
    }

    // All other commands: bootstrap (auto-create .grove/, auto-spawn daemon, sync worktrees).
    let (client, _grove_dir) = bootstrap::bootstrap()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    match args.command {
        Some(Commands::Status) | None => {
            commands::status::execute(&client, args.json).await?;
        }
        Some(Commands::List) => {
            commands::list::execute(&client, args.json).await?;
        }
        Some(Commands::Conflicts { a, b }) => {
            commands::conflicts::execute(&client, &a, &b, args.json).await?;
        }
        // Already handled above; included for exhaustive matching.
        Some(Commands::Daemon { .. }) | Some(Commands::Init { .. }) => {
            unreachable!("handled above");
        }
    }
    Ok(())
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
}
