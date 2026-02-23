use clap::Parser;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiMode {
    Dashboard,
    StatusFallback,
    None,
}

fn is_daemon_start(command: &Option<grove_cli::Commands>) -> bool {
    matches!(
        command,
        Some(grove_cli::Commands::Daemon {
            action: grove_cli::DaemonAction::Start
        })
    )
}

fn ui_mode_for(
    command: &Option<grove_cli::Commands>,
    json_output: bool,
    stdout_is_tty: bool,
) -> UiMode {
    let explicit_dashboard = matches!(command, Some(grove_cli::Commands::Dashboard));
    let fallback_dashboard = command.is_none() && stdout_is_tty && !json_output;
    let fallback_status = command.is_none() && (!stdout_is_tty || json_output);

    if explicit_dashboard || fallback_dashboard {
        UiMode::Dashboard
    } else if fallback_status {
        UiMode::StatusFallback
    } else {
        UiMode::None
    }
}

fn main() {
    let args = grove_cli::CliArgs::parse();

    if is_daemon_start(&args.command) {
        // Find .grove/ directory — the daemon needs it for PID file, socket, DB, and logs.
        let grove_dir = find_grove_dir().unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });

        // CRITICAL: Daemonization (double-fork) MUST happen here, synchronously,
        // BEFORE the tokio runtime is constructed. Forking after tokio spawns
        // threads causes mutex deadlocks because forked processes inherit only
        // the calling thread — all other threads (and their held locks) vanish.
        //
        // For now, the daemon runs in the foreground (useful for development).
        // When daemonize support is added, it will go right here:
        //
        //   daemonize::Daemonize::new()
        //       .pid_file(grove_dir.join("daemon.pid"))
        //       .working_directory(&grove_dir)
        //       .start()
        //       .expect("failed to daemonize");

        // Build tokio runtime AFTER fork (or in foreground mode, just here).
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("error: failed to create tokio runtime: {e}");
                std::process::exit(1);
            }
        };

        let config = grove_daemon::state::GroveConfig::default();
        if let Err(e) = rt.block_on(grove_daemon::run(config, &grove_dir)) {
            eprintln!("daemon error: {e}");
            std::process::exit(1);
        }
    } else {
        // All other CLI commands, including daemon stop/status.
        run_cli(args);
    }
}

/// Build a tokio runtime and run the CLI entry point.
fn run_cli(args: grove_cli::CliArgs) -> ! {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to create tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    let json_output = args.json;

    use crossterm::tty::IsTty;
    let mode = ui_mode_for(&args.command, json_output, std::io::stdout().is_tty());

    // Get the client from the standard CLI run (which handles bootstrap)
    let client = match rt.block_on(grove_cli::run(args)) {
        Ok(c) => c,
        Err(e) => {
            emit_cli_error(&e, json_output);
            std::process::exit(1);
        }
    };

    match mode {
        UiMode::Dashboard => {
            if let Err(e) = rt.block_on(grove_tui::run(client)) {
                eprintln!("Interactive dashboard error: {e}");
                std::process::exit(1);
            }
        }
        UiMode::StatusFallback => {
            // Fallback for non-interactive `grove`
            if let Err(e) = rt.block_on(grove_cli::commands::status::execute(&client, false)) {
                if json_output {
                    emit_cli_error(&e, true);
                } else {
                    eprintln!("error executing status fallback: {e}");
                }
                std::process::exit(1);
            }
        }
        UiMode::None => {}
    }

    std::process::exit(0);
}

fn emit_cli_error(error: &impl Display, json: bool) {
    eprintln!("{}", format_cli_error(error, json));
}

fn format_cli_error(error: &impl Display, json: bool) -> String {
    if json {
        let encoded_error = serde_json::to_string(&error.to_string())
            .unwrap_or_else(|_| "\"failed to serialize error\"".to_string());
        format!("{{\"ok\":false,\"error\":{encoded_error}}}")
    } else {
        format!("error: {error}")
    }
}

/// Walk up from the current directory looking for a `.grove/` directory.
///
/// This duplicates the logic in `grove-cli` intentionally: the binary crate needs
/// the grove directory before handing off to the daemon, independently of CLI.
fn find_grove_dir() -> Result<std::path::PathBuf, String> {
    let dir = std::env::current_dir().map_err(|e| format!("cannot get current directory: {e}"))?;
    find_grove_dir_from(dir)
}

fn find_grove_dir_from(mut dir: std::path::PathBuf) -> Result<std::path::PathBuf, String> {
    loop {
        let grove = dir.join(".grove");
        if grove.is_dir() {
            return Ok(grove);
        }
        if !dir.pop() {
            return Err("not in a grove workspace (no .grove/ directory found)".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{UiMode, find_grove_dir_from, format_cli_error, is_daemon_start, ui_mode_for};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn format_cli_error_plain_prefixes_error() {
        let rendered = format_cli_error(&"workspace not found: feat/foo", false);
        assert_eq!(rendered, "error: workspace not found: feat/foo");
    }

    #[test]
    fn format_cli_error_json_is_structured() {
        let rendered = format_cli_error(&"workspace not found: feat/foo", true);
        let value: serde_json::Value =
            serde_json::from_str(&rendered).expect("json error output should parse");

        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "workspace not found: feat/foo");
    }

    #[test]
    fn daemon_start_detection_matches_only_start_variant() {
        let args = grove_cli::CliArgs::try_parse_from(["grove", "daemon", "start"]).unwrap();
        assert!(is_daemon_start(&args.command));

        let args = grove_cli::CliArgs::try_parse_from(["grove", "daemon", "status"]).unwrap();
        assert!(!is_daemon_start(&args.command));

        let args = grove_cli::CliArgs::try_parse_from(["grove", "status"]).unwrap();
        assert!(!is_daemon_start(&args.command));
    }

    #[test]
    fn ui_mode_selection_handles_dashboard_and_status_fallbacks() {
        let dashboard = grove_cli::CliArgs::try_parse_from(["grove", "dashboard"]).unwrap();
        assert_eq!(
            ui_mode_for(&dashboard.command, false, false),
            UiMode::Dashboard
        );

        let no_command = grove_cli::CliArgs::try_parse_from(["grove"]).unwrap();
        assert_eq!(
            ui_mode_for(&no_command.command, false, true),
            UiMode::Dashboard
        );
        assert_eq!(
            ui_mode_for(&no_command.command, false, false),
            UiMode::StatusFallback
        );
        assert_eq!(
            ui_mode_for(&no_command.command, true, true),
            UiMode::StatusFallback
        );

        let status = grove_cli::CliArgs::try_parse_from(["grove", "status"]).unwrap();
        assert_eq!(ui_mode_for(&status.command, false, true), UiMode::None);
    }

    #[test]
    fn find_grove_dir_from_walks_up_from_nested_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let nested = root.join("a").join("b").join("c");
        std::fs::create_dir_all(root.join(".grove")).unwrap();
        std::fs::create_dir_all(&nested).unwrap();

        let found = find_grove_dir_from(nested).unwrap();
        assert_eq!(found, root.join(".grove"));
    }

    #[test]
    fn find_grove_dir_from_errors_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        let without_grove = temp.path().join("repo");
        std::fs::create_dir_all(&without_grove).unwrap();

        let err = find_grove_dir_from(without_grove).unwrap_err();
        assert!(err.contains("no .grove/ directory found"));
    }

    #[test]
    fn find_grove_dir_from_root_without_grove_errors() {
        let err = find_grove_dir_from(PathBuf::from("/")).unwrap_err();
        assert!(err.contains("no .grove/ directory found"));
    }
}
