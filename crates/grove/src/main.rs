use clap::Parser;

fn main() {
    let args = grove_cli::CliArgs::parse();

    match &args.command {
        Some(grove_cli::Commands::Daemon { action }) => match action {
            grove_cli::DaemonAction::Start => {
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
                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

                let config = grove_daemon::state::GroveConfig::default();
                if let Err(e) = rt.block_on(grove_daemon::run(config, &grove_dir)) {
                    eprintln!("daemon error: {e}");
                    std::process::exit(1);
                }
            }
            grove_cli::DaemonAction::Stop | grove_cli::DaemonAction::Status => {
                // Stop and Status are lightweight CLI commands that talk to the daemon
                // via the socket — safe to use a standard tokio runtime.
                run_cli(args);
            }
        },
        _ => {
            // All other CLI commands (status, list, conflicts, or no subcommand).
            run_cli(args);
        }
    }
}

/// Build a tokio runtime and run the CLI entry point.
fn run_cli(args: grove_cli::CliArgs) -> ! {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    
    // Check if we requested the TUI explicitly
    let is_explicit_dashboard = matches!(args.command, Some(grove_cli::Commands::Dashboard));
    
    // Or if we should fallback to the TUI (no command + interactive TTY)
    use crossterm::tty::IsTty;
    let is_fallback_dashboard = args.command.is_none() && std::io::stdout().is_tty() && !args.json;
    let fallback_to_status = args.command.is_none() && (!std::io::stdout().is_tty() || args.json);

    // Get the client from the standard CLI run (which handles bootstrap)
    let client = match rt.block_on(grove_cli::run(args)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if is_explicit_dashboard || is_fallback_dashboard {
        if let Err(e) = rt.block_on(grove_tui::run(client)) {
            eprintln!("Interactive dashboard error: {e}");
            std::process::exit(1);
        }
    } else if fallback_to_status {
        // Fallback for non-interactive `grove`
        if let Err(e) = rt.block_on(grove_cli::commands::status::execute(&client, false)) {
            eprintln!("error executing status fallback: {e}");
            std::process::exit(1);
        }
    }
    
    std::process::exit(0);
}

/// Walk up from the current directory looking for a `.grove/` directory.
///
/// This duplicates the logic in `grove-cli` intentionally: the binary crate needs
/// the grove directory before handing off to the daemon, independently of CLI.
fn find_grove_dir() -> Result<std::path::PathBuf, String> {
    let mut dir =
        std::env::current_dir().map_err(|e| format!("cannot get current directory: {e}"))?;
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
