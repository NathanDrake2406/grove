pub mod app;
pub mod events;
pub mod ui;

use std::error::Error;

use crossterm::{
    ExecutableCommand,
    event::KeyCode,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use grove_cli::client::DaemonClient;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

const POLL_TICK_HZ: u64 = 1;

/// Run the TUI dashboard.
pub async fn run(client: DaemonClient) -> Result<(), Box<dyn Error>> {
    setup_panic_hook();

    let mut terminal = setup_terminal()?;

    let mut app = app::App::new(client);
    let mut events = events::EventHandler::new(POLL_TICK_HZ);

    let res = run_app(&mut terminal, &mut app, &mut events).await;

    restore_terminal(&mut terminal)?;

    if let Err(err) = res {
        eprintln!("{err:?}");
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<impl ratatui::backend::Backend>,
    app: &mut app::App,
    events: &mut events::EventHandler,
) -> Result<(), Box<dyn Error>> {
    // Initial fetch to populate data
    app.refresh_data().await?;

    // Initial render
    terminal.draw(|frame| ui::render(app, frame))?;

    let mut last_timestamp_redraw = std::time::Instant::now();

    loop {
        // Only draw if the state has changed (is_dirty)
        if app.is_dirty {
            terminal.draw(|frame| ui::render(app, frame))?;
            app.is_dirty = false;
            last_timestamp_redraw = std::time::Instant::now();
        }

        // Redraw every 60s so the "updated Xm ago" stays reasonably current
        if last_timestamp_redraw.elapsed().as_secs() >= 60 {
            app.is_dirty = true;
        }

        if handle_event(app, events.next().await?).await? {
            break;
        }
    }

    Ok(())
}

async fn handle_event(app: &mut app::App, event: events::Event) -> Result<bool, Box<dyn Error>> {
    match event {
        events::Event::Input(key) => {
            // Force an immediate data fetch on manual refresh input.
            if key.code == KeyCode::Char('r') {
                app.refresh_data().await?;
            }

            // If input handling returns true, we need to exit
            if app.handle_input(key) {
                return Ok(true);
            }
        }
        events::Event::Tick => {
            app.refresh_data().await?;
        }
        events::Event::Resize(_, _) => {
            app.is_dirty = true;
        }
        events::Event::DaemonError(err) => {
            app.set_error(err);
        }
    }

    Ok(false)
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>, Box<dyn Error>> {
    enable_raw_mode()?;
    std::io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<(), Box<dyn Error>> {
    disable_raw_mode()?;
    std::io::stdout().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn setup_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Ensure terminal is cleanly restored on panic before logging the panic
        let _ = disable_raw_mode();
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{FocusedPanel, ViewState};
    use crossterm::tty::IsTty;
    use ratatui::backend::TestBackend;
    use serde_json::json;
    use std::path::PathBuf;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::mpsc;

    fn spawn_mock_daemon(
        socket_path: PathBuf,
        responses: Vec<serde_json::Value>,
    ) -> tokio::task::JoinHandle<()> {
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            for response in responses {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                let bytes = reader.read_line(&mut line).await.unwrap();
                assert!(bytes > 0, "expected request line from client");

                let mut stream = reader.into_inner();
                stream
                    .write_all(response.to_string().as_bytes())
                    .await
                    .unwrap();
                stream.write_all(b"\n").await.unwrap();
            }
        })
    }

    fn status_ok() -> serde_json::Value {
        json!({"ok": true, "data": {"base_commit": "1234567890abcdef"}})
    }

    fn workspaces_ok() -> serde_json::Value {
        json!({
            "ok": true,
            "data": [
                {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "alpha",
                    "branch": "feature/a",
                    "path": "/tmp/a",
                    "base_ref": "refs/heads/main",
                    "created_at": "2026-01-01T00:00:00Z",
                    "last_activity": "2026-01-01T00:00:00Z",
                    "metadata": {}
                },
                {
                    "id": "00000000-0000-0000-0000-000000000002",
                    "name": "beta",
                    "branch": "feature/b",
                    "path": "/tmp/b",
                    "base_ref": "refs/heads/main",
                    "created_at": "2026-01-01T00:00:00Z",
                    "last_activity": "2026-01-01T00:00:00Z",
                    "metadata": {}
                }
            ]
        })
    }

    fn analyses_ok() -> serde_json::Value {
        json!({
            "ok": true,
            "data": [
                {
                    "workspace_a": "00000000-0000-0000-0000-000000000001",
                    "workspace_b": "00000000-0000-0000-0000-000000000002",
                    "score": "Yellow",
                    "overlaps": [{
                        "File": {
                            "path": "src/lib.rs",
                            "a_change": "Modified",
                            "b_change": "Modified"
                        }
                    }],
                    "merge_order_hint": "Either",
                    "last_computed": "2026-01-01T00:00:00Z"
                }
            ]
        })
    }

    #[tokio::test]
    async fn run_app_exits_on_quit_input() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let server = spawn_mock_daemon(
            socket.clone(),
            vec![status_ok(), workspaces_ok(), analyses_ok()],
        );

        let client = DaemonClient::new(&socket);
        let mut app = app::App::new(client);
        app.view_state = ViewState::Dashboard;

        let (sender, receiver) = mpsc::unbounded_channel();
        sender
            .send(events::Event::Input(crossterm::event::KeyEvent::from(
                KeyCode::Char('q'),
            )))
            .unwrap();
        drop(sender);
        let mut event_handler = events::EventHandler::from_receiver(receiver);

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        run_app(&mut terminal, &mut app, &mut event_handler)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_app_handles_tick_then_quit() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        // Initial refresh + tick refresh (2 * 3 daemon calls)
        let responses = vec![
            status_ok(),
            workspaces_ok(),
            analyses_ok(),
            status_ok(),
            workspaces_ok(),
            analyses_ok(),
        ];
        let server = spawn_mock_daemon(socket.clone(), responses);

        let client = DaemonClient::new(&socket);
        let mut app = app::App::new(client);
        app.view_state = ViewState::Dashboard;
        app.focused_panel = FocusedPanel::Pairs;

        let (sender, receiver) = mpsc::unbounded_channel();
        sender.send(events::Event::Tick).unwrap();
        sender
            .send(events::Event::Input(crossterm::event::KeyEvent::from(
                KeyCode::Char('q'),
            )))
            .unwrap();
        drop(sender);
        let mut event_handler = events::EventHandler::from_receiver(receiver);

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        run_app(&mut terminal, &mut app, &mut event_handler)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handle_event_sets_dirty_and_error_states() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let server = spawn_mock_daemon(
            socket.clone(),
            vec![status_ok(), workspaces_ok(), analyses_ok()],
        );

        let client = DaemonClient::new(&socket);
        let mut app = app::App::new(client);
        app.refresh_data().await.unwrap();

        app.is_dirty = false;
        let should_exit = handle_event(&mut app, events::Event::Resize(120, 40))
            .await
            .unwrap();
        assert!(!should_exit);
        assert!(app.is_dirty);

        let should_exit = handle_event(
            &mut app,
            events::Event::DaemonError("socket hiccup".to_string()),
        )
        .await
        .unwrap();
        assert!(!should_exit);
        assert_eq!(
            app.view_state,
            ViewState::Error("socket hiccup".to_string())
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handle_event_refresh_key_triggers_data_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        // Initial refresh + manual refresh key = 2 rounds of daemon calls.
        let server = spawn_mock_daemon(
            socket.clone(),
            vec![
                status_ok(),
                workspaces_ok(),
                analyses_ok(),
                status_ok(),
                workspaces_ok(),
                analyses_ok(),
            ],
        );

        let client = DaemonClient::new(&socket);
        let mut app = app::App::new(client);
        app.refresh_data().await.unwrap();

        let should_exit = handle_event(
            &mut app,
            events::Event::Input(crossterm::event::KeyEvent::from(KeyCode::Char('r'))),
        )
        .await
        .unwrap();
        assert!(!should_exit);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_returns_error_when_stdout_is_not_tty() {
        if std::io::stdout().is_tty() {
            return;
        }

        let socket = tempfile::tempdir().unwrap().path().join("missing.sock");
        let client = DaemonClient::new(&socket);
        let result = run(client).await;
        assert!(result.is_err(), "non-tty setup should fail in test env");
    }

    #[test]
    fn setup_panic_hook_installs_without_panicking() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(previous);
        setup_panic_hook();
        let hook = std::panic::take_hook();
        std::panic::set_hook(hook);
    }
}
