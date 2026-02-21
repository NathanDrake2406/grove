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
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
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

        match events.next().await? {
            events::Event::Input(key) => {
                // Force an immediate data fetch on manual refresh input.
                if key.code == KeyCode::Char('r') {
                    app.refresh_data().await?;
                }

                // If input handling returns true, we need to exit
                if app.handle_input(key) {
                    break;
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
    }

    Ok(())
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
