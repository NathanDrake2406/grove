use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum Event {
    /// A keyboard event
    Input(KeyEvent),
    /// A terminal resize event
    Resize(u16, u16),
    /// A periodic tick event (for polling data)
    Tick,
    /// An error communicating with the daemon polling
    DaemonError(String),
}

pub struct EventHandler {
    receiver: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    pub fn new(tick_rate_hz: u64) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let tick_rate = Duration::from_millis(1000 / tick_rate_hz);

        // Spawn a blocking thread to read keyboard events (crossterm blocks)
        let _input_task = {
            let sender = sender.clone();
            tokio::task::spawn_blocking(move || {
                loop {
                    match event::read() {
                        Ok(CrosstermEvent::Key(key)) => {
                            if sender.send(Event::Input(key)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Resize(width, height)) => {
                            if sender.send(Event::Resize(width, height)).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(err) => {
                            if sender.send(Event::DaemonError(err.to_string())).is_err() {
                                break;
                            }
                        }
                    }
                }
            })
        };

        // Spawn an async task for the periodic tick
        let _tick_task = {
            let sender = sender.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tick_rate);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    interval.tick().await;
                    if sender.send(Event::Tick).is_err() {
                        break;
                    }
                }
            })
        };

        Self { receiver }
    }

    pub async fn next(&mut self) -> Result<Event, std::io::Error> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("Event channel closed"))
    }
}
