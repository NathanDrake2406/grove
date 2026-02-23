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
        Self::new_with_input_reader(tick_rate_hz, true)
    }

    fn new_with_input_reader(tick_rate_hz: u64, spawn_input_reader: bool) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let tick_rate = Duration::from_millis(1000 / tick_rate_hz);

        // Spawn a blocking thread to read keyboard events (crossterm blocks)
        if spawn_input_reader {
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
        }

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

    #[cfg(test)]
    pub(crate) fn from_receiver(receiver: mpsc::UnboundedReceiver<Event>) -> Self {
        Self { receiver }
    }

    #[cfg(test)]
    pub(crate) fn new_tick_only(tick_rate_hz: u64) -> Self {
        Self::new_with_input_reader(tick_rate_hz, false)
    }

    pub async fn next(&mut self) -> Result<Event, std::io::Error> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("Event channel closed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn next_returns_error_when_channel_closed() {
        let (sender, receiver) = mpsc::unbounded_channel();
        drop(sender);

        let mut handler = EventHandler::from_receiver(receiver);
        let err = handler.next().await.unwrap_err();
        assert!(err.to_string().contains("Event channel closed"));
    }

    #[tokio::test]
    async fn next_receives_injected_input_event() {
        let (sender, receiver) = mpsc::unbounded_channel();
        sender
            .send(Event::Input(crossterm::event::KeyEvent::from(
                KeyCode::Char('q'),
            )))
            .unwrap();

        let mut handler = EventHandler::from_receiver(receiver);
        let event = handler.next().await.unwrap();
        match event {
            Event::Input(key) => assert_eq!(key.code, KeyCode::Char('q')),
            other => panic!("expected input event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn next_receives_injected_resize_event() {
        let (sender, receiver) = mpsc::unbounded_channel();
        sender.send(Event::Resize(120, 40)).unwrap();

        let mut handler = EventHandler::from_receiver(receiver);
        let event = handler.next().await.unwrap();
        match event {
            Event::Resize(width, height) => {
                assert_eq!(width, 120);
                assert_eq!(height, 40);
            }
            other => panic!("expected resize event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn next_receives_injected_daemon_error_event() {
        let (sender, receiver) = mpsc::unbounded_channel();
        sender
            .send(Event::DaemonError("connection dropped".to_string()))
            .unwrap();

        let mut handler = EventHandler::from_receiver(receiver);
        let event = handler.next().await.unwrap();
        match event {
            Event::DaemonError(message) => assert_eq!(message, "connection dropped"),
            other => panic!("expected daemon error event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tick_generator_emits_ticks() {
        let mut handler = EventHandler::new_tick_only(10);
        let event = timeout(Duration::from_millis(500), handler.next())
            .await
            .expect("tick should arrive within timeout")
            .expect("event stream should be open");

        match event {
            Event::Tick => {}
            other => panic!("expected tick event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_event_handler_emits_tick_or_input_stream_event() {
        let mut handler = EventHandler::new(20);
        let event = timeout(Duration::from_millis(500), handler.next())
            .await
            .expect("an event should arrive within timeout")
            .expect("event stream should stay open");

        match event {
            Event::Tick | Event::Input(_) | Event::Resize(_, _) | Event::DaemonError(_) => {}
        }
    }
}
