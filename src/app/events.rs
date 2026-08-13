//! Event loop: keyboard events, ticks, and agent events.

use std::time::Duration;

use crossterm::event::{Event as CrosstermEvent, KeyEvent};
use tokio::sync::mpsc;

use crate::agent::AgentEvent;

/// Events consumed by the app loop.
#[derive(Debug)]
pub enum Event {
    /// A key was pressed.
    Key(KeyEvent),
    /// A periodic tick (for elapsed-time updates).
    Tick,
    /// The terminal was resized.
    Resize(u16, u16),
    /// The agent produced an event.
    Agent(AgentEvent),
}

/// Spawn a background thread reading terminal input and forwarding it to
/// the app over a tokio channel.
pub fn spawn_input_reader(tx: mpsc::Sender<Event>) {
    std::thread::spawn(move || loop {
        match crossterm::event::poll(Duration::from_millis(50)) {
            Ok(true) => match crossterm::event::read() {
                Ok(CrosstermEvent::Key(key)) => {
                    if tx.blocking_send(Event::Key(key)).is_err() {
                        break;
                    }
                }
                Ok(CrosstermEvent::Resize(w, h)) => {
                    if tx.blocking_send(Event::Resize(w, h)).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            },
            Ok(false) => {}
            Err(_) => break,
        }
    });
}
