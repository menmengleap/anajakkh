//! Screen layout: header, conversation, activity, input, status bar.

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Compute the main layout of the chat screen.
///
/// ```text
/// ┌────────────────────────────────┐
/// │ header (branding)             │ 1
/// │ conversation area             │ *
/// │ agent activity                │ 6
/// │ input                         │ 2
/// │ status bar                    │ 1
/// └────────────────────────────────┘
/// ```
pub fn chat_layout(area: Rect) -> [Rect; 5] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(3),    // conversation
            Constraint::Length(6), // activity
            Constraint::Length(2), // input
            Constraint::Length(1), // status
        ])
        .split(area);
    [chunks[0], chunks[1], chunks[2], chunks[3], chunks[4]]
}

/// Center a popup (help, etc.) within the given area.
pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area)[1];
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup)[1]
}
