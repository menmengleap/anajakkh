//! Terminal UI: themes, layout, widgets, and screens.

pub mod input;
pub mod layout;
pub mod screens;
pub mod theme;
pub mod widgets;

use ratatui::Frame;

use crate::app::App;

use self::screens::render_chat;

/// Render the application into the frame.
pub fn render(frame: &mut Frame, app: &mut App) {
    render_chat(frame, app);
}
