//! The main chat screen: header, conversation, activity, input, status.

use ratatui::Frame;

use crate::app::App;
use crate::tui::theme::Theme;
use crate::tui::widgets;

use super::super::layout::chat_layout;

pub fn render_chat(frame: &mut Frame, app: &mut App) {
    let theme = Theme::default();
    let area = frame.area();
    let [header, conversation, activity, input, status] = chat_layout(area);

    widgets::render_header(frame, header, &theme, app.state());
    widgets::render_conversation(frame, conversation, &theme, app.state());
    widgets::render_activity(frame, activity, &theme, app.state());
    widgets::render_input(frame, input, &theme, app.state());
    widgets::render_status(frame, status, &theme, app.state());

    if app.state().show_help {
        widgets::render_help(frame, area, &theme);
    }
    if app.state().show_findings {
        let findings = app.agent().executor().findings.all();
        widgets::render_findings(frame, area, &theme, &findings);
    }
}
