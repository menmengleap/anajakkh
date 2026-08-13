//! Key → action mapping and the actions the app can perform.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Submit,
    Cancel,
    Exit,
    ToggleHelp,
    DefineScope,
    CommitScope,
    TypeChar(char),
    Backspace,
    Delete,
    MoveLeft,
    MoveRight,
    Home,
    End,
    ScrollUp,
    ScrollDown,
    ReRun,
    ShowLogs,
    ShowFindings,
    ShowTools,
    ShowHistory,
    ShowModel,
}

/// Map a key press to an action.
pub fn action_from_key(key: KeyEvent) -> Option<Action> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c') => Some(Action::Exit),
            KeyCode::Char('l') => Some(Action::ShowLogs),
            KeyCode::Char('f') => Some(Action::ShowFindings),
            KeyCode::Char('s') => Some(Action::DefineScope),
            KeyCode::Char('h') => Some(Action::ShowHistory),
            KeyCode::Char('t') => Some(Action::ShowTools),
            KeyCode::Char('m') => Some(Action::ShowModel),
            KeyCode::Char('r') => Some(Action::ReRun),
            KeyCode::Char('?') | KeyCode::Char('/') => Some(Action::ToggleHelp),
            _ => None,
        };
    }
    match key.code {
        KeyCode::Enter => Some(Action::Submit),
        KeyCode::Esc => Some(Action::Cancel),
        KeyCode::Char(c) => Some(Action::TypeChar(c)),
        KeyCode::Backspace => Some(Action::Backspace),
        KeyCode::Delete => Some(Action::Delete),
        KeyCode::Left => Some(Action::MoveLeft),
        KeyCode::Right => Some(Action::MoveRight),
        KeyCode::Home => Some(Action::Home),
        KeyCode::End => Some(Action::End),
        KeyCode::Up => Some(Action::ScrollUp),
        KeyCode::Down => Some(Action::ScrollDown),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn control_shortcuts() {
        assert_eq!(
            action_from_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL)),
            Some(Action::DefineScope)
        );
        assert_eq!(
            action_from_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::Exit)
        );
        assert_eq!(
            action_from_key(press(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            Some(Action::ReRun)
        );
    }

    #[test]
    fn plain_keys() {
        assert_eq!(
            action_from_key(press(KeyCode::Enter, KeyModifiers::NONE)),
            Some(Action::Submit)
        );
        assert_eq!(
            action_from_key(press(KeyCode::Esc, KeyModifiers::NONE)),
            Some(Action::Cancel)
        );
        assert_eq!(
            action_from_key(press(KeyCode::Char('a'), KeyModifiers::NONE)),
            Some(Action::TypeChar('a'))
        );
    }
}
