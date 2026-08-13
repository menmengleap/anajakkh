//! TUI color theme. Minimal and calm, per the design philosophy.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub accent: Color,
    pub ok: Color,
    pub warn: Color,
    pub error: Color,
    pub dim: Color,
    pub text: Color,
    pub input_fg: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            accent: Color::Cyan,
            ok: Color::Green,
            warn: Color::Yellow,
            error: Color::Red,
            dim: Color::DarkGray,
            text: Color::Gray,
            input_fg: Color::White,
        }
    }
}

impl Theme {
    pub fn accent(&self) -> Style {
        Style::new().fg(self.accent)
    }

    pub fn accent_bold(&self) -> Style {
        Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
    }

    pub fn ok(&self) -> Style {
        Style::new().fg(self.ok)
    }

    pub fn warn(&self) -> Style {
        Style::new().fg(self.warn)
    }

    pub fn error(&self) -> Style {
        Style::new().fg(self.error)
    }

    pub fn dim(&self) -> Style {
        Style::new().fg(self.dim)
    }

    pub fn text(&self) -> Style {
        Style::new().fg(self.text)
    }

    pub fn bold(&self) -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }
}
