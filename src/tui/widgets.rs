//! Reusable widgets: header, conversation, activity, input, status, help.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::state::{AppState, Message, Mode, NoticeKind, Status, StepStatus, ToolStatus};

use super::layout::centered_rect;
use super::theme::Theme;

pub fn render_header(frame: &mut Frame, area: Rect, theme: &Theme, state: &AppState) {
    let title = Line::from(vec![
        Span::styled("ANAJAKKH", theme.accent_bold()),
        Span::styled("  ·  AI Red Team Security Agent", theme.dim()),
    ]);
    let model = Line::from(Span::styled(
        format!("{} / {}", state.provider, state.model),
        theme.dim(),
    ));
    let text = Text::from(vec![
        title,
        Line::from(Span::styled(
            format!("{}", state.workspace.display()),
            theme.dim(),
        )),
    ]);
    frame.render_widget(Paragraph::new(text), area);
    frame.render_widget(
        Paragraph::new(model).alignment(ratatui::layout::Alignment::Right),
        area,
    );
}

pub fn render_conversation(frame: &mut Frame, area: Rect, theme: &Theme, state: &AppState) {
    let mut lines: Vec<Line> = Vec::new();
    for message in &state.messages {
        match message {
            Message::User(text) => {
                for (i, line) in text.lines().enumerate() {
                    if i == 0 {
                        lines.push(Line::from(vec![
                            Span::styled("› ", theme.accent_bold()),
                            Span::styled(line.to_string(), theme.bold()),
                        ]));
                    } else {
                        lines.push(Line::from(Span::styled(line.to_string(), theme.bold())));
                    }
                }
            }
            Message::Agent(text) => {
                for line in text.lines() {
                    lines.push(Line::from(Span::styled(line.to_string(), theme.text())));
                }
            }
            Message::Notice(text, kind) => {
                if text.is_empty() {
                    lines.push(Line::default());
                    continue;
                }
                let style = match kind {
                    NoticeKind::Info => theme.dim(),
                    NoticeKind::Ok => theme.ok(),
                    NoticeKind::Warn => theme.warn(),
                    NoticeKind::Error => theme.error(),
                };
                lines.push(Line::from(Span::styled(text.clone(), style)));
            }
        }
        lines.push(Line::default());
    }

    let mut text = Text::from(lines);
    // Streamed content appended live at the bottom.
    if !state.activity.streaming.is_empty() {
        let tail: String = state
            .activity
            .streaming
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        text.lines.push(Line::from(Span::styled(tail, theme.dim())));
        text.lines
            .push(Line::from(Span::styled("▌", theme.accent())));
    }

    let scroll = if state.is_auto_scroll() {
        0
    } else {
        state.scroll
    };
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}

pub fn render_activity(frame: &mut Frame, area: Rect, theme: &Theme, state: &AppState) {
    let activity = &state.activity;
    let mut lines: Vec<Line> = Vec::new();

    if !activity.visible {
        let welcome = Line::from(Span::styled(
            "● ready — type a task below, or Ctrl+S to set the authorized scope",
            theme.dim(),
        ));
        lines.push(welcome);
    } else {
        if let Some(header) = &activity.header {
            lines.push(Line::from(Span::styled(
                header.clone(),
                theme.accent_bold(),
            )));
            lines.push(Line::default());
        }

        for step in &activity.steps {
            let (glyph, style) = match step.status {
                StepStatus::Pending => ("○", theme.dim()),
                StepStatus::Running => ("●", theme.accent_bold()),
                StepStatus::Done => ("✓", theme.ok()),
                StepStatus::Skipped => ("↷", theme.warn()),
                StepStatus::Failed => ("✗", theme.error()),
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {glyph} "), style),
                Span::styled(step.action.clone(), style),
                Span::styled(format!(" — {}", step.description), theme.dim()),
            ]));
        }

        if let Some(tool) = &activity.tool {
            lines.push(Line::default());
            let status_text = match tool.status {
                ToolStatus::Running => "running...".to_string(),
                ToolStatus::Completed => "completed".to_string(),
                ToolStatus::Unavailable => "unavailable".to_string(),
            };
            lines.push(Line::from(vec![
                Span::styled("  Tool: ", theme.dim()),
                Span::styled(tool.tool.clone(), theme.accent()),
                Span::styled(format!("  Status: {status_text}"), theme.dim()),
            ]));
        }

        if let Some(summary) = &activity.summary {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "✓ Assessment completed",
                theme.ok(),
            )));
            lines.push(Line::from(Span::styled(
                format!(
                    "  Steps {} · tools {} · targets {} · findings {} · evidence {}",
                    summary.steps_completed,
                    if summary.tools_used.is_empty() {
                        "—".to_string()
                    } else {
                        summary.tools_used.join(", ")
                    },
                    summary.targets.len(),
                    summary.findings,
                    summary.evidence,
                ),
                theme.dim(),
            )));
        }
    }

    frame.render_widget(Paragraph::new(Text::from(lines)), area);
}

pub fn render_input(frame: &mut Frame, area: Rect, theme: &Theme, state: &AppState) {
    let prompt = match state.mode {
        Mode::Chat => "› ",
        Mode::ScopeInput => "scope › ",
    };

    let (hint, hint_style) = if state.mode == Mode::ScopeInput {
        ("  (Enter = set scope, Esc = cancel)", theme.warn())
    } else {
        ("  (Enter = send, @path/to/file = attach)", theme.dim())
    };

    let line = Line::from(vec![
        Span::styled(prompt, theme.accent_bold()),
        Span::styled(
            state.input.text().to_string(),
            Style::new().fg(theme.input_fg),
        ),
        Span::styled(hint, hint_style),
    ]);
    frame.render_widget(Paragraph::new(line), area);

    // Render the cursor on the input line (column = character count, not bytes).
    let text = state.input.text();
    let cursor_chars = text[..state.input.cursor().min(text.len())].chars().count() as u16;
    let cursor_col = area.x + prompt.chars().count() as u16 + cursor_chars;
    let cursor_row = area.y;
    frame.set_cursor_position((cursor_col.min(area.right().saturating_sub(1)), cursor_row));
}

pub fn render_status(frame: &mut Frame, area: Rect, theme: &Theme, state: &AppState) {
    let (dot, style) = match state.status {
        Status::Ready => ("● ready", theme.ok()),
        Status::Working => ("● working", theme.warn()),
        Status::Error => ("● error", theme.error()),
    };
    let scope_text = state
        .scope
        .as_ref()
        .map(|s| format!("scope: {}", truncate(&s.summary(), 40)))
        .unwrap_or_else(|| "no scope".to_string());

    let line = Line::from(vec![
        Span::styled(state.workspace.display().to_string(), theme.dim()),
        Span::styled("   ", theme.dim()),
        Span::styled(dot, style),
        Span::styled("   ", theme.dim()),
        Span::styled(scope_text, theme.dim()),
        Span::styled("   ", theme.dim()),
        Span::styled("ctrl+? help", theme.dim()),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().add_modifier(Modifier::BOLD)),
        area,
    );
}

/// Findings popup: severity-ordered list of generated findings.
pub fn render_findings(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    findings: &[crate::findings::Finding],
) {
    let popup = centered_rect(70, 80, area);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(Span::styled("Findings", theme.accent_bold())),
        Line::default(),
    ];
    if findings.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No findings yet — run an assessment first.",
            theme.dim(),
        )));
    }
    for finding in findings {
        let severity_style = match finding.severity {
            crate::findings::Severity::Critical | crate::findings::Severity::High => theme.error(),
            crate::findings::Severity::Medium => theme.warn(),
            crate::findings::Severity::Low | crate::findings::Severity::Informational => theme.ok(),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<13}", finding.severity.as_str()), severity_style),
            Span::styled(finding.title.clone(), theme.bold()),
            Span::styled(
                format!(
                    "  [{:.0}% · {} · {} ev] {}",
                    finding.confidence * 100.0,
                    finding.source.as_str(),
                    finding.evidence_ids.len(),
                    finding.target
                ),
                theme.dim(),
            ),
        ]));
    }

    let block = Block::default()
        .title(" Findings (Esc to close) ")
        .borders(Borders::ALL)
        .border_style(theme.accent());
    frame.render_widget(Paragraph::new(Text::from(lines)).block(block), popup);
}

pub fn render_help(frame: &mut Frame, area: Rect, theme: &Theme) {
    let popup = centered_rect(60, 80, area);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(Span::styled("Keyboard shortcuts", theme.accent_bold())),
        Line::default(),
    ];
    let keys: &[(&str, &str)] = &[
        ("Enter", "Send / commit scope"),
        ("Esc", "Cancel task / close"),
        ("Ctrl+C", "Exit"),
        ("Ctrl+S", "Define authorized scope"),
        ("Ctrl+R", "Re-run last task"),
        ("Ctrl+L", "Tool logs / evidence"),
        ("Ctrl+F", "Findings"),
        ("Ctrl+T", "Tools"),
        ("Ctrl+H", "Session history"),
        ("Ctrl+M", "Show model"),
        ("Ctrl+?", "Help"),
        ("↑/↓", "Scroll conversation"),
    ];
    for (key, desc) in keys {
        lines.push(Line::from(vec![
            Span::styled(format!("  {key:<10}"), theme.accent()),
            Span::styled(desc.to_string(), theme.dim()),
        ]));
    }

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(theme.accent());
    frame.render_widget(Paragraph::new(Text::from(lines)).block(block), popup);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}
