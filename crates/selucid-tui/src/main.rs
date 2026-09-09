// SPDX-License-Identifier: GPL-3.0-or-later
//! `selucid-tui`: full-screen terminal UI (ratatui + crossterm).
//! Vim keys: j/k move, / filter, Enter fix preview, q quit.

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use selucid_core::reader::{LogTailer, parse_lines};
use selucid_core::{AvcEvent, Diagnosis, extract_avc_events, group_by_serial};
use std::io::{self, IsTerminal, Read};
use std::time::Duration;

struct App {
    events: Vec<AvcEvent>,
    diagnoses: Vec<Diagnosis>,
    filter: String,
    filtering: bool,
    show_fix: bool,
    list_state: ListState,
}

impl App {
    fn new(events: Vec<AvcEvent>) -> Self {
        let diagnoses = events
            .iter()
            .map(|e| {
                let expected = e
                    .path
                    .as_deref()
                    .and_then(selucid_core::privileged::expected_context);
                selucid_core::diagnose(e, expected.as_deref(), None)
            })
            .collect();
        let mut list_state = ListState::default();
        if !events.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            events,
            diagnoses,
            filter: String::new(),
            filtering: false,
            show_fix: false,
            list_state,
        }
    }

    fn visible(&self) -> Vec<usize> {
        let q = self.filter.to_lowercase();
        self.events
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                q.is_empty()
                    || e.summary().to_lowercase().contains(&q)
                    || e.scontext.to_lowercase().contains(&q)
                    || e.tcontext.to_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn selected(&self) -> Option<usize> {
        let visible = self.visible();
        self.list_state
            .selected()
            .and_then(|s| visible.get(s).copied())
    }

    fn move_down(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            return;
        }
        let next = match self.list_state.selected() {
            Some(i) => (i + 1).min(len - 1),
            None => 0,
        };
        self.list_state.select(Some(next));
    }

    fn move_up(&mut self) {
        let next = match self.list_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.list_state.select(Some(next));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let events = load_events().await;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(events);
    loop {
        terminal.draw(|f| render(f, &mut app))?;
        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
        {
            if app.filtering {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => app.filtering = false,
                    KeyCode::Backspace => {
                        app.filter.pop();
                    }
                    KeyCode::Char(c) => app.filter.push(c),
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('j') | KeyCode::Down => app.move_down(),
                KeyCode::Char('k') | KeyCode::Up => app.move_up(),
                KeyCode::Char('/') => app.filtering = true,
                KeyCode::Char('c') => app.filter.clear(),
                KeyCode::Enter | KeyCode::Char('p') => app.show_fix = !app.show_fix,
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn render(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(f.area());
    let visible = app.visible();

    let items: Vec<ListItem> = visible
        .iter()
        .map(|&i| {
            ListItem::new(format!(
                "{}  {}",
                app.events[i].serial,
                app.events[i].summary()
            ))
        })
        .collect();
    let title = if app.filter.is_empty() {
        "Denials (j/k move, / filter, q quit)".to_string()
    } else {
        format!("Denials — filter: {} (c clears)", app.filter)
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, chunks[0], &mut app.list_state);

    let detail = match app.selected() {
        Some(i) => detail_text(&app.events[i], &app.diagnoses[i], app.show_fix),
        None => "No denials. Usage:\n  selucid-tui /var/log/audit/audit.log".to_string(),
    };
    let hint = if app.filtering {
        "  [typing filter — Enter/Esc done]"
    } else {
        ""
    };
    let paragraph = Paragraph::new(detail)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Detail (Enter toggles fix preview){hint}")),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, chunks[1]);
}

fn detail_text(event: &AvcEvent, d: &Diagnosis, show_fix: bool) -> String {
    let mut out = format!("{}\n\n{}\n", event.summary(), d.explanation);
    out.push_str(&format!(
        "\nscontext: {}\ntcontext: {}\nraw: {}\n",
        event.scontext, event.tcontext, event.raw
    ));
    out.push_str(&format!("\nSuggested fixes ({:?}):\n", d.confidence));
    for (i, fix) in d.fixes.iter().enumerate() {
        out.push_str(&format!("  {}. {} — ${}\n", i + 1, fix.title, fix.command));
    }
    if show_fix {
        out.push_str("\nRun a fix only after review; privileged fixes need pkexec.\n");
    }
    out
}

async fn load_events() -> Vec<AvcEvent> {
    let arg = std::env::args().nth(1);
    if let Some(path) = arg {
        if let Ok(text) = tokio::fs::read_to_string(&path).await {
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            return extract_avc_events(&group_by_serial(parse_lines(&lines)));
        }
        eprintln!("Cannot read {path}");
        return Vec::new();
    }
    if !io::stdin().is_terminal() {
        let mut text = String::new();
        if io::stdin().read_to_string(&mut text).is_ok() && !text.trim().is_empty() {
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            return extract_avc_events(&group_by_serial(parse_lines(&lines)));
        }
    }
    LogTailer::audit_log()
        .read_all()
        .await
        .map(|lines| extract_avc_events(&group_by_serial(parse_lines(&lines))))
        .unwrap_or_default()
}

#[cfg(test)]
mod app_tests {
    use super::*;

    fn event(serial: u64, comm: &str, scontext: &str) -> AvcEvent {
        AvcEvent {
            audit_id: format!("1.0:{serial}"),
            timestamp: serial as f64,
            serial,
            result: "denied".into(),
            perms: vec!["read".into()],
            scontext: scontext.into(),
            tcontext: "system_u:object_r:var_t:s0".into(),
            tclass: "file".into(),
            pid: Some(1),
            comm: Some(comm.into()),
            exe: None,
            path: Some("/srv/x".into()),
            dest_port: None,
            dev: None,
            ino: None,
            raw: String::new(),
        }
    }

    fn app() -> App {
        let events = vec![
            event(1, "httpd", "system_u:system_r:httpd_t:s0"),
            event(2, "smbd", "system_u:system_r:smbd_t:s0"),
        ];
        // Bypass matchpathcon lookups: construct directly.
        let diagnoses = events
            .iter()
            .map(|e| selucid_core::diagnose(e, None, None))
            .collect();
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        App {
            events,
            diagnoses,
            filter: String::new(),
            filtering: false,
            show_fix: false,
            list_state,
        }
    }

    #[test]
    fn filter_narrows_visible_list() {
        let mut a = app();
        assert_eq!(a.visible().len(), 2);
        a.filter = "smbd".into();
        assert_eq!(a.visible(), vec![1]);
    }

    #[test]
    fn navigation_clamps_at_bounds() {
        let mut a = app();
        a.move_up();
        assert_eq!(a.list_state.selected(), Some(0));
        a.move_down();
        a.move_down();
        a.move_down();
        assert_eq!(a.list_state.selected(), Some(1));
    }
}
