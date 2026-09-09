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
    /// Tab index: 0 = Denials, 1 = Booleans.
    tab: usize,
    booleans: Vec<selucid_core::booleans::BooleanInfo>,
    bool_filter: String,
    bool_state: ListState,
    filter: String,
    filtering: bool,
    show_fix: bool,
    list_state: ListState,
    /// Status line: watcher/rotation notices shown at the bottom.
    status: String,
    /// When set, the TUI tails this path live: new watcher events are
    /// ingested into the denial list as they arrive.
    live_path: Option<String>,
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
        let mut bool_state = ListState::default();
        let booleans = selucid_core::booleans::list_booleans();
        if !booleans.is_empty() {
            bool_state.select(Some(0));
        }
        Self {
            events,
            diagnoses,
            tab: 0,
            booleans,
            bool_filter: String::new(),
            bool_state,
            filter: String::new(),
            filtering: false,
            show_fix: false,
            list_state,
            status: String::new(),
            live_path: None,
        }
    }

    /// Enable live tailing of `path`: the event loop installs a `LogWatcher`
    /// and `ingest`s arrivals. Extracted so tests can assert the wiring.
    fn enable_live(&mut self, path: String) {
        self.status = format!("live: {path}");
        self.live_path = Some(path);
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

    fn visible_booleans(&self) -> Vec<usize> {
        let q = if self.tab == 1 && !self.bool_filter.is_empty() {
            self.bool_filter.to_lowercase()
        } else if self.tab == 1 {
            self.filter.to_lowercase()
        } else {
            String::new()
        };
        self.booleans
            .iter()
            .enumerate()
            .filter(|(_, b)| q.is_empty() || b.name.to_lowercase().contains(&q))
            .map(|(i, _)| i)
            .collect()
    }

    /// Append live denial events (dedup by audit serial) and rebuild their
    /// diagnoses. Called from the notify watcher bridge.
    fn ingest(&mut self, incoming: Vec<AvcEvent>) {
        for event in incoming {
            if self.events.iter().any(|e| e.audit_id == event.audit_id) {
                continue;
            }
            let expected = event
                .path
                .as_deref()
                .filter(|p| p.starts_with('/'))
                .and_then(selucid_core::privileged::expected_context);
            let diagnosis = selucid_core::diagnose(&event, expected.as_deref(), None);
            self.events.push(event);
            self.diagnoses.push(diagnosis);
        }
        if self.list_state.selected().is_none() && !self.events.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    fn move_bool_down(&mut self) {
        let len = self.visible_booleans().len();
        if len == 0 {
            return;
        }
        let next = match self.bool_state.selected() {
            Some(i) => (i + 1).min(len - 1),
            None => 0,
        };
        self.bool_state.select(Some(next));
    }

    fn move_bool_up(&mut self) {
        let next = match self.bool_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.bool_state.select(Some(next));
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
    let (events, live_source) = load_events().await;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(events);
    // Bridge the sync notify callback into the event loop via mpsc: new
    // denials are ingested live, rotations surface on the status line.
    let (tx, rx) = std::sync::mpsc::channel::<selucid_core::WatchEvent>();
    let _live_watch = match live_source {
        Some(path) => {
            app.enable_live(path.clone());
            match selucid_core::LogWatcher::watch(path, move |ev| {
                let _ = tx.send(ev);
            }) {
                Ok(w) => Some(w),
                Err(e) => {
                    app.status = format!("live watch unavailable: {e}");
                    None
                }
            }
        }
        None => None,
    };
    loop {
        // Drain any watcher arrivals before drawing.
        while let Ok(ev) = rx.try_recv() {
            match ev {
                selucid_core::WatchEvent::Denials(incoming) => {
                    let n = incoming.len();
                    app.ingest(incoming);
                    app.status = format!("live: +{n} denial(s)");
                }
                selucid_core::WatchEvent::Rotated => {
                    app.status = "live: log rotated — continuing".to_string();
                }
                selucid_core::WatchEvent::WatchError(e) => {
                    app.status = format!("live watch error: {e}");
                }
            }
        }
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
                KeyCode::Tab | KeyCode::Char('1') | KeyCode::Char('2') => {
                    app.tab = (app.tab + 1) % 2;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    if app.tab == 1 {
                        app.move_bool_down();
                    } else {
                        app.move_down();
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if app.tab == 1 {
                        app.move_bool_up();
                    } else {
                        app.move_up();
                    }
                }
                KeyCode::Char('/') => app.filtering = true,
                KeyCode::Char('c') => {
                    app.filter.clear();
                    app.bool_filter.clear();
                }
                KeyCode::Enter | KeyCode::Char('p') => app.show_fix = !app.show_fix,
                // On the Booleans tab, `t` previews the setsebool command for
                // the selected boolean in the status line (no execution).
                KeyCode::Char('t') if app.tab == 1 => {
                    if let Some(idx) = app
                        .bool_state
                        .selected()
                        .and_then(|s| app.visible_booleans().get(s).copied())
                    {
                        let b = &app.booleans[idx];
                        app.status = format!(
                            "preview: {}  (run with: sudo {})",
                            b.name,
                            selucid_core::booleans::setsebool_command(b.name.as_str(), !b.active),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn render(f: &mut ratatui::Frame, app: &mut App) {
    use ratatui::widgets::Tabs;
    let area = f.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);
    let tabs = Tabs::new(vec!["Denials", "Booleans"])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("selucid-tui (Tab switches)"),
        )
        .select(app.tab)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, rows[0]);
    if app.tab == 1 {
        render_booleans(f, app, rows[1]);
    } else {
        render_denials(f, app, rows[1]);
    }
    let status = if app.status.is_empty() {
        "q quit · Tab tabs · / filter · Enter preview fix · t (Booleans) preview toggle".to_string()
    } else {
        app.status.clone()
    };
    f.render_widget(Paragraph::new(status), rows[2]);
}

fn render_denials(f: &mut ratatui::Frame, app: &mut App, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);
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

fn render_booleans(f: &mut ratatui::Frame, app: &mut App, area: ratatui::layout::Rect) {
    let visible = app.visible_booleans();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|&i| {
            let b = &app.booleans[i];
            ListItem::new(format!(
                "{:<45} {}",
                b.name,
                if b.active { "on" } else { "off" }
            ))
        })
        .collect();
    let title = if app.filter.is_empty() {
        "Booleans (/ filter, t preview toggle)".to_string()
    } else {
        format!("Booleans — filter: {} (c clears)", app.filter)
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut app.bool_state);
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

/// Load initial events plus an optional live source path.
///
/// Returns `(events, live_path)`: `live_path` is `Some` when the TUI should
/// keep tailing that file with `LogWatcher` (explicit file arg, or the audit
/// log when it was readable). Piped stdin is one-shot — no live source.
async fn load_events() -> (Vec<AvcEvent>, Option<String>) {
    let arg = std::env::args().nth(1);
    if let Some(path) = arg {
        if let Ok(text) = tokio::fs::read_to_string(&path).await {
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            return (
                extract_avc_events(&group_by_serial(parse_lines(&lines))),
                Some(path),
            );
        }
        eprintln!("Cannot read {path}");
        return (Vec::new(), None);
    }
    if !io::stdin().is_terminal() {
        let mut text = String::new();
        if io::stdin().read_to_string(&mut text).is_ok() && !text.trim().is_empty() {
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            return (
                extract_avc_events(&group_by_serial(parse_lines(&lines))),
                None,
            );
        }
    }
    let tailer = LogTailer::audit_log();
    match tailer.read_all().await {
        Ok(lines) => (
            extract_avc_events(&group_by_serial(parse_lines(&lines))),
            Some(tailer.path().to_string_lossy().into_owned()),
        ),
        Err(_) => (Vec::new(), None),
    }
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
            tab: 0,
            booleans: Vec::new(),
            bool_filter: String::new(),
            bool_state: ListState::default(),
            filter: String::new(),
            filtering: false,
            show_fix: false,
            list_state,
            status: String::new(),
            live_path: None,
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

    #[test]
    fn live_wiring_sets_status_path() {
        let mut a = app();
        assert!(a.live_path.is_none());
        a.enable_live("/tmp/audit.log".to_string());
        assert_eq!(a.live_path.as_deref(), Some("/tmp/audit.log"));
        assert!(a.status.contains("/tmp/audit.log"));
    }

    #[test]
    fn ingest_dedups_and_appends() {
        let mut a = app();
        let extra = event(3, "httpd", "system_u:system_r:httpd_t:s0");
        let dupe = event(1, "httpd", "system_u:system_r:httpd_t:s0");
        a.ingest(vec![extra, dupe]);
        assert_eq!(a.events.len(), 3);
        assert_eq!(a.diagnoses.len(), 3);
        assert!(a.events.iter().any(|e| e.serial == 3));
    }

    #[test]
    fn boolean_filter_and_preview() {
        use selucid_core::booleans::BooleanInfo;
        let mut a = app();
        a.booleans = vec![
            BooleanInfo {
                name: "httpd_can_network_connect".into(),
                active: false,
                pending: false,
            },
            BooleanInfo {
                name: "samba_export_all_ro".into(),
                active: true,
                pending: true,
            },
        ];
        a.tab = 1;
        a.filter = "httpd".into();
        assert_eq!(a.visible_booleans(), vec![0]);
        a.filter.clear();
        a.bool_state.select(Some(1));
        let idx = a
            .bool_state
            .selected()
            .and_then(|s| a.visible_booleans().get(s).copied());
        assert_eq!(idx, Some(1));
    }
}
