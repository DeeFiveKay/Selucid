// SPDX-License-Identifier: GPL-3.0-or-later
//! Single-window Libadwaita app: Denials + Booleans views over `selucid-core`.
//!
//! GNOME HIG patterns for RHEL and Fedora Workstation.
//! AdwApplicationWindow + AdwHeaderBar, AdwViewSwitcher + AdwViewStack,
//! boxed-list rows, monospace context block, AdwToastOverlay for live and
//! apply feedback. Diagnosis and fix previews reuse `selucid-core` exactly
//! like the CLI and TUI.

use gtk4::prelude::*;
use libadwaita::prelude::*;
use relm4::prelude::*;
use selucid_core::{AvcEvent, Diagnosis, FixKind, LogWatcher, WatchEvent};

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Msg {
    /// Text typed in the search entry.
    SetFilter(String),
    /// User picked a denial row (or cleared the selection).
    SelectDenial(Option<usize>),
    /// Fix radio chosen in the detail pane.
    SelectFix(usize),
    /// audit2why cross-check toggle.
    SetOracle(bool),
    /// New events arrived from the LogWatcher bridge thread.
    Ingest(Vec<AvcEvent>),
    /// Rotation / watcher notices for the toast overlay.
    Notice(String),
    /// User pressed Preview: show the exact privileged argv.
    PreviewFix,
    /// User pressed Apply: pkexec after confirmation (cheap fixes only).
    ApplyFix,
    /// Boolean search text.
    SetBoolFilter(String),
    /// Preview the setsebool toggle command for the selected boolean.
    PreviewBool(usize),
    /// Boolean switch toggled.
    ToggleBool(usize, bool),
    /// Open the About dialog.
    About,
    /// Toggle dark/light theme.
    ToggleTheme,
    /// Open the Preferences dialog.
    ShowPreferences,
    /// Preference: auto-scroll to new denials.
    SetAutoScroll(bool),
    /// Preference: show anomaly detection alerts.
    SetShowAnomalies(bool),
    /// Preference: show container annotations in tooltips.
    SetShowContainerHints(bool),
}

// ---------------------------------------------------------------------------
// View-model: plain data + widget handles.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DenialRow {
    index: usize,
    summary: String,
    subtitle: String,
}

/// The relm4 component *is* the model. Widgets that are built
/// programmatically (the two boxed lists, the detail labels, the fixes box,
/// the toast overlay) are held as `Clone`'d GObject handles so `update`
/// can rebuild the views without access to the generated Widgets struct.
struct App {
    events: Vec<AvcEvent>,
    diagnoses: Vec<Diagnosis>,
    filter: String,
    selected: Option<usize>,
    selected_fix: usize,
    use_oracle: bool,
    bool_filter: String,
    booleans: Vec<selucid_core::booleans::BooleanInfo>,
    /// Sliding-window anomaly tracker fed by live ingest.
    tracker: selucid_core::anomaly::DenialTracker,
    /// Incidents (denial bursts) raised so far.
    incidents: Vec<selucid_core::anomaly::Incident>,
    /// Fix journal loaded at startup (read-only view).
    /// Cached at startup; can be displayed in a History view later.
    #[allow(dead_code)]
    history: Vec<selucid_core::history::HistoryEntry>,

    // User preferences (session-scoped).
    /// Dark theme active.
    dark_theme: bool,
    /// Auto-scroll to new denials during live ingest.
    auto_scroll: bool,
    /// Show anomaly detection alerts as toasts.
    show_anomalies: bool,
    /// Show container annotations in tooltips.
    show_container_hints: bool,

    // Programmatic widget handles (replaced with the real ones in `init`).
    window: Option<libadwaita::ApplicationWindow>,
    toast_overlay: libadwaita::ToastOverlay,
    denials_list_box: gtk4::ListBox,
    detail_summary_label: gtk4::Label,
    detail_explain_label: gtk4::Label,
    detail_context_label: gtk4::Label,
    detail_fixes_box: gtk4::Box,
    booleans_list_box: gtk4::ListBox,
}

impl App {
    fn new() -> Self {
        let events = initial_events();
        let diagnoses = diagnose_all(&events, false);
        let booleans = selucid_core::booleans::list_booleans();
        Self {
            events,
            diagnoses,
            filter: String::new(),
            selected: None,
            selected_fix: 0,
            use_oracle: false,
            bool_filter: String::new(),
            booleans,
            tracker: selucid_core::anomaly::DenialTracker::default(),
            incidents: Vec::new(),
            history: selucid_core::history::list_entries(),
            // Placeholders; `init` swaps in the real handles.
            window: None,
            toast_overlay: libadwaita::ToastOverlay::new(),
            denials_list_box: gtk4::ListBox::new(),
            detail_summary_label: gtk4::Label::new(None),
            detail_explain_label: gtk4::Label::new(None),
            detail_context_label: gtk4::Label::new(None),
            detail_fixes_box: gtk4::Box::new(gtk4::Orientation::Vertical, 8),
            booleans_list_box: gtk4::ListBox::new(),
            // Default preferences.
            dark_theme: false,
            auto_scroll: true,
            show_anomalies: true,
            show_container_hints: true,
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

    fn visible_rows(&self) -> Vec<DenialRow> {
        self.visible()
            .into_iter()
            .map(|index| {
                let e = &self.events[index];
                DenialRow {
                    index,
                    summary: e.summary(),
                    subtitle: format!("{} \u{00b7} {}", e.audit_id, e.tclass),
                }
            })
            .collect()
    }

    fn visible_booleans(&self) -> Vec<usize> {
        let q = self.bool_filter.to_lowercase();
        self.booleans
            .iter()
            .enumerate()
            .filter(|(_, b)| q.is_empty() || b.name.to_lowercase().contains(&q))
            .map(|(i, _)| i)
            .collect()
    }

    fn rediagnose(&mut self) {
        self.diagnoses = diagnose_all(&self.events, self.use_oracle);
        self.selected_fix = 0;
    }

    /// Merge fresh events, then return the notice to show (anomaly alert
    /// outranking the plain "+N denials" toast), if any.
    fn ingest(&mut self, incoming: Vec<AvcEvent>) -> Option<String> {
        let mut added = 0;
        let mut fresh: Vec<AvcEvent> = Vec::new();
        for event in incoming {
            if self.events.iter().any(|e| e.audit_id == event.audit_id) {
                continue;
            }
            let expected = event
                .path
                .as_deref()
                .filter(|p| p.starts_with('/'))
                .and_then(selucid_core::privileged::expected_context);
            let oracle = if self.use_oracle {
                let a = selucid_core::analyze_raw(&event.raw);
                (!a.inconclusive).then_some(a)
            } else {
                None
            };
            let d = selucid_core::diagnose_with_oracle(
                &event,
                expected.as_deref(),
                None,
                oracle.as_ref(),
            );
            self.events.push(event.clone());
            self.diagnoses.push(d);
            fresh.push(event);
            added += 1;
        }
        // Feed the anomaly tracker; a raised incident outranks the plain
        // "+N denials" toast as the user-visible signal.
        for incident in self.tracker.track_batch(&fresh) {
            self.incidents.push(incident);
        }

        // Auto-scroll to the last row if enabled.
        if self.auto_scroll && added > 0 {
            let visible = self.visible();
            if !visible.is_empty() {
                let last_idx = visible[visible.len() - 1];
                let row = self.denials_list_box.row_at_index(last_idx as i32);
                if let Some(r) = row {
                    self.denials_list_box.select_row(Some(&r));
                    r.grab_focus();
                }
            }
        }

        if let Some(last) = self.incidents.last() {
            if self.show_anomalies {
                Some(format!(
                    "ANOMALY: {} denial(s) from {} on {} ({})",
                    last.count,
                    last.scontext,
                    last.tclass,
                    last.severity.as_str()
                ))
            } else {
                Some(format!("Live: +{added} denial(s)"))
            }
        } else if added > 0 {
            Some(format!("Live: +{added} denial(s)"))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------

fn load_events_from_file(path: &str) -> Vec<AvcEvent> {
    use selucid_core::reader::parse_lines;
    use selucid_core::{extract_avc_events, group_by_serial};

    match std::fs::read_to_string(path) {
        Ok(text) => {
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            extract_avc_events(&group_by_serial(parse_lines(&lines)))
        }
        Err(_) => Vec::new(),
    }
}

fn initial_events() -> Vec<AvcEvent> {
    use selucid_core::reader::{LogTailer, parse_lines};
    use selucid_core::{extract_avc_events, group_by_serial};

    if let Some(path) = std::env::args().nth(1) {
        return load_events_from_file(&path);
    }
    let tailer = LogTailer::audit_log();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
        .map(|rt| {
            rt.block_on(tailer.read_all()).map_or_else(
                |_| Vec::new(),
                |lines| extract_avc_events(&group_by_serial(parse_lines(&lines))),
            )
        })
        .unwrap_or_default()
}

fn diagnose_all(events: &[AvcEvent], use_oracle: bool) -> Vec<Diagnosis> {
    events
        .iter()
        .map(|e| {
            let expected = e
                .path
                .as_deref()
                .filter(|p| p.starts_with('/'))
                .and_then(selucid_core::privileged::expected_context);
            let oracle = if use_oracle {
                let a = selucid_core::analyze_raw(&e.raw);
                (!a.inconclusive).then_some(a)
            } else {
                None
            };
            selucid_core::diagnose_with_oracle(e, expected.as_deref(), None, oracle.as_ref())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point called from `main` with the `gui` feature enabled.
pub fn run(path: &str) {
    let init = path.to_string();
    let app = RelmApp::new("io.selucid.Selucid");
    app.run::<App>(init);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

#[relm4::component]
impl SimpleComponent for App {
    type Init = String;
    type Input = Msg;
    type Output = ();

    view! {
        #[name(window)]
        libadwaita::ApplicationWindow {
            set_title: Some("Selucid"),
            set_default_width: 1100,
            set_default_height: 720,
            set_icon_name: Some("selucid"),

            #[name(toast_overlay)]
            libadwaita::ToastOverlay {
                #[wrap(Some)]
                set_child = &gtk4::Box {
                    set_orientation: gtk4::Orientation::Vertical,

                    libadwaita::HeaderBar {
                        pack_start = &gtk4::Box {
                            set_spacing: 6,
                            gtk4::Image {
                                set_icon_name: Some("security-medium-symbolic"),
                            },
                            gtk4::Label {
                                set_label: "Selucid",
                                add_css_class: "title",
                            },
                        },
                        pack_start: view_switcher = &libadwaita::ViewSwitcher {
                            set_policy: libadwaita::ViewSwitcherPolicy::Wide,
                        },
                        pack_end = &gtk4::Box {
                            set_spacing: 6,
                            gtk4::Switch {
                                set_tooltip_text: Some("Cross-check against loaded policy (audit2why)"),
                                set_active: false,
                                connect_state_set[sender] => move |switch, _state| {
                                    sender.input(Msg::SetOracle(switch.is_active()));
                                    gtk4::glib::Propagation::Stop
                                },
                            },
                            gtk4::Label {
                                set_label: "audit2why",
                                set_valign: gtk4::Align::Center,
                                add_css_class: "dim-label",
                            },
                        },
                        pack_end = &gtk4::Button {
                            set_icon_name: "weather-clear-night-symbolic",
                            set_tooltip_text: Some("Toggle dark theme"),
                            connect_clicked[sender] => move |_| {
                                sender.input(Msg::ToggleTheme);
                            },
                        },
                        pack_end = &gtk4::Button {
                            set_icon_name: "preferences-system-symbolic",
                            set_tooltip_text: Some("Preferences"),
                            connect_clicked[sender] => move |_| {
                                sender.input(Msg::ShowPreferences);
                            },
                        },
                        pack_end: filter_entry = &gtk4::SearchEntry {
                            set_placeholder_text: Some("Filter denials\u{2026}"),
                            connect_search_changed[sender] => move |entry| {
                                sender.input(Msg::SetFilter(entry.text().to_string()));
                            },
                        },
                        pack_end = &gtk4::Button {
                            set_icon_name: "help-about-symbolic",
                            set_tooltip_text: Some("About Selucid"),
                            connect_clicked[sender] => move |_| {
                                sender.input(Msg::About);
                            },
                        },
                    },

                    #[name(stack)]
                    libadwaita::ViewStack {
                        set_vexpand: true,
                    },
                },
            }
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut model = App::new();
        if !init.is_empty() {
            let events = load_events_from_file(&init);
            if !events.is_empty() {
                model.events.extend(events);
                model.rediagnose();
            }
        }

        let widgets = view_output!();

        // The ViewSwitcher needs the ViewStack handle; both live in the
        // generated Widgets struct (names from `view!` above).
        widgets.view_switcher.set_stack(Some(&widgets.stack));

        // Build page contents into the stack and remember their handles.
        model.window = Some(widgets.window.clone());
        model.toast_overlay = widgets.toast_overlay.clone();
        build_denials_page(&widgets, &mut model, sender.clone());
        build_booleans_page(&widgets, &mut model, sender.clone());
        widgets.stack.set_visible_child_name("denials");

        // Live watcher bridge: notify pushes new denials, we forward them
        // to the component as Msg::Ingest so they land in the Denials tab
        // and feed the anomaly tracker.
        if !init.is_empty() {
            let tx = sender.clone();
            let _watch = LogWatcher::watch(&init, move |ev| match ev {
                WatchEvent::Denials(events) => {
                    let _ = tx.input(Msg::Ingest(events));
                }
                WatchEvent::Rotated => {
                    let _ = tx.input(Msg::Notice("live: log rotated — continuing".into()));
                }
                WatchEvent::WatchError(e) => {
                    let _ = tx.input(Msg::Notice(format!("live watch error: {e}")));
                }
            });
        }

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        match msg {
            Msg::SetFilter(q) => {
                self.filter = q;
                self.selected = None;
                rebuild_denials_list(self);
                clear_detail(self);
            }
            Msg::SelectDenial(selected) => {
                self.selected = selected;
                self.selected_fix = 0;
                rebuild_denials_list(self);
                if selected.is_some() {
                    show_detail(self, &sender);
                } else {
                    clear_detail(self);
                }
            }
            Msg::SelectFix(i) => {
                self.selected_fix = i;
                refresh_fix_radios(self, &sender);
            }
            Msg::SetOracle(on) => {
                self.use_oracle = on;
                self.rediagnose();
                rebuild_denials_list(self);
                if self.selected.is_some() {
                    show_detail(self, &sender);
                }
            }
            Msg::Ingest(incoming) => {
                if let Some(notice) = self.ingest(incoming) {
                    sender.input(Msg::Notice(notice));
                }
                rebuild_denials_list(self);
                if let Some(idx) = self.selected {
                    if idx < self.events.len() {
                        show_detail(self, &sender);
                    } else {
                        self.selected = None;
                        clear_detail(self);
                    }
                }
            }
            Msg::Notice(text) => {
                toast(self, &text);
            }
            Msg::PreviewFix => {
                toast(self, &preview_for(self));
            }
            Msg::ApplyFix => {
                if let Some(text) = apply_selected(self) {
                    toast(self, &text);
                }
            }
            Msg::SetBoolFilter(q) => {
                self.bool_filter = q;
                rebuild_booleans_list(self, &sender);
            }
            Msg::PreviewBool(pos) => {
                if let Some(idx) = self.visible_booleans().get(pos).copied() {
                    let b = &self.booleans[idx];
                    toast(
                        self,
                        &format!(
                            "preview: sudo {}",
                            selucid_core::booleans::setsebool_command(&b.name, !b.active)
                        ),
                    );
                }
            }
            Msg::ToggleBool(idx, on) => {
                if let Some(i) = self.visible_booleans().get(idx).copied() {
                    let b = &self.booleans[i];
                    let action = selucid_core::privileged::setsebool_action(&b.name, on);
                    match action.execute() {
                        Ok(_stdout) => {
                            if let Some(bi) = self.booleans.get_mut(i) {
                                bi.active = on;
                                bi.pending = on;
                            }
                            rebuild_booleans_list(self, &sender);
                            toast(self, &format!("Applied: {}", action.preview()));
                        }
                        Err(e) => {
                            toast(self, &format!("Error: {e}"));
                        }
                    }
                }
            }
            #[allow(deprecated)]
            Msg::About => {
                // ASCII logo from ascii.txt as a release-notes header.
                let logo_text = include_str!("../../../ascii.txt");
                let about = libadwaita::AboutWindow::builder()
                    .application_name("Selucid")
                    .version(env!("CARGO_PKG_VERSION"))
                    .developer_name("Hugo Hurme")
                    .license_type(gtk4::License::Gpl30)
                    .website("https://github.com/banaani/selucid")
                    .comments("SELinux AVC troubleshooting toolkit — read-only diagnosis, Polkit-escorted remediation, What-If sandbox.")
                    .copyright("© 2026 Hugo Hurme")
                    .release_notes(format!("<pre>
{}
</pre>", logo_text))
                    .modal(true)
                    .build();
                if let Some(window) = &self.window {
                    about.set_transient_for(Some(window));
                }
                about.present();
            }
            Msg::ToggleTheme => {
                self.dark_theme = !self.dark_theme;
                let scheme = if self.dark_theme {
                    libadwaita::ColorScheme::ForceDark
                } else {
                    libadwaita::ColorScheme::ForceLight
                };
                let style = libadwaita::StyleManager::default();
                style.set_color_scheme(scheme);
                toast(self, if self.dark_theme { "Dark theme on" } else { "Light theme on" });
            }
            Msg::ShowPreferences => {
                show_preferences_dialog(self, &sender);
            }
            Msg::SetAutoScroll(on) => {
                self.auto_scroll = on;
                toast(self, if on { "Auto-scroll on" } else { "Auto-scroll off" });
            }
            Msg::SetShowAnomalies(on) => {
                self.show_anomalies = on;
                toast(self, if on { "Anomaly alerts on" } else { "Anomaly alerts off" });
            }
            Msg::SetShowContainerHints(on) => {
                self.show_container_hints = on;
                toast(self, if on { "Container hints on" } else { "Container hints off" });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------

fn build_denials_page(
    widgets: &<App as SimpleComponent>::Widgets,
    model: &mut App,
    sender: ComponentSender<App>,
) {
    let page = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
    page.set_hexpand(true);
    page.set_vexpand(true);
    page.set_margin_all(12);

    // Left column: denial list.
    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("boxed-list");
    list_box.set_hexpand(false);
    list_box.set_vexpand(true);
    list_box.set_selection_mode(gtk4::SelectionMode::Single);
    // Rows are tagged with their model index via the widget name.
    {
        let sender = sender.clone();
        list_box.connect_row_selected(move |box_, _row| {
            if let Some(row) = box_.selected_row() {
                let name = row.widget_name();
                if let Ok(idx) = name.parse::<usize>() {
                    sender.input(Msg::SelectDenial(Some(idx)));
                }
            }
        });
    }
    let list_scroll = gtk4::ScrolledWindow::new();
    list_scroll.set_hexpand(false);
    list_scroll.set_vexpand(true);
    list_scroll.set_child(Some(&list_box));

    // Right column: detail pane.
    let detail_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    detail_box.set_hexpand(true);
    detail_box.set_vexpand(true);
    detail_box.set_margin_all(12);

    let detail_scroll = gtk4::ScrolledWindow::new();
    detail_scroll.set_hexpand(true);
    detail_scroll.set_vexpand(true);

    let detail_inner = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    detail_inner.set_hexpand(true);
    detail_inner.set_vexpand(true);

    let summary_label = gtk4::Label::new(Some("Select a denial to inspect"));
    summary_label.set_halign(gtk4::Align::Start);
    summary_label.set_wrap(true);
    summary_label.add_css_class("headline");
    detail_inner.append(&summary_label);

    let explain_label = gtk4::Label::new(Some(""));
    explain_label.set_halign(gtk4::Align::Start);
    explain_label.set_wrap(true);
    explain_label.add_css_class("dim-label");
    detail_inner.append(&explain_label);

    let context_label = gtk4::Label::new(Some(""));
    context_label.set_halign(gtk4::Align::Start);
    context_label.add_css_class("monospace");
    detail_inner.append(&context_label);

    let fixes_box = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
    fixes_box.set_hexpand(true);
    fixes_box.set_vexpand(true);
    detail_inner.append(&fixes_box);

    detail_scroll.set_child(Some(&detail_inner));
    detail_box.append(&detail_scroll);

    page.append(&list_scroll);
    page.append(&detail_box);

    widgets.stack.add_titled(&page, Some("denials"), "Denials");

    model.denials_list_box = list_box;
    model.detail_summary_label = summary_label;
    model.detail_explain_label = explain_label;
    model.detail_context_label = context_label;
    model.detail_fixes_box = fixes_box;
}

fn build_booleans_page(
    widgets: &<App as SimpleComponent>::Widgets,
    model: &mut App,
    sender: ComponentSender<App>,
) {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    page.set_hexpand(true);
    page.set_vexpand(true);
    page.set_margin_all(12);

    let search_entry = gtk4::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Search booleans\u{2026}"));
    search_entry.set_hexpand(true);
    {
        let sender = sender.clone();
        search_entry.connect_search_changed(move |entry| {
            sender.input(Msg::SetBoolFilter(entry.text().to_string()));
        });
    }
    page.append(&search_entry);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("boxed-list");
    list_box.set_hexpand(true);
    list_box.set_vexpand(true);
    list_box.set_selection_mode(gtk4::SelectionMode::None);
    let list_scroll = gtk4::ScrolledWindow::new();
    list_scroll.set_hexpand(true);
    list_scroll.set_vexpand(true);
    list_scroll.set_child(Some(&list_box));
    page.append(&list_scroll);

    widgets.stack.add_titled(&page, Some("booleans"), "Booleans");

    model.booleans_list_box = list_box;
}

// ---------------------------------------------------------------------------
// Rebuild helpers
// ---------------------------------------------------------------------------

fn rebuild_denials_list(model: &mut App) {
    let list_box = model.denials_list_box.clone();

    // Remove existing rows (row_at_index(0) is the head of the list).
    while let Some(row) = list_box.row_at_index(0) {
        list_box.remove(&row);
    }

    let visible = model.visible_rows();
    for row_data in &visible {
        let row = gtk4::ListBoxRow::new();
        row.set_selectable(true);
        row.set_widget_name(&row_data.index.to_string());

        let label = gtk4::Label::new(Some(&row_data.summary));
        label.set_halign(gtk4::Align::Start);
        label.set_wrap(true);
        label.set_margin_end(12);
        label.add_css_class("title");

        let subtitle = gtk4::Label::new(Some(&row_data.subtitle));
        subtitle.set_halign(gtk4::Align::Start);
        subtitle.set_wrap(true);
        subtitle.add_css_class("dim-label");
        subtitle.set_margin_end(12);

        let row_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        row_box.set_hexpand(true);
        row_box.append(&label);
        row_box.append(&subtitle);

        row.set_child(Some(&row_box));
        list_box.append(&row);
    }

    if visible.is_empty() {
        let empty = gtk4::Label::new(Some("No denials match the filter"));
        empty.set_halign(gtk4::Align::Center);
        empty.set_valign(gtk4::Align::Center);
        empty.add_css_class("dim-label");
        list_box.append(&empty);
    }
}

fn rebuild_booleans_list(model: &mut App, sender: &ComponentSender<App>) {
    let list_box = model.booleans_list_box.clone();

    while let Some(row) = list_box.row_at_index(0) {
        list_box.remove(&row);
    }

    let visible = model.visible_booleans();
    for pos in &visible {
        let info = &model.booleans[*pos];
        let row = libadwaita::ActionRow::new();
        row.set_title(&info.name);
        row.set_subtitle(if info.active { "on" } else { "off" });

        let switch = gtk4::Switch::new();
        switch.set_active(info.active);
        switch.set_hexpand(false);
        switch.set_halign(gtk4::Align::End);
        switch.set_valign(gtk4::Align::Center);

        // Keep the switch honest with reality: applying via pkexec may
        // fail, so the toggle sends the intent (state is authoritative in
        // the model) and the default handler is blocked.
        {
            let sender = sender.clone();
            let pos_val = *pos;
            switch.connect_state_set(move |_switch, state| {
                sender.input(Msg::ToggleBool(pos_val, state));
                gtk4::glib::Propagation::Stop
            });
        }
        // Preview button: shows the setsebool command without executing it.
        {
            let sender = sender.clone();
            let pos_val = *pos;
            let preview_btn = gtk4::Button::new();
            preview_btn.set_icon_name("dialog-information-symbolic");
            preview_btn.set_tooltip_text(Some("Preview toggle command"));
            preview_btn.add_css_class("flat");
            preview_btn.connect_clicked(move |_| {
                sender.input(Msg::PreviewBool(pos_val));
            });
            row.add_suffix(&preview_btn);
        }
        row.add_suffix(&switch);
        list_box.append(&row);
    }

    if visible.is_empty() {
        let empty = gtk4::Label::new(Some("No matching booleans"));
        empty.set_halign(gtk4::Align::Center);
        empty.set_valign(gtk4::Align::Center);
        empty.add_css_class("dim-label");
        list_box.append(&empty);
    }
}

fn clear_detail(model: &App) {
    model.detail_summary_label.set_label("Select a denial to inspect");
    model.detail_explain_label.set_label("");
    model.detail_context_label.set_label("");

    let fixes_box = &model.detail_fixes_box;
    while let Some(c) = fixes_box.first_child() {
        fixes_box.remove(&c);
    }
}

fn show_detail(model: &App, sender: &ComponentSender<App>) {
    let Some(selected) = model.selected else {
        clear_detail(model);
        return;
    };

    let (Some(event), Some(diagnosis)) = (
        model.events.get(selected),
        model.diagnoses.get(selected),
    ) else {
        clear_detail(model);
        return;
    };

    model.detail_summary_label.set_label(&diagnosis.summary);
    model.detail_explain_label.set_label(&diagnosis.explanation);

    let scontext = event.scontext.split(':').next().unwrap_or("?");
    let tcontext = event.tcontext.split(':').next().unwrap_or("?");
    model.detail_context_label.set_markup(&format!(
        "<span font_style=\"italic\" size=\"small\"><b>{}</b> \u{2192} <b>{}</b></span>",
        scontext, tcontext
    ));

    let fixes_box = &model.detail_fixes_box;
    while let Some(c) = fixes_box.first_child() {
        fixes_box.remove(&c);
    }

    for (fix_idx, fix) in diagnosis.fixes.iter().enumerate() {
        let fix_row = libadwaita::ActionRow::new();
        fix_row.set_title(&fix.title);
        fix_row.set_subtitle(&fix.description);

        let radio = gtk4::CheckButton::new();
        radio.set_active(fix_idx == model.selected_fix);
        radio.set_halign(gtk4::Align::Start);
        radio.set_valign(gtk4::Align::Center);
        {
            let sender = sender.clone();
            radio.connect_toggled(move |btn| {
                if btn.is_active() {
                    sender.input(Msg::SelectFix(fix_idx));
                }
            });
        }
        fix_row.add_prefix(&radio);

        let command_label = gtk4::Label::new(Some(&fix.command));
        command_label.set_halign(gtk4::Align::Start);
        command_label.add_css_class("monospace");
        command_label.set_ellipsize(gtk4::pango::EllipsizeMode::End);
        command_label.set_selectable(true);

        let box_ = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        box_.set_hexpand(true);
        box_.append(&command_label);

        let preview_btn = gtk4::Button::with_label("Preview");
        preview_btn.set_hexpand(false);
        preview_btn.add_css_class("flat");
        {
            let sender = sender.clone();
            preview_btn.connect_clicked(move |_| sender.input(Msg::PreviewFix));
        }
        box_.append(&preview_btn);

        let apply_btn = gtk4::Button::with_label("Apply");
        apply_btn.set_hexpand(false);
        apply_btn.add_css_class("suggested-action");
        {
            let sender = sender.clone();
            apply_btn.connect_clicked(move |_| sender.input(Msg::ApplyFix));
        }
        box_.append(&apply_btn);

        fix_row.add_suffix(&box_);
        fixes_box.append(&fix_row);
    }
}

/// Re-render the detail pane after a fix selection (radios reflect state).
fn refresh_fix_radios(model: &App, sender: &ComponentSender<App>) {
    show_detail(model, sender);
}

/// Show a transient toast on the overlay (live ingest, previews, results).
fn toast(model: &App, text: &str) {
    model.toast_overlay.add_toast(libadwaita::Toast::new(text));
}

// ---------------------------------------------------------------------------
// Preview / Apply
// ---------------------------------------------------------------------------

fn preview_for(model: &App) -> String {
    let Some(i) = model.selected else {
        return String::from("Pick a denial first.");
    };
    let Some(d) = model.diagnoses.get(i) else {
        return String::from("Pick a denial first.");
    };
    match d.fixes.get(model.selected_fix) {
        Some(fix) => {
            let mut out = format!("{}\n$ {}", fix.title, fix.command);
            // Read-only What-If: what would this fix change?
            let sim = selucid_core::simulate(fix);
            for c in &sim.changes {
                out.push_str(&format!("\nWould change: {c}"));
            }
            if !sim.domains_gaining.is_empty() {
                out.push_str(&format!(
                    "\nDomains gaining access: {}",
                    sim.domains_gaining.join(", ")
                ));
            }
            for n in &sim.notes {
                out.push_str(&format!("\nNote: {n}"));
            }
            out
        }
        None => String::from("No such fix for this denial."),
    }
}

fn apply_selected(model: &App) -> Option<String> {
    let i = model.selected?;
    let d = model.diagnoses.get(i)?;
    let fix = d.fixes.get(model.selected_fix)?;

    let action = match &fix.kind {
        FixKind::Restorecon => {
            let path = fix.command.strip_prefix("restorecon -v ").unwrap_or("").trim();
            Some(selucid_core::privileged::restorecon_action(path))
        }
        FixKind::SetBoolean => {
            let mut parts = fix.command.split_whitespace();
            parts.next(); // setsebool
            parts.next(); // -P
            let name = parts.next().unwrap_or("");
            let on = parts.next().unwrap_or("1") == "1";
            Some(selucid_core::privileged::setsebool_action(name, on))
        }
        FixKind::SemanageFcontext | FixKind::PolicyModule | FixKind::ContainerVolume => None,
    };

    match action {
        Some(a) => match a.execute_journaled() {
            Ok((_stdout, entry)) => Some(format!(
                "Applied:\n{}\nRevert with: selucid rollback {}",
                a.preview(),
                entry.id
            )),
            Err(e) => Some(format!("Error: {e}")),
        },
        None => Some(format!(
            "Refused: {} needs eyes-on review. Copy the command below and run it manually.",
            fix.title
        )),
    }
}

// ---------------------------------------------------------------------------
// Preferences dialog
// ---------------------------------------------------------------------------

/// Build and present a preferences window bound to the app state.
fn show_preferences_dialog(app: &App, sender: &relm4::ComponentSender<App>) {
    // libadwaita::Window is an AdwWindow — it manages its own title bar.
    // Do NOT call set_titlebar(); that triggers Adwaita-ERROR.
    let prefs_win = gtk4::Window::new();
    prefs_win.set_title(Some("Preferences"));
    prefs_win.set_default_width(420);
    prefs_win.set_default_height(300);
    prefs_win.set_modal(true);
    prefs_win.set_resizable(false);

    // Transient for the main window so WM groups it correctly.
    if let Some(parent) = &app.window {
        prefs_win.set_transient_for(Some(parent));
    }

    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);

    // Preferences list.
    let list = libadwaita::PreferencesGroup::new();
    list.set_title("Behavior");

    // Auto-scroll preference.
    let auto_scroll_row = libadwaita::ActionRow::new();
    auto_scroll_row.set_title("Auto-scroll to new events");
    auto_scroll_row.set_subtitle("Scroll the denials list when new AVCs arrive");
    let auto_scroll_switch = gtk4::Switch::new();
    auto_scroll_switch.set_active(app.auto_scroll);
    auto_scroll_switch.set_valign(gtk4::Align::Center);
    {
        let sender = sender.clone();
        auto_scroll_switch.connect_state_set(move |switch, _| {
            sender.input(Msg::SetAutoScroll(switch.is_active()));
            gtk4::glib::Propagation::Stop
        });
    }
    auto_scroll_row.add_suffix(&auto_scroll_switch);
    auto_scroll_row.set_activatable_widget(Some(&auto_scroll_switch));
    list.add(&auto_scroll_row);

    // Anomaly alerts preference.
    let anomalies_row = libadwaita::ActionRow::new();
    anomalies_row.set_title("Show anomaly alerts");
    anomalies_row.set_subtitle("Notify when denial bursts are detected");
    let anomalies_switch = gtk4::Switch::new();
    anomalies_switch.set_active(app.show_anomalies);
    anomalies_switch.set_valign(gtk4::Align::Center);
    {
        let sender = sender.clone();
        anomalies_switch.connect_state_set(move |switch, _| {
            sender.input(Msg::SetShowAnomalies(switch.is_active()));
            gtk4::glib::Propagation::Stop
        });
    }
    anomalies_row.add_suffix(&anomalies_switch);
    anomalies_row.set_activatable_widget(Some(&anomalies_switch));
    list.add(&anomalies_row);

    // Container hints preference.
    let container_row = libadwaita::ActionRow::new();
    container_row.set_title("Container annotations");
    container_row.set_subtitle("Show container context in tooltips");
    let container_switch = gtk4::Switch::new();
    container_switch.set_active(app.show_container_hints);
    container_switch.set_valign(gtk4::Align::Center);
    {
        let sender = sender.clone();
        container_switch.connect_state_set(move |switch, _| {
            sender.input(Msg::SetShowContainerHints(switch.is_active()));
            gtk4::glib::Propagation::Stop
        });
    }
    container_row.add_suffix(&container_switch);
    container_row.set_activatable_widget(Some(&container_switch));
    list.add(&container_row);

    content.append(&list);

    // Footer hint.
    let footer = gtk4::Label::new(Some("Preferences apply immediately and reset on restart."));
    footer.add_css_class("dim-label");
    footer.set_margin_top(12);
    footer.set_margin_bottom(12);
    footer.set_margin_start(12);
    footer.set_margin_end(12);
    content.append(&footer);

    prefs_win.set_child(Some(&content));
    prefs_win.present();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn event(serial: u64, comm: &str, scontext: &str, tcontext: &str) -> AvcEvent {
        AvcEvent {
            audit_id: format!("1.0:{serial}"),
            timestamp: serial as f64,
            serial,
            result: "denied".into(),
            perms: vec!["open".into()],
            scontext: scontext.into(),
            tcontext: tcontext.into(),
            tclass: "file".into(),
            pid: Some(1),
            comm: Some(comm.into()),
            exe: None,
            path: Some("/var/www/html/index.html".into()),
            dest_port: None,
            dev: None,
            ino: None,
            raw: String::new(),
        }
    }

    fn model() -> App {
        let events = vec![
            event(1, "httpd", "system_u:system_r:httpd_t:s0", "unconfined_u:object_r:user_home_t:s0"),
            event(2, "smbd", "system_u:system_r:smbd_t:s0", "system_u:object_r:default_t:s0"),
        ];
        let diagnoses = diagnose_all(&events, false);
        let mut m = App::new();
        m.events = events;
        m.diagnoses = diagnoses;
        m
    }

    #[test]
    fn filter_matches_summary_and_contexts() {
        let mut m = model();
        assert_eq!(m.visible(), vec![0, 1]);
        m.filter = "smbd".into();
        assert_eq!(m.visible(), vec![1]);
        m.filter = "httpd_t".into();
        assert_eq!(m.visible(), vec![0]);
    }

    #[test]
    fn ingest_dedups_by_audit_id() {
        let mut m = model();
        m.ingest(vec![event(3, "httpd", "system_u:system_r:httpd_t:s0", "system_u:object_r:var_t:s0")]);
        m.ingest(vec![event(1, "httpd", "system_u:system_r:httpd_t:s0", "system_u:object_r:var_t:s0")]);
        assert_eq!(m.events.len(), 3);
        assert_eq!(m.diagnoses.len(), 3);
    }

    #[test]
    fn ingest_reports_notice_and_anomaly_on_burst() {
        let mut m = model();
        assert!(m
            .ingest(vec![event(3, "httpd", "system_u:system_r:httpd_t:s0", "system_u:object_r:var_t:s0")])
            .unwrap()
            .starts_with("Live: +1"));
        assert!(m.ingest(Vec::new()).is_none());
    }

    #[test]
    fn preview_needs_selection() {
        let m = model();
        assert_eq!(preview_for(&m), "Pick a denial first.");
    }
}
