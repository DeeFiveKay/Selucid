// SPDX-License-Identifier: GPL-3.0-or-later
//! Single-window Libadwaita app: Denials + Booleans views over `selucid-core`.
//!
//! GNOME HIG patterns for RHEL and Fedora Workstation.
//! AdwApplicationWindow + AdwHeaderBar, AdwViewSwitcher + GtkStack,
//! boxed-list rows, monospace context block, AdwToastOverlay for live and
//! apply feedback. Diagnosis and fix previews reuse `selucid-core` exactly
//! like the CLI and TUI.

use relm4::prelude::*;
use selucid_core::{AvcEvent, Diagnosis, FixKind};

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
}

// ---------------------------------------------------------------------------
// View-model: plain data, no GTK handles.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DenialRow {
    index: usize,
    summary: String,
    subtitle: String,
}

struct Model {
    events: Vec<AvcEvent>,
    diagnoses: Vec<Diagnosis>,
    filter: String,
    selected: Option<usize>,
    selected_fix: usize,
    use_oracle: bool,
    bool_filter: String,
    booleans: Vec<selucid_core::booleans::BooleanInfo>,
    preview_text: String,
    toast_text: Option<String>,
}

impl Model {
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
            preview_text: String::from("Pick a denial to see the suggested fix."),
            toast_text: None,
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
        self.preview_text = String::from("Pick a denial to see the suggested fix.");
    }

    fn ingest(&mut self, incoming: Vec<AvcEvent>) {
        let mut added = 0;
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
            self.events.push(event);
            self.diagnoses.push(d);
            added += 1;
        }
        if added > 0 {
            self.toast_text = Some(format!("Live: +{added} denial(s)"));
        }
    }
}

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------

fn initial_events() -> Vec<AvcEvent> {
    use selucid_core::reader::{LogTailer, parse_lines};
    use selucid_core::{extract_avc_events, group_by_serial};

    if let Some(path) = std::env::args().nth(1) {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        return extract_avc_events(&group_by_serial(parse_lines(&lines)));
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

struct App {
    model: Model,
}

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

            libadwaita::ToastOverlay {
                #[wrap(Some)]
                set_child = &gtk4::Box {
                    set_orientation: gtk4::Orientation::Vertical,

                    libadwaita::HeaderBar {
                        pack_start = &gtk4::Box {
                            set_spacing: 6,
                            set_hexpand: false,
                            gtk4::Image {
                                set_icon_name: Some("security-medium-symbolic"),
                            },
                            gtk4::Label {
                                set_label: "Selucid",
                                add_css_class: "title",
                            },
                        },
                        pack_start: view_switcher = &libadwaita::ViewSwitcher {
                            set_stack: Some(stack),
                            set_policy: libadwaita::ViewSwitcherPolicy::Wide,
                        },
                        pack_end: filter_entry = &gtk4::SearchEntry {
                            set_placeholder_text: Some("Filter denials\u{2026}"),
                            connect_search_changed[sender] => move |entry| {
                                sender.input(Msg::SetFilter(entry.text().to_string()));
                            },
                        },
                    },

                    #[name(stack)]
                    gtk4::Stack {
                        set_vexpand: true,
                        connect_visible_child_notify[sender] => move |stack| {
                            if let Some(name) = stack.visible_child_name() {
                                if name == "denials" {
                                    sender.input(Msg::SetFilter(model.filter.clone()));
                                }
                            }
                        },
                    },
                },
            }
        }
    }

    fn init(
        init: Self::Init,
        _root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut model = Model::new();
        if !init.is_empty() {
            match std::fs::read_to_string(&init) {
                Ok(text) => {
                    for raw_line in text.lines() {
                        if let Ok(event) = selucid_core::parser::parse_audit_line(raw_line) {
                            if event.result.as_str() == "denied" {
                                model.events.push(event);
                            }
                        }
                    }
                    model.diagnoses = diagnose_all(&model.events, model.use_oracle);
                }
                Err(_) => {
                    let _ = sender;
                }
            }
        }

        let widgets = view_output!();

        // Build page contents.
        build_denials_page(&widgets, &model, sender.clone());
        build_booleans_page(&widgets, &model, sender.clone());
        widgets.stack.set_visible_child_name(Some("denials"));

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        match msg {
            Msg::SetFilter(q) => {
                self.model.filter = q;
                self.model.selected = None;
                rebuild_denials_list(&self.widgets, &self.model, sender.clone());
                clear_detail(&self.widgets);
            }
            Msg::SelectDenial(selected) => {
                self.model.selected = selected;
                self.model.selected_fix = 0;
                rebuild_denials_list(&self.widgets, &self.model, sender.clone());
                if let Some(_idx) = selected {
                    show_detail(&self.widgets, &self.model);
                } else {
                    clear_detail(&self.widgets);
                }
            }
            Msg::SelectFix(i) => {
                self.model.selected_fix = i;
                update_fix_preview(&self.widgets, &self.model);
            }
            Msg::SetOracle(on) => {
                self.model.use_oracle = on;
                self.model.rediagnose();
                rebuild_denials_list(&self.widgets, &self.model, sender.clone());
                if self.model.selected.is_some() {
                    show_detail(&self.widgets, &self.model);
                }
            }
            Msg::Ingest(incoming) => {
                self.model.ingest(incoming);
                rebuild_denials_list(&self.widgets, &self.model, sender.clone());
                if let Some(idx) = self.model.selected {
                    if idx < self.model.events.len() {
                        show_detail(&self.widgets, &self.model);
                    } else {
                        self.model.selected = None;
                        clear_detail(&self.widgets);
                    }
                }
            }
            Msg::Notice(text) => {
                self.model.toast_text = Some(text);
                show_toast(&self.widgets, &text);
            }
            Msg::PreviewFix => {
                self.model.preview_text = preview_for(&self.model);
                update_fix_preview(&self.widgets, &self.model);
            }
            Msg::ApplyFix => {
                if let Some(text) = apply_selected(&self.model) {
                    sender.input(Msg::Notice(text));
                }
            }
            Msg::SetBoolFilter(q) => {
                self.model.bool_filter = q;
                rebuild_booleans_list(&self.widgets, &self.model);
            }
            Msg::PreviewBool(pos) => {
                if let Some(idx) = self.model.visible_booleans().get(pos).copied() {
                    let b = &self.model.booleans[idx];
                    self.model.toast_text = Some(format!(
                        "preview: sudo {}",
                        selucid_core::booleans::setsebool_command(&b.name, !b.active)
                    ));
                }
            }
            Msg::ToggleBool(idx, on) => {
                if let Some(i) = self.model.visible_booleans().get(idx).copied() {
                    let b = &self.model.booleans[i];
                    sender.input(Msg::Notice(format!(
                        "preview: {}",
                        selucid_core::booleans::setsebool_command(&b.name, on)
                    )));
                    let action = selucid_core::privileged::setsebool_action(&b.name, on);
                    match action.execute() {
                        Ok(_stdout) => {
                            if let Some(bi) = self.model.booleans.get_mut(i) {
                                bi.active = on;
                                bi.pending = on;
                            }
                            rebuild_booleans_list(&self.widgets, &self.model);
                            sender.input(Msg::Notice(format!("Applied: {}", action.preview())));
                        }
                        Err(e) => {
                            sender.input(Msg::Notice(format!("Error: {}", e)));
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------

fn build_denials_page(
    widgets: &<App as SimpleComponent>::Widgets,
    model: &Model,
    sender: ComponentSender<App>,
) {
    use gtk4::prelude::*;

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

    let list_box_weak = list_box.downgrade();
    list_box.connect_row_selected(move |box_| {
        if let Some(row) = box_.selected_row() {
            // Find the index from the row's title.
            let label = row.child().and_then(|c| c.downcast_ref::<gtk4::Label>());
            if let Some(label) = label {
                let summary = label.label().unwrap_or_default();
                // Lookup by summary in the model... we need sender.
                // Store index as row data instead.
                let idx = row.data::<usize>().unwrap_or(&0);
                // Send message via a global channel.
                let _ = box_;
                let _ = idx;
            }
        }
    });

    // Right column: detail pane.
    let detail_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    detail_box.set_hexpand(true);
    detail_box.set_vexpand(true);
    detail_box.set_margin_all(12);

    let detail_scroll = gtk4::ScrolledWindow::new();
    detail_scroll.set_hexpand(true);
    detail_scroll.set_vexpand(true);
    detail_scroll.set_margin_all(0);

    let detail_inner = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    detail_inner.set_hexpand(true);
    detail_inner.set_vexpand(true);

    let summary_label = gtk4::Label::new(Some("Select a denial to inspect"));
    summary_label.set_halign(gtk4::Align::Start);
    summary_label.set_wrap(true);
    summary_label.set_line_wrap(true);
    summary_label.add_css_class("headline");
    detail_inner.append(&summary_label);

    let explain_label = gtk4::Label::new(Some(""));
    explain_label.set_halign(gtk4::Align::Start);
    explain_label.set_wrap(true);
    explain_label.set_line_wrap(true);
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

    page.append(&list_box);
    page.append(&detail_box);

    widgets.stack.add_titled(&page, Some("denials"), "Denials");

    widgets.denials_list_box = Some(list_box);
    widgets.detail_summary_label = Some(summary_label);
    widgets.detail_explain_label = Some(explain_label);
    widgets.detail_context_label = Some(context_label);
    widgets.detail_fixes_box = Some(fixes_box);
}

fn build_booleans_page(
    widgets: &mut <App as SimpleComponent>::Widgets,
    _model: &Model,
    sender: ComponentSender<App>,
) {
    use gtk4::prelude::*;
    use libadwaita::prelude::*;

    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    page.set_hexpand(true);
    page.set_vexpand(true);
    page.set_margin_all(12);

    let search_entry = gtk4::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Search booleans\u{2026}"));
    search_entry.set_hexpand(true);
    search_entry.connect_search_changed(move |entry| {
        sender.input(Msg::SetBoolFilter(entry.text().to_string()));
    });
    page.append(&search_entry);

    let list_box = gtk4::ListBox::new();
    list_box.add_css_class("boxed-list");
    list_box.set_hexpand(true);
    list_box.set_vexpand(true);
    list_box.set_selection_mode(gtk4::SelectionMode::None);
    page.append(&list_box);

    widgets.stack.add_titled(&page, Some("booleans"), "Booleans");

    widgets.booleans_list_box = Some(list_box);
    widgets.bool_search_entry = Some(search_entry);
}

// ---------------------------------------------------------------------------
// Rebuild helpers
// ---------------------------------------------------------------------------

fn rebuild_denials_list(
    widgets: &<App as SimpleComponent>::Widgets,
    model: &Model,
    sender: ComponentSender<App>,
) {
    use gtk4::prelude::*;

    let list_box = widgets.denials_list_box.as_ref().unwrap();

    // Remove existing rows.
    list_box.rows().for_each(|row| list_box.remove(&row));

    let visible = model.visible_rows();
    for row_data in visible {
        let row = gtk4::ListBoxRow::new();
        row.set_selectable(true);
        row.set_data(&row_data.index);

        let label = gtk4::Label::new(Some(&row_data.summary));
        label.set_halign(gtk4::Align::Start);
        label.set_wrap(true);
        label.set_line_wrap(true);
        label.set_margin_end(12);
        label.add_css_class("title");

        let subtitle = gtk4::Label::new(Some(&row_data.subtitle));
        subtitle.set_halign(gtk4::Align::Start);
        subtitle.set_wrap(true);
        subtitle.add_css_class("dim-label");
        subtitle.set_margin_end(12);

        let row_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        row_box.set_hexpand(true);
        row_box.set_halign(gtk4::Align::Start);
        row_box.append(&label);
        row_box.append(&subtitle);

        row.set_child(Some(&row_box));

        let sender_clone = sender.clone();
        let idx = row_data.index;
        row.connect_activated(move |_| {
            sender_clone.input(Msg::SelectDenial(Some(idx)));
        });

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

fn rebuild_booleans_list(
    widgets: &<App as SimpleComponent>::Widgets,
    model: &Model,
) {
    use gtk4::prelude::*;
    use libadwaita::prelude::*;

    let list_box = widgets.booleans_list_box.as_ref().unwrap();

    list_box.rows().for_each(|row| list_box.remove(&row));

    let visible = model.visible_booleans();
    for idx in visible {
        let info = &model.booleans[idx];
        let row = libadwaita::ActionRow::new();
        row.set_title(&info.name);
        row.set_subtitle(if info.active { "on" } else { "off" });
        row.add_css_class("boxed-list");

        let switch = gtk4::Switch::new();
        switch.set_active(info.active);
        switch.set_hexpand(false);
        switch.set_halign(gtk4::Align::End);

        let idx2 = idx;
        switch.connect_state_set(move |_switch, active| {
            // We need sender here. We'll store it on the widget.
            glib::Propagation::Stop
        });

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

fn show_detail(
    widgets: &<App as SimpleComponent>::Widgets,
    model: &Model,
) {
    use gtk4::prelude::*;

    let Some(selected) = model.selected else {
        widgets.detail_summary_label.as_ref().unwrap().set_label("Select a denial to inspect");
        widgets.detail_explain_label.as_ref().unwrap().set_label("");
        widgets.detail_context_label.as_ref().unwrap().set_label("");
        widgets.detail_fixes_box.as_ref().unwrap().children().for_each(|c| {
            widgets.detail_fixes_box.as_ref().unwrap().remove(&c);
        });
        return;
    };

    let event = &model.events[selected];
    let diagnosis = &model.diagnoses[selected];

    widgets.detail_summary_label.as_ref().unwrap().set_label(&diagnosis.summary);
    widgets.detail_explain_label.as_ref().unwrap().set_label(&diagnosis.explanation);

    let scontext = event.scontext.split(':').next().unwrap_or("?");
    let tcontext = event.tcontext.split(':').next().unwrap_or("?");
    widgets.detail_context_label.as_ref().unwrap().set_markup(&format!(
        "<span font_family=\"monospace\" size=\"x-small\"><b>{}</b>\u{2192}<b>{}</b></span>",
        scontext, tcontext
    ));

    let fixes_box = widgets.detail_fixes_box.as_ref().unwrap();
    fixes_box.children().for_each(|c| fixes_box.remove(&c));

    for (fix_idx, fix) in diagnosis.fixes.iter().enumerate() {
        let fix_row = libadwaita::ActionRow::new();
        fix_row.set_title(&fix.title);
        fix_row.set_subtitle(&fix.description);
        fix_row.add_css_class("boxed-list");

        let radio = gtk4::CheckButton::new();
        radio.set_active(fix_idx == model.selected_fix);
        radio.set_halign(gtk4::Align::Start);
        fix_row.add_prefix(&radio);

        let command_label = gtk4::Label::new(Some(&fix.command));
        command_label.set_halign(gtk4::Align::Start);
        command_label.add_css_class("monospace");
        command_label.set_wrap(true);
        command_label.set_margin_start(12);
        command_label.set_selectable(true);

        let box_ = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        box_.set_hexpand(true);
        box_.append(&command_label);

        let preview_btn = gtk4::Button::with_label("Preview");
        preview_btn.set_hexpand(false);
        preview_btn.add_css_class("flat");
        box_.append(&preview_btn);

        let apply_btn = gtk4::Button::with_label("Apply");
        apply_btn.set_hexpand(false);
        apply_btn.add_css_class("suggested-action");
        box_.append(&apply_btn);

        fix_row.add_suffix(&box_);
        fixes_box.append(&fix_row);
    }
}

fn clear_detail(widgets: &<App as SimpleComponent>::Widgets) {
    use gtk4::prelude::*;

    widgets.detail_summary_label.as_ref().unwrap().set_label("Select a denial to inspect");
    widgets.detail_explain_label.as_ref().unwrap().set_label("");
    widgets.detail_context_label.as_ref().unwrap().set_label("");

    let fixes_box = widgets.detail_fixes_box.as_ref().unwrap();
    fixes_box.children().for_each(|c| fixes_box.remove(&c));
}

fn update_fix_preview(widgets: &<App as SimpleComponent>::Widgets, model: &Model) {
    if !model.preview_text.is_empty() {
        show_toast(widgets, &model.preview_text);
    }
}

fn show_toast(widgets: &<App as SimpleComponent>::Widgets, text: &str) {
    use libadwaita::prelude::*;
    widgets.toast_overlay.add_toast(
        libadwaita::Toast::with_label(text)
    );
}

// ---------------------------------------------------------------------------
// Preview / Apply
// ---------------------------------------------------------------------------

fn preview_for(model: &Model) -> String {
    let Some(i) = model.selected else {
        return String::from("Pick a denial first.");
    };
    let Some(d) = model.diagnoses.get(i) else {
        return String::from("Pick a denial first.");
    };
    match d.fixes.get(model.selected_fix) {
        Some(fix) => format!("{}\n$ {}", fix.title, fix.command),
        None => String::from("No such fix for this denial."),
    }
}

fn apply_selected(model: &Model) -> Option<String> {
    let Some(i) = model.selected else { return None };
    let Some(d) = model.diagnoses.get(i) else { return None };
    let Some(fix) = d.fixes.get(model.selected_fix) else { return None };

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

    if let Some(a) = action {
        match a.execute() {
            Ok(stdout) => Some(format!("Applied:\n{}", a.preview())),
            Err(e) => Some(format!("Error: {}", e)),
        }
    } else {
        Some(format!(
            "Refused: {} needs eyes-on review. Copy the command below and run it manually.",
            fix.title
        ))
    }
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

    fn model() -> Model {
        let events = vec![
            event(1, "httpd", "system_u:system_r:httpd_t:s0", "unconfined_u:object_r:user_home_t:s0"),
            event(2, "smbd", "system_u:system_r:smbd_t:s0", "system_u:object_r:default_t:s0"),
        ];
        let diagnoses = diagnose_all(&events, false);
        Model {
            events,
            diagnoses,
            filter: String::new(),
            selected: None,
            selected_fix: 0,
            use_oracle: false,
            bool_filter: String::new(),
            booleans: Vec::new(),
            preview_text: String::new(),
            toast_text: None,
        }
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
    fn preview_needs_selection() {
        let m = model();
        assert_eq!(preview_for(&m), "Pick a denial first.");
    }
}
