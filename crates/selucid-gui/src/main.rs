// SPDX-License-Identifier: GPL-3.0-or-later
//! `selucid-gui`: streamlined Libadwaita desktop UI for RHEL/Fedora GNOME.
//!
//! Without the `gui` feature this is a stub that explains the missing system
//! headers. With `--features gui` (and `gtk4-devel` + `libadwaita-devel`
//! installed) it launches the real single-window app from [`app`].

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!(
        "selucid-gui needs its `gui` feature plus system headers:\n\
         \n  sudo dnf install gtk4-devel libadwaita-devel\n  cargo run -p selucid-gui --features gui\n"
    );
    std::process::exit(2);
}

#[cfg(feature = "gui")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or(selucid_core::reader::DEFAULT_AUDIT_LOG);
    app::run(path);
}

#[cfg(feature = "gui")]
mod app;
