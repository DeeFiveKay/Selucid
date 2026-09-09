// SPDX-License-Identifier: GPL-3.0-or-later
//! `selucid-gui` placeholder.
//!
//! The full relm4/GTK4/Libadwaita interface (Live Stream, Detail & Analysis,
//! Boolean Explorer per the blueprint) builds on `selucid-core` once the host
//! provides `gtk4-devel` and `libadwaita-devel`. This stub keeps the workspace
//! resolving and gives a clear error until then.

fn main() {
    eprintln!(
        "selucid-gui is not built yet on this host: install gtk4-devel and \
         libadwaita-devel, enable the relm4/gtk/libadwaita dependencies in \
         crates/selucid-gui/Cargo.toml, and implement the Live Stream, Detail \
         & Analysis, and Boolean Explorer views on top of selucid-core."
    );
    std::process::exit(2);
}
