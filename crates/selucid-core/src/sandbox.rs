// SPDX-License-Identifier: GPL-3.0-or-later
//! Sandbox / What-If simulator: previews what a proposed fix would change
//! *without* executing anything.
//!
//! For a boolean fix it reports the before/after values plus the policy
//! rules (via `sesearch -b <bool> -A`) that would allow new access when the
//! tool is available. For a relabel fix it diffs the file's current context
//! against the policy-expected one. Everything here is read-only: sysfs
//! reads, `sesearch`, `matchpathcon`, and xattr reads — no privileges, no
//! writes, and any unavailable tool degrades to an explicit note.

use crate::inference::{FixKind, SuggestedFix};
use crate::privileged::expected_context;
use crate::{booleans, inspect};
use serde::{Deserialize, Serialize};
use std::process::Command;

/// What one proposed fix would change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationDiff {
    /// The fix being simulated.
    pub fix_title: String,
    /// True when the simulator could fully observe the change (no missing tools).
    pub complete: bool,
    /// Human-readable before/after lines, e.g. `boolean foo: 0 -> 1`.
    pub changes: Vec<String>,
    /// Domains whose allowed access would grow (boolean fixes, `sesearch`).
    pub domains_gaining: Vec<String>,
    /// Explicit notes about what could not be simulated.
    pub notes: Vec<String>,
}

/// Simulate one suggested fix. Read-only by construction.
pub fn simulate(fix: &SuggestedFix) -> SimulationDiff {
    match fix.kind {
        FixKind::SetBoolean => simulate_boolean(fix),
        FixKind::Restorecon => simulate_relabel(fix),
        FixKind::SemanageFcontext => SimulationDiff {
            fix_title: fix.title.clone(),
            complete: false,
            changes: vec![format!(
                "new fcontext mapping: {}",
                fix.command
                    .strip_prefix("semanage fcontext -a -t ")
                    .unwrap_or(&fix.command)
            )],
            domains_gaining: Vec::new(),
            notes: vec![
                "Adds a path-to-type mapping; existing files keep their label \
                 until a relabel runs."
                    .into(),
            ],
        },
        FixKind::PolicyModule => SimulationDiff {
            fix_title: fix.title.clone(),
            complete: false,
            changes: vec!["install a local policy module".into()],
            domains_gaining: Vec::new(),
            notes: vec![
                "Module install grants whatever the generated rules allow; \
                 review the .te with `audit2allow -v` before applying.".into(),
            ],
        },
        FixKind::ContainerVolume => SimulationDiff {
            fix_title: fix.title.clone(),
            complete: true,
            changes: vec![format!(
                "container bind-mount gains the {} flag",
                if fix.command.contains(":Z") { ":Z" } else { ":z" }
            )],
            domains_gaining: Vec::new(),
            notes: vec![
                "Inside-container change: relabels the mount for the runtime's \
                 container_file_t; nothing on the host policy changes.".into(),
            ],
        },
    }
}

/// Boolean What-If: sysfs before/after plus `sesearch -b <bool> -A` domains.
fn simulate_boolean(fix: &SuggestedFix) -> SimulationDiff {
    // Command shape: `setsebool -P <name> <1|0>`.
    let mut parts = fix.command.split_whitespace();
    let _ = parts.next();
    let _ = parts.next();
    let name = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let mut changes = Vec::new();
    let mut notes = Vec::new();
    let mut complete = true;

    let current = booleans::get_boolean(name);
    let before = current
        .as_ref()
        .map(|b| u8::from(b.active).to_string())
        .unwrap_or_else(|| "?".into());
    if current.is_none() {
        complete = false;
        notes.push(format!("boolean {name:?} not found on this system"));
    }
    if target != "1" && target != "0" {
        complete = false;
        notes.push(format!("unexpected target value {target:?}"));
    }
    changes.push(format!("boolean {name}: {before} -> {target}"));

    let (domains, sesearch_ok) = domains_gaining_access(name);
    if !sesearch_ok {
        complete = false;
        notes.push(
            "sesearch unavailable — affected domains not enumerated \
             (install setools-console for a full diff)."
                .into(),
        );
    }

    SimulationDiff {
        fix_title: fix.title.clone(),
        complete,
        changes,
        domains_gaining: domains,
        notes,
    }
}

/// Relabel What-If: current context (xattr) vs expected (matchpathcon).
fn simulate_relabel(fix: &SuggestedFix) -> SimulationDiff {
    // Command shape: `restorecon -v <path>`.
    let path = fix
        .command
        .strip_prefix("restorecon -v ")
        .unwrap_or("")
        .trim();
    let mut changes = Vec::new();
    let mut notes = Vec::new();
    let mut complete = true;

    let current = inspect::actual_context(path);
    let expected = expected_context(path);
    match (&current, &expected) {
        (Some(c), Some(e)) => changes.push(format!("{path}: {c} -> {e}")),
        (None, Some(e)) => {
            // Unreadable/unlabeled: the relabel would set the expected label.
            changes.push(format!("{path}: <current unreadable> -> {e}"));
            complete = false;
            notes.push("current context unreadable (permission or xattr support)".into());
        }
        (Some(c), None) => {
            changes.push(format!("{path}: {c} -> <policy default unknown>"));
            complete = false;
            notes.push("matchpathcon unavailable — expected label not resolved".into());
        }
        (None, None) => {
            complete = false;
            notes.push(format!(
                "cannot read current or expected context for {path:?}"
            ));
        }
    }

    SimulationDiff {
        fix_title: fix.title.clone(),
        complete,
        changes,
        domains_gaining: Vec::new(),
        notes,
    }
}

/// Run `sesearch -b <boolean> -A` and collect the source domains of allow
/// rules that would apply. Returns `(domains, tool_available)`.
fn domains_gaining_access(boolean: &str) -> (Vec<String>, bool) {
    let Ok(output) = Command::new("sesearch").args(["-b", boolean, "-A"]).output() else {
        return (Vec::new(), false);
    };
    if !output.status.success() {
        return (Vec::new(), false);
    }
    // Rule lines look like:
    //   allow httpd_t httpd_sys_content_t:file { getattr open read };
    let mut domains = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some(rest) = line.trim().strip_prefix("allow ") else {
            continue;
        };
        if let Some(src) = rest
            .split_whitespace()
            .next()
            .filter(|src| src.ends_with("_t"))
        {
            if !domains.iter().any(|d: &String| d == src) {
                domains.push(src.to_string());
            }
        }
    }
    domains.sort();
    (domains, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(kind: FixKind, command: &str) -> SuggestedFix {
        SuggestedFix {
            kind,
            title: "test".into(),
            command: command.into(),
            description: "test".into(),
            needs_root: true,
        }
    }

    #[test]
    fn boolean_whatif_reports_before_after() {
        let f = fix(
            FixKind::SetBoolean,
            "setsebool -P httpd_can_network_connect 1",
        );
        let d = simulate(&f);
        assert_eq!(d.changes.len(), 1);
        assert!(
            d.changes[0].starts_with("boolean httpd_can_network_connect: "),
            "got {:?}",
            d.changes
        );
        assert!(d.changes[0].ends_with(" -> 1"));
    }

    #[test]
    fn relabel_whatif_diffs_current_vs_expected() {
        let f = fix(FixKind::Restorecon, "restorecon -v /var/www/html/index.html");
        let d = simulate(&f);
        assert_eq!(d.changes.len(), 1);
        assert!(
            d.changes[0].starts_with("/var/www/html/index.html: "),
            "got {:?}",
            d.changes
        );
        // Either both contexts resolve (real ` -> ` diff) or the diff
        // explains what could not be read.
        if !d.changes[0].contains(" -> ") {
            assert!(!d.notes.is_empty());
        }
    }

    #[test]
    fn compound_fixes_explain_themselves() {
        let f = fix(FixKind::PolicyModule, "semodule -i selucid_1.pp");
        let d = simulate(&f);
        assert!(!d.complete);
        assert!(!d.notes.is_empty());

        let c = fix(FixKind::ContainerVolume, "podman run -v /srv/data:/srv/data:z");
        let dc = simulate(&c);
        assert!(dc.complete);
        assert!(dc.changes[0].contains(":z"));
    }

    #[test]
    fn sesearch_graceful_when_missing() {
        // On hosts without sesearch the flag comes back false and the diff
        // stays well-formed; on hosts with it, domains are real strings.
        let (domains, ok) = domains_gaining_access("httpd_can_network_connect");
        if !ok {
            assert!(domains.is_empty());
        }
        for d in &domains {
            assert!(d.ends_with("_t"));
        }
    }
}
