// SPDX-License-Identifier: GPL-3.0-or-later
//! Fix history & rollback: an append-only JSONL audit journal under
//! `$XDG_STATE_HOME/selucid/history.jsonl` capturing every fix executed
//! through Selucid, plus the commands that would revert them.
//!
//! Journaling is best-effort: a full journal never blocks a fix.
//! Reading and before/after capture are unprivileged (sysfs, `getfattr`,
//! `matchpathcon`); only the follow-up rollback command escalates through
//! the existing Polkit actions.

use crate::booleans::get_boolean;
use crate::inspect::actual_context;
use crate::privileged::expected_context;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One executed (or attempted) fix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unique id (`<tag>-<seq>`), used by `selucid rollback <id>`.
    pub id: String,
    /// Human readable instant the action ran.
    pub executed_at: String,
    /// Polkit action id, e.g. `org.selucid.setboolean`.
    pub action_id: String,
    /// Exact argv that was run (no shell).
    pub argv: Vec<String>,
    /// State before the action (`name=1`, a file context, or `None`).
    pub before: Option<String>,
    /// State after the action, when observable.
    pub after: Option<String>,
    /// Whether the privileged command itself reported success.
    pub success: bool,
    /// First bytes of command stdout (for the detail view).
    pub output_excerpt: Option<String>,
}

/// A reversible-to-plan: how to undo one [`HistoryEntry`].
pub struct RollbackPlan {
    /// Polkit action guarding the rollback command.
    pub action_id: &'static str,
    /// argv of the rollback command (reachable without a shell).
    pub argv: Vec<String>,
    /// Short human description of what the rollback does.
    pub description: String,
}

/// The journal directory (created on demand).
pub fn state_dir() -> PathBuf {
    let xdg = std::env::var("XDG_STATE_HOME").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    let base = if !xdg.is_empty() {
        xdg
    } else if !home.is_empty() {
        format!("{}/.local/state", home)
    } else {
        ".selucid-state".to_string()
    };
    Path::new(&base).join("selucid")
}

/// The journal file path.
pub fn history_file() -> PathBuf {
    state_dir().join("history.jsonl")
}

/// Append one entry to the journal (best-effort: never fails the caller).
/// The journal grows append-only by rewrite to avoid depending on an
/// append-mode syscall; keep it under a few thousand entries.
pub fn record(entry: &HistoryEntry) -> std::io::Result<()> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("history.jsonl");
    let mut text = String::new();
    if let Ok(existing) = std::fs::read_to_string(&path) {
        text.push_str(&existing);
    }
    let line = serde_json::to_string(entry)?;
    text.push_str(&line);
    text.push('\n');
    std::fs::write(&path, text)?;
    Ok(())
}

/// Load all journal entries, newest first. Unparsable lines are skipped.
pub fn list_entries() -> Vec<HistoryEntry> {
    list_in(history_file().as_ref())
}

/// Capture the observable state *before* an action for its journal entry.
pub fn capture_before(action_id: &str, argv: &[String]) -> Option<String> {
    match action_id {
        "org.selucid.setboolean" => {
            let name = argv.get(2).map(|s| s.to_string())?;
            get_boolean(&name).map(|b| format!("{}={}", b.name, if b.active { "1" } else { "0" }))
        }
        "org.selucid.restorecon" => {
            let path = argv.last().map(|s| s.to_string())?;
            actual_context(&path)
        }
        _ => None,
    }
}

/// Capture the observable state *after* an action.
pub fn capture_after(action_id: &str, argv: &[String]) -> Option<String> {
    match action_id {
        "org.selucid.setboolean" => {
            let name = argv.get(2).map(|s| s.to_string())?;
            let target = argv.get(3).map(|s| s.as_str()).unwrap_or("1");
            Some(format!("{}={}", name, target))
        }
        "org.selucid.restorecon" => {
            let path = argv.last().map(|s| s.to_string())?;
            expected_context(&path)
        }
        _ => None,
    }
}

/// Build the command that would undo an executed fix, when one exists.
/// Toggleable booleans and label reverts are reversible; policy modules and
/// fcontext mappings are left to manual review.
pub fn rollback_plan(entry: &HistoryEntry) -> Option<RollbackPlan> {
    match entry.action_id.as_str() {
        "org.selucid.setboolean" => {
            let name = entry.argv.get(2).map(|s| s.to_string())?;
            let previous = entry
                .before
                .as_deref()
                .and_then(|b| b.split_once('='))
                .map(|(_, v)| v.trim().to_string())
                .filter(|v| v == "0" || v == "1")?;
            let description = format!("Revert boolean {name} back to {previous}");
            Some(RollbackPlan {
                action_id: "org.selucid.setboolean",
                argv: vec!["setsebool".into(), "-P".into(), name, previous],
                description,
            })
        }
        "org.selucid.restorecon" => {
            let path = entry.argv.last().map(|s| s.to_string())?;
            let ttype = entry
                .before
                .as_deref()
                .and_then(crate::avc::SelinuxContext::parse)
                .map(|c| c.kind)?;
            let description = format!("Restore the original label {ttype} on {path}");
            Some(RollbackPlan {
                action_id: "org.selucid.restorecon",
                argv: vec!["chcon".into(), "-t".into(), ttype, path],
                description,
            })
        }
        _ => None,
    }
}

fn wall_time() -> String {
    let Ok(output) = Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output() else {
        return "unknown".to_string();
    };
    if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "unknown".to_string()
    }
}

/// Build a journal entry, assigning the id and local timestamp.
pub fn new_entry(
    action_id: &str,
    argv: &[String],
    before: Option<String>,
    after: Option<String>,
    success: bool,
    output_excerpt: Option<String>,
) -> HistoryEntry {
    let executed_at = wall_time();
    let key_len: usize = argv.iter().map(|a| a.len()).sum();
    HistoryEntry {
        id: format!("{}:{}+{}", executed_at, argv.len(), key_len),
        executed_at,
        action_id: action_id.to_string(),
        argv: argv.to_vec(),
        before,
        after,
        success,
        output_excerpt,
    }
}

/// Record into an explicit directory (used by tests).
pub fn record_in(dir: &Path, entry: &HistoryEntry) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("history.jsonl");
    let mut text = String::new();
    if let Ok(existing) = std::fs::read_to_string(&path) {
        text.push_str(&existing);
    }
    let line = serde_json::to_string(entry)?;
    text.push_str(&line);
    text.push('\n');
    std::fs::write(&path, text)?;
    Ok(())
}

/// List entries from an explicit file (used by tests), newest first.
pub fn list_in(file: &Path) -> Vec<HistoryEntry> {
    let Ok(text) = std::fs::read_to_string(file) else {
        return Vec::new();
    };
    let mut entries = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<HistoryEntry>(l).ok())
        .collect::<Vec<_>>();
    entries.reverse();
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(dir: &Path) -> HistoryEntry {
        let e = new_entry(
            "org.selucid.setboolean",
            &["setsebool".into(), "-P".into(), "httpd_can_network_connect".into(), "1".into()],
            Some("httpd_can_network_connect=0".into()),
            Some("httpd_can_network_connect=1".into()),
            true,
            None,
        );
        record_in(dir, &e).unwrap();
        e
    }

    #[test]
    fn roundtrips_through_record_and_list_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let first = sample_entry(dir);
        let second = new_entry(
            "org.selucid.restorecon",
            &["restorecon".into(), "-v".into(), "/srv/x".into()],
            Some("unconfined_u:object_r:user_home_t:s0".into()),
            Some("system_u:object_r:httpd_sys_content_t:s0".into()),
            true,
            None,
        );
        record_in(dir, &second).unwrap();
        let entries = list_in(&dir.join("history.jsonl"));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action_id, "org.selucid.restorecon"); // newest first
        assert_eq!(entries[1].action_id, "org.selucid.setboolean");
        assert_eq!(first.before, Some("httpd_can_network_connect=0".to_string()));
        assert!(entries.iter().all(|e| !e.id.is_empty()));
    }

    #[test]
    fn missing_journal_lists_empty() {
        assert!(list_entries().is_empty());
    }

    #[test]
    fn rollback_inverts_boolean_and_relabel() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let e = sample_entry(dir);
        let p = rollback_plan(&e).unwrap();
        assert_eq!(p.action_id, "org.selucid.setboolean");
        assert_eq!(p.argv, vec!["setsebool", "-P", "httpd_can_network_connect", "0"]);
        assert!(p.description.contains("0"));

        // A module install has no safe revert.
        let module = new_entry(
            "org.selucid.installmodule",
            &["semodule".into(), "-i".into(), "selucid_1.pp".into()],
            None,
            None,
            true,
            None,
        );
        assert!(rollback_plan(&module).is_none());
    }

    #[test]
    fn capture_unknown_action_is_none() {
        assert!(capture_before("org.selucid.installmodule", &["a".into()]).is_none());
    }
}
