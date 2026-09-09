// SPDX-License-Identifier: GPL-3.0-or-later
//! Privileged execution: build reviewed commands, run them via `pkexec`.
//!
//! The frontends always show [`PrivilegedAction::preview`] first and only call
//! [`PrivilegedAction::execute`] after explicit user confirmation. Execution
//! uses direct argv (no shell) so paths containing spaces cannot inject flags.

use std::ffi::OsString;
use std::process::{Command, Output};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[error("pkexec is not installed")]
    NoPkexec,
    #[error("command failed with status {status}: {stderr}")]
    Failed { status: String, stderr: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A reviewed privileged operation: the binary plus its argv.
#[derive(Debug, Clone)]
pub struct PrivilegedAction {
    /// Polkit action id from `policy/org.selucid.policy`.
    pub action_id: &'static str,
    /// Command shown to the user and executed under `pkexec`.
    pub argv: Vec<OsString>,
}

impl PrivilegedAction {
    pub fn new(action_id: &'static str, argv: Vec<OsString>) -> Self {
        Self { action_id, argv }
    }

    /// Shell-quoted preview for display. Quoting is display-only; execution
    /// passes argv directly without a shell.
    pub fn preview(&self) -> String {
        self.argv
            .iter()
            .map(|a| shell_quote(&a.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Run `pkexec <argv>`. Returns stdout on success.
    pub fn execute(&self) -> Result<String, PrivilegeError> {
        let pkexec = which_pkexec().ok_or(PrivilegeError::NoPkexec)?;
        let [program, args @ ..] = self.argv.as_slice() else {
            return Err(PrivilegeError::Failed {
                status: "empty argv".into(),
                stderr: String::new(),
            });
        };
        let output: Output = Command::new(pkexec).arg(program).args(args).output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(PrivilegeError::Failed {
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }

    /// Execute and journal the attempt: captures the observable before/after
    /// state and appends a [`crate::history::HistoryEntry`] no matter how the
    /// command ends. Journaling failures stay non-fatal (best-effort audit).
    pub fn execute_journaled(&self) -> Result<(String, crate::history::HistoryEntry), PrivilegeError> {
        let argv: Vec<String> = self
            .argv
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        let before = crate::history::capture_before(self.action_id, &argv);
        match self.execute() {
            Ok(out) => {
                let after = crate::history::capture_after(self.action_id, &argv);
                let entry = crate::history::new_entry(
                    self.action_id,
                    &argv,
                    before,
                    after,
                    true,
                    excerpt_of(&out),
                );
                let _ = crate::history::record(&entry);
                Ok((out, entry))
            }
            Err(e) => {
                let entry = crate::history::new_entry(
                    self.action_id,
                    &argv,
                    before,
                    None,
                    false,
                    None,
                );
                let _ = crate::history::record(&entry);
                Err(e)
            }
        }
    }
}

/// First ~200 chars of a command's stdout, trimmed, for the journal.
fn excerpt_of(output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.len() > 200 {
        Some(format!("{}…", &trimmed[..200]))
    } else {
        Some(trimmed.to_string())
    }
}

pub fn restorecon_action(path: &str) -> PrivilegedAction {
    PrivilegedAction::new(
        "org.selucid.restorecon",
        vec!["restorecon".into(), "-v".into(), OsString::from(path)],
    )
}

pub fn setsebool_action(boolean: &str, on: bool) -> PrivilegedAction {
    PrivilegedAction::new(
        "org.selucid.setboolean",
        vec![
            "setsebool".into(),
            "-P".into(),
            OsString::from(boolean),
            OsString::from(if on { "1" } else { "0" }),
        ],
    )
}

fn which_pkexec() -> Option<&'static str> {
    ["/usr/bin/pkexec", "/bin/pkexec"]
        .into_iter()
        .find(|candidate| std::path::Path::new(candidate).exists())
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '='))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Resolve the expected context for a path via `matchpathcon` (unprivileged).
pub fn expected_context(path: &str) -> Option<String> {
    let output = Command::new("matchpathcon")
        .arg("-n")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_quotes_paths_with_spaces() {
        let a = restorecon_action("/srv/my data/file.pdf");
        assert_eq!(a.preview(), "restorecon -v '/srv/my data/file.pdf'");
        assert_eq!(a.argv.len(), 3); // no shell splitting at execution
    }

    #[test]
    fn setsebool_argv_is_exact() {
        let a = setsebool_action("httpd_can_network_connect", true);
        let argv: Vec<String> = a
            .argv
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec!["setsebool", "-P", "httpd_can_network_connect", "1"]
        );
    }

    #[test]
    fn live_matchpathcon_resolves_web_root() {
        if let Some(ctx) = expected_context("/var/www/html/index.html") {
            assert!(ctx.contains("httpd_sys_content_t"), "got {ctx}");
        }
    }
}
