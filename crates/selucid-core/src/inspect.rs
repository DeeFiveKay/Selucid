// SPDX-License-Identifier: GPL-3.0-or-later
//! Proactive directory inspection: walk a tree, compare each file's actual
//! SELinux label with the policy default (`matchpathcon`), and report
//! mismatches before an application ever trips over them in production.
//!
//! Reads stay unprivileged: expected contexts come from `matchpathcon -n`,
//! actual labels from the `security.selinux` extended attribute via
//! `getfattr`. Both degrade to "unknown" when the tooling is absent.

use crate::avc::SelinuxContext;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Why a path's label does not match the default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchKind {
    /// Label is `default_t`/`unlabeled_t` — content is effectively unlabeled.
    Unlabeled,
    /// Actual type differs from the `matchpathcon` default.
    WrongLabel,
    /// Label is fine but the policy has no default for this path.
    Unmanaged,
}

impl std::fmt::Display for MismatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MismatchKind::Unlabeled => write!(f, "unlabeled"),
            MismatchKind::WrongLabel => write!(f, "wrong label"),
            MismatchKind::Unmanaged => write!(f, "no default context"),
        }
    }
}

/// One file with a context problem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextMismatch {
    pub path: String,
    /// Current label as seen via `getfattr` (may be `None` when unknown).
    pub actual: Option<String>,
    /// Policy default via `matchpathcon` (may be `None` when unknown).
    pub expected: Option<String>,
    pub kind: MismatchKind,
}

/// Result of scanning one directory tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InspectionReport {
    pub root: String,
    /// Number of paths whose labels could be compared.
    pub scanned: u32,
    /// Paths where no label could be read at all.
    pub unreadable: u32,
    /// Paths that disagree with the default policy.
    pub mismatches: Vec<ContextMismatch>,
}

/// Default traversal limits for [`inspect_directory`].
pub const DEFAULT_MAX_DEPTH: u32 = 6;
pub const DEFAULT_MAX_ENTRIES: u32 = 2000;

/// Read the current SELinux label of a path (unprivileged). Returns `None`
/// when `getfattr` is missing or the label cannot be read.
pub fn actual_context(path: &str) -> Option<String> {
    let output = Command::new("getfattr")
        .arg("-n")
        .arg("security.selinux")
        .arg("--only-values")
        .arg("--absolute-names")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Pure classification of one `(actual, expected)` pair. Returns `None` when
/// the file is correctly labeled (or the actual label is unreadable).
pub fn compare_context(actual: Option<&str>, expected: Option<&str>) -> Option<MismatchKind> {
    let actual_ctx = actual?;
    let atype = SelinuxContext::parse(actual_ctx).map(|c| c.kind).unwrap_or_default();
    if atype == "default_t" || atype == "unlabeled_t" {
        return Some(MismatchKind::Unlabeled);
    }
    if let Some(exp) = expected {
        let etype = SelinuxContext::parse(exp).map(|c| c.kind).unwrap_or_default();
        if !etype.is_empty() && etype != atype {
            return Some(MismatchKind::WrongLabel);
        }
    }
    if expected.is_none() {
        return Some(MismatchKind::Unmanaged);
    }
    None
}

/// Walk a directory tree, comparing every file's label against the policy.
/// Same as [`inspect_directory`] but with explicit traversal limits.
pub fn inspect_directory_with(root: &str, max_depth: u32, max_entries: u32) -> InspectionReport {
    let mut report = InspectionReport {
        root: root.to_string(),
        scanned: 0,
        unreadable: 0,
        mismatches: Vec::new(),
    };
    for path in walk_files(Path::new(root), max_depth, max_entries) {
        let path_str = path.display().to_string();
        let Some(actual) = actual_context(&path_str) else {
            report.unreadable += 1;
            continue;
        };
        report.scanned += 1;
        let expected = crate::privileged::expected_context(&path_str);
        if let Some(kind) = compare_context(Some(actual.as_str()), expected.as_deref()) {
            report.mismatches.push(ContextMismatch {
                path: path_str,
                actual: Some(actual),
                expected,
                kind,
            });
        }
    }
    report
}

/// Walk a directory tree with default limits ([`DEFAULT_MAX_DEPTH`] /
/// [`DEFAULT_MAX_ENTRIES`]).
pub fn inspect_directory(root: &str) -> InspectionReport {
    inspect_directory_with(root, DEFAULT_MAX_DEPTH, DEFAULT_MAX_ENTRIES)
}

/// Breadth-ish walker bounded by `max_depth` and `max_entries`. Directories
/// are detected by successful `read_dir` (no metadata dependency).
fn walk_files(root: &Path, max_depth: u32, max_entries: u32) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let cap = max_entries as usize;
    let mut stack: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
    while !stack.is_empty() {
        let Some((dir, depth)) = stack.pop() else {
            break;
        };
        if out.len() >= cap {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if out.len() >= cap {
                break;
            }
            let path = entry.path();
            out.push(path.clone());
            // Directories keep the traversal going (bounded by max_depth).
            if depth < max_depth && std::fs::read_dir(&path).is_ok() {
                stack.push((path.clone(), depth + 1));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_contexts_purely() {
        // Correctly labeled -> None (not a mismatch).
        assert!(
            compare_context(
                Some("system_u:object_r:httpd_sys_content_t:s0"),
                Some("system_u:object_r:httpd_sys_content_t:s0"),
            )
            .is_none()
        );
        // WrongLabel: actual differs from the default.
        assert_eq!(
            compare_context(
                Some("unconfined_u:object_r:user_home_t:s0"),
                Some("system_u:object_r:httpd_sys_content_t:s0"),
            ),
            Some(MismatchKind::WrongLabel),
        );
        // Unlabeled content.
        assert_eq!(
            compare_context(Some("system_u:object_r:default_t:s0"), None),
            Some(MismatchKind::Unlabeled),
        );
        // Unknown actual -> no verdict.
        assert!(compare_context(None, None).is_none());
        // Labeled but policy has no default -> Unmanaged.
        assert_eq!(
            compare_context(Some("system_u:object_r:app_rand_t:s0"), None),
            Some(MismatchKind::Unmanaged),
        );
    }

    #[test]
    fn walk_visits_tree_bounded_by_depth() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("f1"), "x").unwrap();
        std::fs::write(root.join("a").join("deep.txt"), "y").unwrap();
        // depth 2 finds the nested file too
        let deep = walk_files(root.as_ref(), 2, 100);
        assert!(
            deep.iter().any(|p| p.file_name().filter(|n| *n == "deep.txt").is_some()),
            "nested file missing: {deep:?}",
        );
        // cap limits the count
        let capped = walk_files(root.as_ref(), 10, 2);
        assert!(capped.len() <= 2);
    }

    #[test]
    fn inspecting_nonexistent_dir_is_empty() {
        let r = inspect_directory("/nonexistent/selucid-test-dir");
        assert_eq!(r.scanned, 0);
        assert!(r.mismatches.is_empty());
    }
}
