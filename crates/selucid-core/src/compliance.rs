// SPDX-License-Identifier: GPL-3.0-or-later
//! CIS / Red Hat style SELinux hardening audit: read-only checks that surface
//! the configuration posture of the host (mode, policy type, permissive
//! domains, local policy customizations, pending relabel).
//!
//! Every check degrades to [`CheckStatus::Unknown`] when the backing tool or
//! file is unavailable — an audit never fabricates a pass. Nothing here
//! escalates privileges; `semanage -l` style queries run unprivileged and a
//! failing store access simply reports as unknown.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

/// Outcome of one hardening check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Configuration meets the recommendation.
    Pass,
    /// Not a hardening failure, but worth reviewing.
    Warn,
    /// Posture actively weakens SELinux containment.
    Fail,
    /// Tool or file unavailable; the check could not run.
    Unknown,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
            CheckStatus::Unknown => "unknown",
        }
    }
}

/// One audit result line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceCheck {
    /// Stable machine id, e.g. `enforcing_mode`.
    pub id: String,
    /// Human title, e.g. "SELinux mode is enforcing".
    pub title: String,
    pub status: CheckStatus,
    /// What was observed (or why the check could not run).
    pub detail: String,
    /// Benchmark-style reference for manual verification.
    pub reference: String,
}

/// The full hardening audit: every check plus a coarse summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub checks: Vec<ComplianceCheck>,
}

impl ComplianceReport {
    /// `pass/warn/fail/unknown` tally, e.g. `5 pass, 1 warn, 1 unknown`.
    pub fn summary(&self) -> String {
        let mut pass = 0;
        let mut warn = 0;
        let mut fail = 0;
        let mut unknown = 0;
        for c in &self.checks {
            match c.status {
                CheckStatus::Pass => pass += 1,
                CheckStatus::Warn => warn += 1,
                CheckStatus::Fail => fail += 1,
                CheckStatus::Unknown => unknown += 1,
            }
        }
        let mut parts = vec![format!("{pass} pass")];
        if warn > 0 {
            parts.push(format!("{warn} warn"));
        }
        if fail > 0 {
            parts.push(format!("{fail} fail"));
        }
        if unknown > 0 {
            parts.push(format!("{unknown} unknown"));
        }
        parts.join(", ")
    }

    /// True when nothing is worse than a warning and at least one check ran.
    pub fn is_clean(&self) -> bool {
        !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|c| matches!(c.status, CheckStatus::Pass | CheckStatus::Warn))
    }
}

/// Run the full hardening audit against the live system.
pub fn run_audit() -> ComplianceReport {
    ComplianceReport {
        checks: vec![
            check_enforcing(Path::new("/sys/fs/selinux/enforce")),
            check_configured_mode(Path::new("/etc/selinux/config")),
            check_policy_type(Path::new("/etc/selinux/config")),
            check_permissive_domains(),
            check_custom_modules(),
            check_customized_booleans(),
            check_autorelabel(Path::new("/.autorelabel")),
        ],
    }
}

/// Runtime SELinux mode from sysfs (`1` = enforcing).
fn check_enforcing(enforce_path: &Path) -> ComplianceCheck {
    let check = ComplianceCheck {
        id: "enforcing_mode".into(),
        title: "SELinux runs in enforcing mode".into(),
        reference: "CIS: Ensure the SELinux mode is enforcing (not disabled or permissive)".into(),
        status: CheckStatus::Unknown,
        detail: String::new(),
    };
    match std::fs::read_to_string(enforce_path) {
        Ok(text) => match text.trim() {
            "1" => ComplianceCheck {
                status: CheckStatus::Pass,
                detail: "Runtime mode: enforcing".into(),
                ..check
            },
            "0" => ComplianceCheck {
                status: CheckStatus::Fail,
                detail: "Runtime mode: permissive — denials are logged but not blocked".into(),
                ..check
            },
            other => ComplianceCheck {
                detail: format!("Unexpected sysfs value {other:?}"),
                ..check
            },
        },
        Err(e) => ComplianceCheck {
            detail: format!(
                "Cannot read {} ({e}); SELinux may not be active",
                enforce_path.display()
            ),
            ..check
        },
    }
}

/// `SELINUX=` from `/etc/selinux/config` — the persistent mode.
fn check_configured_mode(config_path: &Path) -> ComplianceCheck {
    let check = ComplianceCheck {
        id: "configured_mode".into(),
        title: "Persistent SELinux mode is enforcing".into(),
        reference: "CIS: Ensure the SELinux mode is enforced in the configuration".into(),
        status: CheckStatus::Unknown,
        detail: String::new(),
    };
    let Some(text) = read_config(config_path) else {
        return ComplianceCheck {
            detail: format!("{} missing or unreadable", config_path.display()),
            ..check
        };
    };
    match parse_config_field(&text, "SELINUX").as_deref() {
        Some("enforcing") => ComplianceCheck {
            status: CheckStatus::Pass,
            detail: "config: SELINUX=enforcing".into(),
            ..check
        },
        Some("permissive") => ComplianceCheck {
            status: CheckStatus::Warn,
            detail: "config: SELINUX=permissive".into(),
            ..check
        },
        Some(other) => ComplianceCheck {
            status: CheckStatus::Fail,
            detail: format!("config: SELINUX={other}"),
            ..check
        },
        None => ComplianceCheck {
            detail: "config has no SELINUX= entry".into(),
            ..check
        },
    }
}

/// `SELINUXTYPE=` — which policy is loaded (targeted/minimum/mls).
fn check_policy_type(config_path: &Path) -> ComplianceCheck {
    let check = ComplianceCheck {
        id: "policy_type".into(),
        title: "A policy type is configured".into(),
        reference: "CIS: Ensure the SELinux policy is configured (targeted, minimum, or mls)".into(),
        status: CheckStatus::Unknown,
        detail: String::new(),
    };
    let Some(text) = read_config(config_path) else {
        return ComplianceCheck {
            detail: format!("{} missing or unreadable", config_path.display()),
            ..check
        };
    };
    match parse_config_field(&text, "SELINUXTYPE") {
        Some(policy) if matches!(policy.as_str(), "targeted" | "minimum" | "mls") => {
            ComplianceCheck {
                status: CheckStatus::Pass,
                detail: format!("config: SELINUXTYPE={policy}"),
                ..check
            }
        }
        Some(other) => ComplianceCheck {
            status: CheckStatus::Warn,
            detail: format!("config: SELINUXTYPE={other} (unrecognized)"),
            ..check
        },
        None => ComplianceCheck {
            detail: "config has no SELINUXTYPE= entry".into(),
            ..check
        },
    }
}

/// Domains running permissively via `semanage permissive -l`.
fn check_permissive_domains() -> ComplianceCheck {
    let check = ComplianceCheck {
        id: "permissive_domains".into(),
        title: "No permissive domains".into(),
        reference: "CIS: Ensure no SELinux permissive domains are configured".into(),
        status: CheckStatus::Unknown,
        detail: String::new(),
    };
    let Some(lines) = semanage_list(&["permissive", "-l"]) else {
        return ComplianceCheck {
            detail: tool_unavailable_detail(),
            ..check
        };
    };
    let domains = parse_semanage_domains(&lines);
    if domains.is_empty() {
        ComplianceCheck {
            status: CheckStatus::Pass,
            detail: "semanage permissive -l reports no permissive domains".into(),
            ..check
        }
    } else {
        ComplianceCheck {
            status: CheckStatus::Fail,
            detail: format!(
                "{} permissive domain(s): {}",
                domains.len(),
                domains.join(", ")
            ),
            ..check
        }
    }
}

/// Locally installed policy modules via `semanage module -l -C`.
fn check_custom_modules() -> ComplianceCheck {
    let check = ComplianceCheck {
        id: "custom_modules".into(),
        title: "Local policy modules are known".into(),
        reference: "CIS/Red Hat: Review locally installed policy modules (semanage module -l -C)".into(),
        status: CheckStatus::Unknown,
        detail: String::new(),
    };
    let Some(lines) = semanage_list(&["module", "-l", "-C"]) else {
        return ComplianceCheck {
            detail: tool_unavailable_detail(),
            ..check
        };
    };
    let modules = parse_semanage_names(&lines);
    if modules.is_empty() {
        ComplianceCheck {
            status: CheckStatus::Pass,
            detail: "No local policy module customizations".into(),
            ..check
        }
    } else {
        ComplianceCheck {
            status: CheckStatus::Warn,
            detail: format!(
                "{} local module(s) — review with `semanage module -l -C`: {}",
                modules.len(),
                modules.join(", ")
            ),
            ..check
        }
    }
}

/// Customized booleans via `semanage boolean -l -C` (review item, not a fault).
fn check_customized_booleans() -> ComplianceCheck {
    let check = ComplianceCheck {
        id: "customized_booleans".into(),
        title: "Customized booleans are known".into(),
        reference: "CIS/Red Hat: Review customized SELinux booleans (semanage boolean -l -C)".into(),
        status: CheckStatus::Unknown,
        detail: String::new(),
    };
    let Some(lines) = semanage_list(&["boolean", "-l", "-C"]) else {
        return ComplianceCheck {
            detail: tool_unavailable_detail(),
            ..check
        };
    };
    let names = parse_semanage_names(&lines);
    if names.is_empty() {
        ComplianceCheck {
            status: CheckStatus::Pass,
            detail: "All booleans at distribution defaults".into(),
            ..check
        }
    } else {
        ComplianceCheck {
            status: CheckStatus::Warn,
            detail: format!(
                "{} customized boolean(s) — review with `semanage boolean -l -C`: {}",
                names.len(),
                names.join(", ")
            ),
            ..check
        }
    }
}

/// A pending full relabel (`/.autorelabel`) delays the next boot.
fn check_autorelabel(flag: &Path) -> ComplianceCheck {
    let check = ComplianceCheck {
        id: "pending_autorelabel".into(),
        title: "No pending filesystem relabel".into(),
        reference: "Red Hat: a /.autorelabel file forces a full relabel at next boot".into(),
        status: CheckStatus::Unknown,
        detail: String::new(),
    };
    match std::fs::exists(flag) {
        Ok(true) => ComplianceCheck {
            status: CheckStatus::Warn,
            detail: format!("{} exists — a full relabel runs at next boot", flag.display()),
            ..check
        },
        Ok(false) => ComplianceCheck {
            status: CheckStatus::Pass,
            detail: "No /.autorelabel flag present".into(),
            ..check
        },
        Err(e) => ComplianceCheck {
            detail: format!("Cannot stat {}: {e}", flag.display()),
            ..check
        },
    }
}

fn tool_unavailable_detail() -> String {
    "semanage unavailable or policy store not readable (unprivileged); run as root for this check"
        .into()
}

/// Run `semanage` unprivileged; `None` when missing, failing, or erroring
/// (e.g. "SELinux policy is not managed" store errors).
fn semanage_list(args: &[&str]) -> Option<Vec<String>> {
    let output = Command::new("semanage").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
    )
}

/// Extract `KEY=value` (uncommented) from `/etc/selinux/config` style text.
fn parse_config_field(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

fn read_config(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Domain names from `semanage permissive -l`: skip banner/blank lines; real
/// entries look like `foo_t               (uuid ...)` or a bare `foo_t`.
fn parse_semanage_domains(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| w.ends_with("_t") && !w.contains('=') && !w.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Names from `semanage <kind> -l -C` output, skipping headers and priority
/// numbers (`module -l` prefixes each row with its priority, e.g. `400`).
fn parse_semanage_names(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| {
            let mut cols = l.split_whitespace();
            let first = cols.next()?;
            if first.chars().all(|c| c.is_ascii_digit()) {
                cols.next().map(str::to_string)
            } else {
                Some(first.to_string())
            }
        })
        .filter(|w| w.contains('_') && !w.starts_with('#'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = "\
# comment
SELINUX=enforcing
SELINUXTYPE=targeted
";

    #[test]
    fn parses_config_fields() {
        assert_eq!(
            parse_config_field(SAMPLE_CONFIG, "SELINUX"),
            Some("enforcing".into())
        );
        assert_eq!(
            parse_config_field(SAMPLE_CONFIG, "SELINUXTYPE"),
            Some("targeted".into())
        );
        assert_eq!(parse_config_field(SAMPLE_CONFIG, "MISSING"), None);
        assert_eq!(
            parse_config_field("SELINUX=\"permissive\"", "SELINUX"),
            Some("permissive".into())
        );
    }

    #[test]
    fn enforcing_check_reads_sysfs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enforce");
        std::fs::write(&path, "1").unwrap();
        assert_eq!(check_enforcing(&path).status, CheckStatus::Pass);
        std::fs::write(&path, "0").unwrap();
        assert_eq!(check_enforcing(&path).status, CheckStatus::Fail);
        std::fs::write(&path, "bogus").unwrap();
        assert_eq!(check_enforcing(&path).status, CheckStatus::Unknown);
        assert_eq!(
            check_enforcing(dir.path().join("nope").as_path()).status,
            CheckStatus::Unknown
        );
    }

    #[test]
    fn mode_checks_classify_config_states() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, SAMPLE_CONFIG).unwrap();
        assert_eq!(check_configured_mode(&path).status, CheckStatus::Pass);
        assert_eq!(check_policy_type(&path).status, CheckStatus::Pass);

        std::fs::write(&path, "SELINUX=disabled\n").unwrap();
        assert_eq!(check_configured_mode(&path).status, CheckStatus::Fail);

        std::fs::write(&path, "SELINUX=permissive\n").unwrap();
        assert_eq!(check_configured_mode(&path).status, CheckStatus::Warn);
        assert_eq!(check_policy_type(&path).status, CheckStatus::Unknown);
    }

    #[test]
    fn parses_semanage_listings() {
        let permissive = vec![
            "Permissive Domains".to_string(),
            "insmod_t            (uuid 1234)".to_string(),
            String::new(),
            "mysqld_t            (uuid 5678)".to_string(),
        ];
        assert_eq!(
            parse_semanage_domains(&permissive),
            vec!["insmod_t", "mysqld_t"]
        );

        let modules = vec![
            "Priority   SELinux Module".to_string(),
            "400        selucid_fix".to_string(),
            "400        my_custom_te".to_string(),
        ];
        assert_eq!(
            parse_semanage_names(&modules),
            vec!["selucid_fix", "my_custom_te"]
        );

        let booleans = vec![
            "SELinux Boolean".to_string(),
            "httpd_can_network_connect (off,  off)  Determine whether".to_string(),
        ];
        assert_eq!(
            parse_semanage_names(&booleans),
            vec!["httpd_can_network_connect"]
        );
    }

    #[test]
    fn autorelabel_check_detects_flag() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_autorelabel(dir.path().join("none").as_path()).status,
            CheckStatus::Pass
        );
        let flag = dir.path().join(".autorelabel");
        std::fs::write(&flag, "").unwrap();
        assert_eq!(check_autorelabel(&flag).status, CheckStatus::Warn);
    }

    #[test]
    fn summary_and_clean_track_worst_status() {
        let report = ComplianceReport {
            checks: vec![
                check_autorelabel(Path::new("/definitely/not/here/autorelabel")),
                ComplianceCheck {
                    id: "x".into(),
                    title: "x".into(),
                    status: CheckStatus::Fail,
                    detail: String::new(),
                    reference: String::new(),
                },
            ],
        };
        assert_eq!(report.summary(), "1 pass, 1 fail");
        assert!(!report.is_clean());
    }

    #[test]
    fn live_audit_reports_coherent_results() {
        // On the real host every check resolves (possibly Unknown); the hard
        // requirements are unique ids and a non-empty detail for every status.
        let report = run_audit();
        let mut ids = report
            .checks
            .iter()
            .map(|c| c.id.clone())
            .collect::<Vec<_>>();
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n);
        assert!(report
            .checks
            .iter()
            .all(|c| !c.detail.is_empty() || c.status == CheckStatus::Unknown));
    }
}
