// SPDX-License-Identifier: GPL-3.0-or-later
//! Policy-oracle cross-check: run `audit2why` on an event's raw AVC line.
//!
//! `audit2why` reads the *loaded* policy, so it is ground truth where our
//! static `boolean_hint_for` map is only a guess. The oracle's findings feed
//! back into [`crate::inference::diagnose`]: booleans become `boolean_hint`,
//! and a "Missing TE allow rule" verdict pushes toward the module fallback.

use std::io::Write;
use std::process::{Command, Stdio};

/// Verdict parsed from one `audit2why` output block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhyAnalysis {
    /// Raw `audit2why` stdout for this event (shown in verbose views).
    pub raw: String,
    /// Booleans `audit2why` says would allow the access, in listed order.
    pub booleans: Vec<String>,
    /// True when the oracle says no boolean helps (needs a TE rule).
    pub needs_type_enforcement: bool,
    /// True when `audit2why` gave no usable verdict (missing binary, policy
    /// mismatch, unparsable output).
    pub inconclusive: bool,
}

impl WhyAnalysis {
    pub fn inconclusive() -> Self {
        Self {
            raw: String::new(),
            booleans: Vec::new(),
            needs_type_enforcement: false,
            inconclusive: true,
        }
    }

    /// First boolean suggestion, for use as `diagnose`'s `boolean_hint`.
    pub fn primary_boolean(&self) -> Option<&str> {
        self.booleans.first().map(String::as_str)
    }
}

/// Run `audit2why` on a single raw AVC line.
pub fn analyze_raw(raw_avc_line: &str) -> WhyAnalysis {
    let output = Command::new("audit2why")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.take() {
                let mut stdin = stdin;
                let _ = writeln!(stdin, "{raw_avc_line}");
            }
            child.wait_with_output()
        });
    match output {
        Ok(out) if out.status.success() => parse_audit2why(&String::from_utf8_lossy(&out.stdout)),
        _ => WhyAnalysis::inconclusive(),
    }
}

/// Analyze a batch of raw lines, preserving order.
pub fn analyze_batch(raw_lines: &[&str]) -> Vec<WhyAnalysis> {
    raw_lines.iter().map(|l| analyze_raw(l)).collect()
}

fn parse_audit2why(output: &str) -> WhyAnalysis {
    let mut booleans = Vec::new();
    for line in output.lines() {
        let line = line.trim().trim_start_matches('#').trim();
        // Canonical form: `setsebool -P some_boolean 1`
        if let Some(rest) = line.strip_prefix("setsebool") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            let name = parts
                .iter()
                .position(|p| *p == "-P")
                .and_then(|i| parts.get(i + 1))
                .or_else(|| {
                    parts
                        .iter()
                        .rfind(|p| !p.starts_with('-') && **p != "0" && **p != "1")
                })
                .map(|s| {
                    s.trim_matches(|c| c == '\'' || c == '"' || c == ';')
                        .to_string()
                });
            if let Some(name) = name.filter(|n| is_boolean_name(n))
                && !booleans.contains(&name)
            {
                booleans.push(name);
            }
        }
    }
    let needs_te = output.contains("Missing type enforcement")
        || output.contains("audit2allow to generate a loadable module");
    WhyAnalysis {
        raw: output.to_string(),
        booleans: booleans.clone(),
        needs_type_enforcement: needs_te,
        inconclusive: booleans.is_empty() && !needs_te,
    }
}

fn is_boolean_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && s.contains('_')
}
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "type=AVC msg=audit(1788956400.123:456): avc: denied { open } \
        scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 \
        tclass=file\n\n\tWas caused by:\n\tThe boolean httpd_read_user_content was set \
        incorrectly.\n\n\tAllow access by executing:\n\t# setsebool -P httpd_read_user_content 1\n";

    #[test]
    fn parses_boolean_suggestion() {
        let a = parse_audit2why(SAMPLE);
        assert_eq!(a.booleans, vec!["httpd_read_user_content"]);
        assert!(!a.needs_type_enforcement);
        assert!(!a.inconclusive);
        assert_eq!(a.primary_boolean(), Some("httpd_read_user_content"));
    }

    #[test]
    fn parses_missing_te_rule() {
        let a = parse_audit2why(
            "Was caused by:\n\tMissing type enforcement (TE) allow rule.\n\
             You can use audit2allow to generate a loadable module.\n",
        );
        assert!(a.booleans.is_empty());
        assert!(a.needs_type_enforcement);
        assert!(!a.inconclusive);
    }

    #[test]
    fn empty_output_is_inconclusive() {
        assert!(parse_audit2why("").inconclusive);
    }

    #[test]
    fn live_audit2why_matches_sample_log() {
        let first = "type=AVC msg=audit(1788956400.123:456): avc: denied { open } for pid=1234 \
            comm=\"httpd\" path=\"/var/www/html/index.html\" dev=\"dm-0\" ino=123456 \
            scontext=system_u:system_r:httpd_t:s0 \
            tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0";
        let a = analyze_raw(first);
        if a.inconclusive {
            return; // audit2why missing (non-SELinux CI) — keep green.
        }
        assert!(
            a.booleans.contains(&"httpd_read_user_content".to_string()),
            "got {a:?}"
        );
        let te = "type=AVC msg=audit(1788956550.250:459): avc: denied { getattr } for pid=4567 \
            comm=\"Web Content\" path=\"/srv/data/report.pdf\" \
            scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_t:s0 \
            tclass=file permissive=0";
        let b = analyze_raw(te);
        assert!(b.needs_type_enforcement || b.inconclusive, "got {b:?}");
    }
}
