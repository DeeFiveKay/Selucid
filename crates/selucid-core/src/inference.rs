// SPDX-License-Identifier: GPL-3.0-or-later
//! Inference: turn an [`AvcEvent`] into a human explanation plus an ordered
//! list of [`SuggestedFix`]es.
//!
//! Fix ordering encodes the safe-first doctrine: relabel what is mislabeled
//! (`restorecon`), make the label permanent (`semanage fcontext`), flip a
//! purpose-built boolean (`setsebool -P`), and only then compile a local
//! policy module (`audit2allow`).

use crate::avc::{AvcEvent, SelinuxContext};
use serde::{Deserialize, Serialize};

/// Fix strategy, in the order it should be tried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FixKind {
    Restorecon,
    SemanageFcontext,
    SetBoolean,
    PolicyModule,
}

/// One concrete remediation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedFix {
    pub kind: FixKind,
    /// Short label for buttons/menus, e.g. `Restore file context`.
    pub title: String,
    /// Exact shell command (argv-joined) the privileged helper would run.
    pub command: String,
    /// Why this fix helps, in one or two sentences.
    pub description: String,
    /// True when the fix needs root/Polkit.
    pub needs_root: bool,
}

/// How much we trust the diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// A full diagnosis: what happened, in plain language, plus fixes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    pub summary: String,
    pub explanation: String,
    pub confidence: Confidence,
    pub fixes: Vec<SuggestedFix>,
}

/// Diagnose a denial.
///
/// `expected_tcontext` is the `matchpathcon` result for the target path when
/// known. `boolean_hint` names a boolean (e.g. `httpd_can_network_connect`)
/// when the denial vector matches a known boolean-gated access.
pub fn diagnose(
    event: &AvcEvent,
    expected_tcontext: Option<&str>,
    boolean_hint: Option<&str>,
) -> Diagnosis {
    diagnose_with_oracle(event, expected_tcontext, boolean_hint, None)
}

/// Diagnose with an optional [`crate::analysis::WhyAnalysis`] oracle result.
///
/// When the oracle names booleans they take precedence over the static hint
/// map; when it reports a missing TE rule (and no booleans), the diagnosis
/// skips straight to the module fallback regardless of heuristics.
pub fn diagnose_with_oracle(
    event: &AvcEvent,
    expected_tcontext: Option<&str>,
    boolean_hint: Option<&str>,
    oracle: Option<&crate::analysis::WhyAnalysis>,
) -> Diagnosis {
    let perms = event.perms.join(", ");
    let who = event.comm.clone().unwrap_or_else(|| "?".to_string());
    let stype = event.source_type().unwrap_or_else(|| "?".to_string());
    let ttype = event.target_type().unwrap_or_else(|| "?".to_string());

    let summary = format!(
        "{} ({}), running as {}, was denied {} on {} ({}:{})",
        who,
        event
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".into()),
        stype,
        if perms.is_empty() {
            "access".into()
        } else {
            perms
        },
        event.path.clone().unwrap_or_else(|| event.tclass.clone()),
        event.tclass,
        ttype,
    );

    let mut explanation = format!(
        "Process \"{who}\" in domain {stype} tried to access a {} labeled \
         {ttype}, and the loaded policy does not allow that combination. \
         SELinux stayed enforcing — nothing was permitted, so do not disable \
         SELinux; apply the narrowest fix below instead.",
        event.tclass,
    );

    let context_mismatch = match (expected_tcontext, event.path.as_ref()) {
        (Some(expected), Some(_)) => {
            let expected_type = SelinuxContext::parse(expected)
                .map(|c| c.kind)
                .unwrap_or_default();
            !expected_type.is_empty() && Some(expected_type) != event.target_type()
        }
        _ => looks_like_mislabeled_home_content(event) || looks_like_default_label(event),
    };

    if context_mismatch {
        explanation.push_str(
            " The target label looks like a file-context \
            mismatch (for example content created under a home directory and \
            moved into a web root), which `restorecon` can repair.",
        );
    }

    let mut fixes = Vec::new();
    let confidence;

    // Oracle verdict: missing TE rule with no boolean candidates means the
    // heuristics below cannot help — go straight to the module fallback.
    let oracle_forces_module = oracle
        .map(|o| !o.inconclusive && o.booleans.is_empty() && o.needs_type_enforcement)
        .unwrap_or(false);
    // Oracle booleans outrank the static map and the caller-supplied hint.
    let oracle_boolean = oracle.and_then(|o| o.primary_boolean());
    let hint = oracle_boolean.or(boolean_hint);

    if oracle_forces_module {
        confidence = Confidence::Low;
        explanation.push_str(
            " The system policy oracle (audit2why) confirms no boolean covers \
             this access — it requires a new type-enforcement rule.",
        );
        fixes.push(module_fix(event));
    } else if event.tclass == "tcp_socket" || event.tclass == "udp_socket" {
        confidence = Confidence::High;
        if let Some(boolean) = hint.or_else(|| boolean_hint_for(event)) {
            fixes.push(boolean_fix(&stype, &event.tclass, boolean));
        }
        fixes.push(module_fix(event));
    } else if context_mismatch {
        confidence = Confidence::High;
        if event.path.is_some() {
            fixes.push(restorecon_fix(event));
            fixes.push(semanage_fix(event, expected_tcontext));
        }
        if let Some(boolean) = hint.or_else(|| boolean_hint_for(event)) {
            fixes.push(SuggestedFix {
                kind: FixKind::SetBoolean,
                title: format!("Allow via boolean {boolean}"),
                command: format!("setsebool -P {boolean} 1"),
                description: "Alternatively, this access may be intentionally \
                    gated by a boolean for your workload. Check \
                    `semanage boolean -l` first."
                    .to_string(),
                needs_root: true,
            });
        }
        fixes.push(module_fix(event));
    } else if let Some(boolean) = hint.or_else(|| boolean_hint_for(event)) {
        confidence = Confidence::Medium;
        fixes.push(boolean_fix(&stype, &event.tclass, boolean));
        fixes.push(module_fix(event));
    } else {
        confidence = Confidence::Low;
        fixes.push(module_fix(event));
    }

    Diagnosis {
        summary,
        explanation,
        confidence,
        fixes,
    }
}

fn restorecon_fix(event: &AvcEvent) -> SuggestedFix {
    let path = event.path.clone().unwrap_or_default();
    SuggestedFix {
        kind: FixKind::Restorecon,
        title: "Restore file context".to_string(),
        command: format!("restorecon -v {path}"),
        description: "Resets the file label to the policy default. Safe and \
            immediate; fixes moved or miscreated content."
            .to_string(),
        needs_root: true,
    }
}
fn semanage_fix(event: &AvcEvent, expected: Option<&str>) -> SuggestedFix {
    let ttype = expected
        .and_then(SelinuxContext::parse)
        .map(|c| c.kind)
        .or_else(|| event.target_type())
        .unwrap_or_else(|| "var_t".to_string());
    let command = match event.path.clone() {
        Some(path) => format!("semanage fcontext -a -t {ttype} \"{path}\" && restorecon -v {path}"),
        None => format!("semanage fcontext -l | grep {ttype}"),
    };
    SuggestedFix {
        kind: FixKind::SemanageFcontext,
        title: "Make the label permanent".to_string(),
        command,
        description: "Adds a file-context mapping so future files and \
            relabels keep the right type."
            .to_string(),
        needs_root: true,
    }
}

fn boolean_fix(stype: &str, tclass: &str, boolean: &str) -> SuggestedFix {
    SuggestedFix {
        kind: FixKind::SetBoolean,
        title: format!("Allow via boolean {boolean}"),
        command: format!("setsebool -P {boolean} 1"),
        description: format!(
            "This access ({stype} → {tclass}) is gated by the {boolean} \
             boolean. Enabling it persistently (-P) keeps the rest of the \
             policy intact; verify with `semanage boolean -l` first."
        ),
        needs_root: true,
    }
}

fn module_fix(event: &AvcEvent) -> SuggestedFix {
    let serial = event.serial;
    SuggestedFix {
        kind: FixKind::PolicyModule,
        title: "Generate local policy module".to_string(),
        command: format!(
            "ausearch -m avc -ts recent 2>/dev/null | audit2allow -M selucid_{serial} && semodule -i selucid_{serial}.pp"
        ),
        description: "Last resort: compile the denial into a custom module. \
            Review the generated .te file before installing — it grants exactly \
            what was denied and nothing else."
            .to_string(),
        needs_root: true,
    }
}

/// Home content (`user_home_t`) leaking into confined domains is the classic
/// mislabel: `cp ~/x /var/www/html/` preserves the home label.
fn looks_like_mislabeled_home_content(event: &AvcEvent) -> bool {
    let target = event.target_type().unwrap_or_default();
    let path = event.path.clone().unwrap_or_default();
    (target == "user_home_t" || target == "admin_home_t")
        && (path.starts_with("/var/www")
            || path.starts_with("/srv")
            || path.starts_with("/var/lib"))
}

/// Freshly created files under a generic parent inherit `default_t`.
fn looks_like_default_label(event: &AvcEvent) -> bool {
    matches!(
        event.target_type().unwrap_or_default().as_str(),
        "default_t" | "unlabeled_t"
    )
}

/// Static hint map for the most common boolean-gated denials.
pub fn boolean_hint_for(event: &AvcEvent) -> Option<&'static str> {
    let stype = event.source_type()?;
    let target = event.target_type();
    if stype == "httpd_t" && (event.tclass == "tcp_socket" || event.tclass == "udp_socket") {
        return Some("httpd_can_network_connect");
    }
    if stype == "httpd_t" && target.as_deref() == Some("cifs_t") {
        return Some("httpd_use_cifs");
    }
    if stype == "httpd_t" && target.as_deref() == Some("nfs_t") {
        return Some("httpd_use_nfs");
    }
    if stype == "smbd_t" {
        return Some("samba_export_all_ro");
    }
    if stype == "ftpd_t" {
        return Some("ftpd_full_access");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn httpd_home() -> AvcEvent {
        AvcEvent {
            audit_id: "1788956400.123:456".into(),
            timestamp: 1788956400.123,
            serial: 456,
            result: "denied".into(),
            perms: vec!["open".into()],
            scontext: "system_u:system_r:httpd_t:s0".into(),
            tcontext: "unconfined_u:object_r:user_home_t:s0".into(),
            tclass: "file".into(),
            pid: Some(1234),
            comm: Some("httpd".into()),
            exe: Some("/usr/sbin/httpd".into()),
            path: Some("/var/www/html/index.html".into()),
            dest_port: None,
            dev: Some("dm-0".into()),
            ino: Some("123456".into()),
            raw: String::new(),
        }
    }

    #[test]
    fn file_mismatch_suggests_restorecon_first() {
        let d = diagnose(
            &httpd_home(),
            Some("system_u:object_r:httpd_sys_content_t:s0"),
            None,
        );
        assert_eq!(d.confidence, Confidence::High);
        assert_eq!(d.fixes[0].kind, FixKind::Restorecon);
        assert!(
            d.fixes[0]
                .command
                .contains("restorecon -v /var/www/html/index.html")
        );
        assert!(d.fixes.iter().any(|f| f.kind == FixKind::SemanageFcontext));
    }

    #[test]
    fn socket_denial_suggests_boolean() {
        let mut e = httpd_home();
        e.tclass = "tcp_socket".into();
        e.perms = vec!["name_connect".into()];
        e.path = None;
        let d = diagnose(&e, None, None);
        assert_eq!(d.fixes[0].kind, FixKind::SetBoolean);
        assert!(d.fixes[0].command.contains("httpd_can_network_connect"));
    }

    #[test]
    fn oracle_boolean_outranks_static_hint() {
        use crate::analysis::WhyAnalysis;
        let mut e = httpd_home();
        e.tclass = "tcp_socket".into();
        e.perms = vec!["name_connect".into()];
        e.path = None;
        let oracle = WhyAnalysis {
            raw: String::new(),
            booleans: vec!["httpd_can_network_relay".into()],
            needs_type_enforcement: false,
            inconclusive: false,
        };
        let d = diagnose_with_oracle(&e, None, Some("ignored_hint"), Some(&oracle));
        assert_eq!(d.fixes[0].kind, FixKind::SetBoolean);
        assert!(d.fixes[0].command.contains("httpd_can_network_relay"));
    }

    #[test]
    fn oracle_missing_te_forces_module_fallback() {
        use crate::analysis::WhyAnalysis;
        // Even a textbook mislabel bows to the oracle: if the loaded policy
        // has no boolean for it, only a module helps.
        let oracle = WhyAnalysis {
            raw: String::new(),
            booleans: Vec::new(),
            needs_type_enforcement: true,
            inconclusive: false,
        };
        let d = diagnose_with_oracle(
            &httpd_home(),
            Some("system_u:object_r:httpd_sys_content_t:s0"),
            None,
            Some(&oracle),
        );
        assert_eq!(d.fixes.len(), 1);
        assert_eq!(d.fixes[0].kind, FixKind::PolicyModule);
        assert!(d.explanation.contains("audit2why"));
    }

    #[test]
    fn unknown_denial_falls_back_to_module() {
        let mut e = httpd_home();
        e.scontext = "system_u:system_r:odd_t:s0".into();
        e.tcontext = "system_u:object_r:odd2_t:s0".into();
        e.path = Some("/opt/odd/file".into());
        let d = diagnose(&e, Some("system_u:object_r:odd2_t:s0"), None);
        assert!(d.fixes.iter().any(|f| f.kind == FixKind::PolicyModule));
    }
}
