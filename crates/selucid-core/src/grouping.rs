// SPDX-License-Identifier: GPL-3.0-or-later
//! Grouping: merge multi-line audit events that share an `audit(ts:serial)`
//! id, then lift AVC records into enriched [`AvcEvent`]s.

use crate::avc::{AuditRecord, AvcEvent};
use std::collections::BTreeMap;

/// Group records by `audit_id`, preserving first-seen order of the ids.
pub fn group_by_serial(records: Vec<AuditRecord>) -> Vec<Vec<AuditRecord>> {
    let mut order: Vec<String> = Vec::new();
    let mut map: BTreeMap<String, Vec<AuditRecord>> = BTreeMap::new();
    for rec in records {
        map.entry(rec.audit_id.clone())
            .or_insert_with(|| {
                order.push(rec.audit_id.clone());
                Vec::new()
            })
            .push(rec);
    }
    // BTreeMap is sorted; re-emit in first-seen order via the order vec.
    let mut out = Vec::with_capacity(order.len());
    for id in order {
        if let Some(group) = map.remove(&id) {
            out.push(group);
        }
    }
    out
}

/// Build one [`AvcEvent`] per group that contains an `AVC` record.
///
/// Sibling `SYSCALL` records contribute `pid`/`comm`/`exe`; sibling `PATH`
/// records contribute the full `name` and object context when the AVC line
/// itself lacks a `path`.
pub fn extract_avc_events(groups: &[Vec<AuditRecord>]) -> Vec<AvcEvent> {
    let mut events = Vec::new();
    for group in groups {
        let Some(avc) = group.iter().find(|r| r.record_type == "AVC") else {
            continue;
        };
        let syscall = group.iter().find(|r| r.record_type == "SYSCALL");
        let path_rec = group.iter().find(|r| r.record_type == "PATH");
        events.push(enrich(avc, syscall, path_rec));
    }
    // Oldest first.
    events.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());
    events
}

fn field<'a>(
    primary: &'a AuditRecord,
    fallback: Option<&'a AuditRecord>,
    key: &str,
) -> Option<String> {
    primary
        .fields
        .get(key)
        .cloned()
        .or_else(|| fallback.and_then(|r| r.fields.get(key).cloned()))
}

fn enrich(
    avc: &AuditRecord,
    syscall: Option<&AuditRecord>,
    path_rec: Option<&AuditRecord>,
) -> AvcEvent {
    let f = &avc.fields;
    let perms: Vec<String> = f
        .get("avc_perms")
        .map(|s| s.split(',').map(|p| p.to_string()).collect())
        .unwrap_or_default();
    let path = f
        .get("path")
        .cloned()
        .or_else(|| f.get("name").cloned())
        .or_else(|| {
            path_rec.and_then(|p| {
                // PATH `name` may be `(null)` for anonymous sockets; ignore those.
                p.fields.get("name").filter(|n| *n != "(null)").cloned()
            })
        });
    let comm = field(avc, syscall, "comm");
    let pid: Option<u32> = field(avc, syscall, "pid").and_then(|p| p.parse().ok());
    let exe = syscall.and_then(|s| s.fields.get("exe").cloned());
    let dest_port: Option<u16> = f.get("dest").and_then(|d| d.parse().ok());

    AvcEvent {
        audit_id: avc.audit_id.clone(),
        timestamp: avc.timestamp,
        serial: avc.serial,
        result: f.get("avc_result").cloned().unwrap_or_default(),
        perms,
        scontext: f.get("scontext").cloned().unwrap_or_default(),
        tcontext: f
            .get("tcontext")
            .cloned()
            .or_else(|| {
                path_rec.and_then(|p| p.fields.get("obj").filter(|o| *o != "(null)").cloned())
            })
            .unwrap_or_default(),
        tclass: f.get("tclass").cloned().unwrap_or_default(),
        pid,
        comm,
        exe,
        path,
        dest_port,
        dev: f.get("dev").cloned(),
        ino: f.get("ino").cloned(),
        raw: avc.raw.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_audit_line;

    fn sample_group() -> Vec<AuditRecord> {
        [
            r#"type=AVC msg=audit(1788956400.123:456): avc: denied { open } for pid=1234 comm="httpd" path="/var/www/html/index.html" dev="dm-0" ino=123456 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0"#,
            r#"type=SYSCALL msg=audit(1788956400.123:456): arch=c000003e syscall=2 success=no exit=-13 pid=1234 comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0"#,
            r#"type=PATH msg=audit(1788956400.123:456): item=0 name="/var/www/html/index.html" inode=123456 dev=fd:00 mode=0100644 obj=unconfined_u:object_r:user_home_t:s0 nametype=NORMAL"#,
        ]
        .iter()
        .map(|l| parse_audit_line(l).unwrap())
        .collect()
    }

    #[test]
    fn groups_and_enriches() {
        let groups = group_by_serial(sample_group());
        assert_eq!(groups.len(), 1);
        let events = extract_avc_events(&groups);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.perms, vec!["open"]);
        assert_eq!(e.exe.as_deref(), Some("/usr/sbin/httpd"));
        assert_eq!(e.path.as_deref(), Some("/var/www/html/index.html"));
        assert_eq!(e.pid, Some(1234));
    }

    #[test]
    fn skips_groups_without_avc() {
        let rec = parse_audit_line(
            r#"type=SYSCALL msg=audit(1788956400.123:999): arch=c000003e syscall=2 success=yes pid=1 comm="init" exe="/usr/lib/systemd/systemd""#,
        )
        .unwrap();
        assert!(extract_avc_events(&group_by_serial(vec![rec])).is_empty());
    }
}
