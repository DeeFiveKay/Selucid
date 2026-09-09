// SPDX-License-Identifier: GPL-3.0-or-later
//! Core event types: raw audit records, parsed AVC denials, SELinux contexts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single `type=... msg=audit(ts:serial): ...` audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Record type, e.g. `AVC`, `SYSCALL`, `PATH` (uppercased).
    pub record_type: String,
    /// Full `timestamp:serial` identifier, e.g. `1788956400.123:456`.
    pub audit_id: String,
    /// Seconds-since-epoch portion of the audit id.
    pub timestamp: f64,
    /// Serial portion of the audit id.
    pub serial: u64,
    /// Parsed `key=value` fields of the record body.
    pub fields: HashMap<String, String>,
    /// Original log line (kept for detail views and export).
    pub raw: String,
}

/// Parsed SELinux security context `user:role:type:level`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelinuxContext {
    pub user: String,
    pub role: String,
    pub kind: String,
    pub level: String,
}

impl SelinuxContext {
    /// Parse `user:role:type:level`. The level itself may contain `:`.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.splitn(4, ':');
        Some(Self {
            user: parts.next()?.to_string(),
            role: parts.next()?.to_string(),
            kind: parts.next()?.to_string(),
            level: parts.next().unwrap_or_default().to_string(),
        })
    }

    /// The policy type, e.g. `httpd_t`. This is the field that matters most
    /// for diagnosis.
    pub fn context_type(&self) -> &str {
        &self.kind
    }
}

impl std::fmt::Display for SelinuxContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.level.is_empty() {
            write!(f, "{}:{}:{}", self.user, self.role, self.kind)
        } else {
            write!(
                f,
                "{}:{}:{}:{}",
                self.user, self.role, self.kind, self.level
            )
        }
    }
}

/// A unified AVC denial, enriched with sibling `SYSCALL`/`PATH` data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AvcEvent {
    pub audit_id: String,
    pub timestamp: f64,
    pub serial: u64,
    /// `denied` or `granted`.
    pub result: String,
    /// Permissions from the `{ ... }` set, e.g. `["open"]`, `["name_connect"]`.
    pub perms: Vec<String>,
    pub scontext: String,
    pub tcontext: String,
    pub tclass: String,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub path: Option<String>,
    pub dest_port: Option<u16>,
    pub dev: Option<String>,
    pub ino: Option<String>,
    /// Raw AVC line for the detail view.
    pub raw: String,
}

impl AvcEvent {
    pub fn source_type(&self) -> Option<String> {
        SelinuxContext::parse(&self.scontext).map(|c| c.kind)
    }

    pub fn target_type(&self) -> Option<String> {
        SelinuxContext::parse(&self.tcontext).map(|c| c.kind)
    }

    /// Short one-line summary used by list views.
    pub fn summary(&self) -> String {
        let who = self.comm.clone().unwrap_or_else(|| "?".to_string());
        let what = self.path.clone().unwrap_or_else(|| self.tclass.clone());
        format!("{} denied {} on {}", who, self.perms.join(","), what)
    }
}
