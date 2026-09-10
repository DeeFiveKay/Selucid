// SPDX-License-Identifier: GPL-3.0-or-later
//! selucid-core: AVC parsing, grouping, diagnosis, and privileged-action helpers.
//!
//! All types here are UI-agnostic so the GTK GUI, ratatui TUI, and CLI share
//! one diagnostic engine. Nothing in this crate escalates privileges on its
//! own; see [`privileged`] for the reviewed-command builders.

pub mod anomaly;
pub mod analysis;
pub mod avc;
pub mod booleans;
pub mod compliance;
pub mod container;
pub mod grouping;
pub mod history;
pub mod inspect;
pub mod inference;
pub mod parser;
pub mod privileged;
pub mod reader;
pub mod report;
pub mod sandbox;

pub use anomaly::{DenialTracker, Incident, Severity, DEFAULT_THRESHOLD, DEFAULT_WINDOW_SECS};
pub use analysis::{WhyAnalysis, analyze_batch, analyze_raw};
pub use avc::{AuditRecord, AvcEvent, SelinuxContext};
pub use compliance::{CheckStatus, ComplianceCheck, ComplianceReport, run_audit};
pub use container::{
    ContainerEngine, ContainerHint, ContainerIssue, classify, container_fix, is_container_source,
    mount_flag_suspected,
};
pub use grouping::{extract_avc_events, group_by_serial};
pub use history::{HistoryEntry, RollbackPlan, capture_after, capture_before, history_file, list_entries, new_entry, record, rollback_plan, state_dir};
pub use inspect::{ContextMismatch, InspectionReport, MismatchKind, actual_context, compare_context, inspect_directory};
pub use inference::{
    Confidence, Diagnosis, FixKind, SuggestedFix, boolean_hint_for, diagnose, diagnose_with_oracle,
};
pub use parser::{ParseError, parse_audit_line};
pub use reader::{LogWatcher, WatchEvent};
pub use report::{ReportFormat, render_ansible, render_bash, render_markdown, render_report};
pub use sandbox::{SimulationDiff, simulate};
