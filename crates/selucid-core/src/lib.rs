// SPDX-License-Identifier: GPL-3.0-or-later
//! selucid-core: AVC parsing, grouping, diagnosis, and privileged-action helpers.
//!
//! All types here are UI-agnostic so the GTK GUI, ratatui TUI, and CLI share
//! one diagnostic engine. Nothing in this crate escalates privileges on its
//! own; see [`privileged`] for the reviewed-command builders.

pub mod avc;
pub mod booleans;
pub mod grouping;
pub mod inference;
pub mod parser;
pub mod privileged;
pub mod reader;

pub use avc::{AuditRecord, AvcEvent, SelinuxContext};
pub use grouping::{extract_avc_events, group_by_serial};
pub use inference::{Confidence, Diagnosis, FixKind, SuggestedFix, diagnose};
pub use parser::{ParseError, parse_audit_line};
