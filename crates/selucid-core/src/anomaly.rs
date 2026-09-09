// SPDX-License-Identifier: GPL-3.0-or-later
//! Security anomaly detection: a sliding-window denial-rate tracker that
//! flags incident-like bursts of denials from one source instead of surfacing
//! routine one-off configuration noise.
//!
//! The tracker keys on `(scontext, tclass)` — the pair that identifies *who*
//! is repeatedly being blocked and *what* class of access it wants. It is
//! fed from the frontends' [`crate::reader::LogWatcher`] streams and is
//! purely observational: it raises incidents, never actions.
//!
//! Timestamps come from the audit id (`msg=audit(ts:serial)`), so the window
//! logic is deterministic and testable without a wall clock.

use crate::avc::AvcEvent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Default observation window (seconds) before an incident is considered over.
pub const DEFAULT_WINDOW_SECS: u64 = 60;
/// Default denials-per-window per `(scontext, tclass)` needed to raise an incident.
pub const DEFAULT_THRESHOLD: u32 = 30;

/// How severe one incident-like burst is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Above threshold, barely — likely a misconfigured service in a loop.
    Low,
    /// Clearly elevated rate.
    Medium,
    /// High rate, or elevated rate on sensitive permissions.
    High,
    /// Extreme rate on sensitive permissions (relabel/transition/ports).
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// One raised anomaly: a burst of denials from one source domain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    /// Source context, e.g. `unconfined_u:unconfined_r:mysqld_t:s0`.
    pub scontext: String,
    /// Target class, e.g. `file`, `tcp_socket`.
    pub tclass: String,
    /// Denials observed within the window at raise time.
    pub count: u32,
    /// Threshold that was exceeded (display: "32 in 60s / limit 30").
    pub threshold: u32,
    /// Window length in seconds.
    pub window_secs: u64,
    /// Severity of this burst.
    pub severity: Severity,
    /// Audit-epoch seconds of the first and latest denial of the burst.
    pub first_seen: f64,
    pub last_seen: f64,
}

/// Sliding-window denial-rate tracker: config plus mutable per-key state.
#[derive(Debug)]
pub struct DenialTracker {
    window_secs: u64,
    threshold: u32,
    /// Recent denial timestamps per `(scontext, tclass)`.
    buckets: HashMap<(String, String), VecDeque<f64>>,
    /// Keys whose incident has been raised; a new incident is only raised
    /// again after the rate falls back under the threshold.
    raised: HashSet<(String, String)>,
}

impl Default for DenialTracker {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SECS, DEFAULT_THRESHOLD)
    }
}

impl DenialTracker {
    /// A tracker with a custom window and per-window threshold.
    pub fn new(window_secs: u64, threshold: u32) -> Self {
        Self {
            window_secs,
            threshold,
            buckets: HashMap::new(),
            raised: HashSet::new(),
        }
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Record one denial; returns an incident when this key newly exceeds the
    /// threshold (once per burst — the rate falling below the threshold
    /// re-arms the key for future incidents).
    pub fn record(&mut self, event: &AvcEvent) -> Option<Incident> {
        let key = (event.scontext.clone(), event.tclass.clone());
        let cutoff = event.timestamp - self.window_secs as f64;
        let bucket = self.buckets.entry(key).or_default();
        bucket.retain(|&ts| ts > cutoff);
        bucket.push_back(event.timestamp);
        let count = bucket.len() as u32;

        if count < self.threshold {
            // Rate under the threshold: re-arm so a later burst re-alerts.
            self.raised
                .remove(&(event.scontext.clone(), event.tclass.clone()));
            return None;
        }
        let raised_key = (event.scontext.clone(), event.tclass.clone());
        if !self.raised.insert(raised_key) {
            return None; // incident already raised for this ongoing burst
        }
        let first_seen = *bucket.front().unwrap_or(&event.timestamp);
        Some(self.build_incident(
            &event.scontext,
            &event.tclass,
            count,
            first_seen,
            event.timestamp,
        ))
    }

    /// Convenience: record a batch (e.g. [`crate::reader::WatchEvent::Denials`]).
    pub fn track_batch(&mut self, events: &[AvcEvent]) -> Vec<Incident> {
        events.iter().filter_map(|e| self.record(e)).collect()
    }

    /// Number of denials currently inside the window for a key.
    pub fn window_count(&self, scontext: &str, tclass: &str) -> u32 {
        self.buckets
            .get(&(scontext.to_string(), tclass.to_string()))
            .map(|b| b.len() as u32)
            .unwrap_or(0)
    }

    /// Drop all state (e.g. when a frontend stops watching).
    pub fn clear(&mut self) {
        self.buckets.clear();
        self.raised.clear();
    }

    fn build_incident(
        &self,
        scontext: &str,
        tclass: &str,
        count: u32,
        first_seen: f64,
        last_seen: f64,
    ) -> Incident {
        Incident {
            scontext: scontext.to_string(),
            tclass: tclass.to_string(),
            count,
            threshold: self.threshold,
            window_secs: self.window_secs,
            severity: classify_severity(count, self.threshold, tclass),
            first_seen,
            last_seen,
        }
    }
}

/// Severity from burst size relative to the threshold; access to port/socket
/// classes rates as more suspicious than a plain `file` denial loop.
fn classify_severity(count: u32, threshold: u32, tclass: &str) -> Severity {
    let ratio = count / threshold.max(1);
    let base = if ratio >= 4 {
        Severity::High
    } else if ratio >= 2 {
        Severity::Medium
    } else {
        Severity::Low
    };
    let sensitive_class = matches!(
        tclass,
        "tcp_socket" | "udp_socket" | "unix_stream_socket" | "association"
    );
    match (base, sensitive_class) {
        (Severity::High, true) | (Severity::Medium, true) => Severity::Critical,
        (Severity::Low, true) => Severity::Medium,
        (base, _) => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denial(ts: f64, serial: u64, scontext: &str, tclass: &str) -> AvcEvent {
        AvcEvent {
            audit_id: format!("{ts}:{serial}"),
            timestamp: ts,
            serial,
            result: "denied".into(),
            perms: vec!["read".into()],
            scontext: scontext.into(),
            tcontext: "system_u:object_r:httpd_sys_content_t:s0".into(),
            tclass: tclass.into(),
            pid: Some(1),
            comm: Some("test".into()),
            exe: None,
            path: None,
            dest_port: None,
            dev: None,
            ino: None,
            raw: String::new(),
        }
    }

    #[test]
    fn crosses_threshold_once_per_burst() {
        let mut t = DenialTracker::new(60, 3);
        let src = "u:r:mysqld_t:s0";
        assert_eq!(t.record(&denial(100.0, 1, src, "file")), None);
        assert_eq!(t.record(&denial(101.0, 2, src, "file")), None);
        let inc = t.record(&denial(102.0, 3, src, "file")).unwrap();
        assert_eq!(inc.count, 3);
        assert_eq!(inc.severity, Severity::Low);
        assert_eq!(inc.window_secs, 60);
        assert!((inc.first_seen - 100.0).abs() < f64::EPSILON);
        // Same ongoing burst → no duplicate incident.
        assert_eq!(t.record(&denial(103.0, 4, src, "file")), None);
        // Window slides past the burst → re-armed; a new burst re-alerts.
        assert_eq!(t.record(&denial(200.0, 5, src, "file")), None);
        assert_eq!(t.record(&denial(201.0, 6, src, "file")), None);
        let again = t.record(&denial(202.0, 7, src, "file")).unwrap();
        assert_eq!(again.count, 3);
        assert!((again.first_seen - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn keys_are_independent() {
        let mut t = DenialTracker::new(60, 2);
        let a = "u:r:mysqld_t:s0";
        let b = "u:r:sshd_t:s0";
        assert_eq!(t.record(&denial(1.0, 1, a, "file")), None);
        assert_eq!(t.record(&denial(1.5, 2, b, "file")), None);
        // a reaches 2/2, b stays 1/2 → only a crosses.
        let inc = t.record(&denial(2.0, 3, a, "file")).unwrap();
        assert_eq!(inc.scontext, a);
        assert_eq!(t.window_count(a, "file"), 2);
        assert_eq!(t.window_count(b, "file"), 1);
    }

    #[test]
    fn severity_scales_with_ratio_and_class() {
        assert_eq!(classify_severity(31, 30, "file"), Severity::Low);
        assert_eq!(classify_severity(60, 30, "file"), Severity::Medium);
        assert_eq!(classify_severity(120, 30, "file"), Severity::High);
        // Socket classes rate as more suspicious at every level.
        assert_eq!(classify_severity(31, 30, "tcp_socket"), Severity::Medium);
        assert_eq!(classify_severity(120, 30, "tcp_socket"), Severity::Critical);
    }

    #[test]
    fn clear_resets_all_state() {
        let mut t = DenialTracker::new(60, 1);
        let src = "u:r:x_t:s0";
        assert!(t.record(&denial(1.0, 1, src, "file")).is_some());
        t.clear();
        assert_eq!(t.window_count(src, "file"), 0);
        // After clear the key is un-raised and will alert again.
        assert!(t.record(&denial(2.0, 2, src, "file")).is_some());
    }

    #[test]
    fn track_batch_collects_new_incidents() {
        let mut t = DenialTracker::new(60, 2);
        let src = "u:r:burst_t:s0";
        let batch: Vec<AvcEvent> = (0..3)
            .map(|i| denial(10.0 + i as f64, i, src, "file"))
            .collect();
        let incidents = t.track_batch(&batch);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].count, 2); // raised at the crossing event
    }
}
