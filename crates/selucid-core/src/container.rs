// SPDX-License-Identifier: GPL-3.0-or-later
//! Container and Flatpak awareness: classify AVC denials involving container
//! domains and detect the classic Podman "forgot the `:z` volume flag"
//! mistake before it becomes a support ticket.
//!
//! Pure classification ([`classify`]) is string work only and always usable.
//! The stronger [`mount_flag_suspected`] cross-check shells out to
//! `matchpathcon` (still unprivileged), matching the rest of the crate.

use crate::avc::AvcEvent;
use crate::inference::{FixKind, SuggestedFix};
use serde::{Deserialize, Serialize};

/// Which container ecosystem a denial implicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerEngine {
    Podman,
    Docker,
    Flatpak,
    /// A container-ish domain we cannot attribute (e.g. `spc_t`).
    Unknown,
}

impl std::fmt::Display for ContainerEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerEngine::Podman => write!(f, "Podman"),
            ContainerEngine::Docker => write!(f, "Docker"),
            ContainerEngine::Flatpak => write!(f, "Flatpak"),
            ContainerEngine::Unknown => write!(f, "container"),
        }
    }
}

/// Category of container-related problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerIssue {
    /// A container process read a host-labeled path — the volume may be
    /// mounted without the `:z`/`:Z` relabel flag.
    VolumeMountFlag,
    /// A Flatpak sandbox restriction.
    FlatpakSandbox,
    /// A container network access denial.
    Network,
    /// Everything else.
    Other,
}

/// Result of classifying one denial through the container lens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerHint {
    pub engine: ContainerEngine,
    pub issue: ContainerIssue,
    /// Plain-language explanation for report/detail views.
    pub explanation: String,
    /// Concrete suggestion when one exists.
    pub suggestion: Option<String>,
}
/// Classify a denial as container/Flatpak related, or return `None` when the
/// event has nothing to do with containers.
pub fn classify(event: &AvcEvent) -> Option<ContainerHint> {
    let engine = container_engine(event)?;
    let (issue, explanation, suggestion) = issue_for(event, engine);
    Some(ContainerHint {
        engine,
        issue,
        explanation,
        suggestion,
    })
}

/// True when the source domain of this event is container-like (`container_t`,
/// `spc_t`, `flatpak_*`, …) or the command line names a container runtime.
/// Pure — safe for filters in every frontend.
pub fn is_container_source(event: &AvcEvent) -> bool {
    container_engine(event).is_some()
}

/// Whether the denial is a file-class access that looks like the missing
/// `:z`/`:Z` volume-flag symptom.
///
/// Requires a `/`-prefixed path whose policy-default context is a *host* type
/// (i.e. `matchpathcon` returns something other than `container_file_t` and
/// the svirt/container family). When `matchpathcon` is unavailable this
/// conservatively reports `false`.
pub fn mount_flag_suspected(event: &AvcEvent) -> bool {
    if !is_container_engine_domain(event) || !is_file_class(&event.tclass) {
        return false;
    }
    let Some(path) = event.path.clone().filter(|p| p.starts_with('/')) else {
        return false;
    };
    let Some(expected) = crate::privileged::expected_context(&path) else {
        return false;
    };
    let expected_type = crate::avc::SelinuxContext::parse(&expected)
        .map(|c| c.kind)
        .unwrap_or_default();
    !expected_type.is_empty() && !is_container_object_type(&expected_type)
}

/// A [`SuggestedFix`] for the container volume-mount mistake, when detected.
/// The command is *guidance* (adjust the `podman run` invocation): it is
/// never executed by `fix --execute`, mirroring compound commands.
pub fn container_fix(event: &AvcEvent) -> Option<SuggestedFix> {
    let path = event
        .path
        .clone()
        .filter(|p| p.starts_with('/'))?;
    if !mount_flag_suspected(event) {
        return None;
    }
    Some(SuggestedFix {
        kind: FixKind::ContainerVolume,
        title: "Re-mount volume with :z flag".to_string(),
        command: format!("podman run … -v {path}:<dest>:z …"),
        description: format!(
            "The container domain {} is blocked from a host-labeled path; \
             the Podman bind mount is missing the `:z` (or `:Z`) relabel \
             flag. Add it to the affected volume in the container's run \
             command so SELinux relabels the source while the container \
             runs. Note: passing `:Z` also restores the original label on \
             stop.",
            event.source_type().unwrap_or_default(),
        ),
        needs_root: false,
    })
}

// ---------------------------------------------------------------------------
// Implementation

fn container_engine(event: &AvcEvent) -> Option<ContainerEngine> {
    let stype = event.source_type().unwrap_or_default();
    let comm = event.comm.clone().unwrap_or_default();
    if is_flatpak(&stype, &comm) {
        Some(ContainerEngine::Flatpak)
    } else if is_podman_like(&stype, &comm) {
        Some(ContainerEngine::Podman)
    } else if is_docker_like(&comm) {
        Some(ContainerEngine::Docker)
    } else if is_container_type(&stype) {
        Some(ContainerEngine::Unknown)
    } else {
        None
    }
}

/// A container engine *domain* (as opposed to a helper command line) drove
/// the denied process. Used by the mount-flag cross-check.
fn is_container_engine_domain(event: &AvcEvent) -> bool {
    let stype = event.source_type().unwrap_or_default();
    is_container_type(&stype)
        || stype == "svirt_t"
        || stype == "svirt_lxc_t"
        || stype == "nspawn_t"
}

fn is_container_type(t: &str) -> bool {
    !t.is_empty()
        && (t.starts_with("container_")
            || t.starts_with("flatpak_")
            || t == "spc_t"
            || t == "nspawn_t"
            || t == "container_t")
}

fn is_flatpak(t: &str, comm: &str) -> bool {
    t.starts_with("flatpak_") || comm == "flatpak" || comm == "bwrap"
}

fn is_podman_like(t: &str, comm: &str) -> bool {
    matches!(comm, "podman" | "systemd-nspawn") || t.starts_with("container_")
}

fn is_docker_like(comm: &str) -> bool {
    matches!(comm, "docker" | "dockerd" | "containerd" | "docker-compose")
}

/// Host/container object types that a bind-mounted path is *expected* to get
/// when the `:z` flag is in use.
fn is_container_object_type(t: &str) -> bool {
    t.starts_with("container_") || t.starts_with("svirt_") || matches!(t, "content_t" | "vmt_t")
}

fn is_file_class(tclass: &str) -> bool {
    matches!(
        tclass,
        "file" | "dir" | "lnk_file" | "fifo_file" | "sock_file" | "blk_file" | "chr_file"
    )
}

fn issue_for(
    event: &AvcEvent,
    engine: ContainerEngine,
) -> (ContainerIssue, String, Option<String>) {
    match engine {
        ContainerEngine::Flatpak => (
            ContainerIssue::FlatpakSandbox,
            format!(
                "The Flatpak sandbox for {} was denied this access. Prefer \
                 granting the single file or directory to the specific app \
                 over broad `--filesystem=host` overrides.",
                event.comm.clone().unwrap_or_else(|| "an application".to_string()),
            ),
            Some("flatpak override --filesystem=<path> <app-id>".to_string()),
        ),
        ContainerEngine::Podman
            | ContainerEngine::Docker
            | ContainerEngine::Unknown => {
            if is_file_class(&event.tclass) && event.path.is_some() {
                (
                    ContainerIssue::VolumeMountFlag,
                    format!(
                        "{} domain {} was denied a file-class access. If the \
                         path is exposed through a bind mount, the volume is \
                         most likely missing the `:z`/`:Z` relabel flag.",
                        engine,
                        event.source_type().unwrap_or_default(),
                    ),
                    Some("add `:z` to the Podman volume: -v SRC:DEST:z".to_string()),
                )
            } else if event.tclass.ends_with("socket") {
                (
                    ContainerIssue::Network,
                    format!(
                        "Container domain {} was denied a network access. \
                         Check the container networking booleans for the \
                         exact scope needed (narrow beats `*_connect_any`).",
                        event.source_type().unwrap_or_default(),
                    ),
                    Some("setsebool -P container_connect_any 1".to_string()),
                )
            } else {
                (
                    ContainerIssue::Other,
                    format!(
                        "Container domain {} hit a routine denial; apply the \
                         narrowest fix suggested by the diagnosis.",
                        event.source_type().unwrap_or_default(),
                    ),
                    None,
                )
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn container_event(tclass: &str, path: Option<&str>) -> AvcEvent {
        AvcEvent {
            audit_id: "1788956400.123:456".into(),
            timestamp: 1788956400.123,
            serial: 456,
            result: "denied".into(),
            perms: vec!["read".into()],
            scontext: "system_u:system_r:container_t:s0".into(),
            tcontext: "system_u:object_r:var_t:s0".into(),
            tclass: tclass.into(),
            pid: Some(1234),
            comm: Some("podman".into()),
            exe: Some("/usr/bin/podman".into()),
            path: path.map(String::from),
            dest_port: None,
            dev: Some("dm-0".into()),
            ino: Some("123456".into()),
            raw: String::new(),
        }
    }

    fn httpd_event() -> AvcEvent {
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
    fn flatpak_source_is_classified() {
        let mut e = container_event("file", Some("/home/u/Documents/x.pdf"));
        e.scontext = "system_u:system_r:flatpak_t:s0".into();
        e.comm = Some("flatpak".into());
        let h = classify(&e).unwrap();
        assert_eq!(h.engine, ContainerEngine::Flatpak);
        assert_eq!(h.issue, ContainerIssue::FlatpakSandbox);
        assert!(is_container_source(&e));
    }

    #[test]
    fn podman_file_denial_flags_volume_issue() {
        let e = container_event("file", Some("/srv/www/index.html"));
        let h = classify(&e).unwrap();
        assert_eq!(h.engine, ContainerEngine::Podman);
        assert_eq!(h.issue, ContainerIssue::VolumeMountFlag);
        assert!(is_container_source(&e));
    }

    #[test]
    fn podman_socket_denial_flags_network() {
        let e = container_event("tcp_socket", None);
        let h = classify(&e).unwrap();
        assert_eq!(h.issue, ContainerIssue::Network);
    }

    #[test]
    fn non_container_source_is_none() {
        let e = httpd_event();
        assert!(classify(&e).is_none());
        assert!(!is_container_source(&e));
    }

    #[test]
    fn container_fix_needs_absolute_path_and_container_source() {
        // Relative name (no leading '/') cannot be cross-checked.
        let mut e = container_event("file", Some("report.pdf"));
        assert!(e.path.as_deref().filter(|p| p.starts_with('/')).is_none());
        assert!(container_fix(&e).is_none());
        // An httpd event is not a container source, regardless of path shape.
        e.comm = Some("httpd".into());
        e.scontext = "system_u:system_r:httpd_t:s0".into();
        assert!(container_fix(&e).is_none());
    }

    #[test]
    fn mount_flag_suspected_preconditions_are_pure() {
        // Not a container domain — must never fire, even with a path.
        let h = httpd_event();
        assert!(!mount_flag_suspected(&h));
        // Not a file class — network denials are never volume-flag events.
        let s = container_event("tcp_socket", Some("/srv/www/index.html"));
        assert!(!mount_flag_suspected(&s));
        // Relative paths are never safe to query against matchpathcon.
        let rel = container_event("file", Some("report.pdf"));
        assert!(!mount_flag_suspected(&rel));
    }

    #[test]
    fn mount_flag_suspected_is_total() {
        // Whether matchpathcon resolves /srv/www/index.html depends on the
        // host (SELinux + policy coverage); the contract is that the function
        // stays total (no panic) in either environment.
        let e = container_event("file", Some("/srv/www/index.html"));
        mount_flag_suspected(&e);
    }
}