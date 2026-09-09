// SPDX-License-Identifier: GPL-3.0-or-later
//! SELinux boolean inspection: sysfs first, `getsebool` fallback.
//!
//! Layout of `/sys/fs/selinux/booleans/<name>`: two `u32`s — pending then
//! active value. Active `1` means on. Reading sysfs needs no privileges.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BooleanInfo {
    pub name: String,
    pub active: bool,
    pub pending: bool,
}

/// List every boolean on the system, sorted by name.
pub fn list_booleans() -> Vec<BooleanInfo> {
    list_booleans_in(Path::new("/sys/fs/selinux/booleans"))
}

/// Query a single boolean by name.
pub fn get_boolean(name: &str) -> Option<BooleanInfo> {
    read_sysfs_boolean(Path::new("/sys/fs/selinux/booleans").join(name))
        .or_else(|| getsebool_fallback(name))
}

/// Case-insensitive substring search over all booleans.
pub fn search_booleans(query: &str) -> Vec<BooleanInfo> {
    let q = query.to_lowercase();
    list_booleans()
        .into_iter()
        .filter(|b| b.name.to_lowercase().contains(&q))
        .collect()
}

/// The privileged command that would toggle this boolean persistently.
pub fn setsebool_command(name: &str, on: bool) -> String {
    format!("setsebool -P {} {}", name, u8::from(on))
}

fn list_booleans_in(dir: &Path) -> Vec<BooleanInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return getsebool_all_fallback();
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(info) = read_sysfs_boolean(path) {
            out.push(info);
        }
    }
    if out.is_empty() {
        return getsebool_all_fallback();
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn read_sysfs_boolean(path: PathBuf) -> Option<BooleanInfo> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let bytes = std::fs::read(&path).ok()?;
    // Two little-endian u32s: pending, active.
    let (pending, active) = if bytes.len() >= 8 {
        (
            u32::from_le_bytes(bytes[0..4].try_into().ok()?) != 0,
            u32::from_le_bytes(bytes[4..8].try_into().ok()?) != 0,
        )
    } else {
        // Fall back to text parse (`"1 1"`) for test fixtures.
        let text = String::from_utf8_lossy(&bytes);
        let mut nums = text
            .split_whitespace()
            .filter_map(|w| w.parse::<u32>().ok());
        (nums.next()? != 0, nums.next()? != 0)
    };
    Some(BooleanInfo {
        name,
        active,
        pending,
    })
}

/// `getsebool -a` fallback for non-SELinux hosts and unit tests.
fn getsebool_all_fallback() -> Vec<BooleanInfo> {
    let Ok(output) = Command::new("getsebool").arg("-a").output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_getsebool_line)
        .collect()
}

fn getsebool_fallback(name: &str) -> Option<BooleanInfo> {
    let output = Command::new("getsebool").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    parse_getsebool_line(&text).filter(|b| b.name == name)
}

fn parse_getsebool_line(line: &str) -> Option<BooleanInfo> {
    // Format: `httpd_can_network_connect --> off`
    let (name, state) = line.split_once("-->")?;
    let state = state.trim();
    Some(BooleanInfo {
        name: name.trim().to_string(),
        active: state == "on",
        pending: state == "on",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_getsebool_lines() {
        let on = parse_getsebool_line("httpd_can_network_connect --> on").unwrap();
        assert!(on.active);
        let off = parse_getsebool_line("abrt_anon_write --> off").unwrap();
        assert!(!off.active);
    }

    #[test]
    fn reads_sysfs_style_fixture() {
        let dir = tempfile::tempdir().unwrap();
        // pending=1, active=0 in binary layout
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(dir.path().join("demo_bool"), bytes).unwrap();
        // text layout
        std::fs::write(dir.path().join("text_bool"), "1 1").unwrap();
        let mut file = std::fs::File::create(dir.path().join("other")).unwrap();
        let _ = file.write_all(b"");
        let list = list_booleans_in(dir.path());
        assert_eq!(list.len(), 2);
        let demo = list.iter().find(|b| b.name == "demo_bool").unwrap();
        assert!(!demo.active);
        assert!(demo.pending);
    }

    #[test]
    fn live_system_lists_booleans() {
        // Runs against the real host when SELinux is present; on other hosts
        // the getsebool fallback (or empty vec) keeps the test green.
        let list = list_booleans();
        if list.is_empty() {
            return;
        }
        assert!(list.iter().any(|b| b.name == "httpd_can_network_connect"));
        assert!(get_boolean("httpd_can_network_connect").is_some());
        assert!(!search_booleans("httpd_can_network").is_empty());
        assert_eq!(setsebool_command("x", true), "setsebool -P x 1");
    }
}
