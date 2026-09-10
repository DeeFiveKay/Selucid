// SPDX-License-Identifier: GPL-3.0-or-later
//! Built-in ASCII logo, embedded from the project root `ascii.txt`
//! so every frontend ships the same banner with no runtime file dependency.

/// The full-width ASCII logo from `ascii.txt`.
///
/// 100 columns wide, 22 lines tall — designed to render cleanly in the
/// CLI, the GUI About dialog, and trimmed in the TUI header.
pub const LOGO: &str = include_str!("../../../ascii.txt");

/// Logo + centered app name + tagline, ready to print.
pub fn banner() -> String {
    let mut out = String::new();
    for line in LOGO.lines() {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("\nSelucid — SELinux + Lucid\n");
    out.push_str("Open-source AVC troubleshooting toolkit for RHEL, Fedora, and compatibles.\n");
    out
}

/// Trimmed logo suitable for narrow spaces (first `n` leading lines).
pub fn trimmed(lines: usize) -> String {
    LOGO
        .lines()
        .take(lines)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_is_non_empty() {
        assert!(!LOGO.is_empty());
    }

    #[test]
    fn logo_is_ascii_only() {
        // The logo should be pure ASCII so it renders identically on every
        // terminal regardless of locale.
        for ch in LOGO.chars() {
            assert!(
                ch.is_ascii_graphic() || ch.is_ascii_whitespace(),
                "non-ASCII char {ch:?} found"
            );
        }
    }

    #[test]
    fn banner_ends_with_tagline() {
        let b = banner();
        assert!(b.contains("Selucid — SELinux + Lucid"));
    }

    #[test]
    fn trimmed_narrows() {
        assert_eq!(trimmed(3).lines().count(), 3);
        assert!(trimmed(0).is_empty());
    }
}
