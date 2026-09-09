# Selucid — SELinux + Lucid

Selucid is an open-source, system-level visualizer and troubleshooting toolkit
for RHEL, Fedora, and compatible distributions. It bridges the gap between
cryptic SELinux AVC denials and the humans who must fix them.

- **Zero-overhead audit parsing** — high-throughput log processing in Rust (`nom`).
- **Context-aware diagnostics** — raw denials translated into plain language.
- **Non-destructive remediation** — guided `restorecon`, `setsebool`, `semanage`,
  or `audit2allow` module generation via Polkit authorization. Nothing runs as
  root without explicit approval.
- **Dual interface** — native GTK4/Libadwaita GUI for desktops, `ratatui` TUI
  for headless servers and SSH sessions.

SELinux stays **enforcing**. Selucid shows you why something was denied and the
safest way to allow it.

## Quick start

```sh
# Explain recent denials (pipe ausearch output or a log file)
ausearch -m avc -ts recent 2>/dev/null | selucid explain
selucid explain /var/log/audit/audit.log

# Show only remediation commands
selucid suggest /var/log/audit/audit.log

# Follow the audit log live
selucid watch

# Inspect SELinux booleans
selucid booleans --search httpd

# Full-screen terminal UI (Vim keys: j/k navigate, / filter, q quit)
selucid-tui /var/log/audit/audit.log
```

The GUI (`selucid-gui`) additionally needs `gtk4-devel` and
`libadwaita-devel`, then: `cargo build -p selucid-gui`.

## Layout

```text
crates/selucid-core  # parser, grouping, inference, booleans, privileged runner
crates/selucid-cli   # `selucid` command (explain/suggest/watch/booleans)
crates/selucid-tui   # `selucid-tui` full-screen terminal interface
crates/selucid-gui   # `selucid-gui` GTK4/Libadwaita desktop app (optional)
policy/              # Polkit action definitions (org.selucid.*)
docs/ARCHITECTURE.md # component design, privilege model
```

## Privilege model

`selucid`, `selucid-tui` and `selucid-gui` run **unprivileged**. Reading
protected logs and applying fixes escalates only through `pkexec`/Polkit with a
native authentication prompt, and every privileged command is previewed first.

## License

GPL-3.0-or-later. See `LICENSE` and `docs/ARCHITECTURE.md`.
