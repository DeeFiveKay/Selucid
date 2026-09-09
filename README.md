# Selucid — SELinux + Lucid

Selucid is an open-source, system-level visualizer and troubleshooting toolkit
for RHEL, Fedora, and compatible distributions. It bridges the gap between
cryptic SELinux AVC denials and the humans who must fix them.

- **Zero-overhead audit parsing** — high-throughput log processing in Rust (`nom`).
- **Context-aware diagnostics** — raw denials translated into plain language,
  cross-checked against the loaded policy via `audit2why`.
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

# Cross-check against the loaded policy (audit2why ground truth)
selucid explain --why /var/log/audit/audit.log
selucid why /var/log/audit/audit.log

# Show only remediation commands
selucid suggest /var/log/audit/audit.log

# Follow the audit log live (inotify-driven, polling fallback)
selucid watch

# Preview a fix, then apply it via pkexec after confirmation
selucid fix audit.log --index 1 --fix 1
selucid fix audit.log --index 1 --fix 1 --execute

# Export for scripting / tickets / SIEM pipelines
selucid export audit.log --format json --with-diagnoses -o report.json
selucid export audit.log --format csv --with-diagnoses
selucid export audit.log --format jsonl -o denials.jsonl

# Inspect SELinux booleans
selucid booleans --search httpd

# Full-screen terminal UI: Denials + Booleans tabs, live tailing
# (Vim keys: j/k navigate, Tab switch tab, / filter, t preview toggle, q quit)
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
