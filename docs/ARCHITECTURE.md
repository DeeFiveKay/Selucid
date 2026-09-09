# Selucid Architecture

Mirrors the blueprint §2: unprivileged frontends over `selucid-core`, with
privileged execution isolated behind Polkit.

```text
 [selucid-gui]   [selucid(-cli) / selucid-tui]
       \                    | Direct API (rlib)
        \  D-Bus/Polkit     v
         \-------> +------------------+
                   |   selucid-core   |
                   | parser -> group  |
                   | -> inference     |
                   +--------+---------+
                            | previewed commands only
                            v
                   pkexec / Polkit helper
```

## Crates

- **`selucid-core`** (no UI deps): `parser` (nom AVC/audit tokenizer),
  `grouping` (merge `AVC+SYSCALL+PATH` records by `msg=audit(serial)`),
  `inference` (human explanation + `SuggestedFix` list), `booleans`
  (`/sys/fs/selinux/booleans` with `getsebool` fallback), `privileged`
  (`pkexec` argv builder, dry-run preview), `reader` (tokio file tailer).
- **`selucid-cli`**: thin `clap` wrapper. `explain`, `suggest`, `watch`,
  `booleans`. JSON output for scripting.
- **`selucid-tui`**: `ratatui` + `crossterm`, Vim keys, filter, fix preview.
- **`selucid-gui`**: `relm4` + `libadwaita`, excluded from the default
  workspace build until GTK dev headers are present.

## Data flow

1. `reader` tails `/var/log/audit/audit.log` (or stdin/`ausearch` pipe).
2. `parser::parse_audit_line` tokenizes each record; `grouping::group_by_serial`
   merges multi-line events; `extract_avc_events` enriches AVC records with
   sibling `SYSCALL` (`pid`/`comm`) and `PATH` (`name`) fields.
3. `inference::diagnose` matches the denial vector against boolean hints and
   `matchpathcon` expected contexts, emitting fixes ordered by confidence:
   `restorecon` → `semanage fcontext` → `setsebool -P` → `audit2allow` module.
4. Frontends render the diagnosis; `privileged::PrivilegedAction::preview`
   shows the exact command; `execute` re-runs it under `pkexec` only after the
   user confirms.

## Security notes

- No setuid, no daemon, no ambient root. The tool never writes policy state
  except through the user's explicit approval of a previewed command.
- Boolean/file reads prefer sysfs (`/sys/fs/selinux`) so diagnosis works
  without privileges; only remediation escalates.
- Direct `argv` execution (no shell) throughout `privileged` to avoid injection.
- `notify`-based live reload is Phase 2; the MVP tails with `tokio` polling,
  which also covers truncation/rotation.
