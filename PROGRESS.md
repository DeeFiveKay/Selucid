# Selucid Progress

Living tracker for the `Future Plan.md` road map and the pre-publish work.
Update this file at the end of every feature/session — it is the single
source of truth for what remains before publishing.

Legend: `[ ]` planned · `[-]` in progress · `[x]` done · `[!]` done + tested

## Milestone: v1.0 pre-publish

Definition of done (all must hold before publishing):

- [ ] `cargo check --workspace` clean
- [ ] `cargo test` green (all crates)
- [ ] `cargo clippy --workspace --all-targets` warning-free
- [ ] No uncommitted work in `git status` (each feature is its own commit)
- [ ] `README.md` documents every new subcommand
- [ ] `docs/ARCHITECTURE.md` reflects the new modules
- [ ] `PROGRESS.md` fully checked off

---

## Feature checklist

### Phase 0 — Housekeeping & progress tracking

- [x] `PROGRESS.md` tracker created (this file)
- [x] Pending GUI work, `data/`, `icons/`, logos, and `Future Plan.md` committed
- [x] `Future Plan.md` reviewed; exclusions honoured (no custom policy
      compiler, no system monitoring, no auto-remediation, no `.te` editor,
      no SSH agent)

### Phase 1 — Core engine (`selucid-core`)

- [x] **1. Sandbox & What-If simulator** (`src/sandbox.rs`)
      Read-only diff before a `setsebool`/`semanage`/`restorecon` execution:
      before/after state, affected domains via `sesearch -b <bool> -A`
      (graceful fallback when `sesearch` is missing).
- [x] **2. Container integration (Podman & Flatpak)** (`src/container.rs`)
      Classify `container_t`/`flatpak_*` denials; detect the missing `:z`/`:Z`
      volume-mount flag and suggest the corrected Podman invocation.
      Wired into `diagnose_with_oracle` (new `FixKind::ContainerVolume`);
      CLI/GUI treat it as review-only guidance.
- [x] **3. Proactive context inspection** (`src/inspect.rs`)
      Directory walker; per-file `matchpathcon` expected vs actual label
      (`getfattr`), producing a mismatch report (unlabeled / wrong label).
- [x] **4. Exporting & reporting** (`src/report.rs`)
      Denial reports as Markdown, runnable Bash remediation script, and a
      ready-to-run Ansible playbook (PDF deferred — Markdown satisfies the
      plan and avoids a heavy dependency).
- [x] **5. Fix history & rollback** (`src/history.rs`)
      JSONL audit journal in `$XDG_STATE_HOME/selucid/` recording every
      executed fix with before/after state; single-command rollback that
      inverts the change (boolean flips and reversible relabels only).
- [x] **6. CIS / Red Hat hardening checks** (`src/compliance.rs`)
      `selucid audit`: enforcing mode, policy type, permissive domains,
      custom `.pp` modules, customized booleans, pending autorelabel. Each
      check carries a CIS/DISA-style reference.
- [x] **7. Security anomaly detection** (`src/anomaly.rs`)
      Sliding-window denial-rate tracker per source domain; flags
      incident-like bursts (> threshold within the window) as incidents
      instead of routine configuration noise.

### Phase 2 — CLI (`selucid-cli`)

- [x] Subcommands `simulate`, `inspect`, `report`, `history`, `rollback`,
      `audit`; `watch --anomaly`; container-aware fixes in `explain`/`suggest`.
      Live-verified: `audit`, `inspect /tmp` (599 paths), `simulate`,
      `report --format markdown|bash`, `history`, `--help`.
- [x] Journaling wired into `selucid fix --execute` (via `execute_journaled`).

### Phase 3 — Frontends

- [x] **TUI**: 4 tabs (Denials/Booleans/Incidents/History); `[c]` container
      markers, live anomaly incident banner + tracker status, What-If sandbox
      preview on `t` (Denials tab), journal listing (History tab).
- [x] **GUI** (`app.rs`): anomaly incidents surface in the live toast,
      What-If simulation appended to fix preview, execution journaled with
      rollback id shown. Syntax-checked with rustfmt — this host lacks
      `gtk4-devel`/`libadwaita-devel`, so a full
      `cargo build -p selucid-gui --features gui` remains to be run on a
      GUI-capable host before publishing.

### Phase 4 — Pre-publish polish

- [x] Full test + clippy pass (66/66 workspace tests excluding GUI; clippy clean).
- [x] README quick-start updated (all new subcommands, journal/rollback notes).
- [x] `docs/ARCHITECTURE.md` updated (new core modules, data flow, privilege notes).
- [ ] Version bump decision (`0.1.0` → `0.2.0` recommended) + tag before publish.
- [ ] GUI-capable host: `cargo build -p selucid-gui` (needs gtk4/libadwaita devel).

---

## Exclusions (from `Future Plan.md`, deliberately NOT building)

- No custom SELinux policy compiler from scratch (rely on `audit2allow`).
- No general system monitoring (CPU/RAM/systemd) — out of scope.
- No background auto-remediation without explicit user confirmation.
- No built-in graphical `.te` editor.
- No built-in remote SSH agent engine (run `selucid-tui` over SSH instead).

---

## Session log

| Date | Session | Outcome |
|---|---|---|
| 2026-09-10 | Session 1 | Phase 0 done. Baseline: 29/29 tests green, clippy clean. |
| 2026-09-10 | Session 2 | Features 2-5 committed (container, inspect, report, history+journal hook). Baseline of feature 6 laid. |
| 2026-09-10 | Session 3 | Feature 5 finalized (49 tests, clippy clean). Feature 6 committed (`selucid audit` core). Live host: Enforcing, semanage store unreadable unprivileged → `Unknown` path exercised. |
| 2026-09-10 | Session 4 | Feature 6 committed. Feature 7 (`anomaly.rs`, DenialTracker) committed — **Phase 1 complete**, 54/54 tests, clippy clean. Next: Phase 2 CLI. |
| 2026-09-10 | Session 5 | Feature 1 (`sandbox.rs`) committed — 58/58 tests. Phase 2 CLI + Phase 3 TUI/GUI committed; all new subcommands live-verified on the host (Enforcing, targeted). GUI needs a gtk4-capable host for a full build check. Next: Phase 4 polish. |
| 2026-09-10 | Session 6 | **All 7 features done.** Phase 4: README + ARCHITECTURE updated; 66/66 workspace tests, clippy clean; CLI smoke test re-run (`audit` 4 pass/3 unknown, `report`, `history`, `simulate`, `inspect /tmp`). Remaining pre-publish: version bump + GUI build on capable host. |
| 2026-09-10 | Session 7 | GUI fixed on RHEL (66 gtk/relm4 trait errors resolved). Now compiles and launches on a gtk4-capable host. Workspace tests 66/66 (58 core + 8 TUI). Final pre-publish: version bump decision. |
| 2026-09-10 | Session 8 | ASCII logo integration: `logo.rs` core module (embedded via `include_str!`), CLI banner (terminal-aware, suppressed on pipe), TUI splash + header, GUI About dialog with logo + release notes. All 62 core + 8 TUI tests pass. |