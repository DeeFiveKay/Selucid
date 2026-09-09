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

- [ ] **1. Sandbox & What-If simulator** (`src/sandbox.rs`)
      Read-only diff before a `setsebool`/`semanage`/`restorecon` execution:
      before/after state, affected domains via `sesearch -b <bool> -A`
      (graceful fallback when `sesearch` is missing).
- [!] **2. Container integration (Podman & Flatpak)** (`src/container.rs`)
      Classify `container_t`/`flatpak_*` denials; detect the missing `:z`/`:Z`
      volume-mount flag and suggest the corrected Podman invocation.
      Wired into `diagnose_with_oracle` (new `FixKind::ContainerVolume`);
      CLI/GUI treat it as review-only guidance.
- [!] **3. Proactive context inspection** (`src/inspect.rs`)
      Directory walker; per-file `matchpathcon` expected vs actual label
      (`getfattr`), producing a mismatch report (unlabeled / wrong label).
- [ ] **4. Exporting & reporting** (`src/report.rs`)
      Denial reports as Markdown, runnable Bash remediation script, and a
      ready-to-run Ansible playbook (PDF deferred — Markdown satisfies the
      plan and avoids a heavy dependency).
- [ ] **5. Fix history & rollback** (`src/history.rs`)
      JSONL audit journal in `$XDG_STATE_HOME/selucid/` recording every
      executed fix with before/after state; single-command rollback that
      inverts the change (boolean flips and reversible relabels only).
- [ ] **6. CIS / Red Hat hardening checks** (`src/compliance.rs`)
      `selucid audit`: enforcing mode, policy type, permissive domains,
      custom `.pp` modules, customized booleans, pending autorelabel. Each
      check carries a CIS/DISA-style reference.
- [ ] **7. Security anomaly detection** (`src/anomaly.rs`)
      Sliding-window denial-rate tracker per source domain; flags
      incident-like bursts (> threshold within the window) as incidents
      instead of routine configuration noise.

### Phase 2 — CLI (`selucid-cli`)

- [ ] Subcommands `simulate`, `inspect`, `report`, `history`, `rollback`,
      `audit`; `watch --anomaly`; container-aware fixes in `explain`/`suggest`.
- [ ] Journaling wired into `selucid fix --execute` (via `execute_journaled`).

### Phase 3 — Frontends

- [ ] **TUI**: incident banner, sandbox diff in the fix-preview pane,
      history listing.
- [ ] **GUI** (`app.rs`): sandbox confirm dialog before execute, incident
      badge; verify builds with `cargo build -p selucid-gui --features gui`
      on a host with `gtk4-devel` + `libadwaita-devel`.

### Phase 4 — Pre-publish polish

- [ ] Full test + clippy pass; README quick-start updated; architecture doc
      updated; version bump decision; one commit per feature.

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