---
name: cmtraceopen-memory
description: Durable facts about adamgell/cmtraceopen, covering architecture, gates, workflow rules, and where knowledge lives. Loaded every turn for this project.
version: 1.0.0
author: Adam Gell
license: MIT
platforms: [linux, macos, windows]
---

# CMTrace Open — Memory

Durable facts about `adamgell/cmtraceopen`. These are loaded into every turn when working on this project.

## Repo Facts

- **Repository:** https://github.com/adamgell/cmtraceopen
- **Stack:** Tauri v2 + React 19 + TypeScript + Rust (cmtraceopen-parser)
- **Editions:** Full (all features) and Lite (log viewer only)
- **License:** MIT (PR #384 merged at `a686daef` with provenance visible, CodeRabbit clean)
- **Distribution:** MSIs/NSIS (Windows), DMG (macOS arm64), .deb/.AppImage (Linux) + Homebrew cask + Scoop bucket

## Architecture Overview

Three structural layers:

1. **Frontend** (`src/`) — React 19, TypeScript, Fluent UI, Zustand stores (log-store, filter-store, ui-store, marker-store). Workspaces: intune, esp-diagnostics, dsregcmd, sysmon, secureboot, event-log, macos-diag, jamf, timeline, deployment, dns-dhcp
2. **Backend IPC** (`src-tauri/src/`) — Tauri v2 Rust. IPC commands in `src-tauri/src/commands/`. Platform modules: intune, dsregcmd, esp, collector, state, watcher
3. **Parser Crate** (`crates/cmtraceopen-parser/`) — Pure Rust, wasm32-compatible. No OS I/O. Contains parser/, intune/, esp/, dsregcmd/, error_db/

Hard boundary: cmtraceopen-parser is pure Rust only. No OS I/O, registry, WMI, Tauri, network, DB, or live collection in the parser crate.

## Build Commands (From CLAUDE.md)

```bash
npm ci                          # Install deps (run once after clone)
npm run app:dev                 # Dev — full Tauri app with hot reload
npm run frontend:dev            # Frontend only — Vite dev server on :1420
npm run app:build:release       # Full release (MSI, DMG, etc.)
npm run app:build:exe-only      # Executable only, no bundler

cargo check                     # Rust type check
cargo test                      # All tests
cargo clippy -- -D warnings     # Lint — CI enforces zero warnings
cargo bench                     # Criterion benchmarks (intune_pipeline)

npx tsc --noEmit                # TypeScript check
```

CI gates: `cargo fmt --all -- --check`, parser wasm32 check, `cargo check + cargo test + clippy` (Ubuntu), `npx tsc` (Node 20), Tauri build on macOS-arm64, Windows-x64, Linux-x64. `.github/workflows/cmtrace-ci.yml` is authoritative.

## Live State and History

This file holds no checkpoint SHAs or issue status. Read live state from GitHub and `git ls-remote` when you act.

- The SCCM diagnostics epic (#317) is closed. Its program plans remain in `docs/superpowers/plans/2026-07-30-sccm-*.md`.
- `codex/recovery-*` branches on origin are unreviewed evidence from the 2026-08-03 recovery. The handling rules and the per-slice gates are in `.claude/skills/cmtraceopen/references/execution-charter.md`.

## Clairvoyance Staff Org

The repo has an internal parallel agent team structure documented under `.Clairvoyance/staff/`:

| Role | Charter File | Model Tier | Notes |
|---|---|---|---|
| **CEO** | `.Clairvoyance/staff/ceo-charter.md` | Reasoning (gpt-5.6-sol, claude-opus-4-8) | Runs the org; Adam runs CEO. Owns execution board (#317), quality bar, architecture boundary, budget, truth-telling |
| **Coder** | `.Clairvoyance/staff/coder-charter.md` | Scaffold/Mid (kimi-k3/k2.7-code/grok-4-20-reasoning) | Implementation pool — one per issue lane. Red-first, anchor-grounded, worktree discipline, full gates |
| **UI/Design** | `.Clairvoyance/staff/ui-design-charter.md` | Mid (kimi-k3) | Product designer frontend engineer — stable contracts only, coverage states as first-class UI |
| **Tech Writer** | `.Clairvoyance/staff/tech-writer-charter.md` | Scaffold (kimi-k2.7-code) | Docs from merged code only — no unshipped behavior documented |
| **Code Reviewer** | `.Clairvoyance/staff/code-review-charter.md` | Reasoning | Contract, adversarial, then mechanical review layers; reports gate states, never merges |
| **Reducer Contract / Adversary / Integration** | `.Clairvoyance/staff/reducer-*-charter.md` | Reasoning or Mid (per charter) | Reducer semantics, false-story testing, restack and exact-head conformance |

`.Clairvoyance/staff/roger/index.md` and `.Clairvoyance/staff/theo/index.md` route to personal notes that are not checked in; treat those routes as empty.

## Lanes and Worktrees

- Issue lanes are git worktrees under `.worktrees/<lane>` (gitignored), one branch per lane, cut from `origin/main`.
- `.cargo/config.toml` pins the build output to `src-tauri/target`, so every worktree carries its own multi-GB target directory. Run `cargo clean` in a lane before `git worktree remove`; removing the worktree does not delete its branch.
- Origin carries many parallel `codex/*` lane branches from agent sessions. A branch existing is not evidence it was reviewed or merged.

## Model Tiering

Tiers and their scopes are defined in `soul.md`. Scaffold-tier delegation and the grading every model must pass are in `.claude/skills/cmtraceopen/references/scaffold-pipeline.md`.

## Hard Rules Recap (The Core Three)

From the execution charter and the Clairvoyance charters; these override everything:

1. **No backward-compat → Remove obsolete paths, never add fallbacks**
2. **Simplest implementation wins — no speculative abstractions, no unfinished complexity**  
3. **Evidence over assumption — missing/malformed = coverage gap, not "good"**

## Key File Paths (Quick Reference)

| Purpose | Path |
|---|---|
| Agent soul (this file's sibling) | `soul.md` |
| Agent memory (this) | `memory.md` |
| Execution charter and per-slice gates | `.claude/skills/cmtraceopen/references/execution-charter.md` |
| Dev architecture | `.Clairvoyance/library.md`, `CLAUDE.md` |
| Staff org charters | `.Clairvoyance/staff/` |
| Scaffold-tier delegation | `.claude/skills/cmtraceopen/references/scaffold-pipeline.md` |
| Execution plans | `docs/superpowers/plans/2026-07-30-sccm-*.md` (7 docs) |
| Specs | `docs/superpowers/specs/` |
| Collection scripts | `scripts/collection/`, profile `scripts/collection/intune-evidence-profile.json` |
