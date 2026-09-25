---
name: cmtraceopen-memory
description: Durable facts about adamgell/cmtraceopen — architecture, checkpoints, workflow rules, and ecosystem state. Loaded every turn for this project.
version: 1.0.0
author: Adam Gell / Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [cmtraceopen, memory, durable-facts, architecture, checkpoints, workflow]
---

# CMTrace Open — Memory

Durable facts about `adamgell/cmtraceopen`. These are loaded into every turn when working on this project.

## Repo Facts

- **Repository:** https://github.com/adamgell/cmtraceopen
- **Stack:** Tauri v2 + React 19 + TypeScript + Rust (cmtraceopen-parser)
- **Editions:** Full (all features) and Lite (log viewer only)
- **License:** MIT (PR #384 merged at `a686daef` with provenance visible, CodeRabbit clean)
- **Distribution:** MSIs/NSIS (Windows), DMG (macOS arm64), .deb/.AppImage (Linux) + Homebrew cask + Scoop bucket
- **Main HEAD:** `a9a67422` as of 2026-08-03

## Architecture Overview

Three structural layers:

1. **Frontend** (`src/`) — React 19, TypeScript, Fluent UI, Zustand stores (log-store, filter-store, ui-store, marker-store). Workspaces: intune, esp-diagnostics, dsregcmd, sysmon, secureboot, event-log, macos-diag, jamf, timeline, deployment, dns-dhcp
2. **Backend IPC** (`src-tauri/src/`) — Tauri v2 Rust. IPC commands in `commands/`. Platform modules: intune, dsregcmd, esp, collector, state, watcher
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

CI gates: seven jobs — Source Quality (fmt, changed-range whitespace, wasm32 portability), Check & Test (Rust, both feature sets, the parser crate's tests and clippy, `cargo deny`, `cargo audit`), Rust MSRV 1.88 (Ubuntu and Windows), TypeScript Check, E2E (Playwright), ESP Diagnostics (Windows), Build (macos-arm64, Windows-x64, Linux-x64). The three-item shorthand that used to sit here came from `CLAUDE.md` and was understated in both places.

## Verified Checkpoints

All SHAs are from Adam's PM charter (`~/.hermes/cmtrace-pm-charter.md`). Reverify with `git ls-remote` before acting.

**That source is not readable on this workstation** — the path does not exist here, checked 2026-09-24 — and the CEO charter treats an unreadable contract as a fail-closed condition. So the citation above cannot be followed, and the table has to stand on its own: the SHAs are quoted in full precisely so a reader does not need the charter to verify them. If the file lives on the operator's machine only, this line should say so rather than pointing at a path a session cannot open.

**Every row below was stale when rechecked on 2026-09-24**: the four issues had all merged
weeks earlier while the table still said NOT merge-ready, hold the PR, gate pending, findings
outstanding. The SHAs are preserved on origin branches, so the rows were never wrong about the
*commits* — only about whether the work had landed. That is the failure mode this table is
supposed to prevent, and it read as current for seven weeks. Treat a row here as a pointer to
verify, never as state.

| Issue | Branch SHA | State | Blockers |
|---|---|---|---|
| #320 client health | `6ccf8dafa791ad7d07d3b7bb450e6fe31e8dfb3c` | **MERGED into `main` via #490** 2026-08-05; #340 was preparation into `codex/parser-family-skeleton` | none |
| #329 DP lifecycle | `a03af515fa692948a8fce0435c4ef34128f0bf5e` | **MERGED into `main` via #490** 2026-08-05; #385 was preparation into `codex/parser-family-skeleton` | none |
| #330 SUP coverage | `76e2b0b910d028cddbb6d9109bf124e95facdcb4` | **MERGED into `main` via #490** 2026-08-05; #377 was preparation into `codex/parser-family-skeleton` | none |
| #366 Intune CP | `04e1ecba6f2d93977d9c011427a2b7b787214d54` | **MERGED** via #460 | none |

## Recovery Branches (Evidence Only)

Never batch-merge these. Extract reviewed issue-scoped slices into fresh worktrees. Preserve refs. Check merged equivalents for closed macOS/iOS issues before any PR.

| Branch | SHA | Target Issue |
|---|---|---|
| `codex/recovery-intune365-overlay-20260803` | `9fb2f9a2d7769449cdb60ab5ab5da63107fd0437` | #365 (WUfB) |
| `codex/recovery-intune-windows-remediations-20260803` | `2e016ab65289372cec4dc0a0204ad285cee6b8ef` | #360 (remediations) |
| `codex/recovery-intune-macos-logs-20260803` | `871003949f1d1acbddbecc271497a68d2bf5d335` | macOS logs |
| `codex/recovery-intune-macos-unified-log-20260803` | `27d58a2aeee535346f8e32fa5305f0bea95b39f8` | macOS unified log |
| `codex/recovery-intune-ios-diagnostics-20260803` | `4cf3ad15f1bc4f97d21f3046bd4abc8989c18aa4` | iOS diagnostics |
| `codex/recovery-intune-ios-console-round2-20260803` | `952b48f442f761380ec8a650d6feba1b5cebe7cd` | iOS console round 2 |

**Checked 2026-09-24:** all six branches are still present on `origin`, so the refs are preserved as promised — this table is accurate about what it holds. What has changed is the *second* instruction: the targets have since landed. `#365` and `#360` are done, the macOS and iOS parser families exist on `main` (`intune/apps/macos`, `intune/portal/{macos,ios_ipados}`), and the epic tracker marks the corresponding rows complete. So these branches are now history rather than pending recovery, and "check merged equivalents" is answered rather than open — worth keeping only as evidence, which is what the heading already says.

## Execution Order (From PM Charter)

1. SUP correction → DP exact-profile → Client health → Intune CP corrections → Recovery WUfB remediator → Downstream SCCM families
2. Correlation last: starting at policy-to-MP, then content-to-DP

Per-slice gates: Red test recorded → smallest implementation → focused green → aggregate (Rust tests, full parser, wasm32, Clippy, fmt) → CodeRabbit exact diff → independent review → push reviewed commit, verify remote SHA.

## Clairvoyance Staff Org

The repo has an internal parallel agent team structure documented under `.Clairvoyance/staff/`:

| Role | Charter File | Model Tier | Notes |
|---|---|---|---|
| **CEO** | `staff/ceo-charter.md` | Reasoning (gpt-5.6-sol, claude-opus-4-8) | Runs the org; Adam runs CEO. Owns execution board (#317), quality bar, architecture boundary, budget, truth-telling |
| **Coder** | `staff/coder-charter.md` | Scaffold/Mid (kimi-k3/k2.7-code/grok-4-20-reasoning) | Implementation pool — one per issue lane. Red-first, anchor-grounded, worktree discipline, full gates |
| **UI/Design** | `staff/ui-design-charter.md` | Mid (kimi-k3) | Product designer frontend engineer — stable contracts only, coverage states as first-class UI |
| **Tech Writer** | `staff/tech-writer Charter.md` | Scaffold (kimi-k2.7-code) | Docs from merged code only — no unshipped behavior documented |

Staff notes live in each member's subdirectory:
- **Roger:** SCCM Epic #317, issues #318–#335, recovery branches, execution planning
- **Theo:** Docs-audit phases (phase 2 = `docs/audit-phase2`, phase 3 = `docs/audit-phase3`)

## Ecosystem State: The Worktree Forest

`cmtraceopen` has an extraordinary development footprint across multiple git worktree directories. This is not just "developed in Claude/Codex" — it IS a parallel development ecosystem.

- **87 git worktrees** registered, measured 2026-09-24 — counted rather than described, because the
  previous figure here read "450+": 86 in `.worktrees/`, 31 in `~/.codex/worktrees/`, and none in
  `/private/tmp/cmtraceopen-*`. The forest is real; it is a fifth of the size the layout block below
  used to claim, which is what cleaning up merged lanes does to a count nobody retakes.
- **246 SCCM branches** for issues #318 through #482 (diagnostic program: client health, intake, policy, DP, SUP, hierarchy, cross-side correlation)
- **~40 Intune branches** covering IME corrections, Company Portal multi-platform (Windows/macOS/iOS/Android), WUfB recovery, device inventory
- Many worktrees have **1,000+ commits** from main — deep parallel feature development with real code changes and merge activity

### Worktree Directory Layout
```
Users/Adam.Gell/repo/cmtraceopen/
  .worktrees/                 # 86 worktrees, all registered with `git worktree list`
  ~/.codex/worktrees/         # 31 Codex-specific worktrees
  /private/tmp/cmtraceopen-*  # none present as of 2026-09-24
```

These directories track the full state of every Claude/Codex agent session as parallel working copies.

## Model Tiering Details

| Tier | Models | Scope | Provider |
|---|---|---|---|
| Scaffold | `kimi-k2.7-code`, `deepseek-v4-flash`, `qwen-flash`, `gpt-5-luna` | Fixture matrices, test boilerplate, doc skeletons — ALWAYS with real anchors in the brief | `custom:api.llmgateway.io` |
| Mid | `kimi-k3`, `grok-4-20-reasoning` | Parser logic, reducers, diagnostic rules | Same provider |
| Reasoning | `gpt-5.6-sol`, `claude-opus-4-8` | Diagnostic contracts, cross-side correlation (#333-class), architecture decisions | Default or gateway |

> **MLX local tier is UNPROVEN** for codegen on CMTrace Open. Must pass pilot-grading gauntlet first. Max-tokens raised from 512 to 4096+ before meaningful tests.

## Hard Rules Recap (The Core Three)

From Adam's handoff and the Clairvoyance charters — these override everything:

1. **No backward-compat → Remove obsolete paths, never add fallbacks**
2. **Simplest implementation wins — no speculative abstractions, no unfinished complexity**  
3. **Evidence over assumption — missing/malformed = coverage gap, not "good"**

## Key File Paths (Quick Reference)

| Purpose | Path |
|---|---|
| Agent soul (this file's sibling) | `soul.md` |
| Agent memory (this) | `memory.md` |
| PM charter / checkpoints | `~/.hermes/cmtrace-pm-charter.md` |
| Dev architecture | `.Clairvoyance/library.md`, `CLAUDE.md` |
| Staff org charters | `.Clairvoyance/staff/` |
| Scaffold pipeline skill | `~/.hermes/skills/software-development/cmtrace-scaffold-pipeline/` |
| Execution plans | `docs/superpowers/plans/2026-07-30-sccm-*.md` (7 docs) |
| Specs | `.Clairvoyance/specs/2026-*/` |
| Collection scripts | `scripts/collection/` + `intune-evidence-profile.json` |
