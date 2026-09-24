# SCCM BGB Configured Root Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure production discovery marks advanced BGB capture observed only when the management-point root came from a successfully read `Log Directory` registry fact.

**Architecture:** Add a private enum to each `SccmCaptureRoot` recording whether its path came from a configured role log directory, the site installation fallback, a service executable, or a platform default. Normal collection may use every trusted root origin; advanced BGB assembly admits only `ConfiguredRoleLogDirectory`, clears injected advanced facts, and keeps every inferred/fallback origin operator-declared.

**Tech Stack:** Rust 1.88, `winreg`, Tauri v2, Cargo tests, Vitest/TypeScript, GitHub Actions, `gh` CLI.

---

### Task 1: Preserve native root origin

**Files:**
- Modify: `src-tauri/src/sccm/collector/mod.rs`
- Modify: `src-tauri/src/sccm/collector/discovery.rs`
- Test: `src-tauri/src/sccm/collector/discovery.rs`

- [x] **Step 1: Add failing production-path assembly tests**

Cover genuine configured MP root, unreadable/missing MP `Log Directory` with an existing default root, site-install fallback, mismatched root origin, and pre-injected advanced facts. Assert only the genuine configured fact creates `advanced-client-notification-bgb` with `managementPoint` / `configuredRoleLogRoot`.

- [x] **Step 2: Run the focused tests red**

Run `cargo test --locked -p cmtrace-open --lib production_assembly_ --all-features`. Expected: fallback/default cases incorrectly become observed until root origin is preserved.

- [x] **Step 3: Add the private root-origin enum**

Add explicit variants for configured role registry paths, site-install roots/fallbacks, service-executable roots, and default locations. Populate the variant at the same branch where discovery chooses each path; do not infer provenance later from path shape or existence.

- [x] **Step 4: Gate advanced assembly on configured provenance**

Clear `advanced_source_facts`, require both observed `ManagementPoint` role and a `ManagementPoint` root whose origin is `ConfiguredRoleLogDirectory`, then emit the existing closed BGB fact. Never promote site/default/service roots.

- [x] **Step 5: Run focused discovery and capture tests green**

Run the production assembly tests plus advanced capture, IPC, and native collection suites. Expected: genuine configured roots yield observed manifest role/path provenance and every fallback remains operator-declared.

### Task 2: Update root fixtures without weakening production

**Files:**
- Modify only Rust tests/fixtures that construct `SccmCaptureRoot` directly.

- [x] **Step 1: Assign explicit fixture origins**

Use the origin represented by each fixture; do not add a default/fallback constructor that could silently turn a test root into configured evidence.

- [x] **Step 2: Run full Rust contracts**

Run intake/privacy/timestamp/#507 framing and tail tests, then full parser and app workspaces. Expected: all pass with advanced payload budgets, provenance, and `parser_eligible=false` unchanged.

### Task 3: Quality and hosted artifact gates

**Files:**
- Verify all changed Rust and existing SCCM TypeScript surfaces.

- [x] **Step 1: Run local quality gates**

Run focused SCCM Vitest, TypeScript, frontend build, strict parser/app clippy, scoped rustfmt, `git diff --check`, and verify both existing #500 routes plus this route occur exactly once.

- [x] **Step 2: Integrate current main if needed and freeze**

Fetch `origin/main`; if it advanced beyond `bba7eea9176cf7ae25d4a417216fb036320b15c3`, merge that exact commit, rerun affected combined gates, and record both merge parents. Commit and push one new frozen head without merging PR #500.

- [ ] **Step 3: Verify exact hosted MSI**

Wait for exact-head CI success, download only that run's `cmtrace-open-Windows-x64` artifact into a fresh SHA-keyed directory, and independently verify MSI filename, bytes, SHA-256, and `sourceCommit` provenance.

- [ ] **Step 4: Publish sanitized evidence**

Post target/base/parents, claims, reproduction results, exact CI/artifact evidence, and residual formatting baseline to PR #500. Do not request or post raw SCCM data.
