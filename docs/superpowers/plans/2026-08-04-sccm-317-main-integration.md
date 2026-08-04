# SCCM Epic #317 Main Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the independently accepted SCCM diagnostics candidate with current `origin/main`, preserve both product lines at the two conflicting seams, and produce a newly validated frozen SHA for PR #490.

**Architecture:** Merge `origin/main` into the dedicated SCCM worktree so the reviewed SCCM history remains inspectable. Keep the parser crate's new private wire module alongside the public SCCM module, and accept main's application-wide elevation replacement by deleting the obsolete ESP-specific relaunch module. Re-run the complete cross-platform gate, compare formatting against main's inherited baseline, and obtain independent review of the new merge SHA before changing PR readiness.

**Tech Stack:** Git, Rust/Cargo, Tauri v2, TypeScript, GitHub Actions

---

### Task 1: Merge the current protected-branch head

**Files:**
- Modify: merge index only; do not edit conflict content in this task

- [ ] **Step 1: Verify the frozen input**

Run:

```bash
git merge-base --is-ancestor 112bc4b55166567095db8a76662152ebdc8720f5 HEAD
test -z "$(git status --porcelain)"
```

Expected: both commands exit `0` with no output. The accepted SHA remains an ancestor; a documentation-only integration-plan commit may follow it.

- [ ] **Step 2: Merge current main without committing**

Run:

```bash
git merge --no-ff --no-commit origin/main
```

Expected: merge stops with conflicts only in `crates/cmtraceopen-parser/src/lib.rs` and `src-tauri/src/esp/relaunch.rs`.

### Task 2: Preserve both parser crate modules

**Files:**
- Modify: `crates/cmtraceopen-parser/src/lib.rs`

- [ ] **Step 1: Resolve the module list**

Make the final module tail exactly:

```rust
pub mod intune;
pub mod models;
pub mod parser;
pub mod sccm;
pub(crate) mod wire;
```

This preserves the SCCM public API while retaining main's crate-private wire module.

- [ ] **Step 2: Verify both module trees compile**

Run:

```bash
cargo check --locked -p cmtraceopen-parser
```

Expected: `Finished` with exit `0`.

### Task 3: Accept the application-wide elevation owner

**Files:**
- Delete: `src-tauri/src/esp/relaunch.rs`
- Verify: `src-tauri/src/elevation/relaunch.rs`
- Verify: `src-tauri/src/lib.rs`

- [ ] **Step 1: Resolve the modify/delete conflict by deletion**

Run:

```bash
git rm src-tauri/src/esp/relaunch.rs
```

Expected: the obsolete ESP-specific relaunch module is staged as deleted. Current main routes elevation through `elevation::relaunch`, so retaining the old module would violate the repository's no-backward-compatibility rule.

- [ ] **Step 2: Confirm no production reference retains the obsolete owner**

Run:

```bash
rg -n "esp::relaunch|mod relaunch" src-tauri/src/esp src-tauri/src/lib.rs
```

Expected: no `esp::relaunch` or ESP-local `mod relaunch` reference.

### Task 4: Commit the integration

**Files:**
- Modify: Git merge index

- [ ] **Step 1: Confirm every conflict is resolved**

Run:

```bash
test -z "$(git diff --name-only --diff-filter=U)"
git diff --check
```

Expected: both commands exit `0` with no unresolved paths or whitespace errors.

- [ ] **Step 2: Create the merge commit**

Run:

```bash
git commit -m "merge: integrate current main into SCCM diagnostics"
```

Expected: one merge commit with parents `112bc4b5` and current `origin/main`.

### Task 5: Re-run the frozen-candidate gate

**Files:**
- Test: workspace and parser targets only; do not change code to mask failures

- [ ] **Step 1: Run the complete native workspace suite**

Run:

```bash
cargo test --locked --workspace --all-targets --quiet
```

Expected: exit `0`, including benches compiled as test targets.

- [ ] **Step 2: Run portability and lint gates**

Run:

```bash
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
```

Expected: both commands exit `0`.

- [ ] **Step 3: Run frontend and repository hygiene gates**

Run:

```bash
npx tsc --noEmit
rustfmt --edition 2021 --check --config skip_children=true crates/cmtraceopen-parser/src/lib.rs
git diff --check
test -z "$(git status --porcelain)"
```

Expected: every command exits `0` and the worktree remains clean. A detached `origin/main` comparison establishes that repo-wide `cargo fmt --all -- --check` already fails on inherited Jamf, Intune, ESP, and elevation files; do not churn those unrelated files in this integration.

### Task 6: Freeze, review, and publish the successor

**Files:**
- Verify: PR #490 head and evidence pack

- [ ] **Step 1: Record the successor SHA and obtain independent review**

Run:

```bash
git rev-parse HEAD
git show --no-patch --format='%H %P %s' HEAD
```

Expected: a clean merge SHA with exactly two parents. The critic inspects this SHA, the two conflict resolutions, and the full gate results, returning `ACCEPT` or specific rework.

- [ ] **Step 2: Publish without rewriting history**

Run:

```bash
git push origin codex/sccm333-integration-timestamp-gate
```

Expected: fast-forward update of PR #490. Keep the PR draft until authorized Windows SCCM lab evidence passes.
