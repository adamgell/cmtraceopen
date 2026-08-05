# SCCM Advanced Capture Main Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate SCCM advanced capture PR #500 onto current main while preserving both the accepted #409 privacy grammar and the advanced capture provenance, budget, and parser-ineligible contracts.

**Architecture:** Merge current main into the existing PR branch once, resolve only the overlapping intake/test/dependency seams, and keep normal server sources owned exclusively by the catalog. Advanced source IDs remain capture-contract identifiers validated by the advanced branch; they never become normal parser source catalog entries or semantic evidence.

**Tech Stack:** Git, Rust 1.88, Cargo, Tauri v2, React/TypeScript, Vitest, GitHub Actions, `gh` CLI.

---

## File structure

- Modify `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`: retain #409 opaque identity validators and catalog-owned normal source IDs while preserving the isolated advanced-capture validation branch.
- Modify `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`: retain #409 Unicode/personal-name regressions and PR #500 capture-contract/provenance/budget/parser-ineligible tests.
- Modify `src-tauri/Cargo.toml`: retain current-main dependency floors and every PR #500 advanced integration-test registration.
- Retain `Cargo.lock`: preserve the branch's `getrandom` dependency while regenerating only if Cargo requires it.
- Modify `library.md`: retain main routes and add this integration route.
- Create this plan as the durable integration and evidence checklist.

### Task 1: Freeze and merge the accepted parents

**Files:**
- Modify only conflict paths listed above plus the plan/library route.

- [x] **Step 1: Record exact parent identities and cleanliness**

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git merge-base HEAD origin/main
```

Expected: PR head is `078892967cd07ff288a2f3a8e460563983aff1d5`, current main is `e59aed306b4f8f5ee1b862970169a26b24886f4d`, and only this plan/library route is uncommitted.

- [x] **Step 2: Merge current main without committing**

```bash
git merge --no-commit --no-ff e59aed306b4f8f5ee1b862970169a26b24886f4d
```

Result: Git auto-merged the three overlapping code paths. `library.md` was the only textual conflict because the integration-plan route and main's #409 route were concurrent; both routes were retained.

- [x] **Step 3: Resolve intake around ownership, not compatibility**

Keep `is_declared_server_source_id` as the sole normal-source membership check. Keep advanced IDs behind `captureContract` validation and preserve `operatorDeclared`/`observed` provenance, per-source budgets, and `parser_eligible=false`. Keep the exact synthetic identity grammar:

```rust
fn synthetic_identity(value: &str, domain: &str) -> bool {
    let Some((actual_domain, digest)) = value
        .strip_prefix("synthetic:")
        .and_then(|value| value.split_once(":sha256.v1:"))
    else {
        return false;
    };
    actual_domain == domain
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
```

- [x] **Step 4: Resolve tests and manifests additively**

Keep the #409 `alice-smith` and `ALC-CM0１` fail-closed cases. Keep every advanced capture test registration and the current-main dependency floor. Confirm `Cargo.lock` still contains `getrandom` and no package is silently removed.

### Task 2: Prove the privacy and source-catalog boundary

**Files:**
- Test `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`
- Test `crates/cmtraceopen-parser/tests/sccm_server_advanced_roles_catalog.rs`
- Test `src-tauri/tests/sccm_advanced_server_capture.rs`

- [x] **Step 1: Run exact privacy regressions**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake server_intake_rejects_personal_name_shaped_synthetic_identities
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake server_intake_rejects_unicode_and_malformed_synthetic_identities_without_panicking
```

Expected: both pass; `alice-smith` is rejected on every identity-bearing field and `ALC-CM0１` returns a typed error without panic.

- [x] **Step 2: Prove advanced IDs are not normal catalog IDs**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
rg -n 'smspxe|CloudMgr|ProxyConnector|BgbServer|srsrp|crp' crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs
```

Expected: catalog tests pass and the production normal-source catalog scan has no advanced source literals.

- [x] **Step 3: Run complete intake and advanced native contracts**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtrace-open --test sccm_advanced_ipc --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
```

Expected: all pass with operator-declared rows unsupported/parser-ineligible and all capture budgets/provenance intact.

### Task 3: Run combined local gates

**Files:**
- Verify all changed Rust and TypeScript surfaces.

- [x] **Step 1: Run parser/privacy/timestamp/native matrix**

```bash
cargo test --locked -p cmtraceopen-parser
cargo test --locked -p cmtraceopen-parser --test issue_413_unicode_panics
cargo test --locked -p cmtraceopen-parser --lib signless
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract signless_ccm_fraction_is_not_timeline_orderable
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory_compliance_metering_fixture_contract signless_fractional_tail_is_not_usable_recovery_chronology
cargo test --locked -p cmtraceopen-parser --test sccm_client_management_fixture_contract additive_timestamp_and_capture_chronology_mutations_fail_closed
```

Expected: every suite passes.

- [x] **Step 2: Run frontend contracts**

```bash
npx vitest run src/lib/commands.test.ts src/workspaces/sccm/SccmWorkspace.test.tsx src/workspaces/sccm/sccm-store.test.ts
npx tsc --noEmit
npm run frontend:build
```

Expected: every command exits zero.

- [x] **Step 3: Run strict quality gates**

```bash
cargo fmt --all -- --check
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
git diff --check
```

Result: both clippy commands, the scoped rustfmt check over the PR Rust delta, and `git diff --check` pass. Full-repository `cargo fmt --all -- --check` remains red on pre-existing out-of-scope Intune, Jamf, and elevation formatting drift; no unrelated files were reformatted for this integration.

### Task 4: Freeze, push, and publish evidence

**Files:**
- Update PR #500 body/comment with sanitized evidence only.

- [ ] **Step 1: Commit one integration artifact**

```bash
git add Cargo.lock crates/cmtraceopen-parser src-tauri src library.md docs/superpowers/plans/2026-08-05-sccm-advanced-capture-main-integration.md
git commit
git rev-parse HEAD
```

Expected: one merge commit whose second parent is `e59aed306b4f8f5ee1b862970169a26b24886f4d`.

- [ ] **Step 2: Push the exact branch head**

```bash
git push origin HEAD:codex/sccm-advanced-server-capture
```

Expected: remote PR #500 head equals the frozen local SHA.

- [ ] **Step 3: Inspect hosted checks and retrieve only a matching MSI**

Use `gh pr checks 500 --watch`. If a Windows workflow attached to the frozen SHA publishes an MSI, download it to a temporary review directory and record its workflow run, artifact name, size, and SHA-256. Never reuse the old `078892` artifact.

- [ ] **Step 4: Update PR #500 with the evidence pack**

Include target/base/parent SHAs, conflict resolutions, privacy/catalog assertions, exact commands/results, hosted CI/package state, and remaining Windows-only Registry/CIM/reparse validation. Do not include raw SCCM/server evidence.

## Self-review

- Spec coverage: merge ownership, #409 privacy, advanced capture isolation, dependency/test registrations, combined gates, push, CI/MSI, and PR evidence each have an explicit task.
- Placeholder scan: no deferred implementation markers or compatibility paths are introduced.
- Type consistency: existing parser and advanced capture types remain authoritative; integration adds no replacement wire type.
