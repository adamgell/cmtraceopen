# Intune Parser Family Phase 0A Truth and Quality Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record the approved issue #356 contract, reconcile the live epic tracker, establish one behavior-free Rust formatting baseline, and enforce formatting, whitespace, and parser wasm portability on pull requests targeting `main` or `codex/parser-family-skeleton` and on pushes to either branch.

**Architecture:** This is the first independently reviewable sub-project from the approved closeout design. It changes no parser or application behavior: documentation and GitHub establish program truth, one mechanical commit removes inherited rustfmt drift, and one dedicated GitHub Actions job enforces the three source-quality gates before later Intune slices build on the repository.

**Tech Stack:** Git, GitHub CLI, GitHub Actions YAML, Rust 1.92.0 rustfmt, Cargo, wasm32-unknown-unknown, Node.js built-in test runner, actionlint

**Spec:** `docs/superpowers/specs/2026-08-29-intune-parser-family-closeout-design.md`

**ADR:** `docs/architecture/decisions/ADR-004-redaction-scope-revision-2.md`

## Global Constraints

- Execute in a fresh issue-scoped worktree created from the exact current `origin/main`; never edit, clean, reset, rebase, or merge the dirty primary checkout.
- Do not add compatibility layers, fallbacks, migrations, dual readers, or deprecated facades.
- Keep `cmtraceopen-parser` pure Rust and compatible with `wasm32-unknown-unknown`; no OS I/O, registry, WMI, Tauri, network, database, or live collection enters the parser crate.
- Missing, denied, capped, skipped, unsupported, unknown-version, malformed, and partial evidence remain coverage states and never imply success.
- Do not create fixtures or introduce customer, tenant, account, device, secret, private URL, or raw diagnostic data in this sub-project.
- The formatter baseline is mechanical only. A semantic edit discovered in a formatting hunk is removed and handled by its owning vertical slice.
- Rust formatting is pinned to toolchain `1.92.0` for this gate; the crate's declared MSRV remains `1.88` and its existing MSRV CI job remains unchanged.
- Each commit contains one reviewable concern. Push exact committed work and verify the remote SHA before reporting it.
- Do not merge the resulting pull request. CodeRabbit and independent review establish readiness; the repository owner decides integration.

## Program Decomposition

The approved design spans independent systems and is intentionally executed as separate plans. This plan delivers the first working foundation. Subsequent plans are written from the then-current integrated contracts in this order:

1. canonical IME/ESP ownership and obsolete-path deletion;
2. Intune fixture provenance classes and admission audit;
3. accepted redaction foundation, ESP projected publication, V2 native replay, and #366 pilot;
4. acceptance ledger, signer policy, validators, clean-candidate runner, and fresh-clone verifier;
5. existing-lane debt for #354, #357, #359, #360, #366, #367, and #372;
6. native handoffs for #357, #358, #362, #363, #364, #368, and #370;
7. new leaf implementations for #365, #361, #369, and #371;
8. exact-candidate native evidence, aggregate proof, tracker reconciliation, and epic closure.

Each later plan must leave a working product at its own review boundary. Recovery branches remain donor evidence and are never integration bases.

---

### Task 1: Materialize the Accepted Contract on Current Main

**Files:**
- Create: `docs/superpowers/specs/2026-08-29-intune-parser-family-closeout-design.md`
- Create: `docs/architecture/decisions/ADR-004-redaction-scope-revision-2.md`
- Create: `docs/superpowers/plans/2026-08-30-intune-parser-family-phase-0a-truth-and-quality-gates.md`

**Interfaces:**
- Consumes: the reviewed planning branch `origin/codex/issue356-epic-closeout-20260829`, whose history begins at audited baseline `59679c06b5dd1f5d59849a14d527f4b262b30a1c`.
- Produces: the accepted spec, accepted ADR, and this executable plan in the Phase 0A branch without importing product code from the planning branch.

- [ ] **Step 1: Verify the execution base and planning input**

Run:

```bash
(
set -euo pipefail
git fetch --prune origin
execution_base="$(git rev-parse origin/main)"
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
verified_planning_head=1b2d06b6b57b88b5cab29e03fc7858cbe6dcc2ae
remote_planning_head="$(git ls-remote origin refs/heads/codex/issue356-epic-closeout-20260829 | awk '{print $1}')"
test "$execution_base" = "$remote_main"
test "$remote_planning_head" = "$verified_planning_head"
git cat-file -e "${verified_planning_head}^{commit}"
git merge-base --is-ancestor 59679c06b5dd1f5d59849a14d527f4b262b30a1c "$verified_planning_head"
planning_commits="$(git rev-list --reverse 59679c06b5dd1f5d59849a14d527f4b262b30a1c.."$verified_planning_head")"
test -n "$planning_commits"
planning_paths="$(
  while IFS= read -r commit; do
    git diff-tree --no-commit-id --name-only -r -m "$commit" || exit 1
  done <<< "$planning_commits"
)"
diff -u \
  <(printf '%s\n' \
    docs/architecture/decisions/ADR-004-redaction-scope-revision-2.md \
    docs/superpowers/plans/2026-08-30-intune-parser-family-phase-0a-truth-and-quality-gates.md \
    docs/superpowers/specs/2026-08-29-intune-parser-family-closeout-design.md | sort) \
  <(printf '%s\n' "$planning_paths" | sort -u)
)
```

Expected: local and remote `main` are identical; the planning branch resolves once
to accepted immutable SHA `1b2d06b6b57b88b5cab29e03fc7858cbe6dcc2ae`; that
literal is a commit descending from the audited baseline; and every commit in
that exact range touches only the spec, ADR, and this plan.

- [ ] **Step 2: Import only the approved documentation history**

Run:

```bash
git cherry-pick 59679c06b5dd1f5d59849a14d527f4b262b30a1c..1b2d06b6b57b88b5cab29e03fc7858cbe6dcc2ae
git diff --name-only origin/main...HEAD | sort
```

Expected: the cherry-pick succeeds without conflict and the branch differs from `origin/main` only in the three documentation paths named above.

- [ ] **Step 3: Verify accepted authority and plan integrity**

Run:

```bash
test "$(rg -o 'ACCEPTED by the repository owner on 2026-08-30' docs/architecture/decisions/ADR-004-redaction-scope-revision-2.md | wc -l | tr -d ' ')" = 1
test "$(rg -o 'approved this design plus ADR-004 Revision 2' docs/superpowers/specs/2026-08-29-intune-parser-family-closeout-design.md | wc -l | tr -d ' ')" = 1
test "$(rg -o '^# Intune Parser Family Phase 0A Truth and Quality Gates Implementation Plan' docs/superpowers/plans/2026-08-30-intune-parser-family-phase-0a-truth-and-quality-gates.md | wc -l | tr -d ' ')" = 1
git diff --check origin/main...HEAD
```

Expected: each authority marker appears once and the imported documentation range has no whitespace errors.

### Task 2: Reconcile the Live Epic Tracker

**Files:**
- Modify externally: GitHub issue #356 body and comments
- Modify externally: closed child issues #357, #358, #359, #360, #362, #363, #364, #366, #367, #368, #370, and #372 comments

**Interfaces:**
- Consumes: live GitHub child state and the approved current-state table in the spec.
- Produces: a 12-closed/5-open tracker whose checkboxes match issue state while preserving the distinction between closure history and accepted closeout evidence.

- [ ] **Step 1: Reproduce the stale tracker state**

Run:

```bash
(
set -euo pipefail
for issue in 354 357 358 359 360 361 362 363 364 365 366 367 368 369 370 371 372; do
  gh issue view "$issue" --repo adamgell/cmtraceopen --json number,state,title --jq '[.number,.state,.title] | @tsv'
done
gh issue view 356 --repo adamgell/cmtraceopen --json body --jq .body | rg '^\s*- \[[ x]\] #[0-9]+'
)
```

Expected: live state is 12 closed and five open; #354, #361, #365, #369, and #371 are open; the epic body still leaves closed #357 and #363 unchecked.

- [ ] **Step 2: Correct only the two stale checkboxes**

Run:

```bash
(
set -euo pipefail
: "${ISSUE_356_BODY_EDIT_LEASE:?repository owner must hold the exclusive issue #356 body-edit lease}"
test "$ISSUE_356_BODY_EDIT_LEASE" = repository-owner-held-exclusive
original_body_file="$(mktemp)"
updated_body_file="$(mktemp)"
prewrite_body_file="$(mktemp)"
postwrite_body_file="$(mktemp)"
gh api repos/adamgell/cmtraceopen/issues/356 | jq -jr .body > "$original_body_file"
test "$(rg -c -- '- \[ \] #357([^0-9]|$)' "$original_body_file")" = 1
test "$(rg -c -- '- \[ \] #363([^0-9]|$)' "$original_body_file")" = 1
sed -E 's/- \[ \] #357([^0-9]|$)/- [x] #357\1/; s/- \[ \] #363([^0-9]|$)/- [x] #363\1/' \
  "$original_body_file" > "$updated_body_file"
test "$(rg -c -- '- \[x\] #357([^0-9]|$)' "$updated_body_file")" = 1
test "$(rg -c -- '- \[x\] #363([^0-9]|$)' "$updated_body_file")" = 1
gh api repos/adamgell/cmtraceopen/issues/356 | jq -jr .body > "$prewrite_body_file"
cmp -s "$original_body_file" "$prewrite_body_file"
jq -Rs '{body: .}' "$updated_body_file" \
  | gh api --method PATCH repos/adamgell/cmtraceopen/issues/356 --input - >/dev/null
gh api repos/adamgell/cmtraceopen/issues/356 | jq -jr .body > "$postwrite_body_file"
cmp -s "$updated_body_file" "$postwrite_body_file"
)
```

`ISSUE_356_BODY_EDIT_LEASE=repository-owner-held-exclusive` means the repository
owner has exclusively reserved issue #356 body editing for this operation.
GitHub does not support conditional unsafe `PATCH` requests for this endpoint,
so the lease plus exact immediate pre-write and post-write byte comparisons is
the required serialization path. Expected: the stale pre-write check succeeds,
GitHub updates #356, and the post-write body exactly matches `updated_body`.

- [ ] **Step 3: Verify the corrected body against live state**

Run:

```bash
(
set -euo pipefail
tracker_lines="$(gh issue view 356 --repo adamgell/cmtraceopen --json body --jq .body | rg '^\s*- \[[ x]\] #[0-9]+')"
test "$(printf '%s\n' "$tracker_lines" | rg -c '^\s*- \[[ x]\] #[0-9]+')" = 17
test "$(printf '%s\n' "$tracker_lines" | rg -c '^\s*- \[x\] #[0-9]+')" = 12
test "$(printf '%s\n' "$tracker_lines" | rg -c '^\s*- \[ \] #[0-9]+')" = 5
diff -u \
  <(printf '%s\n' 354 361 365 369 371) \
  <(printf '%s\n' "$tracker_lines" | sed -nE 's/^[[:space:]]*-[[:space:]]+\[ \][[:space:]]+#([0-9]+).*/\1/p' | sort -n)
)
```

Expected: exactly 12 entries are `[x]`; only #354, #361, #365, #369, and #371 remain `[ ]`.

- [ ] **Step 4: Record approval and the acceptance distinction on the epic**

Run:

```bash
(
set -euo pipefail
main_sha="$(git rev-parse origin/main)"
printf '%s\n' \
  'Repository-owner approval recorded on 2026-08-30.' \
  '' \
  "Approved closeout contract: codex/issue356-epic-closeout-20260829, verified against origin/main ${main_sha}." \
  '' \
  'The tracker now matches live issue state at 12 closed / 5 open. A checked box records child-issue closure history only; it is not final native, provenance, redaction, exact-head, or aggregate acceptance evidence. The approved closeout design remains the authority for every child row.' \
  | gh issue comment 356 --repo adamgell/cmtraceopen --body-file -
)
```

Expected: one new issue #356 comment records approval, the exact current-main SHA, and the evidence limitation.

- [ ] **Step 5: Annotate every closed child without reopening it prematurely**

Run:

```bash
(
set -euo pipefail
for issue in 357 358 359 360 362 363 364 366 367 368 370 372; do
  printf '%s\n' \
    'Issue #356 closeout audit note (2026-08-30): this issue remains closed as implementation history, but closure is not final epic acceptance evidence.' \
    '' \
    "The approved closeout contract for #${issue} is the matching row in docs/superpowers/specs/2026-08-29-intune-parser-family-closeout-design.md. Its issue-scoped plan must reproduce each remaining provenance, application/native, redaction, and exact-head criterion against current main before the epic can use this row as accepted evidence." \
    | gh issue comment "$issue" --repo adamgell/cmtraceopen --body-file -
done
)
```

Expected: each closed child receives one policy annotation with its own issue number. No issue is reopened by this task; a lane plan may reopen its original issue only after reproducing a missing acceptance criterion.

- [ ] **Step 6: Prove failed reads and comments stop before later mutations**

Run this local negative proof. Its substituted commands do not contact GitHub:

```bash
failed_read_marker="$(
  bash -c 'set -euo pipefail; issue_body="$(false)"; printf edit-reached' \
    2>/dev/null || true
)"
test -z "$failed_read_marker"

failed_comment_marker="$(
  bash -c '
    set -euo pipefail
    for issue in 357 358; do
      if test "$issue" = 357; then
        printf body | false
      else
        printf body | true
      fi
    done
    printf later-comment-reached
  ' 2>/dev/null || true
)"
test -z "$failed_comment_marker"

changed_prewrite_marker="$(
  bash -c '
    set -euo pipefail
    original_body_file="$(mktemp)"
    prewrite_body_file="$(mktemp)"
    printf original > "$original_body_file"
    printf changed > "$prewrite_body_file"
    if cmp -s "$original_body_file" "$prewrite_body_file"; then
      printf edit-reached
    fi
  '
)"
test -z "$changed_prewrite_marker"
```

Expected: all three assertions exit `0`. A failed precondition read prevents the
edit marker, a changed pre-write body prevents the edit marker, and a failed
earlier child comment prevents all later loop work.

### Task 3: Establish the Mechanical Rustfmt Baseline

**Files:**
- Modify: `crates/cmtraceopen-parser/src/collector/profile.rs`
- Modify: `crates/cmtraceopen-parser/src/esp/redaction.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/reducer.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/apps/windows/win32/findings.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/apps/windows/win32/reducer.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/device/windows/compliance/reducer.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/reducer.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/event_tracker.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/ime_parser.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/normalized.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs`
- Modify: `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/mod.rs`
- Modify: `crates/cmtraceopen-parser/tests/esp_export_boundary.rs`
- Modify: `crates/cmtraceopen-parser/tests/intune_skeleton_contract.rs`
- Modify: `crates/cmtraceopen-parser/tests/intune_windows_autopilot.rs`
- Modify: `crates/cmtraceopen-parser/tests/intune_windows_compliance.rs`
- Modify: `crates/cmtraceopen-parser/tests/intune_windows_configuration.rs`
- Modify: `crates/cmtraceopen-parser/tests/intune_windows_microsoft_store_semantics.rs`
- Modify: `crates/cmtraceopen-parser/tests/support/mod.rs`
- Modify: `src-tauri/src/commands/intune.rs`
- Modify: `src-tauri/src/event_log/mod.rs`

**Interfaces:**
- Consumes: current-main Rust source and rustfmt from Rust `1.92.0`.
- Produces: a behavior-free formatting commit after which `cargo +1.92.0 fmt --all -- --check` is green.

- [ ] **Step 1: Install and verify the pinned formatter**

Run:

```bash
rustup toolchain install 1.92.0 --profile minimal --component rustfmt
cargo +1.92.0 fmt --version
```

Expected: the command reports rustfmt from Rust `1.92.0`.

- [ ] **Step 2: Record the failing formatting gate**

Run:

```bash
cargo +1.92.0 fmt --all -- --check
```

Expected: FAIL with formatting diffs in the 23 files listed for this task. This RED result is inherited baseline debt, not a product-behavior failure.

- [ ] **Step 3: Apply only rustfmt output**

Run:

```bash
cargo +1.92.0 fmt --all
```

Expected: rustfmt exits `0` and changes tracked Rust source/tests only.

- [ ] **Step 4: Prove the path allowlist**

Run:

```bash
diff -u \
  <(printf '%s\n' \
    crates/cmtraceopen-parser/src/collector/profile.rs \
    crates/cmtraceopen-parser/src/esp/redaction.rs \
    crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs \
    crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/reducer.rs \
    crates/cmtraceopen-parser/src/intune/apps/windows/win32/findings.rs \
    crates/cmtraceopen-parser/src/intune/apps/windows/win32/reducer.rs \
    crates/cmtraceopen-parser/src/intune/device/windows/compliance/reducer.rs \
    crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs \
    crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/reducer.rs \
    crates/cmtraceopen-parser/src/intune/event_tracker.rs \
    crates/cmtraceopen-parser/src/intune/ime_parser.rs \
    crates/cmtraceopen-parser/src/intune/normalized.rs \
    crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs \
    crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/mod.rs \
    crates/cmtraceopen-parser/tests/esp_export_boundary.rs \
    crates/cmtraceopen-parser/tests/intune_skeleton_contract.rs \
    crates/cmtraceopen-parser/tests/intune_windows_autopilot.rs \
    crates/cmtraceopen-parser/tests/intune_windows_compliance.rs \
    crates/cmtraceopen-parser/tests/intune_windows_configuration.rs \
    crates/cmtraceopen-parser/tests/intune_windows_microsoft_store_semantics.rs \
    crates/cmtraceopen-parser/tests/support/mod.rs \
    src-tauri/src/commands/intune.rs \
    src-tauri/src/event_log/mod.rs | sort) \
  <(git diff --name-only | sort)
```

Expected: no output and exit `0`. Any additional path blocks this commit.

- [ ] **Step 5: Inspect the mechanical diff and turn the gate green**

Run:

```bash
git diff --stat
git diff --word-diff=plain
cargo +1.92.0 fmt --all -- --check
git diff --check
```

Expected: review shows layout-only changes, the formatter check passes, and Git reports no whitespace errors.

- [ ] **Step 6: Verify formatting did not change behavior**

Run:

```bash
cargo test --locked -p cmtraceopen-parser
cargo check --locked --workspace --all-features
```

Expected: both commands exit `0`. Test counts are recorded in the issue/PR evidence rather than inferred from the formatter result.

- [ ] **Step 7: Commit the mechanical baseline**

Run:

```bash
formatter_files=(
  crates/cmtraceopen-parser/src/collector/profile.rs
  crates/cmtraceopen-parser/src/esp/redaction.rs
  crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs
  crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/reducer.rs
  crates/cmtraceopen-parser/src/intune/apps/windows/win32/findings.rs
  crates/cmtraceopen-parser/src/intune/apps/windows/win32/reducer.rs
  crates/cmtraceopen-parser/src/intune/device/windows/compliance/reducer.rs
  crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs
  crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/reducer.rs
  crates/cmtraceopen-parser/src/intune/event_tracker.rs
  crates/cmtraceopen-parser/src/intune/ime_parser.rs
  crates/cmtraceopen-parser/src/intune/normalized.rs
  crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs
  crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/mod.rs
  crates/cmtraceopen-parser/tests/esp_export_boundary.rs
  crates/cmtraceopen-parser/tests/intune_skeleton_contract.rs
  crates/cmtraceopen-parser/tests/intune_windows_autopilot.rs
  crates/cmtraceopen-parser/tests/intune_windows_compliance.rs
  crates/cmtraceopen-parser/tests/intune_windows_configuration.rs
  crates/cmtraceopen-parser/tests/intune_windows_microsoft_store_semantics.rs
  crates/cmtraceopen-parser/tests/support/mod.rs
  src-tauri/src/commands/intune.rs
  src-tauri/src/event_log/mod.rs
)
git add -- "${formatter_files[@]}"
diff -u \
  <(printf '%s\n' "${formatter_files[@]}" | sort) \
  <(git diff --cached --name-only | sort)
git commit -m "style(rust): establish formatter baseline"
```

Expected: one commit containing exactly the 23 allowlisted Rust files and no documentation or workflow changes.

### Task 4: Add Executable Source-Quality CI Coverage

**Files:**
- Create: `.github/scripts/source-quality-workflow.test.mjs`
- Modify: `.github/workflows/cmtrace-ci.yml`

**Interfaces:**
- Consumes: the clean Rustfmt baseline from Task 3, GitHub pull-request/push event SHAs, and the existing pinned checkout/Rust setup actions.
- Produces: a `source-quality` CI job that runs Rust 1.92.0 rustfmt, parser wasm check, and commit-range whitespace validation; a Node contract test pins the required workflow structure.

- [ ] **Step 1: Write the failing workflow contract test**

Create `.github/scripts/source-quality-workflow.test.mjs` with:

```javascript
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowUrl = new URL("../workflows/cmtrace-ci.yml", import.meta.url);

function assertRequiredTriggers(workflow) {
  assert.match(
    workflow,
    /^on:\n  push:\n    branches: \[main, codex\/parser-family-skeleton\]\n  pull_request:\n(?:    #.*\n)*    branches: \[main, codex\/parser-family-skeleton\]$/m,
    "required push and pull-request branch triggers missing"
  );
}

function sourceQualityJob(workflow) {
  const sourceQuality = workflow.match(/^  source-quality:\n/m);
  assert.ok(sourceQuality, "source-quality job missing");

  const jobLines = [];
  for (const line of workflow.slice(sourceQuality.index + sourceQuality[0].length).split("\n")) {
    if (line === "" || /^ {4}/.test(line)) {
      jobLines.push(line);
    } else {
      break;
    }
  }

  return jobLines.join("\n");
}

function assertSourceQualityRequirements(workflow) {
  const job = sourceQualityJob(workflow);

  assert.match(job, /^    steps:\n/m, "source-quality steps missing");
  assert.match(
    job,
    /^      - uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1\n        with:\n          fetch-depth: 0\n          persist-credentials: false$/m,
    "full-history credential-free checkout missing"
  );
  assert.match(
    job,
    /^      - name: Setup pinned Rust quality toolchain\n        uses: dtolnay\/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n        with:\n          toolchain: "1\.92\.0"\n          components: rustfmt\n          targets: wasm32-unknown-unknown$/m,
    "pinned rustfmt and wasm toolchain missing"
  );
  assert.match(
    job,
    /^      - name: Rust formatting\n        run: cargo fmt --all -- --check$/m,
    "format gate missing"
  );
  assert.match(
    job,
    /^      - name: Parser wasm portability\n        run: cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown$/m,
    "parser wasm gate missing"
  );
  assert.match(
    job,
    /^          if \[\[ "\$GITHUB_EVENT_NAME" == "pull_request" \]\]; then\n            base="\$PR_BASE_SHA"\n          else\n            base="\$BEFORE_SHA"\n          fi$/m,
    "event-specific changed-range base selection missing"
  );
  assert.match(
    job,
    /^          if ! git cat-file -e "\$\{base\}\^\{commit\}" 2>\/dev\/null; then\n            base="\$\(git rev-list --max-parents=0 HEAD\)"\n          fi$/m,
    "unavailable changed-range base fallback missing"
  );
  assert.match(
    job,
    /^      - name: Changed-range whitespace\n        env:\n          BEFORE_SHA: \$\{\{ github\.event\.before \}\}\n          PR_BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \}\}\n        run: \|\n(?:          .*\n|\n)*          if git rev-parse --verify "\$\{base\}\^" >\/dev\/null 2>&1; then\n            git diff --check "\$base\.\.\.HEAD"\n          else\n            git diff --check "\$\(git hash-object -t tree \/dev\/null\)" HEAD\n          fi$/m,
    "range whitespace gate must compare every no-parent base from the empty tree"
  );
}

test("source-quality gates formatting, wasm portability, and the changed range", async () => {
  const workflow = await readFile(workflowUrl, "utf8");

  assertRequiredTriggers(workflow);
  assertSourceQualityRequirements(workflow);
});

test("source-quality requirements cannot be satisfied outside the job", () => {
  const inertWorkflow = `jobs:
  source-quality:
    name: Source Quality
    runs-on: ubuntu-latest
    steps:
      - run: true
  check:
    # fetch-depth: 0
    # persist-credentials: false
    # toolchain: "1.92.0"
    # components: rustfmt
    # targets: wasm32-unknown-unknown
    # cargo fmt --all -- --check
    # cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
    # git diff --check "$base...HEAD"
    # github.event.pull_request.base.sha
    # github.event.before
`;

  assert.throws(() => assertSourceQualityRequirements(inertWorkflow));
});
```

- [ ] **Step 2: Run the test to verify RED**

Run:

```bash
node --test .github/scripts/source-quality-workflow.test.mjs
```

Expected: FAIL with `source-quality job missing`.

- [ ] **Step 3: Add the source-quality job**

Insert this job immediately after `jobs:` in `.github/workflows/cmtrace-ci.yml`:

```yaml
  source-quality:
    name: Source Quality (fmt / wasm / whitespace)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Setup pinned Rust quality toolchain
        uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable
        with:
          toolchain: "1.92.0"
          components: rustfmt
          targets: wasm32-unknown-unknown

      - name: Rust formatting
        run: cargo fmt --all -- --check

      - name: Parser wasm portability
        run: cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown

      - name: Changed-range whitespace
        env:
          BEFORE_SHA: ${{ github.event.before }}
          PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then
            base="$PR_BASE_SHA"
          else
            base="$BEFORE_SHA"
          fi

          if [[ ! "$base" =~ ^[0-9a-f]{40}$ ]] || [[ "$base" =~ ^0+$ ]]; then
            base="$(git rev-list --max-parents=0 HEAD)"
          fi

          if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
            base="$(git rev-list --max-parents=0 HEAD)"
          fi

          if git rev-parse --verify "${base}^" >/dev/null 2>&1; then
            git diff --check "$base...HEAD"
          else
            git diff --check "$(git hash-object -t tree /dev/null)" HEAD
          fi
```

In the existing frontend job's `Release script tests` step, make the command:

```yaml
        run: >-
          node --test
          .github/scripts/updater-manifest.test.mjs
          .github/scripts/nightly-channel.test.mjs
          .github/scripts/installer-policy.test.mjs
          .github/scripts/source-quality-workflow.test.mjs
```

- [ ] **Step 4: Run the focused workflow checks**

Run:

```bash
node --test .github/scripts/source-quality-workflow.test.mjs
actionlint .github/workflows/cmtrace-ci.yml
cargo +1.92.0 fmt --all -- --check
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
```

Expected: the Node test passes `2/2`, actionlint emits no finding, formatting and wasm checks pass, and Git reports no whitespace error.

- [ ] **Step 5: Commit the executable CI gate**

Run:

```bash
git add .github/workflows/cmtrace-ci.yml .github/scripts/source-quality-workflow.test.mjs
git commit -m "ci: enforce source quality gates"
```

Expected: one commit containing only the workflow and its contract test.

### Task 5: Run Aggregate Gates and Obtain Exact-Head Review

**Files:**
- Verify: all Phase 0A committed files
- Verify externally: draft pull request and review state

**Interfaces:**
- Consumes: the accepted documentation commits, mechanical formatter commit, and source-quality CI commit.
- Produces: one pushed exact head with aggregate local evidence, a draft PR, CodeRabbit review, and an independent review decision; it does not produce native Intune acceptance.

- [ ] **Step 1: Run the complete local gate**

Run:

```bash
cargo +1.92.0 fmt --all -- --check
cargo test --locked -p cmtraceopen-parser
cargo test --locked -p cmtrace-open --all-features
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo check --locked --workspace --all-features
npm test
npx tsc --noEmit
node --test .github/scripts/source-quality-workflow.test.mjs
actionlint .github/workflows/cmtrace-ci.yml
git diff --check origin/main...HEAD
test -z "$(git status --porcelain)"
```

Expected: every command exits `0`, the worktree is clean, and the recorded evidence separates test, lint, wasm, workflow, and hygiene results.

- [ ] **Step 2: Inspect the exact committed range**

Run:

```bash
git log --oneline --decorate origin/main..HEAD
git diff --stat origin/main...HEAD
git diff --check origin/main...HEAD
git status --short --branch
```

Expected: documentation authority, mechanical formatting, and CI enforcement remain separate commits; no product-semantic file differs beyond rustfmt output.

- [ ] **Step 3: Push and verify the remote head**

Run:

```bash
git push -u origin codex/issue356-phase0a-quality-gates
local_head="$(git rev-parse HEAD)"
remote_head="$(git ls-remote origin refs/heads/codex/issue356-phase0a-quality-gates | awk '{print $1}')"
test "$local_head" = "$remote_head"
```

Expected: the push is a fast-forward publication and local/remote 40-character SHAs match exactly.

- [ ] **Step 4: Open one draft pull request**

Run:

```bash
gh pr create \
  --repo adamgell/cmtraceopen \
  --base main \
  --head codex/issue356-phase0a-quality-gates \
  --draft \
  --title "ci(intune): establish issue 356 source-quality foundation" \
  --body-file - <<'EOF'
## Scope

- record the repository-owner-approved issue #356 design and ADR;
- reconcile the epic tracker with live child state;
- apply one behavior-free Rust 1.92.0 formatting baseline;
- enforce rustfmt, parser wasm portability, and changed-range whitespace in CI.

## Verification

- `cargo +1.92.0 fmt --all -- --check`
- `cargo test --locked -p cmtraceopen-parser`
- `cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings`
- `cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown`
- `cargo check --locked --workspace --all-features`
- `node --test .github/scripts/source-quality-workflow.test.mjs`
- `actionlint .github/workflows/cmtrace-ci.yml`
- `git diff --check origin/main...HEAD`

## Acceptance boundary

This PR establishes Phase 0A program truth and source-quality gates only. It contains no parser behavior change and makes no Windows, macOS, Android, iOS, native-source, or epic-closure claim.

Refs #356
EOF
```

Expected: exactly one draft PR targets `main` from the Phase 0A branch.

- [ ] **Step 5: Run CodeRabbit on the exact committed range**

Run:

```bash
coderabbit review --committed --base origin/main
```

Expected: CodeRabbit reviews the current committed range. Verify every finding against the actual diff; fix only technically valid findings, commit them separately, rerun Task 5 Step 1, push, and rerun review at the successor head.

- [ ] **Step 6: Obtain independent review at the same head and base**

Provide the reviewer with:

```text
Scope: Issue #356 Phase 0A only.
Base: exact origin/main SHA reported by the draft PR.
Head: exact draft PR head SHA.
Review: accepted design/ADR authority, tracker truth, formatter-only semantic neutrality, workflow event-range correctness, wasm gate, and no widened product claims.
Required result: findings with exact file:line and mechanism, or a clean decision with covered areas. Do not treat CodeRabbit or CI as independent proof.
```

Expected: the independent decision binds the same head/base as CodeRabbit and reports no unresolved blocker. A finding creates a new head and invalidates both earlier reviews.

### Task 6: Publish the Phase 0A Evidence Boundary

**Files:**
- Modify externally: GitHub issue #356 comment
- Verify externally: draft PR head/base/checks/reviews

**Interfaces:**
- Consumes: exact remote SHA, local gate results, draft PR URL, CodeRabbit state, and independent review state.
- Produces: a precise program update that distinguishes committed, pushed, reviewed, CI-observed, merged, and native-validated states.

- [ ] **Step 1: Verify the final remote and PR identity**

Run:

```bash
local_head="$(git rev-parse HEAD)"
remote_head="$(git ls-remote origin refs/heads/codex/issue356-phase0a-quality-gates | awk '{print $1}')"
pr_head="$(gh pr view --repo adamgell/cmtraceopen --json headRefOid --jq .headRefOid)"
pr_base="$(gh pr view --repo adamgell/cmtraceopen --json baseRefOid --jq .baseRefOid)"
test "$local_head" = "$remote_head"
test "$local_head" = "$pr_head"
test "$pr_base" = "$(git rev-parse origin/main)"
```

Expected: local, remote, and PR head match; the PR base is the currently fetched `origin/main` SHA. If `main` advanced, rerun the base-sensitive gates and both reviews rather than claiming a current-base result.

- [ ] **Step 2: Comment the exact Phase 0A state on #356**

Run:

```bash
head_sha="$(git rev-parse HEAD)"
base_sha="$(git rev-parse origin/main)"
pr_url="$(gh pr view --repo adamgell/cmtraceopen --json url --jq .url)"
printf '%s\n' \
  'Phase 0A: program truth and source-quality gates' \
  '' \
  "Base: ${base_sha}" \
  "Head: ${head_sha}" \
  "Draft PR: ${pr_url}" \
  '' \
  'Local gates: rustfmt PASS; parser tests PASS; app all-features tests PASS; parser strict Clippy PASS; workspace all-targets all-features Clippy PASS; parser wasm PASS; workspace all-features check PASS; frontend tests PASS; TypeScript noEmit PASS; workflow contract PASS; actionlint PASS; diff check PASS.' \
  'Review gates: record the exact-head CodeRabbit and independent-review decisions from the PR before changing readiness.' \
  'State boundary: committed and pushed; not merged; no native Intune acceptance performed or claimed; no child acceptance row completed by this foundation slice.' \
  | gh issue comment 356 --repo adamgell/cmtraceopen --body-file -
```

Expected: issue #356 receives one exact-SHA update with no claim of merge, native validation, child completion, or epic closure.

- [ ] **Step 3: Stop at owner integration authority**

Run:

```bash
gh pr view --repo adamgell/cmtraceopen --json number,url,isDraft,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,reviews
```

Expected: report the observed draft PR state exactly. Do not mark ready, merge, close a child, or begin the canonical IME/ESP path slice until this foundation is integrated or the repository owner explicitly authorizes work against an unmerged dependency.
