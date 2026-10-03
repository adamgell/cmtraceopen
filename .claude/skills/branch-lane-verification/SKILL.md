---
name: branch-lane-verification
description: "Use when verifying another agent's branch before merging it."
---

# Branch-Lane Verification Gates

Operating procedure for verifying and completing an issue-lane branch produced by
another agent (Codex/Claude/etc.) before integration: trust nothing on say-so,
verify remote state first, gate on local review tools, and never mark an
independent-review gate passed unless a review actually happened.

## Step 1 — Reverify remote state before planning

Charters and handoffs drift. Before acting on any branch list from a charter:

```bash
git ls-remote https://github.com/<org>/<repo>.git 'refs/heads/<lane-branch>' 'refs/heads/main'
```

If a lane head differs from the chartered SHA, diff the drift before planning
(`gh api repos/<org>/<repo>/compare/<old>...<new>`) — the delta may contain
unreviewed fixes, and it changes the CodeRabbit base commit. Also check the issue's
state: a closed issue with new lane commits means the board state is stale and the
reporting channel needs a user decision, not an assumption.

## Step 1.5 — Detect a rollup / mega-PR before treating it as one lane

A "lane" branch can silently carry more than its named issue. Before reviewing or
merging, scope it:

```bash
git rev-list --count origin/main..HEAD          # commits ahead
git rev-list --left-right --count origin/main...HEAD   # behind / ahead
git log --oneline origin/main..HEAD             # which issues (#NNN) appear
git diff --name-only origin/main...HEAD         # which lanes/modules it touches
```

Red flags that it's a **rollup, not a slice**: the commit list references several
issue numbers (e.g. `#456 #457 #458 #459 #330`); the branch is many commits behind
main (a large left count) so a merge drags in unrelated drift; or the touched paths
span lanes the charter marks not-merge-ready (other modules' reducers/admission
code). A direct merge of a rollup violates no-mega-PR policy and can import
P1-blocked lanes. Surface it as a user decision (merge whole rollup / cherry-pick
the named slice onto fresh `origin/main` / hold), and run the full-range CodeRabbit
gate on the whole `origin/main...HEAD` range — findings may land in a shared
primitive from an older, already-merged issue rather than in the named lane.

## Step 1.6 — Check whether main already superseded the branch

Divergence is not always "branch ahead, main behind" — an active repo can converge
the SAME program on main through a different path (squash/rebase merges) while the
lane branch sits stale. Before planning extraction, cherry-picks, or a merge, test:

```bash
# Is each branch commit's PR already on main under a different SHA?
git log origin/main --oneline --grep='#458'     # repeat per PR number

# Do same-named files exist on BOTH sides with incompatible content?
git show origin/main:<path> | wc -l; git show HEAD:<path> | wc -l

# Patch-id comparison detects same-change-different-SHA
git show <commit> | git patch-id --stable
```

Signals the branch is **superseded, not mergeable**: main's same-named files are
larger/newer (rewrites, not ancestors); branch PR numbers already appear in main's
log under different SHAs; same-named test files on both sides would collide on any
cherry-pick; the branch's fixes target a data model main has replaced with a richer
one. In that state, cherry-picking produces conflicted, non-compiling nonsense —
the correct moves are: verify main covers the branch's fixes natively (read main's
implementation, do not assume), treat main as authoritative, and preserve the
branch as an archive per repo policy.

**Correct downstream artifacts:** if you filed tracker issues for defects found on
the branch (e.g. a CodeRabbit major), re-check whether the defect exists on MAIN
before leaving the issue open. A defect in a superseded branch's stale file version
may already be engineered out on main — close the issue with the evidence, do not
leave a phantom blocker.

**User intent guardrail:** "don't lose work" does not mean "merge the branch at any
cost." Work converged into main in a better form is not lost. Present the evidence
and let the user choose; never silently delete or force-push a stale branch.
Session detail: `references/superseded-branch-reconciliation.md`.

**Related pattern — recovery extraction:** if main LACKS the lane's files entirely
(stub on main + a large per-lane `recovery-*` branch), the lane is unmerged prior
work on a stale base, not superseded. Use review-first extract onto fresh
`origin/main` worktrees, one subagent per lane, orchestrator verifies transcripts
and re-runs gates before any PR. See `references/recovery-branch-extraction.md`.

## Step 1.7 — Extract a stale lane conservatively when salvage is requested

When the deliverable is an extraction rather than a merge, start from a fresh branch at `origin/main` in the isolated worktree and restrict the comparison to the named lane paths:

```bash
git diff --stat origin/main...origin/<lane> -- <lane-paths>
git diff --name-status origin/main...origin/<lane> -- <lane-paths>
```

Read the target stub and current shared contracts on main before applying anything. Apply only the restricted diff (for example, pipe `git diff --binary ... -- <paths>` to `git apply`), then compile the focused target immediately. This catches API drift without importing unrelated rollup work. Treat main's implementation as authoritative: skip a recovery component only when equivalent/newer main coverage is verified by reading it, not merely because names overlap.

Keep fixtures and tests within the lane boundary and reject real tenant/device identity material. If a broad formatter reports unrelated pre-existing drift, format/check only touched lane files with `--config skip_children=true`, restore any shared harness files changed accidentally, and report the full-format baseline separately. For exact test counts, capture complete test output and derive counts from real `running N tests` and `test result` lines; never infer counts from a truncated terminal display. See `references/recovery-branch-extraction.md` for the detailed extraction and gate recipe.

### RED-only test commits when main lacks the lane

For a requested RED-first test-only commit, first fetch and verify `origin/main`. If main contains only a reserved stub and the named lane exists only on an exact PR head, create the isolated worktree from `origin/main` as the requested baseline, then use the exact PR head as the temporary implementation/test context only when necessary to compile the focused RED test. Record both SHAs and explain why the PR head was required; do not silently present the PR head as main-based.

Keep the change strictly to the allowed focused test/fixture paths. Run the exact focused test after adding the test and capture the real expected failure (including exit code and assertion location). A compile-only `--no-run` check is useful secondary evidence, but it is not a passing behavioral verification. Do not repair production code, weaken the assertion, or rerun/report a green test when the deliverable is intentionally RED. Commit only the test/fixture change, verify the worktree is clean, and report worktree, branch, parent/base SHAs, commit SHA, exact command, and concise real failure output.

## Exact plan-hash and source-head binding (fail closed)

For infrastructure or external-state changes where a saved binary plan and a
JSON/rendered plan are reviewed by digest, treat the pair and source head as one
immutable review identity. Report identity lines first: repository, branch,
actual `HEAD`, signed/reviewed source head, binary SHA-256, and JSON SHA-256.
Never review a plan merely because its JSON summary looks equivalent.

Before disposition:

1. Verify the worktree is clean and record the actual `HEAD` plus its tree SHA.
2. Confirm the saved binary and JSON digests directly; ensure the JSON is derived
   from that exact binary (not an empty, stale, or independently regenerated
   file).
3. Compare the plan's provenance/source head with the current source `HEAD`.
   Any intervening commit, including tests or preflight-only changes, invalidates
   the prior exact-plan approval. Require regeneration and fresh review rather
   than reasoning that the changed files cannot affect Terraform.
4. Review privilege scope, replacement ordering, rollback gaps, hidden drift, and
   recovery-state effects. A narrowly scoped role can still be unsafe if
   delete/create replacement creates an authority gap or if a failed cleanup
   leaves state/recovery material stranded.
5. Use an explicit disposition: `NO BLOCKERS TO APPLY THIS EXACT PLAN` only when
   the exact binary+JSON pair and exact source head match and all required review
   lanes have approved. Otherwise report `HOLD`/`REQUEST CHANGES` with the
   precise mismatch or missing artifact; do not treat stale approvals as
   transferable.

A current source head with no matching saved binary plan is a blocker, even when
an independently regenerated JSON exists. Likewise, a known old plan pair must
be identified as stale rather than reviewed again. See
`references/exact-plan-source-binding.md` for the compact checklist and report
shape.

## Live-state exact-plan integration review

For infrastructure POCs whose saved plan is expected to match both a source head and live Azure state, review the **named POC worktree**, not the repository's primary checkout. Record `git status --short --branch`, `git rev-parse HEAD`, and the exact signed/source head before evaluating the plan. A clean worktree at the wrong HEAD is still a blocker.

Verify the binary and JSON artifacts independently with SHA-256, and inspect the JSON metadata for its recorded source head, completeness, action set, and resource count. Do not treat an empty placeholder JSON or a regenerated JSON without a paired binary as the reviewed artifact. If source drift exists after plan generation, require regeneration from the current HEAD; prior approvals do not carry forward.

For the integration lane, perform read-only live-state checks against the exact subscription/resource group/account/container named by the plan: authenticated tenant/subscription, resource inventory, network default/bypass, Shared Key setting, versioning/retention, exact-scope role assignment, container privacy, and any recovery-marker/version inventory. Compare observed state to both the plan's prior inventory and intended changes. Redact credentials, tokens, backend coordinates, state contents, and customer data from reports.

When a source correction addresses a provider/CLI compatibility issue, reproduce the live CLI invocation read-only before disposition. Some `az storage account blob-service-properties` commands reject `--auth-mode`; test the exact command shape and ensure the source change and its regression test are present in the current worktree. This confirms the fix is integrated without applying Terraform.

A live-state match does not cure a stale plan/source binding. Report `HOLD`/`BLOCK` unless the current source head, exact binary+JSON pair, and live-state tuple all match and the required review dispositions are present. See `references/live-state-exact-plan-review.md` for the compact evidence checklist.

## Step 1.8 — Delivering a test artifact from a verified branch

When the user asks for a portable binary from an issue/PR lane, bind the artifact
identity before downloading it: repository, exact source commit, workflow run, and
platform/architecture. Prefer a successful CI artifact built on the target OS over
cross-compiling locally from macOS/Linux, especially for Windows/MSVC targets.

Inspect the artifact archive rather than trusting its label. A Windows CI artifact
may contain an MSI and an NSIS `*-setup.exe` installer but no standalone portable
EXE. Never relabel an installer as portable. If only installers are published,
report that limitation; if a signed workflow publishes staged standalone EXEs,
select the exact edition/architecture file.

After download, extract in a temporary directory and verify the payload with `file`,
SHA-256, size, and—where practical—archive/PE extraction. Report the exact source
SHA and whether the binary was actually run on Windows. CI success is build evidence,
not Windows runtime acceptance. See `references/ci-artifact-delivery.md` for the
command recipe and reporting shape.

## Step 2 — Isolated worktree pinned to the exact SHA

```bash
git worktree add --detach /tmp/<repo>-<lane>-verify <full-remote-sha>
```

Never verify in the dirty root checkout. Detached at the exact remote SHA keeps the
verification honest; commits land on top of the verified head. If repo policy
requires re-verifying later, `git status` must be empty and the HEAD must match the
reviewed commit before citing old gate results.

## Step 3 — Baseline matrix before touching anything

Run the repo's full gate set on the untouched head first: focused tests, full
suites, strict lint (e.g. `cargo clippy --all-targets -- -D warnings`), wasm/target
checks, `git diff --check`, formatting. A red baseline changes the job from
"verify" to "triage" — report before fixing.

**Rust fmt drift pitfall:** repo-wide `cargo fmt --all -- --check` fails on repos
whose `main` predates the local rustfmt version — dozens of pre-existing diffs
unrelated to the branch. Verify by running the same check on a worktree of `main`.
Gate on **lane-touched files only** (grep the fmt output for changed paths);
report the pre-existing drift, never bulk-reformat it into the lane.

**Rustfmt module-recursion pitfall:** formatting a test file that declares
`mod support;` can recursively reformat the existing shared `tests/support` tree,
creating unrelated modifications. Restore those files and validate only the lane
with rustfmt's child-module traversal disabled:

```bash
rustfmt --edition 2021 --check --config skip_children=true \\
  crates/.../lane/*.rs crates/.../tests/lane.rs
```

Use the same `skip_children=true` configuration when formatting lane files; do
not leave rustfmt-only changes in shared harness files. Report both statuses when
the global check is red: the repo-wide baseline result and the lane-specific
result.

## Rustfmt scope pitfall for integration tests

When checking only lane-touched Rust files, invoke rustfmt with `--config skip_children=true` for integration-test roots. Without this option, rustfmt follows `mod` declarations and may rewrite shared support modules that were not part of the lane. Restore any such unrelated files before reporting the worktree scope. A reliable touched-file check is:

```bash
rustfmt --edition 2021 --config skip_children=true --check \
  crates/<crate>/src/<lane>/*.rs \
  crates/<crate>/tests/<lane>.rs
```

Keep the distinction explicit in the report: a repository-wide `cargo fmt --all -- --check` may fail on pre-existing drift, while the lane-scoped rustfmt check can still pass. Do not reformat unrelated files merely to make the global check green.

## Step 4 — CodeRabbit local gates

See `references/coderabbit-gates.md` for the exact commands, output-shape pitfalls,
and finding-triage discipline. Summary:

- Review the exact committed drift range AND the full PR-range vs `origin/main` —
  they find different things.
- Verify every finding technically; severities can be inflated. Skip invalid ones
  with recorded reasons; fix valid in-lane items with red-test-first discipline.
- Gate is a final 0-finding run over the fix diff before commit.

## Step 5 — Independent review must be fail-closed

When dispatching the independent review to a subagent:

- **Check the transcript/result before marking the gate passed.** A delegated
  reviewer can die on infrastructure (model fallback 404, auth failure) and the
  delegation still "completes" — with no review. Read the final result; if the
  reviewer never produced a verdict, the gate is NOT passed. Do the review yourself
  or re-dispatch with a working model.
- Reviewer gets the diff and constraints only — no shared implementer context.
- APPROVE / APPROVE-WITH-COMMENTS / REQUEST-CHANGES with file:line citations;
  anything unverifiable is a comment, not a pass.

## Step 6 — Merge-policy gate before integration

Green CI is necessary but not sufficient for merge. Before attempting the merge,
re-read the live PR state and repository policy:

```bash
gh pr view <number> --repo <org>/<repo> \\
  --json state,isDraft,mergeable,mergeStateStatus,reviewDecision,headRefOid,statusCheckRollup

gh api repos/<org>/<repo> --jq '{allow_auto_merge,allow_squash_merge,allow_rebase_merge}'
gh api repos/<org>/<repo>/rulesets --jq '.[] | {id,name,enforcement,target}'
```

Require all of the following before calling a normal merge attempt ready:

- exact reviewed head still matches the live PR head;
- required status checks are complete and successful;
- the PR is not draft;
- `reviewDecision` is satisfied, not merely that review bots reported success;
- `mergeStateStatus` is not blocked;
- repository rulesets and required approving-review count permit the acting
  identity to merge.

A bot's `COMMENTED` review or a CodeRabbit `pass` status does not satisfy a
required approving review. If the PR author is also the acting identity, do not
assume the author's own approval can satisfy the rule. Inspect the ruleset's
`required_approving_review_count` and bypass actors before deciding what remains.

Do not repeatedly retry `gh pr merge` when GitHub reports a policy block. If the
repository disallows auto-merge, `--auto` cannot be used; if a required approval is
missing, an admin merge would bypass policy. Stop and report the exact blocker,
then request explicit authorization before using an administrator bypass. Do not
create downstream branches from a PR that is only checks-green but not actually
merged; wait for and verify the resulting `main` SHA.

### Phase 2 branch creation after merge

Once the PR is actually merged, independently verify the merge and base:

```bash
gh pr view <number> --repo <org>/<repo> --json state,mergedAt,mergeCommit,baseRefName

git fetch origin main
git show -s --format='%H %s' origin/main
git switch -c <phase-2-branch> origin/main
git rev-parse HEAD
```

Record the post-merge `origin/main` SHA as the branch parent. Never use the
pre-merge governance head or a stale local `main` as the Phase 2 base.

## Step 7 — Commit and hold

Commit fixes locally with a message recording: findings fixed, findings skipped +
why, and the exact gate results. Do not push, open PRs, or update tracking issues
without explicit user approval — especially when issues/boards turned out to be
closed or state drifted mid-flight.

## Reporting style

Lead with what moved and what is verified vs assumed. Separate
committed/pushed/reviewed/merged explicitly. Surface blockers (closed issues,
stale boards, broken review infra) as decisions for the user rather than resolving
them by assumption.
