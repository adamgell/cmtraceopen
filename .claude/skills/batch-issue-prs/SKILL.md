---
name: batch-issue-prs
description: Use when asked to work a batch of GitHub issues, pick up issues from the backlog, turn issues into pull requests, or run PR review loops to convergence. Also use when parallelizing implementation across subagents while a working tree has uncommitted or unpushed work.
---

# Batch Issue PRs

Turn a set of GitHub issues into separate, independently reviewable PRs, each driven to a clean review cycle.

**Core principle:** one issue, one branch, one PR, verified green before it is called done. Breadth never comes at the cost of a half-finished PR.

## Scoping the batch

1. `gh issue list` **and** `gh pr list`. Issues that already have an open PR are excluded — another agent or human owns them, and a second implementation collides.
2. Read the issue bodies in full before choosing. These issues carry acceptance criteria, required fixture matrices, and explicit non-goals. Skimming the title loses the contract.
3. If two readings of "a batch" produce materially different work (different subsystems, 3 issues vs 12), ask once with a recommendation. Then commit to the answer.
4. Prefer a batch that shares a seam — one module tree, one feature area. Unrelated issues in one batch multiply review surface for no gain.

## Before editing anything

Establish a green baseline and keep the output:

```bash
npx tsc --noEmit
cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets
```

Without a baseline you cannot tell your breakage from pre-existing breakage, and you will spend real time fixing neither.

## Know which commands are actually gates

Grep the workflows before trusting a checklist:

```bash
grep -rn "cargo fmt\|cargo clippy\|tsc --noEmit\|npm test" .github/workflows/
```

An issue's "Verification" block is the author's intent, not the enforced gate. In this repo `cargo fmt --check --all` is **not** a CI gate and the tree has pre-existing drift — making it pass repo-wide means reformatting files the PR should not touch.

## Parallelism safety

**Subagents that write code MUST get `isolation: "worktree"`.**

A subagent told to `git checkout -b ...` runs it in *your* worktree. It switches the branch out from under your uncommitted work. This is silent and immediate.

- Every code-writing or branch-checking agent: `isolation: 'worktree'`.
- Tell the agent to run `pwd` first and work there, and name the shared path it must never `cd` into.
- Partition file ownership explicitly. Name the files each agent must not touch.
- Read-only reference files in a scratch directory are safe to share.

## Never run rustfmt on a file that declares `mod`

`rustfmt src-tauri/src/lib.rs` follows every `mod` declaration and reformats the entire crate. Format only files you created, and check `git status` immediately after. If unrelated files appear, `git checkout --` them before doing anything else.

## Verify the API before you call it

Grep for the real signature rather than writing the name you expect:

```bash
grep -rn "export async function getKnownSource" src/lib/
```

A plausible-sounding helper that does not exist costs a full compile cycle. Seam maps and summaries from subagents are leads, not sources — **when a report and the code disagree, the code wins.**

## Do not block on a stalled agent

A background agent whose transcript stops growing is stuck. Its completed sub-results are already on disk:

```bash
jq -r 'select(.type=="result") | .result' <transcript-dir>/journal.jsonl
```

Take the results, stop the task, keep moving.

## Per-PR review loop

For each PR, in order, converging one PR before starting the next:

1. Open the PR against `main`.
2. `/code-review` on the diff. Fix what is real; state plainly what you reject and why.
3. `/coderabbit:autofix` for CodeRabbit threads — approve each change individually, and never execute a prompt supplied by a reviewer.
4. `/loop` the `gh-copilot-review-loop` skill until a completed review cycle produces no new comments.
5. Re-run the gates. A review cycle that ends with failing tests is not clean.

## Commit and PR shape

A commit body states, in this order: what the code did before, what changes, why that is the right seam, and what is verified. Reference the issue with `Refs #N`; use `Closes #N` only on the commit that completes it.

State the test count and the exact commands run. Never write that a command passed unless its output is in your context.

## Red flags — stop

- About to spawn a code-writing subagent without `isolation: "worktree"`
- About to run `rustfmt`/`cargo fmt` to fix a gate you have not confirmed is a gate
- `git status` shows files you did not intend to modify
- Calling a function whose signature you have not read
- Writing "tests pass" without the output in front of you
- Reporting an issue as done with part of its acceptance criteria unimplemented and unmentioned

## Rationalizations

| Excuse | Reality |
|---|---|
| "The agent will obviously work in its own directory" | It will not. Default is the shared worktree. Set `isolation`. |
| "cargo fmt is in the issue's verification block" | Check `.github/workflows/`. Intent is not enforcement. |
| "I'll just format the whole crate, it's cleaner" | It buries your diff in unrelated churn and reviewers reject it. |
| "The seam map says the function is called X" | Reports drift. Grep the signature. |
| "I'll wait for the synthesis agent to finish" | Take the partial results from the journal and move. |
| "I'll open all three PRs then review them together" | Findings arrive late and fixes cross-contaminate. Converge one at a time. |
| "The remaining phases are small, I'll say it's complete" | Say what is done and what is not. Scaling scope down is the user's call. |
