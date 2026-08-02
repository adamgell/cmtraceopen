# Takeover brief: SCCM diagnostics program (epic #317)

You are taking over an in-flight program in `adamgell/cmtraceopen`. The previous
session ran out of subscription usage. This session runs through LLM Gateway on
pay-per-token billing. Read the cost section before doing anything.

---

## 1. Cost constraint. Read this first.

Billing is now per token, not a subscription cap. The previous session burned
roughly 9 million output tokens in a single afternoon by fanning out review
workflows and subagents. That pattern is affordable under a subscription and
expensive here.

Concretely:

- Do NOT launch multi-agent review workflows or large subagent fleets unless the
  human explicitly asks for one and accepts the cost.
- Prefer doing the work yourself in the main loop.
- When you do delegate, delegate one narrow task at a time, not a fan-out.
- Read only the file ranges you need. Several files here exceed 2,000 lines and
  reading them whole is pure waste.

If you think a task needs a fleet, say what it would cost and ask first.

**What the main-loop approach actually cost.** The session that merged #384,
#442, #443, #444 and repaired the #391 rebase ran entirely in the main loop with
zero subagents and zero review workflows, for a low five-figure output token
count. That covered four merges, a 35-commit rebase, three collision root
causes, and a class audit. Delegation was not needed for any of it. The expensive
part of this program was never the work; it was reviewing the work in parallel.

Two habits that keep main-loop cost down here: grep for the specific line ranges
you need instead of reading files (`policy.rs` alone is 1918 lines added), and
prefer `--message-format=short` on cargo to get one line per error instead of
full diagnostic blocks.

---

## 2. What the program is

Epic #317 builds SCCM end-to-end diagnostics across child issues #318 to #335.
Client-side lanes diagnose policy, health, deployment, updates, task sequences,
inventory. Server-side lanes diagnose site core, management point, distribution
point, software update point, hierarchy, provider.

Most SCCM lane PRs target the long-lived integration branch
`codex/parser-family-skeleton`, not `main`. That branch is roughly 276 commits
ahead of main and has never merged to main. It is the program's staging area.

---

## 3. Current state

Last updated 2026-08-02 by the LLM Gateway session, after merging #384, #442,
#443, #444 and rebasing #391.

Open PRs:

| PR | Base | State | Notes |
|----|------|-------|-------|
| #389 | main | CONFLICTING | Company Portal Windows. Needs rebase onto main. |
| #390 | main | CHANGES_REQUESTED | Company Portal macOS unified log. |
| #391 | skeleton | MERGEABLE, UNSTABLE, CHANGES_REQUESTED, draft | policy transactions. Rebase repaired, see below. Five defects still open. |
| #392 | #391 | APPROVED, draft | health and location. Stacked on #391, so #391 must land first. Needs a rebase after #391 moves. |
| #397 | main | CHANGES_REQUESTED | Device Inventory agent log family. |
| #402 | main | CHANGES_REQUESTED | iOS/iPadOS Company Portal console. |
| #403 | main | CHANGES_REQUESTED, BLOCKED | removes a stale `docs/` ignore rule. Needs human review approval. |
| #407 | skeleton | CONFLICTING, CHANGES_REQUESTED | deployment transactions. Needs rebase. |

Merged by this session, all four verified green before merge:

| PR | Merge commit | Base |
|----|--------------|------|
| #384 elevation | `05bd8e4e` | main |
| #442 cycle hardening | `76784c38` | skeleton |
| #443 MP canonical intake | `4684eb45` | skeleton |
| #444 discovery normalization | `c622c9ec` | skeleton |

#384's confirmed defect was verified fixed at its head before merging:
`classify_open_failure` in `src-tauri/src/commands/file_ops.rs:100` stats the
path and returns `InvalidInput("path is a folder, not a file")` for directories
before any permission classification can run. All 16 checks were green.

#442, #443 and #444 were drafts and needed `gh pr ready` first. Mergeability was
rechecked after each merge, since all three shared one base.

Earlier merges: #421 (CI trigger fix), #420 (spine overlap ranges), #404 (spine
hardening), #405 (site core), #408 (CCM timestamp fix), #390/#387 (IPv6
redaction).

Auto-merge is disabled repo-wide. Every merge needs a manual step. Branch
protection requires a review approval, and you cannot approve the human's own
PRs, so #403 is genuinely blocked on them.

### #391's rebase is repaired, its five defects are not fixed

`486e982f` on `codex/sccm-321-policy-analysis` rebases the 35-commit lane onto
the merged skeleton and repairs the result. #391 moved from CONFLICTING to
MERGEABLE. **None of the five defects in section 3.2 are fixed yet.** That is
the next task.

The rebase applied with one trivial conflict and then did not build: seven
compile errors, one failing contract test, and one clippy error, from three
collisions that all had the same shape, both sides adding the same contract
separately.

1. `SccmCoverageState::Partial` is introduced by this lane, while the skeleton
   independently added seven exhaustive matches over that enum. Each was given a
   semantic placement rather than a wildcard: `Partial` carries real evidence, so
   it outranks every noncaptured state and loses only to a complete capture,
   matching `findings::coverage_state_order`, which is the canonical ordering.
   Sites fixed: `client/intake.rs` (`coverage_rank`, `coverage_reason`,
   `source_coverage_reason`), `server/windows/intake.rs` (`coverage_sort_key`),
   `server/windows/management_point.rs` (`coverage_order`),
   `server/windows/site_core.rs` (`coverage_rejection_reason`,
   `coverage_sort_key`).
2. `SOURCE_CATALOG` and its frozen expected-tuple list in
   `tests/sccm_spine_contract.rs` each carried a duplicated run of `CIAgent`,
   `CIDownloader`, `StateMessage`, `StatusAgent`. The skeleton already declares
   every client-policy entry this lane wanted to add, in a different order, so
   git appended instead of merging. Duplicate run dropped from both.
3. `SccmClientWorkflow` was defined in both `client/intake.rs` and
   `client/policy.rs`, making the two glob re-exports in `client/mod.rs`
   ambiguous. The intake definition is the shared four-variant client contract;
   policy's was a single-variant stub predating it. `policy.rs` now imports the
   shared type.

Class audit performed for the `Partial` fix, since the compiler only catches
exhaustive matches and is blind to wildcard arms and equality comparisons:

- Searched all 38 `SccmCoverageState::Captured` occurrences across 8 files to
  enumerate every match site, not just the 7 the compiler flagged.
- Searched for wildcard arms in coverage matches. Found two.
  `server/windows/intake.rs:1855` (`_ => false`) is a capture-limit validity
  check where `Partial` correctly falls to `false`.
  `client/intake.rs:1599` is `_ => unreachable!(...)`, a panic in a published
  crate reachable through a public `Deserialize`.
- Verified that panic stays sound: `validate_capture_gap_shape` at
  `client/intake.rs:1161` enforces `Capped | ParseFailed` on both the serialize
  and deserialize boundary, so `Partial` cannot reach it from the wire.

### #391 has five confirmed defects

An executed review (probes actually run, not just source reasoning) confirmed
these in `crates/cmtraceopen-parser/src/sccm/client/policy.rs`:

1. Score 92. `canonical_basename` (around line 1266) does not strip rotation
   suffixes, so `PolicyAgent.log.1` is silently invisible: no fact, no
   rejection, no coverage gap. An AccessDenied `Scheduler.log.1` produces an
   empty coverage gap list where `Scheduler.log` correctly reports one. Note
   `catalog.rs::ParsedArtifactName::from_name` already handles all four rotation
   forms case-insensitively, so policy.rs re-implemented a weaker parser. Reuse
   the catalog one.
2. Score 88 and 85. Rotation-split finding and repair hardcode `PolicyAgent`
   while detection covers the whole policy-agent group, so a torn `Scheduler.log`
   tells the operator to collect `PolicyAgent.log`, a file not in the bundle.
   Independent splits also collapse into one finding via constant ids.
3. Score 85. A confirmed terminal failure with no Request record is reported as
   "did not match a validated profile" at Warning/Low instead of an Error-severity
   confirmed failure. The file's own doc at lines 296 to 306 states the violated
   rule verbatim.
4. Score 82. `quarantine_overlapping_evidence` builds its index from parsed facts
   only, so an overlap where one side failed to parse survives and anchors a
   transaction.

---

## 4. Repository constraints that will bite you

**`cmtraceopen-parser` is published on crates.io and must compile for
wasm32-unknown-unknown.** Pure Rust only: no filesystem, Windows, Tauri, async,
registry, or network dependencies. Note that `sccm/server/windows/` is a domain
name, not a platform gate. Always run:

```
cargo check --target wasm32-unknown-unknown -p cmtraceopen-parser
```

**Verification before claiming anything is done.** From `src-tauri/`:
`cargo check`, `cargo test`, `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`. From repo root: `npx tsc --noEmit`. CI enforces zero clippy
warnings.

**`cargo fmt --check` fails repo-wide with a recent local rustfmt, and this is
not a regression.** There is no `rust-toolchain.toml`, so rustfmt version is
whatever the contributor has. With rustfmt 1.8.0-stable (2025-12-08), `main`
reports 44 offending files and the skeleton reports 13, while CI is green on
both, so CI's rustfmt formats differently. Do not chase these, and do not
reformat files you did not touch. Instead check only your own files:

```
rustfmt --check --edition 2021 <each file you changed>
```

Pinning the toolchain would remove this whole class of confusion and is worth
doing.

**Count test failures, do not eyeball them.** `cargo test` output is long enough
that a single `FAILED` line scrolls past. This session's first pass reported
"zero failures" from too narrow a grep and missed a real broken contract test.
Aggregate instead:

```
cargo test 2>&1 | awk '/test result:/{p+=$4; f+=$6} END{print "passed="p" failed="f}'
```

Current expected baselines: parser crate 1290 passed, `src-tauri` 754 passed.

**Worktrees.** Use absolute paths under `/Users/Adam.Gell/repo/cmtraceopen/.worktrees/`.
Never use a `cd`-then-`git worktree add` compound command; that repeatedly
created nested worktrees. Check `git worktree list` first, since a branch may
already be checked out. There are over 400 registered worktrees, so grep that
list rather than reading it: `git worktree list | grep <branch>`. Every branch
this session needed was already checked out. Note that `gh pr merge
--delete-branch` fails its local-delete step when a worktree holds the branch;
the remote delete still succeeds and the merge is unaffected.

**Windows code cannot be verified locally.** The host is macOS and cross-compiling
to `x86_64-pc-windows-msvc` fails in ring's C build. Verify `#[cfg(windows)]`
code through CI's Windows jobs. When a finding depends on Windows semantics, say
explicitly that it is reasoned from source rather than executed.

---

## 5. Lessons this program learned the hard way

These are not style preferences. Each cost a full correction round.

**Close the class, not the instance.** The dominant failure mode here is fixing
the exact case a reviewer reported and leaving the same defect live one function
over. Before any GREEN commit, grep for every other call site with the same
shape and fix them together, then state the audit in your report. A passing test
is not evidence the class is closed; ask what your test would still accept.

**Lane review is structurally blind to merged code.** Every gate reviews a diff
against a base, so already-merged shared code is invisible to all of them. A CCM
timestamp defect made `10:00:00.123456` parse as 123ms plus a +456 minute offset,
shifting evidence UTC by 7h36m and stamping it `NormalizedUtc`, the highest
confidence ordering state. Fourteen agent reviews and multiple CodeRabbit passes
ran while it sat in merged code. None saw it. The human found it by hand.
Periodically audit merged shared surfaces directly, not via a diff.

**Decide semantically, never positionally.** The CCM tail was mis-split twice,
each time by a heuristic that decided what a number meant by counting digits
instead of checking whether the value was valid. A real timezone offset satisfies
`|minutes| <= 840` and in practice is a multiple of 15. Digit count may narrow
candidates; only validity may choose between them.

**Missing checks usually mean no trigger.** A PR showing few or no checks
normally means its base branch is absent from the workflow trigger list. GitHub
reports nothing for this, not "pending" or "skipped", and the PR still reports
mergeable. Diagnostic order: base branch in the trigger list, then is the PR
CONFLICTING (a conflicted PR has no computable `refs/pull/N/merge`, so CI
vanishes), then is it a draft. Also: checks are listed by job name
(`Check & Test (Rust)`), not workflow name (`CMTrace Open: CI`). Grepping for the
workflow name returns nothing and looks identical to missing CI. That mistake was
already made once here and produced a false report of systemic CI breakage.

**A clean rebase is not a compiling rebase.** A #392 rebase applied cleanly and
did not build, because a type had moved modules and one broken `super::` import
produced six cascading type errors that looked independent. On a burst of type
errors, look for a single moved or renamed item before fixing errors one by one.
Confirmed again on #391: one trivial conflict, then seven compile errors, one
failing contract test, and one clippy error. All three root causes were the same
shape, and the pattern generalizes:

**On a long-lived integration branch, expect both sides to have added the same
contract separately.** Lanes and the skeleton evolve in parallel, so the same
enum variant, catalog entry, or type gets introduced twice. Git resolves this as
"append both" and produces silent duplication rather than a conflict. Symptoms
seen: a duplicated run of four catalog entries that only a uniqueness contract
test caught, and two definitions of one enum that only surfaced as an ambiguous
glob re-export under clippy. Before resolving any add/add conflict, diff the two
sides for the entity you are about to add and check whether the base already has
it, possibly under a different order or name. When it does, prefer the base's
version and delete the lane's, especially when the base's is the superset.

**Duplicated data has a second copy in the tests.** Frozen contract lists mirror
production tables. The catalog duplicate had to be removed from both
`SOURCE_CATALOG` and `expected_catalog_tuples`; fixing only the source turned one
failing test into a different failing test. When you dedupe a table, grep the
test tree for the same literals.

**RED before GREEN, and prove the RED fails.** Use strawman implementations to
confirm a new test actually has teeth.

---

## 6. Suggested order of work

Steps 1 and 2 of the original plan are done: #384 merged to main, and #442, #443,
#444 merged to the skeleton. #391 is rebased and building. Remaining:

1. **Fix #391's five defects** (section 3.2). The lane is rebased, MERGEABLE, and
   green locally, so the defects are the only thing left. Start with defect 1,
   since reusing `catalog.rs::ParsedArtifactName::from_name` changes which files
   the policy lane can see and the other defects are downstream of that. Expect
   the class audit to reach past `policy.rs`.
2. **Rebase #392 onto the new #391 head.** It is APPROVED and was MERGEABLE, but
   #391 was force-pushed to `486e982f`, so #392 now needs a rebase. It is the
   PR that previously produced the clean-but-broken rebase, so build it, do not
   just look at the apply.
3. **Rebase #407 onto the skeleton.** Still CONFLICTING. It will very likely hit
   the same both-sides-added-it collisions #391 did, so read that section first.
4. Rebase #389 onto main.
5. Work the CHANGES_REQUESTED threads on #390, #397, #402.
6. Now that #421 made CI actually run on skeleton-based PRs for the first time,
   expect red builds on lanes that never had signal. Triage those before adding
   features.

Also worth doing, both cheap and both cause repeated confusion: add a
`rust-toolchain.toml` to end the `cargo fmt --check` noise described in section
4, and prune the 400-plus stale worktrees.

Open non-lane defects: #409 (intake production source hardcodes about 53 test
fixture literals), #410 (public timestamp projection is knowingly wrong for
backward compatibility, a product decision), #413 (Unicode digit panics),
#417 (chrono floor declared `0.4` while code calls `from_timestamp_millis`,
which needs 0.4.35, so a downstream consumer of the published crate can resolve
a version that will not compile).

---

## 7. Things only the human can do

- Approve and merge #403. Branch protection requires a human review.
- Decide #410: keep the knowingly wrong public timestamp projection for backward
  compatibility, or fix it.
- Decide whether Codex keeps running the SCCM lanes. It is still opening PRs
  (#442, #443, #444 are recent, and all three are now merged). Nothing has been
  turned off. Note that #442, #443 and #444 all had to be taken out of draft
  before they could merge, so Codex is opening them as drafts.
- Licensing of `.claude/skills/gh-copilot-review-loop/SKILL.md`, adapted from an
  upstream repo that publishes no license.

---

## 8. Backup you should know about

32 local `codex/*` branches had tip commits that existed nowhere on origin. They
are bundled at:

```
~/cmtraceopen-backups/codex-unpushed-20260802-141542.bundle
```

Verified complete. Those branches were checked and are stale pre-rebase snapshots
whose content is already superseded on the corresponding PR heads, so nothing is
missing from any PR. Restore with `git bundle unbundle <file>` if ever needed.

#391's pre-rebase tip is preserved as the local branch
`backup/sccm-321-pre-rebase-20260802` (`1bdcd9c4`) in the
`.worktrees/sccm-321-policy-analysis` worktree. It is local only. Delete it once
#391 lands.
