# Recovery-Branch Extraction + Parallel Lane Delegation (cmtraceopen Intune, Aug 2026)

Session detail for a sibling pattern to verify-and-merge: a set of lanes looked
greenfield (10-line `mod.rs` stubs on main, "Implementation pending") but every
one had a substantial prior-work recovery branch. Adam's chosen method:
**review first, extract only what's still valid** — never blind-copy, never
batch-merge.

## Detecting that "greenfield" is actually recovery work

Stub on main + open issue ≠ no prior work. Before planning a from-scratch build:

```bash
# Per-lane recovery branches exist and are named predictably
git ls-remote origin 'refs/heads/codex/recovery-*'

# Size up what each carries vs main
git rev-list --left-right --count origin/main...<recovery-sha>   # e.g. 581 behind / 1 ahead
git diff --stat origin/main...<recovery-sha>                     # +6.6K..+11K lines per lane
```

Signal: recovery branch ~1 commit of work on a many-hundred-behind base carrying
thousands of lines (parser + reducer + rules + sources + fixtures + tests) that
main lacks entirely = a **review-and-extract lane**, not a build lane.

Distinguish from the superseded case (Step 1.6): there, main HAS the lane's files
in richer form. Here, main LACKS them — the work is real and unmerged, only the
BASE is stale. Extraction is viable; it just has to clear API drift.

## The extraction method (per lane)

1. Fresh isolated worktree at `origin/main`, detached, one per lane:
   `git worktree add --detach /tmp/<repo>-<lane> origin/main`
2. `git diff origin/main...origin/<recovery-branch>` restricted to the lane's
   files only (module dir + its test file + its fixtures) — the recovery branch
   may carry unrelated WIP.
3. Per piece, classify: still-valid / superseded-on-main / bit-rotted (references
   types or APIs main has since renamed or removed).
4. Extract only the still-valid parts, adapted to compile against main's CURRENT
   shared types. Expect drift in shared modules (evidence/models/normalized
   contracts) — reconcile, don't copy.
5. Full gate matrix: focused tests, full crate suite, strict clippy `-D warnings`,
   wasm32 check, fmt on touched files, `git diff --check`.

## Delegating it in parallel (what worked)

- One subagent per lane, each pinned to its own worktree path with "do NOT touch
  any other path" (charter: agents never share worktrees).
- Brief must be fully self-contained: worktree path, recovery branch name +
  fetch command, target module, the 4-step method, architecture constraints
  (pure Rust/wasm32, conservative failure, synthetic fixtures only), and a
  structured deliverable (VERDICT: EXTRACTED / PARTIAL / SUPERSEDED / STUB-ONLY +
  what was extracted vs skipped and why + exact gate numbers + files touched +
  API drift reconciled).
- No pushes, no PRs from subagents — the orchestrator gates.
- The runtime's concurrent-subagent limit caps the batch size; raise it (with user
  approval) rather than serializing a 5-lane program into 3+2.

## Orchestrator verification before any PR

- Read each subagent's transcript for a REAL verdict (fail-closed per SKILL.md
  Step 5 — a subagent that died on infra still "completes").
- Independently re-run the gates in each lane worktree; never accept "gates
  passed" on say-so.
- Only then propose scoped PRs, one per issue, closing only that issue.

## Formatter and evidence-counting lessons

In the Store extraction, formatting the integration-test root with plain rustfmt
recursively rewrote the shared `tests/support/mod.rs`; restore that file and use
`--config skip_children=true` for lane-scoped checks. The global formatter still
reported unrelated baseline drift, while the lane-scoped check and `git diff
--check` were clean. For large Rust test output, the complete log contained 45
suite result lines and 1,981 passing tests; derive totals from the saved output,
not the terminal's truncated head/tail display.

## Tracker hygiene

Don't post issue/epic comments until there are verified results — no tracker
noise on an in-flight extraction. Update the epic's checkboxes only as lanes
actually complete.

## Remediation delegation (fixing CodeRabbit majors per lane)

Extracted recovery code routinely carries real defects CodeRabbit finds on the
full-range review (~20 majors across 5 lanes in the Aug 2026 Intune batch — privacy
redaction gaps, transaction-identity collisions, coverage-ordering, KB-revision
joins). Triage FIRST into blockers vs advisory (see coderabbit-gates.md), THEN
delegate one fix-agent per lane:

- Brief lists the exact triaged blockers with file:line and the intended behavior,
  AND an explicit **DO-NOT-TOUCH list** of the advisory findings (keyed-hash,
  rustdoc, wildcard exports). Without the do-not-touch list a subagent "fixes" the
  advisory items too and churns fixtures unnecessarily.
- Tell it the expected baseline ("currently 2005/0 — keep all green") so a
  fix-surfaced regression is visible, and that a NEW red test from a correct fix
  means update the stale assertion, not revert.
- Same fail-closed gate: read the transcript, re-run the gates yourself, re-run
  CodeRabbit on the fix diff to confirm the majors cleared, before proposing a PR.
- One lane (#358 Store) came back with only 2 advisory minors — land that PR first
  while the others remediate; don't hold a clean lane hostage to the dirty ones.

## Flaky-subagent mid-task death (Aug 2026, real cost)

`gpt-5.6-luna` subagents repeatedly died mid-remediation on
`HTTP 400: encrypted content missing recognized prefix (expected rsn_/smry_)` /
`encrypted content ... could not be decrypted` — an llmgateway/provider streaming
fault, not a task failure. The batch still reports `status=completed`, so the
consolidated result looks fine while individual lanes are silently half-done.

**The damage pattern is specific and recoverable.** A subagent killed mid-fix
leaves the worktree in one of three states — inspect before trusting:

- **Clean commit, gates green** — finished just before dying. Verify and keep.
- **Uncommitted source edits + red tests** — fix applied but fixtures/goldens not
  reconciled. The code change is often correct; the goldens just assert the old
  output. Do NOT revert — reconcile.
- **Zero diff** — died before doing anything. The whole lane is still open.

**Recovery moves that worked:**

- `git status` + `git log` per worktree tells you which state you're in; never
  assume from the batch summary.
- **Guard against a poisoned golden:** a dying subagent that regenerates
  `expected.json` can bake a *broken* run into the golden (proven: a parse error
  "trailing characters" got committed as the expected findings). Before accepting
  any regenerated golden, read WHY the output changed — if the new golden encodes
  an error state, revert the golden (`git checkout HEAD -- <expected.json>`) and
  fix the underlying cause, then regenerate from correct output. A golden is only
  trustworthy if you can justify every changed field.
- Prefer the project's **guarded regeneration harness** when one exists (e.g. a
  test gated behind `UPDATE_*_FINDINGS=1` that rewrites only the `findings` key
  and keeps `findingIds` hand-written as a cross-check) over hand-editing
  interdependent golden fields — it regenerates surgically and won't mask drift in
  scenarios you didn't touch.
- Fixture-contract suites pin mechanical details (first-line `SYNTHETIC FIXTURE`
  marker, `bytesCopied` == actual file size). A pretty-printing edit breaks both;
  restore the exact first-line form and re-count bytes.

**Prevention:** when a remediation batch has lanes in the "uncommitted + red" or
"zero diff" states, finish those lanes yourself rather than re-delegating into the
same flaky backend. Reserve subagents for lanes that complete cleanly.

## Orchestrator finishing a subagent's half-done lane (proven sequence)

When you take over an "uncommitted + red" lane, the finish is mechanical once you
see the pattern:

1. Read the source diff — the fix is usually correct and well-formed (e.g. the
   privacy keys added, the time-basis gate wired). Keep it.
2. Revert any golden the dying subagent regenerated (`git checkout HEAD --
   <expected.json>`) — it may encode a broken run.
3. Run the focused suite; read the EXACT assertion that fails. It is usually a
   contract-mechanical detail, not the logic: a dropped first-line `SYNTHETIC
   FIXTURE` marker from a pretty-print, a `bytesCopied` that no longer matches the
   file size after an edit, or a golden asserting the pre-fix behavior.
4. Fix the mechanical detail (restore the exact marker line, re-count bytes), and
   for intended behavior changes update the golden's semantic fields to the new
   correct values (use the guarded `UPDATE_*=1` regen harness if present, after
   hand-updating the hand-written `findingIds` cross-check).
5. Full gates (whole crate suite, not just focused — see coderabbit-gates.md),
   strict clippy, wasm, `git diff --check`. Commit with a message noting the
   subagent did the fix and you reconciled the goldens.
