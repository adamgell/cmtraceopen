# CodeRabbit CLI Gates (coderabbit 0.7.x)

Commands proven in a live verification lane (Aug 2026, cmtraceopen SUP lane).

## Commands

```bash
# Exact committed range — e.g. drift commits past a chartered checkpoint
coderabbit review --committed --base-commit <sha> --agent

# Full PR-range diff vs main (finds pre-existing issues in the wider branch)
coderabbit review --committed --base origin/main --agent

# Working-tree fixes, before committing them — gate is 0 findings on THIS diff
coderabbit review --uncommitted --agent

# Full text of stored findings from the most recent review (no new review run)
coderabbit review findings --agent
```

## Output shape

`--agent` emits NDJSON, one JSON object per line:
- `{"type":"review_context", ...}` — echoes the resolved base branch/commit
- `{"type":"status", ...}` heartbeats
- `{"type":"finding", "severity":"minor|major|critical", "fileName":"...", "codegenInstructions":"..."}`
- `{"type":"complete", "findings":N, "reviewedFiles":[...]}` — final line

**Pitfall:** piping a review through `tail -N` can cut findings off mid-stream (a
3-finding review showed only 2 through `tail -5`). After any findings>0 run,
retrieve the full list with `coderabbit review findings --agent` before triaging.

## Two-range discipline

Review BOTH the exact drift range AND the full PR-range vs `origin/main`. They find
different things: in the proven session, the 4-commit drift range was clean (0
findings) while the full range returned 3 findings in older branch code. Triage the
full-range findings even when the drift range is clean.

## Finding triage discipline

- Verify each finding technically against the code before acting. Severities can be
  inflated: a "major" demanding a public re-export of a `pub(crate)` struct whose
  producing method is only called in-crate is a nit — there is no external caller to
  break. Check the item's actual visibility and call sites.
- **Adversarial-to-design findings:** CodeRabbit sometimes recommends a "more secure"
  change that would break an intentional design contract. Proven case (Aug 2026, Intune
  lanes): it repeatedly flagged the deterministic FNV redaction token (`stable_token`)
  as needing a keyed/HMAC hash with a per-export secret. But cross-run, cross-export
  correlation IS the designed feature — two records naming the same UPN must resolve to
  the same token so an operator can trace one user across an export. Verify before
  "fixing": grep the fixtures for literal tokens (`\[upn:[0-9a-f]{16}\]`) — if no
  fixture pins a token value AND the module doc states correlation is the goal, the
  determinism is intentional and the finding is overreach. Same lens for "add rustdoc
  to every public field" / "replace wildcard pub use" — style, not blockers.
- **A correct fix can surface a NEW test failure — that is not the fix being wrong.**
  Proven case: moving the expected-artifact `Missing` loop before `degraded_coverage`
  was computed turned a unit test red (`confidence` High→Medium), because the test fed
  a partial bundle and the OLD code had been silently over-confident. CodeRabbit had
  explicitly predicted this ("update the affected test assertion... expect the
  resulting lower confidence"). Read the failing assertion, confirm the new value is
  the intended-more-conservative one, then update the test/fixture to match — do not
  revert the fix to make a stale assertion pass.
- Skip invalid/out-of-scope findings; record each skip + reason in the commit message.
- Fix valid in-lane findings even when severity is below the mandatory bar if they are
  cheap and make the branch strictly more conservative/correct.
- Behavioral findings: write the failing (red) test FIRST, confirm it fails for the
  expected reason, then apply the smallest implementation, then re-run the FULL test
  matrix — fixture/contract suites may pin the old behavior.
- **Focused-suite blind spot:** a focused `--test <lane>` run can stay green while the
  full `cargo test -p <crate>` suite goes red. Proven: the Win32 focused suite passed
  21/21 while the full suite failed 1 — a `#[cfg(test)]` unit test inside the source
  file (in the lib target, not the lane's integration test) asserted a stale value.
  Always run the full crate suite, not just the lane's focused target, before calling
  a lane green.
- Doc-comment findings are safe to fix in place; keep the claim precise (e.g. do not
  claim byte-for-byte binding when the code trims before hashing).

## Pre-commit gate

Final step before committing review fixes: `coderabbit review --uncommitted --agent`
must return 0 findings. Then commit with a message that records the gate results,
the findings fixed, and the findings skipped with reasons.

## Re-review drift (the moving target)

A fresh CodeRabbit run after fixes can surface NEW findings that were absent from
the first pass — the reviewer samples differently per run. Proven (Aug 2026 Win32
lane): after the original 11 majors were fixed and verified, a re-review returned 4
new "majors" that were mostly style/robustness (add doc comments, replace a derived
Default, make a test require keys). Decide the bar with the user BEFORE re-reviewing:
is the gate "the original triaged blockers cleared" or "zero findings on a fresh
run"? The latter can churn indefinitely on freshly-extracted code. Triage new
findings the same way (blocker vs advisory) instead of auto-fixing whatever appears.

## Semantic/contract findings may be a user call, not a bug

A finding that challenges a domain semantic (e.g. "windowsUpdate must NOT match
windowsUpdateForBusiness") can be a design disagreement plus a doc-comment lie, not
a code bug. Verify what the code actually does vs what the doc claims, then present
the options to the user (distinct / match / match-but-distinguish) — a genuine
product-SME call. Proven resolution (Aug 2026 WUfB lane): user chose
match-but-distinguish, so the fix was to correct the lying doc comment to the code's
real contract and pin the behavior with unit tests — no reducer change. If the
struct already records the two values separately (expected vs scanned), the
distinction is already visible in output and only the doc needs fixing.

## Clippy: test module must come last in the file

`error: items after a test module` fires when a `#[cfg(test)] mod tests` (or any
test mod) is followed by a non-test item. Subagents repeatedly added a helper/test
mod mid-file and broke strict clippy. Fix: move the test module to the END of the
file (or move the stray helper above it). Verify with
`cargo clippy -p <crate> --all-targets -- -D warnings`.

## Reviewer dispatch health (for the SKILL's Step 5 independent review)

A misconfigured subagent backend makes every reviewer die on an API error while
the dispatch still "completes", which is exactly the silent failure Step 5 warns
about. Verify the backend once before relying on it for a gate: dispatch a trivial
read-only task and check both the returned content and the model the runtime
reports it used. Healthy means accurate content and a normal completion. Anything
else means the gate cannot pass until the backend is fixed.
