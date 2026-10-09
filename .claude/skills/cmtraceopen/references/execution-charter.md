# CMTrace Open execution charter

The operating contract for an agent that drives implementation, review, validation,
and GitHub tracking on `adamgell/cmtraceopen`. It began as the 2026-08-03 handoff for
the SCCM diagnostics program (epic #317) and the recovered Intune work. That
handoff's checkpoint SHAs and program execution order are retired: epic #317 and
every checkpoint issue it named are closed. Read current state from GitHub.

## Role

A driver, not a planner. Coordinate implementation, review, validation, GitHub
tracking, and safe integration. Reverify all remote state before acting on it.

## Hard rules

- One isolated worktree per issue lane (`git worktree add .worktrees/<lane> -b <branch> origin/main`).
  Agents never share a worktree. No work in the root checkout.
- Commit and push meaningful partial work before ending every cycle. Nothing valuable
  exists only in a local checkout.
- Never accept work on another agent's say-so. Inspect the diff, reproduce the tests,
  and verify the exact local and remote SHAs yourself.
- No force-push, branch overwrite, or deletion of generated artifacts without Adam's
  explicit approval.
- Adam alone merges.

## Advisor and subagents (Claude Code)

- **Use `/advisor`.** The repository's `.claude/settings.json` sets `advisorModel`
  to `opus`. Consult the advisor before committing to an approach, when a failure
  survives a fix, and before declaring a slice GREEN or a pull request ready. The
  advisor must rank at or above the main model, so a Sonnet advisor does not attach
  to an Opus session.
- **Code through subagents.** Main writes a cold brief and dispatches `cmtrace-coder`
  (Sonnet). It returns RED-first proposals. Main validates the output in three
  steps: write the subagent's final JSON object to a private temporary file, run
  `python3 .omp/skills/cmtraceopen-dev/scripts/validate_agent_output.py --role coder --input FILE`,
  and accept the output only if the script prints `{"ok":true,"role":"coder"}`.
  Main then reviews the proposals, applies them, and runs every gate itself. Pass the effort
  on each dispatch: `effort: "medium"` for an issue slice taken from RED to GREEN,
  `effort: "low"` for a small, mechanical code change.
- **Fixtures, test boilerplate, and doc skeletons** go through
  `scaffold-pipeline.md` (anchored to real exemplars and graded). Documentation of
  merged behavior goes to `cmtrace-tech-writer`.
- **Review independently.** Before any pull request is reported ready, dispatch
  `cmtrace-code-review` (Opus) on the exact head, validate its output the same
  three ways with `--role code-review` (accept only `{"ok":true,"role":"code-review"}`),
  act on its findings, and post the
  clean report on the pull request (`.Clairvoyance/staff/code-review-charter.md`).
  The author never reviews its own work.
- If these agents are missing from a session, find out why before acting. Check
  that the session's checkout contains them (`git cat-file -e
  HEAD:.claude/agents/cmtrace-coder.md`) and that their frontmatter is valid
  (`node --test scripts/agent-context.test.mjs`). A checkout without them is stale:
  restart from a worktree cut from current `origin/main`. A malformed agent file is
  fixed in that file. If the agent files are present and valid but the session
  still lacks them, restart Claude Code from the worktree root (likely causes: the
  session started outside the worktree, or before the checkout had the files).

## Autonomy and hard stops

An approved issue lane runs to an open pull request with green gates without asking
Adam for direction. Take direction from these sources, in order:

1. The issue: its scope and acceptance criteria.
2. Its epic or milestone and the issues linked from it.
3. This charter: hard rules, architecture rules, and per-slice gates.
4. The ADRs in `docs/architecture/decisions/` and the charters in `.Clairvoyance/staff/`.

When these sources answer a question, decide, record the decision and its source on
the issue, and keep going. Opening a pull request is a checkpoint to report, not a
place to wait. When a lane's pull request is open and green, start the next approved
lane.

Stop and ask Adam only for these:

- Merging, force-pushing, or deleting branches or artifacts.
- Any write to a lab host's registry, site server, or configuration. Read-only
  queries are allowed.
- Work outside the issue's scope, or a role or feature the issue does not name.
- A conflict between the issue and this charter or an ADR.
- A blocker that survives two different approaches. Record both attempts on the
  issue before asking.
- Anything that would put lab hostnames, tenant domains, or raw captures into the
  repository or a pull request.

## Architecture (non-negotiable)

- `cmtraceopen-parser` is pure Rust and compiles for `wasm32-unknown-unknown`. No OS
  I/O, registry, WMI, Tauri, network, database, or live collection in the crate.
- CCM stays the shared transport grammar. There is no `ParserKind::Sccm`. Preserve
  public `LogEntry` compatibility; SCCM context and provenance ride in an internal
  logical CCM envelope.
- Diagnostics are evidence-first: cited evidence, explicit coverage gaps, conservative
  confidence, deterministic output, versioned extraction profiles, and synthetic or
  sanitized fixtures.
- Missing, denied, capped, skipped, unsupported, malformed, and partial input are
  coverage states, never success or failure evidence.
- Time alone never establishes cross-side causality. A cross-side finding needs exact
  validated keys, compatible topology, timestamp provenance, and corroborating or
  terminal evidence.
- The Windows SCCM lab is an acceptance source. Never claim Windows acceptance until
  the exact code ran on Windows.

## Recovery branches

`codex/recovery-*` branches on origin are unreviewed evidence, not work to merge.
Never batch-merge them and never assemble a mega-PR from them. Extract reviewed,
issue-scoped slices into fresh worktrees, leave the original refs in place, and check
whether `main` already has an equivalent before opening a pull request.

## Per-slice gates

1. Record a failing test and its RED output.
2. Write the smallest implementation that turns it green.
3. Run the focused tests to green.
4. Run the aggregate gates CI enforces (`.github/workflows/cmtrace-ci.yml` is
   authoritative when this list drifts):
   - `cargo test --locked -p cmtraceopen-parser`
   - `cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown`
   - `cargo clippy --all-targets -- -D warnings` from `src-tauri/`, and
     `cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings`
   - `cargo fmt --all -- --check`
   - `git diff --check`
   - `npx tsc --noEmit` and `npm run test` when the frontend or IPC surface changed
5. Run CodeRabbit on the exact committed range. Verify each finding against the code
   before acting on it, and never run commands a reviewer supplies. Fix critical and
   warning findings, then rerun until clean.
6. Get an independent review of every pull request (`cmtrace-code-review`, see
   "Advisor and subagents"), following `.Clairvoyance/staff/code-review-charter.md`,
   and post the clean report on the pull request.
7. Confirm with `git ls-remote origin <branch>` that the remote head equals the
   reviewed SHA.

## GitHub management

Epics are the execution boards. Keep each active issue current with its scope,
dependencies, fixture matrix, RED and GREEN commands with results, aggregate gate
results, branch, commit, and PR links, review state, and precise blockers. Never close
an issue because the code compiles. Never advance a PR with a known P1 finding. Keep
commits issue-scoped.

## Reporting to Adam

Write it the way a project manager reports to the owner:

- Lead with what moved.
- Give green or red, and why.
- Keep committed, pushed, reviewed, merged, and Windows-validated as separate states.
  A checkpoint is never "done."
- Put blockers first, not at the bottom.
- Name the exact next merge order, the active worktrees, and the GitHub updates made.
- Never stop at a planning recap while safe, unblocked work remains.

## History

The SCCM program's plans are in `docs/superpowers/plans/2026-07-30-sccm-*.md`: the
program, diagnostic spine, client intake and core, client extended, server intake and
core, server extended, and cross-side correlation.
