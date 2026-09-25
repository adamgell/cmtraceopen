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
6. Get an independent review for shared interfaces, following
   `.Clairvoyance/staff/code-review-charter.md`.
7. Push the exact reviewed commit and confirm the remote SHA with `git ls-remote`.

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
