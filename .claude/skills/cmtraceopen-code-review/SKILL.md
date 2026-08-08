---
name: cmtraceopen-code-review
description: Use when reviewing any cmtraceopen change - a diff, branch, or PR - or when asked whether cmtraceopen work is merge-ready. Runs the review against the repo's own gates instead of generic criteria.
---

# CMTrace Open — Code Review

Thin wrapper. The canonical review contract is
`.Clairvoyance/staff/code-review-charter.md` — read it FIRST and follow its load
order and review recipe exactly (contract layer, then adversarial layer, then
mechanical layer).

The charter routes to everything else: the routing indexes
(`.Clairvoyance/library.md`, repo-root `library.md`), the four reducer ADRs
(`docs/architecture/decisions/`), the reducer review checklist
(`docs/superpowers/plans/2026-08-07-reducer-framework-v1.md`), the reviewer role
charters (`reducer-contract`, `reducer-adversary`, `reducer-integration`), and the
specialist context (repo-root `soul.md`, `memory.md`).

The deliverable is the charter's gate-state report: findings ranked most-severe
first, named gate states (CI, CodeRabbit `approved_at_head` via the
`coderabbit-review-loop` skill's state script, contract conformance), and rejected
feedback with reasoning. Merging is the repository owner's action; the review ends
at the report.

## Delegating a review to Hermes

Launch rules, each learned from a failed launch (2026-08-08):

1. Everything the review needs must exist ON MAIN and on disk before launching -
   an unmerged skill or charter branch means Hermes finds nothing and wanders
   into stale refs.
2. Launch from the repo directory so relative paths resolve, and state in the
   prompt that all charter files are on main.
3. The prompt must say, verbatim: "read branch files ONLY via git show
   origin/BRANCH:PATH - never git checkout." A --yolo session in the shared root
   checkout once checked out the PR branch, which yanked the charter and skills
   out from under every other session. Verify `git branch --show-current` is
   main after any Hermes session ends.
4. Do not pass `-m`: Hermes routes per his own tiering (his direct API keys are
   unset; gateway model names are not enumerable from the CLI). If a GPT tier is
   explicitly required, Adam's pick is luna, never sol.
5. Redirect output straight to a log file, never through a pipe (`| tail`
   buffers everything and hides a silent death). `hermes --cli` also buffers
   stdout until exit when non-interactive, so the desktop UI is the live view -
   monitor the observable outcome (the PR comment, the process), not the log.
6. After launching, verify the process exists (`pgrep`) before reporting it
   running, and arm a watcher that fires on success AND on death.

Working launch shape:

```bash
cd /Users/Adam.Gell/repo/cmtraceopen && hermes --cli --yolo \
  --skills cmtraceopen-code-review \
  -z "<task: target PR; charter on main; git show only, never checkout; read-only; one report comment>" \
  > /tmp/hermes-review.log 2>&1 &
```
