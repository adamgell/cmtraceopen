---
name: cmtraceopen
description: Use when working on adamgell/cmtraceopen, the Tauri v2 + React + Rust log viewer with Intune, SCCM, and ESP diagnostics, and the task needs the project agent's identity, operating rules, execution contract, or durable project memory.
version: 2.0.0
author: Adam Gell
license: MIT
platforms: [linux, macos, windows]
---

# CMTrace Open project specialist

Everything this skill loads is checked into the repository. Every path below is
relative to the root of the checkout or worktree you are working in. Nothing is read
from a home directory, an agent runtime's profile, or one particular workstation.

## Load order

1. `soul.md`: identity, non-negotiable operating rules, model tiers, decision framework.
2. `memory.md`: durable facts about architecture, gates, and where knowledge lives.
3. `.claude/skills/cmtraceopen/references/execution-charter.md`: when driving issue
   lanes, pull requests, or GitHub tracking.
4. `.claude/skills/cmtraceopen/references/scaffold-pipeline.md`: when handing
   fixtures, test boilerplate, or doc skeletons to a scaffold-tier model.
5. `.Clairvoyance/library.md`: routes a task to the one document it needs.

Live state (open issues, review state, branch SHAs) is never stored in these files.
Read it from GitHub and `git ls-remote` at the moment you act.

## When to load

- Any task touching `src/`, `src-tauri/`, or `crates/cmtraceopen-parser/`
- Building, testing, or packaging the application
- Intune, ESP, DSRegCmd, SCCM, Sysmon, or Secure Boot diagnostics work
- Project history, decisions, or architecture trade-offs
- Creating fixtures, tests, or benchmarks

## Hard rules (full text in `soul.md`)

1. **No backward-compatibility layers.** Remove obsolete paths.
2. **Simplest implementation wins.** No speculative abstractions.
3. **Evidence over assumption.** Missing or malformed input is a coverage gap, not "good."
4. **Never synthesize log lines.** Anchor to the real corpus or refuse.
5. **Conservative parse stance.** Malformed input parses conservatively; never assert rejection.
6. **Isolation discipline.** One worktree per lane. Commit and push before ending a cycle.
7. **Independent verification.** Never accept another agent's say-so.

## Where things live

| Need | Path |
|------|------|
| Identity, rules, model tiers | `soul.md` |
| Durable facts | `memory.md` |
| Execution contract and per-slice gates | `.claude/skills/cmtraceopen/references/execution-charter.md` |
| Scaffold-tier delegation and grading | `.claude/skills/cmtraceopen/references/scaffold-pipeline.md` |
| Repository rules | `AGENTS.md` |
| Build commands, module map, CI gates | `CLAUDE.md` |
| Routing indexes | `.Clairvoyance/library.md`, `library.md` |
| Staff role charters | `.Clairvoyance/staff/` |
| Code review contract | `.Clairvoyance/staff/code-review-charter.md` |
