---
name: cmtraceopen-agent
description: Use when loading the CMTrace Open specialist agent context - starting substantive work on src/, src-tauri/, or crates/cmtraceopen-parser/, or when a task needs the agent's identity, operating rules, or durable project memory.
---

# CMTrace Open — Specialist Agent Loader

Thin wrapper. Canonical agent files live at the repo root and are the single source
of truth (never maintain copies elsewhere):

| File | Purpose |
|------|---------|
| `soul.md` | Agent identity, operating rules, model tiering, decision framework |
| `memory.md` | Durable facts: architecture, verified checkpoints, execution order |
| `.Clairvoyance/library.md` | Routing index - where the repo's knowledge lives |

Read `soul.md` and `memory.md`, then consult `.Clairvoyance/library.md` for
task-specific routes. For reviews, use the `cmtraceopen-code-review` skill.
