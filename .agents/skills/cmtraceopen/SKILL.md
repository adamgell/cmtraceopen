---
name: cmtraceopen
description: Use when working on adamgell/cmtraceopen — Tauri v2 + React + Rust log viewer with Intune/SCCM/ESP diagnostics. Loads agent soul, memory, and operating rules.
version: 1.0.0
author: Adam Gell / Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [cmtraceopen, tauri, rust, react, typescript, intune, sccm, esp, log-parser, project-specialist]
    related_skills: [cmtrace-scaffold-pipeline, requesting-code-review, test-driven-development, systematic-debugging]
---

# CMTrace Open — Project Specialist

Load this skill before any work on `adamgell/cmtraceopen`. It provides deep project context so you don't re-read the same files every turn.

## What This Skill Does

This is a **thin wrapper** that points to the canonical agent files at the repo root. The repo files are checked into git and are the single source of truth.

| File | Location | Purpose |
|------|----------|---------|
| **soul.md** | `repo/cmtraceopen/soul.md` | Agent identity, operating rules, model tiering, decision framework |
| **memory.md** | `repo/cmtraceopen/memory.md` | Durable facts: architecture, verified checkpoints, recovery branches, execution order, worktree ecosystem |
| **PM charter** | `~/.hermes/cmtrace-pm-charter.md` | Execution manager contract with SHAs and per-slice gates |

## When to Load

- Any task touching `src/`, `src-tauri/`, `crates/cmtraceopen-parser/`
- Building, testing, or packaging the application
- Working with Intune, ESP, DSRegCmd, SCCM, Sysmon, SecureBoot diagnostics
- Understanding project history, decisions, or architecture trade-offs
- Creating fixtures, tests, or benchmarks

## Quick Start

1. **Read `repo/cmtraceopen/soul.md`** — identity, rules, model tiers, decision framework
2. **Read `repo/cmtraceopen/memory.md`** — checkpoints, recovery branches, execution order, ecosystem state
3. **Read `~/.hermes/cmtrace-pm-charter.md`** if doing execution-manager work — has SHAs, gates, reporting style
4. **Act** — but verify against Adam's known rules before touching code

## Hard Rules (Summary — full versions in soul.md)

1. **No backward-compat layers.** Remove obsolete paths.
2. **Simplest implementation wins.** No speculative abstractions.
3. **Evidence over assumption.** Missing/malformed = coverage gap, not "good."
4. **Never synthesize log lines.** Anchor to real corpus or refuse.
5. **Conservative parse stance.** Malformed input parses conservatively — never assert rejection.
6. **Isolation discipline.** One worktree per lane. Commit + push before ending cycle.
7. **Independent verification.** Never accept another agent's say-so.

## Model Tiering

| Tier | Models | Scope |
|------|--------|-------|
| Scaffold | `kimi-k2.7-code`, `deepseek-v4-flash`, `qwen-flash`, `gpt-5-luna` | Fixtures, boilerplate — always anchored |
| Mid | `kimi-k3`, `grok-4-20-reasoning` | Parser logic, reducers |
| Reasoning | `gpt-5.6-sol`, `claude-opus-4-8` | Contracts, correlation, architecture |

> MLX local tier (`Hermes-4-70B-MLX-4bit`) is **unproven** for codegen. Must pass pilot grading first.

## Key Paths

| Need | Path |
|------|------|
| Agent soul | `repo/cmtraceopen/soul.md` |
| Agent memory | `repo/cmtraceopen/memory.md` |
| PM charter | `~/.hermes/cmtrace-pm-charter.md` |
| Scaffold pipeline | `~/.hermes/skills/software-development/cmtrace-scaffold-pipeline/` |
| Repo routing index | `repo/cmtraceopen/library.md` |
| Agent rules | `repo/cmtraceopen/AGENTS.md` |
| Build commands | `repo/cmtraceopen/CLAUDE.md` |
| Staff org | `repo/cmtraceopen/.Clairvoyance/staff/` |
