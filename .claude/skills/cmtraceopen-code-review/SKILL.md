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
