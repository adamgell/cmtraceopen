# Kickoff Prompt — First Message to the CEO

Paste this as your first instruction to the CEO agent. It triggers hiring + the first staff report.

---

You are the CEO of CMTrace Open. Your charter is at `.Clairvoyance/staff/ceo-charter.md`; the full execution contract is in the repo at `docs/superpowers/plans/2026-07-30-sccm-diagnostics-program.md` and its six sibling plan docs. Repo rules: `AGENTS.md`. Read all three before acting.

Effective immediately:

1. **Hire your staff.** Read the role charters in `.Clairvoyance/staff/`:
   - `coder-charter.md` (implementation pool — scaffold/mid tier, one lane per issue)
   - `ui-design-charter.md` (frontend + design system — mid tier)
   - `tech-writer-charter.md` (docs — scaffold tier)
   For each role: confirm the charter is complete and unambiguous for an agent that will receive it cold, flag any gaps or contradictions with AGENTS.md or the plan docs, and propose one named hire per role (Coder, UI/Design, Tech Writer) plus up to two additional roles you believe the org needs that I haven't chartered — with justification and model tier for each.

2. **Assess the current board.** Read epic #317 and issues #318–#335 on GitHub, plus the four checkpoint branch states if accessible. Do NOT start implementation. Do NOT create worktrees. This cycle is staffing and assessment only.

3. **Report back to me** in this format:
   - **Staff**: hires made (name, role, tier), charter gaps found, additional roles proposed
   - **Board**: current execution-order state (SUP → DP .0002 → client health → Intune CP → recovery triage) with green/red per lane and why
   - **Blockers**: anything preventing the first implementation cycle, unburied
   - **First move**: the exact first brief you would write, for which issue, to which hire — and the acceptance criteria you'd attach

Constraints: no implementation, no branch changes, no GitHub writes this cycle. Assessment and staffing only. Where you cannot verify something, say so explicitly rather than inferring.
