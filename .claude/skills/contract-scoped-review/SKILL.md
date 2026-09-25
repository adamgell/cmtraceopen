---
name: contract-scoped-review
description: Review exact plans against contracts; report disposition.
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
---

# Contract-Scoped Review

Use when asked to review an exact correction plan, bootstrap plan, implementation plan, or proposed diff against an authorized contract. The goal is scope and contract compliance—not implementation, cleanup, or a general code review.

## Required workflow

1. **Establish the authority.** Identify the exact contract, plan, acceptance criteria, and repository/worktree under review. If the governing text is unavailable, stop and report that precise blocker; do not infer authorization from commit history or nearby documentation.
2. **Remain read-only.** Inspect status, relevant files, plan text, and the exact diff/commit. Never edit, stage, commit, merge, reset, auto-fix, or alter generated artifacts during this review.
3. **Verify actual state.** Check that paths, URLs, symbols, and behavior in the plan match the current repository. Do not approve from a commit title or summary alone.
4. **Build a scope ledger.** For every changed file/behavior, classify it as required, required consequence, or unauthorized. “Helpful,” “accurate,” and “low risk” do not make an incidental change authorized.
5. **Check contract invariants.** Confirm the correction satisfies the requested behavior without adding fallback paths, cleanup, unrelated documentation, changelog edits, version bumps, or refactors unless explicitly authorized.
6. **Choose one disposition.** Approve only when all required changes are present and no unauthorized changes exist. Otherwise block/reject and name the exact file or behavior that must be removed or corrected.

## Output contract

If the caller requests an exact disposition, return only:

- `APPROVE — [one-line reason]`, or
- `BLOCK — [precise blocker and minimal correction]`.

Do not include a process recap, broad suggestions, or a speculative plan. A good blocker names the exact extra file/behavior and the minimal fix, e.g. `BLOCK — unrelated CHANGELOG.md and bucket/README.md edits exceed the authorized URL correction; remove those edits.`

## Bootstrap/documentation corrections

For bootstrap URL/path corrections, independently verify both the executable's expected repository path and every documentation example. A duplicated README may require synchronized correction, but unrelated README bullets, changelog links, version examples, or packaging instructions remain out of scope unless the contract names them.

## Pitfalls

- Treating a clean current worktree as proof that a proposed historical commit is approved.
- Treating a commit title, branch name, or plan summary as the authorization boundary.
- Expanding a narrow correction into “while here” documentation or release cleanup.
- Reporting a general code-review summary when the caller requested only disposition/blocker.
- Guessing missing contract text from repository history.
