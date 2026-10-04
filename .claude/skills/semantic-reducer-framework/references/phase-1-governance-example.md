# Phase 1 governance example

Use this as a compact execution pattern when Adam authorizes a governance-only reducer-framework slice.

## Scope

- Inspect the target PR's actual head and files.
- Use an isolated worktree/branch from the exact PR head.
- Add four short ADRs and a workload semantic issue inventory.
- Reconcile the design so Evidence and Normalization are lane phases, not permanent agents.
- State that v1 begins as a workload-driven semantic test kit, not a universal reducer framework.
- Do not change runtime code, reducer code, or production behavior.

## Verification

1. Confirm no `crates/`, `src/`, or `src-tauri/` files changed.
2. Run `git diff --check`.
3. Commit with a focused documentation message.
4. Push only when explicitly authorized.
5. Verify the remote branch SHA and PR head SHA match.

## Reporting

Report only:

- exact PR/head/commit;
- files added or changed;
- runtime-change status;
- verification results;
- the next RED-test branch plan.

Keep the report short. Do not relitigate the full architecture after the governance slice is complete.
