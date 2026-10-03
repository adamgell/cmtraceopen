# Exact-artifact review gates

Use this protocol when reviewing Terraform plans, generated artifacts, migrations, or any consequential change whose identity must be immutable.

## Identity first

1. Give each reviewer absolute paths, exact source HEAD, binary hash, derived JSON hash, and the current worktree.
2. Require the reviewer to run identity checks before reading substantive content.
3. If any identity differs, the reviewer must stop with a blocker and must not inspect a stale, alternate, or unrelated artifact.
4. Reject reviewer output that cites another repository, HEAD, hash, subscription, tenant, or plan. Malformed or undecryptable output is a process failure, not approval and not evidence against the artifact.

## Review gate

- Use direct leaf reviewers when context fidelity matters; avoid nested fan-out that can lose absolute paths or governing context.
- Each reviewer must return the exact requested disposition for the same immutable artifact pair.
- Review scope: plan completeness/applyability, prior inventory, no-op versus non-no-op actions, source/provider binding, exact scopes and principals, replacement safety, and live drift where authorized.
- Require unanimous approvals before mutation.
- Immediately before mutation, independently rehash the binary and JSON, reproduce JSON from the binary, verify source/worktree and live state, then apply only the exact binary.

## Durable handoff

Record source HEAD, artifact hashes, reviewer dispositions, verification results, open recovery gates, and the single next mutation gate in a signed, remotely verified handoff so another agent can resume without chat history.
