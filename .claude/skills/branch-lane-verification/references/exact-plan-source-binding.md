# Exact plan/source binding checklist

Use this for Terraform or other external-state changes reviewed by artifact
hashes.

## Identity block

Record, in this order:

- repository and branch;
- actual worktree `HEAD` and tree SHA;
- signed/reviewed source head;
- binary plan SHA-256;
- JSON/rendered-plan SHA-256;
- whether the JSON was derived from that exact binary.

## Fail-closed checks

- A clean worktree is necessary but not sufficient; compare the actual `HEAD` to
the source head named by the review.
- Any intervening commit invalidates an exact-plan approval, including tests,
preflight changes, documentation changes, or changes believed unrelated to
Terraform.
- Do not pair a newly regenerated JSON file with an older binary. Do not accept
an empty file or a human-readable log as the JSON artifact.
- Review both privilege scope and lifecycle ordering. Exact-container scope does
not remove the risk of a delete/create role replacement gap.
- Check whether a failed prior cleanup leaves a recovery marker, state version,
lease, or other recovery object stranded. Do not proceed from unchanged recovery
state merely because the plan is applyable.

## Disposition vocabulary

- **NO BLOCKERS TO APPLY THIS EXACT PLAN** — only when the exact pair, source
head, live preconditions, and all required review lanes match.
- **HOLD / REQUEST CHANGES** — identify the precise stale hash, source-head drift,
missing artifact, privilege concern, ordering/rollback hazard, or recovery-state
blocker. Never silently downgrade this to approval.

## Minimal verification commands

```bash
git status --short --branch
git rev-parse HEAD
 git rev-parse HEAD^{tree}
shasum -a 256 <binary-plan>
shasum -a 256 <json-plan>
```

If the plan tool supports it, derive JSON from the binary in the same review
workspace and hash that output; retain the binary and JSON together until the
apply decision is complete.
