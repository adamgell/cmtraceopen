# Live-state exact-plan review checklist

Use this when an infrastructure POC has a saved Terraform plan, a signed source head, and an existing external state/bootstrap environment.

## Identity

Capture, before interpretation:

- repository and named POC worktree path;
- branch and clean/dirty status;
- actual `HEAD` and signed/reviewed source HEAD;
- binary plan SHA-256 and JSON/rendered-plan SHA-256;
- JSON provenance showing it was derived from the exact binary.

A plan pair generated from an older head is stale even when intervening edits appear unrelated or test-only. An empty JSON, independently regenerated JSON, or unmatched binary is not review evidence.

## Read-only live tuple

Against the exact plan coordinates, verify and record only non-sensitive facts:

1. authenticated tenant and subscription;
2. resource-group and resource inventory;
3. account public-network setting, default network action, and bypass list;
4. Shared Key authorization and container public access;
5. versioning and retention settings;
6. role assignments at the exact intended scope, including role name and principal type;
7. recovery-marker/version inventory and whether the active state is unchanged;
8. any expected pre-apply drift.

Do not copy state contents, credentials, SAS values, ETags, backend coordinates, private URLs, or customer data into the review.

## Compatibility correction check

If the current branch changes an Azure CLI invocation, execute the old and new read-only command forms when safe. Confirm the failing/unsupported flag is removed only from the affected command, the live command succeeds, and a focused regression test asserts the argument contract. For example, `az storage account blob-service-properties show` may reject `--auth-mode login` even though other `az storage` commands accept it.

## Disposition

Use `NO BLOCKERS TO APPLY THIS EXACT PLAN` only when source HEAD, binary/JSON pair, and live tuple all match and all required independent reviews are present. Otherwise use `HOLD` or `BLOCK`, identify the exact mismatch, and require regeneration/re-review rather than applying or treating prior approvals as transferable.
