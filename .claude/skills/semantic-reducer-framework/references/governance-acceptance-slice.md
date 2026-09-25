# Governance acceptance slice — reducer framework

Use this reference when correcting a directionally accepted reducer-governance PR before merge.

## Required reconciliation

- **Plan:** Store typed-intent and input-order RED tests, then concrete Store fixes/adversarial coverage, then generic conformance or semantic runtime extraction only if proven reusable.
- **Inventory:** Include app-ID-only/package-identity mismatch as a correlation defect, not merely a missing-data case.
- **ADR-001:** Treat `Authoritative`, `Strong`, `Corroborating`, `Weak`, and `Untrusted` as conceptual reasoning levels. Do not require a shared runtime enum or evidence envelope.
- **ADR-004:** Accept the redaction architecture boundary while leaving token algorithm, keying, equality scope, and cross-artifact/session/export semantics provisional until explicit tests exist.
- **Routing:** Merge duplicate Clairvoyance routes into one canonical route that points to the design, ADRs, and pilot inventory.
- **Scope:** Governance PRs remain documentation-only. Phase 2 starts on a separate Store branch with real RED tests; do not add production reducer code to the governance PR.

## Verification checklist

1. Inspect the exact PR head and changed-file list.
2. Search plan/spec/ADR/inventory/routing/PR body for stale sequencing or status language.
3. Confirm no runtime paths (`crates/`, `src/`, `src-tauri/`) changed.
4. Run `git diff --check`.
5. Commit and push; verify the remote branch SHA.
6. Re-read the live PR body after `gh pr edit`; shell quoting can leave a literal outer quote if the body is passed incorrectly.
