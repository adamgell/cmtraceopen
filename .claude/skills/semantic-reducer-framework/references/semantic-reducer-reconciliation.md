# Semantic Reducer Reconciliation Reference

## Reviewed architecture/orchestration pattern

Reconcile before implementation: inspect project rules, Clairvoyance staff charters and repository skills, shared evidence/normalized contracts, representative reducers, active PRs, exact SHAs, and unresolved review findings. Report harness assessment, contract gaps, staff changes, PR assessment, pilot findings, and the first cycle before launching broad runtime work.

## PR/design completeness check

Compare the PR body and promised deliverables to the actual file list. A governance PR promising four ADRs is incomplete if it contains only a design spec, plan, charters, and routing. Do not treat a draft design handoff as unquestionable truth.

## Microsoft Store pilot clusters

Group review findings by semantic root cause:

1. Typed assignment intent must come only from an approved typed assignment origin; caller-writable `named_data` cannot override it.
2. Terminal reduction must not depend on artifact/vector order; chronology requires explicit source semantics.
3. Retry linkage and terminal precedence must be explicit; unrelated or ambiguously linked success cannot overwrite failure.
4. AppX/UWP and Store Win32 families require separate semantics and findings.
5. Redaction equality and key scope require an ADR before new token algorithms establish precedent.
6. Unknown event/schema version is distinct from known event with unexpected level.
7. Source classification requires approved provider/channel combinations, not arbitrary substrings.
8. Expected fixtures must not claim phases or confidence unsupported by assessable evidence.

## First-cycle template

Governance correction: reasoning-tier Contract owner, fresh worktree from the exact design PR SHA, docs/ADR/charter/routing files only, no runtime changes. Produce four short ADRs, a grouped Store semantic inventory, and an invariant matrix naming the first RED fixtures.

First executable slice: use current main in a fresh branch. Add only the smallest pure helpers proven necessary by the Store cases—typically assessability, timestamp quality, and citation membership. Avoid a universal reducer trait or rules engine.

Store pilot: Adversary writes the typed-intent RED fixture first, then permutation/chronology and family-isolation cases. Implementation fixes only after RED is observed. Integration verifies exact head, parser, Clippy, rustfmt with skip_children, wasm, and semantic review.

## Reporting distinctions

Always distinguish implementation-green, conformance-green, review-green, merged, and native/lab-validation-green. Delegated completion is not a review verdict until the transcript/result is inspected. Synthetic fixtures never establish native Windows/SCCM acceptance.
