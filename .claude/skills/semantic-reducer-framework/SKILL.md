---
name: semantic-reducer-framework
description: Use for cross-lane diagnostic reducer architecture.
version: 1.0.0
platforms: [macos, linux, windows]
---

# Semantic Reducer Framework

Use this skill when parallel agents design, implement, review, or integrate evidence-driven diagnostic reducers, especially Intune/SCCM/ESP workloads.

## Reconcile before implementation

Treat pasted ChatGPT/Codex/Claude proposals as **discussion handoffs by default**, not execution authorization. First determine whether Adam wants critique, planning, or execution; do not infer coding permission from a detailed checklist.

Before launching a coding fleet:

1. Read project rules, soul/memory, staff charters, relevant skills, shared evidence/normalized contracts, representative reducers, active PRs, and unresolved review findings.
2. Verify the target PR/branch SHA and inspect its actual file list; do not trust a handoff's promised files.
3. Identify the repository's existing mechanisms (.Clairvoyance/staff/ charters, .claude/skills/, .omp/) for orchestration, isolated worktrees, TDD, adversarial review, and exact-head integration.
4. Report harness assessment, contract gaps, staff changes, PR assessment, pilot findings, and an exact first cycle. Keep the decision report short enough to skim; lead with the recommendation and the one decision Adam must make.
5. If Adam authorizes a governance slice, implement only that slice; do not expand into runtime work or a coding fleet.
6. Wait for approval before broad runtime implementation when the request explicitly asks for reconciliation first.

When reporting the reconciliation, separate three states explicitly: **proposal quality**, **what was actually changed**, and **what remains pending approval**. Do not bury a critique under a long implementation plan.

## Governance-only acceptance slice

When a governance PR is directionally accepted with requested changes, keep the correction slice documentation-only and reconcile every governance artifact before Phase 2:

1. Reorder the implementation plan so the workload pilot's RED tests and concrete fixes precede any generic conformance harness, semantic runtime layer, or shared abstraction.
2. Add every confirmed pilot defect to the workload semantic inventory, including identity mismatches that look superficially correlated (for example, `app_id` matching without compatible package/product identity).
3. Keep conceptual taxonomies conceptual. An evidence-strength vocabulary must not silently become a mandatory shared enum, envelope, or runtime representation unless a concrete pilot proves that need.
4. Distinguish accepted architecture boundaries from provisional implementation scope. For redaction, the cross-lane boundary may be accepted while token algorithm, keying, equality scope, and cross-artifact/session/export behavior remain provisional pending explicit tests.
5. Consolidate duplicate routing entries rather than adding another overlapping Clairvoyance route; one canonical route should point to the design, ADRs, and pilot inventory.
6. Do not add production reducer code to the governance PR. Phase 2 belongs on a separate workload branch and starts with typed-intent and input-order RED tests; record the real failures before implementing fixes.

Verify the governance slice by checking plan, design spec, ADRs, inventory, routing, and PR body for contradictory sequencing or status language. Inspect the exact changed-file list and reject any runtime/source changes. After editing a PR body through `gh`, re-read the live body and check for shell-quoting artifacts such as an unintended literal outer quote.

## Ownership

- CEO/orchestrator: sequencing, truth reporting, merge recommendation, final escalation.
- Reducer Contract owner (reasoning tier): normative cross-lane semantics, ADRs, shared helpers, semantic review.
- Reducer Adversary: independent attacks; produces minimal RED fixtures before fixes.
- Integration verifier: current-main restack, shared-contract drift, exact-head gates, conformance/full parser/wasm checks.
- Evidence and Normalizer: required lane phases initially, not permanent staff unless reuse proves it.
- Reducer implementation agent: workload-specific state transitions only; raises cross-lane contract questions instead of inventing precedent.

Only one owner edits shared semantic contracts at a time. Feature lanes use isolated worktrees and submit contract-change requests.

## Semantic pipeline

```text
raw artifact → source classification → normalized typed observation → assessability
→ identity → chronology → correlation → workload reduction → findings → redacted export
```

Do not bypass stages. Raw/untyped metadata cannot establish authoritative intent or identity. Timestamp proximity cannot establish causality. Coverage gaps cannot become success/failure evidence.

## Minimum contracts

Prefer small pure helpers over a second evidence envelope. Start from the existing observation context and define only what real cases prove necessary:

- `is_assessable`, `can_correlate`, and `can_drive_terminal_state`.
- timestamp/order quality: explicit UTC/offset/sequence semantics; local/unspecified/invalid remains ambiguous.
- evidence strength separate from finding confidence.
- correlation decisions record strength, reason, and supporting evidence references.
- unresolved authoritative conflict becomes `Unknown`/`Conflicting`, not an arbitrary winner.

Do not build a universal reducer, configurable rules engine, numeric-confidence system, or broad generic trait speculatively.

## ADR ledger

Before more lanes establish precedent, write short ADRs covering:

1. evidence strength → finding confidence;
2. identity/correlation and prohibition on time-only causality;
3. chronology and terminal-state precedence;
4. redaction token scope, keying, and equality across records/artifacts/sessions/exports.

Each ADR contains Context, Decision, Consequences, and executable invariants/tests. See `references/semantic-reducer-reconciliation.md` for the reviewed Store pilot pattern.

## Conformance invariants

Start deterministic and add property testing only where it earns leverage:

1. permutation does not change results unless ordering is explicit evidence;
2. duplication does not inflate confidence or change terminal state without a defined reason;
3. irrelevant evidence cannot affect another package/session/transaction;
4. weak identity cannot create strong correlation;
5. time-only correlation cannot create high-confidence causality;
6. malformed/missing/denied/capped/skipped/unsupported evidence cannot create terminal success/failure;
7. unresolved authoritative contradictions become conflict/unknown;
8. installer/workload families remain isolated;
9. findings cite evidence/coverage that actually supports the conclusion;
10. redaction preserves non-sensitive semantic conclusions.

## Microsoft Store pilot

Use the active Store reducer as the first proof, but convert real review findings into tests before extracting abstractions. Group root-cause-equivalent findings:

- typed assignment intent must not be overridden by caller-writable `named_data`;
- terminal reduction must not depend on artifact/vector order;
- retry linkage and terminal precedence must be explicit;
- AppX/UWP and Store Win32 families must remain isolated;
- redaction equality/key scope requires an ADR;
- unknown event version must be distinct from level mismatch;
- source classification must require approved provider/channel combinations;
- expected fixtures must not claim phases/confidence unsupported by assessable evidence.

### Reasoning-tier adversarial review pitfalls

When reviewing a reducer PR, inspect the normalized contract fields—not only the workload-local payload. In particular:

- If the normalized input has an explicit schema/event-version field, verify the reducer actually gates on it. Checking only an optional payload `named_data["Version"]` can let unsupported versions drive terminal outcomes.
- Distinguish chronology from linkage. Same-artifact monotonic record numbers establish ordering, but do not by themselves prove that a later success is a retry of an earlier failure. Require an explicit activity/session/transaction link or a documented source contract that establishes both.
- Exercise duplicate observations with identical provenance keys and conflicting payloads. A sort keyed only by `(artifact_id, record_number)` can leave error selection dependent on stable-sort input order.
- Review finding projections independently from reducer conclusions: citation order, duplicate references, and rendered counts should be canonicalized even when transaction conclusions are permutation-invariant.
- Treat GitHub status checks separately from review state: a CodeRabbit `SUCCESS` status is not `approved_at_head`; inspect the actual review state and commit SHA.

The report should use the contract/adversary/mechanical layers in that order, cite `file:line`, provide a concrete false-story input, state disposition, and separate observed CI, local tests, formatting, CodeRabbit, conformance, and native-validation gates. See `references/reasoning-tier-adversarial-review.md` for the compact review matrix.

Begin with the smallest RED fixture: typed assignment intent paired with conflicting untyped metadata. Then reverse input order for a known lifecycle case. Fix only after the adversary records the red result.

## Verification gates

For every lane: verify exact SHA and scope; observe RED; implement the smallest fix; run focused green; run full parser tests, strict Clippy, lane-scoped rustfmt with `skip_children=true`, wasm32 check, and `git diff --check`; obtain independent semantic review with file/line citations; verify the exact head; separate implementation-green, conformance-green, review-green, and native/lab-validation-green.

Never claim a delegated review or gate passed without reading its actual transcript/result. Never claim synthetic fixture success is native Windows/SCCM acceptance.

## References

- `references/semantic-reducer-reconciliation.md` — session-derived PR/Store assessment and first-cycle template.
