---
name: semantic-reducer-development
description: Use for evidence-driven reducer design and testing.
version: 1.0.0
platforms: [macos, linux, windows]
---

# Semantic Reducer Development

Use this skill when parallel agents are designing, implementing, reviewing, or integrating diagnostic reducers whose output may form a plausible but false story.

## Core rule

Parallel agents may specialize in workload evidence, but they must not independently define shared semantic truth. Keep workload-specific state machines workload-specific; centralize only proven cross-lane semantics.

## Reconciliation before execution

When given a design handoff or an existing governance PR:

1. Inspect the repository, current agent organization, relevant contracts, active reducer branch/PR, and unresolved review findings.
2. Separate the handoff into correct, missing, unnecessary, and contradicted-by-current-code.
3. Report the reconciliation before broad implementation.
4. Do not launch coding agents from a pasted handoff unless Adam explicitly requests execution. If execution is explicit, begin with the smallest approved slice.

Do not confuse a design discussion with permission to implement. Conversely, once Adam says to proceed, act rather than repeatedly asking for confirmation.

## Framework boundary

Prefer a workload-driven semantic test kit over a universal reducer framework. Do not introduce a generic reducer trait, configurable rules engine, or second evidence envelope speculatively. Reuse existing observation context and normalized types; add small helpers only after real reducer failures demonstrate reuse.

Evidence and normalization are lane phases, not permanent staff roles, unless repeated work proves a durable cross-lane ownership need. Permanent semantic roles should be limited to Contract, Adversary, and Integration.

## Required semantic stages

Keep reducer work legible as:

```text
raw artifact -> source classification -> typed observation -> assessability
-> identity -> chronology -> correlation -> workload reduction
-> findings -> redacted projection
```

A later stage must not bypass an earlier authority boundary. In particular:

- caller-writable or untyped metadata cannot establish typed assignment intent;
- display name or timestamp proximity cannot establish strong identity;
- malformed, denied, capped, skipped, unsupported, or incomplete evidence cannot create terminal success/failure;
- input vector order is not chronology unless the source contract says so;
- unresolved authoritative conflict becomes Unknown/Conflicting rather than an arbitrary winner;
- findings cite evidence or coverage gaps that actually support the conclusion.

## RED-first pilot workflow

For each semantic defect:

1. Create a fresh worktree from the exact reducer PR head.
2. Add the smallest deterministic failing test under the workload lane.
3. Run that exact test and preserve the real RED output.
4. Commit the test-only RED change.
5. Create a second fresh implementation worktree and apply the RED commits.
6. Make the smallest workload-specific fix; do not add framework abstractions during the RED/GREEN slice.
7. Run focused RED tests, the full workload integration suite, lane-scoped formatting, strict Clippy/lint, and diff checks.
8. Independently inspect the diff and verify the exact commit before pushing or proposing integration.

## Conformance invariants

Apply the invariants that fit the workload:

- permutation of non-ordered input does not change semantic output;
- duplication does not inflate confidence or alter terminal state without an explicit reason;
- irrelevant evidence cannot alter another identity/session/transaction;
- weak identity cannot create strong correlation;
- time-only proximity cannot create high-confidence causality;
- coverage gaps remain coverage gaps;
- family/session boundaries remain isolated;
- conflicting authoritative evidence remains conservative;
- citations belong to the reduced input and support the finding;
- redaction preserves intended non-sensitive semantics within its declared scope.

## Verification reporting

Always separate:

```text
RED test verified
GREEN implementation verified
committed
pushed
reviewed
merged
native/lab validated
```

Never report a delegated result as accepted without reading the actual transcript/result. Infrastructure completion is not a semantic verdict.

## Scope discipline

Do not mix governance, RED tests, implementation fixes, and broad refactors in one branch. Governance changes should contain no runtime code. A pilot implementation should touch only the workload module, focused tests, and fixtures unless a contract change is explicitly approved.

## Supporting references

- Store pilot issue inventory and root-cause grouping: `references/store-pilot.md`.
