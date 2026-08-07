# Reducer Framework v1 — Design

**Status:** Proposed
**Date:** 2026-08-07
**Scope:** `cmtraceopen-parser` diagnostic reducers and the agent workflow that builds/reviews them

## Problem

CMTrace Open now has multiple parallel diagnostic lanes that normalize heterogeneous evidence and reduce it into findings. The parser-family skeleton already provides shared evidence, provenance, coverage, finding, and normalized Windows input contracts. The remaining risk is semantic drift between workload reducers: different interpretations of identity, chronology, correlation, confidence, coverage, terminal-state precedence, conflict handling, and redaction can each be locally plausible while producing incompatible or false diagnostic stories.

Parallel agents may specialize in workload evidence. They must not independently redefine shared semantic truth.

## Goals

1. Make reducer-wide semantic invariants explicit and testable.
2. Preserve workload-specific domain semantics without building a generic mega-reducer.
3. Make false positive causal conclusions harder than conservative `Unknown`/`Conflicting` outcomes.
4. Turn adversarial review findings into reusable failing fixtures or property tests.
5. Give parallel agents clear ownership boundaries and escalation rules.
6. Keep `cmtraceopen-parser` pure Rust and `wasm32-unknown-unknown` compatible.
7. Introduce the framework incrementally, proving it on one active workload before broad migration.

## Non-goals

- Do not rewrite all existing reducers in one change.
- Do not unify ESP, Intune, SCCM, or other domains into one public schema.
- Do not create a configurable rules engine.
- Do not assign numeric confidence scores.
- Do not infer causality from timestamp proximity.
- Do not make raw `named_data` authoritative merely because a field name looks useful.
- Do not add compatibility layers for obsolete reducer behavior.

## Pipeline contract

Reducer lanes should remain legible as the following stages:

```text
Raw artifact
  -> source classification
  -> normalized typed observation
  -> trust / assessability
  -> identity resolution
  -> temporal ordering
  -> correlation
  -> workload state reduction
  -> findings
  -> redacted/export projection
```

A later stage may consume the output of an earlier stage. It must not bypass an earlier semantic boundary. In particular:

- raw parser metadata does not directly establish a terminal workload outcome;
- arbitrary `named_data` does not become authoritative intent or identity until explicitly normalized into a typed concept;
- timestamps can order otherwise-correlated evidence but do not create strong correlation by themselves;
- malformed, denied, capped, skipped, unsupported, or otherwise non-assessable evidence cannot silently become success/failure evidence;
- findings cite the observations or coverage gaps that support them.

## Shared semantic contracts

### Assessability

The existing `IntuneObservationContext` remains the source of provenance, parse state, access state, timestamp, and sensitivity. Reducer Framework v1 adds shared helpers that answer semantic questions without each reducer reimplementing boolean combinations.

Initial helpers should include concepts equivalent to:

- `is_assessable()` — source is available and parsed strongly enough to drive semantic outcomes;
- `can_correlate()` — observation is usable as correlation evidence;
- `can_drive_terminal_state()` — observation is sufficiently authoritative for a terminal state;
- `timestamp_quality()` — normalized ordering strength, not an inferred timezone.

These should be small functions/enums over existing contracts, not a new parallel evidence envelope unless implementation proves the current context cannot express the distinction.

### Evidence strength

Evidence strength and conclusion confidence are separate concepts.

Recommended evidence-strength lattice:

```text
Authoritative
Strong
Corroborating
Weak
Untrusted
```

A reducer maps workload-specific observations into this shared strength vocabulary. Multiple weak observations do not automatically become authoritative.

Existing `IntuneFindingConfidence::{Low, Medium, High}` may remain the public finding projection for v1. The framework must document how evidence strength constrains confidence rather than introducing a breaking public confidence model immediately.

### Correlation

Correlation is an explicit decision with a reason, not a side effect of grouping records.

Recommended shared strength/order:

```text
Exact transaction/session key       -> strong
Exact package/workload identity      -> strong
Explicit shared correlation key      -> strong
Stable secondary identity            -> moderate
Composite name + version             -> weak/candidate
Display name alone                   -> never sufficient
Timestamp proximity alone            -> candidate only
```

The shared framework should return a typed correlation decision containing at least the strength/reason and the evidence references used to make it. Workload reducers decide which correlation strengths are sufficient for their state transitions.

### Chronology

Reducers must not depend on caller-provided vector ordering unless the source contract explicitly defines that order as evidence. Temporal reduction should use explicit normalized timestamps and/or source-native sequence/record identifiers.

Rules:

- explicit transaction/session ordering beats wall-clock proximity;
- source-native monotonic record identifiers may order records within their defined scope;
- UTC/offset-normalized timestamps may order evidence when their timestamp quality is sufficient;
- local/unspecified/invalid timestamps cannot be silently promoted to UTC ordering;
- ties or incomparable clocks remain ambiguous unless another key resolves them.

### Terminal-state precedence

Terminal outcomes must be selected from assessable, correlated observations. A later-looking record from a different identity/family/session cannot overwrite an earlier terminal state.

Retries must be modeled explicitly. A failure followed by a success is not automatically success unless the evidence establishes that both belong to the same logical operation/retry chain.

When authoritative terminal evidence conflicts and no contract resolves precedence, the reducer should prefer `Conflicting`/`Unknown` over an arbitrary winner.

### Coverage

The existing Intune coverage model remains authoritative. Missing, permission denied, capped, skipped, parse-failed, and unsupported evidence are distinct diagnostic states.

A coverage gap can lower confidence or prevent a conclusion. It cannot be interpreted as proof that the missing signal did not occur.

### Findings

Every finding must satisfy the existing evidence-backed invariant and additionally:

- cite evidence that actually participates in the conclusion;
- not cite an unrelated observation merely to satisfy `is_evidence_backed()`;
- preserve the distinction between observed failure and inability to assess;
- name the smallest useful next artifact/check when uncertainty remains.

### Redaction

Redaction policy is a cross-lane architecture concern. Workload reducers must not independently choose incompatible token semantics.

Reducer Framework v1 must document and test:

- which identifiers may survive export unchanged for diagnostic correlation;
- which values require redaction;
- whether redacted equality may persist across records, artifacts, sessions, or exports;
- whether correlation tokens require caller-controlled/session-scoped keying;
- that redaction does not accidentally change reducer semantics.

Until that ADR is accepted, new workload-specific token algorithms should not be introduced.

## Reducer conformance suite

Create a reusable test harness under the parser crate. It should make the following invariants cheap to assert for each participating reducer:

1. **Permutation invariant:** shuffling input observations does not change the result unless source ordering is itself explicit evidence.
2. **Duplicate invariant:** duplicate evidence does not strengthen a conclusion beyond the defined contract.
3. **Irrelevant-evidence invariant:** unrelated observations do not alter another transaction/package/session outcome.
4. **Weak-identity invariant:** weak identity cannot produce strong correlation.
5. **Time-only invariant:** time proximity alone cannot create high-confidence causality.
6. **Coverage invariant:** inaccessible/malformed/capped/skipped evidence cannot create a terminal success/failure.
7. **Conflict invariant:** unresolved authoritative contradictions produce conflict/unknown rather than arbitrary winner selection.
8. **Family-isolation invariant:** unrelated installer/workload families do not collapse implicitly.
9. **Citation invariant:** every finding is backed by evidence or a real coverage gap and those references belong to the reduced input.
10. **Redaction invariant:** redacted/export projection does not change non-sensitive semantic outcomes.

Use deterministic table-driven tests first. Add `proptest` only where it materially increases coverage (permutations, duplication, irrelevant-observation injection, optional-observation deletion, and safe mutation of non-key display fields). Do not add property testing merely for novelty.

## Adversarial scenario library

Each workload should include negative scenarios, not only happy-path fixtures. The adversary role should attempt cases such as:

- same display name, different package identity;
- same app ID, incompatible package/product identity;
- out-of-order observations;
- caller-provided artifact order contradicting evidence chronology;
- later success from a different installer family;
- assignment intent present only in untyped/untrusted metadata;
- overlapping sessions with no shared identifier;
- malformed source plus successful sibling source;
- terminal failure followed by a retry with ambiguous linkage;
- duplicate events;
- missing event channel;
- unknown schema/event version;
- contradictory authoritative observations;
- privacy-sensitive values whose redaction could alter equality/correlation.

A discovered semantic defect should preferably become a failing fixture/property case before implementation changes.

## Agent organization

### Reducer Architecture / Contract Agent

Reasoning tier. Owns the normative contracts, ADRs, conformance rules, and cross-lane semantic review. Does not implement workload feature lanes by default.

### Evidence Agent

Produces an evidence card before reducer implementation: source provenance, authoritative fields, identity keys, ordering guarantees, known schema/version bounds, privacy classification, and unsupported assumptions. Real/sanitized evidence anchors are required where project rules require them.

### Normalizer Agent

Maps raw artifacts into typed observations. It does not choose terminal outcomes. Untyped fields remain raw until a contract explicitly promotes them.

### Reducer Agent

Implements workload-specific state transitions using approved normalized types and shared semantic helpers. It cannot redefine global confidence/correlation/coverage/redaction semantics inside the lane.

### Reducer Adversary Agent

Does not start by editing implementation. Attempts to make the reducer tell a false story. Preferred deliverable is a failing fixture/property test plus a short explanation of the violated invariant.

### Integration Agent

Restacks against current `main`, detects shared-contract drift between sibling lanes, runs conformance and full parser gates, and reports exact-head status. It does not waive unresolved semantic findings.

## Parallel-work rules

- Multiple workload lanes may run in parallel.
- Shared semantic contract files have one owner at a time: the Contract Agent.
- Feature agents consume shared contracts and raise change requests instead of casually editing them.
- Agents do not concurrently edit the same branch/worktree.
- A reducer implementation is not complete because its happy-path suite is green. It is complete when the adversarial/conformance pass cannot produce an unresolved false-story case within the agreed contract.
- Architecture questions with cross-lane impact become ADRs before local implementation hardens them into precedent.

## ADR ledger

Create `docs/architecture/decisions/` for short, durable decisions. Initial reducer ADRs should cover:

1. evidence strength and finding-confidence mapping;
2. identity/correlation strength and time-only prohibition;
3. reducer chronology and terminal-state precedence;
4. redaction token scope and cross-artifact/export correlation.

ADRs should contain context, decision, consequences, and concrete invariants/tests. They are not essays.

## Pilot

Use the Microsoft Store evidence lane as the first pilot because it exercises multiple identities, installer families, assignment intent, Windows event evidence, chronology, coverage, findings, and redaction.

The pilot should not require the Store PR to adopt speculative framework abstractions. First encode the review-discovered failure modes as conformance/adversarial cases, then extract only helpers proven useful by more than one case or clearly shared by the parser-family contract.

After the Store pilot, apply the same conformance suite to Autopilot and Company Portal before broadening the framework further.

## Definition of done for Reducer Framework v1

- Normative reducer contract is documented and routed from the project knowledge library.
- Contract/Adversary/Integration agent charters exist and are referenced by the CEO workflow.
- Initial ADRs are accepted for correlation, chronology, confidence/evidence strength, and redaction.
- A reusable conformance harness exists in `cmtraceopen-parser`.
- Microsoft Store passes the agreed conformance/adversarial suite.
- At least one second reducer demonstrates that the shared helpers are actually reusable.
- Full parser tests, strict Clippy, formatting, and wasm32 checks pass.
- No public compatibility layer or generic rules engine was introduced merely to support the framework.
