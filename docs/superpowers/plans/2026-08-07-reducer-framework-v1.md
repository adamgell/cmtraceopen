# Reducer Framework v1 — Implementation Plan

**Design:** `docs/superpowers/specs/2026-08-07-reducer-framework-v1-design.md`

## Delivery strategy

Land the governance and pilot work as small reviewable slices. Do not refactor every reducer in parallel. The Microsoft Store RED tests and concrete fixes come first; only then may a generic conformance or semantic runtime layer be extracted from proven needs.

## PR 1 — Governance and semantic contract

**Purpose:** make the rules durable before changing reducer code.

Deliverables:

- reducer design spec;
- Contract, Adversary, and Integration agent charters;
- routing updates in `.Clairvoyance/library.md` and project specialist guidance;
- ADR directory and four initial ADRs:
  - evidence strength / finding confidence;
  - identity and correlation;
  - chronology / terminal-state precedence;
  - redaction token scope.
- Microsoft Store semantic issue inventory grouped by root cause.

Acceptance:

- no runtime behavior change;
- charters do not contradict `AGENTS.md`, CEO charter, parser purity, or existing Intune evidence contracts;
- shared semantic questions have one escalation owner;
- Store/Autopilot/Company Portal agents can identify which rules are global vs workload-local.

## PR 2 / Phase 2 — Store typed-intent and input-order RED tests

**Purpose:** start the first implementation phase on a separate Store branch with RED tests for confirmed semantic risks, not a universal reducer abstraction.

First tests:

- typed assignment intent cannot be overridden by caller-writable `named_data` from package/installer observations;
- equivalent input permutation cannot change reduction when the source does not define caller order as chronology.

Record the real failing results against the current Store reducer before changing production behavior. Only after the Store tests and concrete fixes are complete should a shared helper be considered.

## PR 3 — Microsoft Store concrete fixes and adversarial pilot

**Purpose:** fix the confirmed Store defects and extend targeted adversarial coverage while keeping the reducer workload-specific.

Deliverables:

- smallest fixes for the typed-intent and input-order failures;
- app ID/package-identity correlation guard;
- targeted tests for terminal precedence/retries, installer-family isolation, source classification, evidence degradation, confidence propagation, and redaction behavior where the contract is decided;
- corrected fixture expectations only where the prior expectation encoded unsafe semantics.

Acceptance:

- Store happy-path and adversarial tests are green after each smallest fix;
- all Store happy-path fixtures remain green unless an expected output was semantically wrong;
- every changed expected output documents why the prior conclusion was unsafe;
- permutation/duplication/irrelevant-evidence cases pass;
- no time-only strong correlation;
- no terminal outcome from non-assessable evidence;
- full parser/Clippy/wasm gates green.

## PR 4 — Conformance harness foundation

**Purpose:** extract only the generic conformance or semantic runtime layer proven necessary by the completed Store pilot.

Candidate paths:

```text
crates/cmtraceopen-parser/src/intune/conformance.rs
crates/cmtraceopen-parser/src/intune/semantics.rs
crates/cmtraceopen-parser/tests/intune_reducer_conformance.rs
```

Deliverables:

- assessability helpers over `IntuneObservationContext` only where Store and a shared parser contract prove the need;
- reusable assertions/helpers for finding citations and input evidence membership;
- deterministic test utilities for permutation, duplication, irrelevant evidence, and coverage mutation;
- property-test dependency only if deterministic tests cannot economically cover the invariant.

Acceptance:

- no OS I/O and wasm32 remains clean;
- existing reducers continue to compile without mandatory migration unless a bug is exposed;
- helpers are small and domain-neutral rather than a generic reducer;
- `cargo test -p cmtraceopen-parser` green;
- strict Clippy green;
- wasm32 check green.

## PR 5 — Second-lane proof

**Purpose:** prove the framework is shared rather than Store-specific.

Preferred candidate: Windows Autopilot, because it already has explicit sibling-reducer boundaries with ESP, correlation keys, timestamp-quality concerns, conflicts, and redaction.

Alternative: Windows compliance if Autopilot branch integration makes the proof unnecessarily large.

Deliverables:

- apply conformance helpers without redesigning the workload;
- add adversarial cases for weak identity, time-only linkage, conflicting sessions, malformed/denied evidence, and input permutation;
- extract additional shared helper only when both Store and the second lane need it.

Acceptance:

- shared code becomes simpler/more authoritative, not a generic abstraction tax;
- no cross-workload state machine;
- exact-head full parser/Clippy/wasm gates green.

## PR 6 — Workflow enforcement

**Purpose:** make the improved parallel-agent workflow the default.

Deliverables:

- CEO brief template requires an evidence card and lists semantic invariants relevant to the lane;
- reducer implementation brief requires a red-first scenario and explicit non-goals;
- adversary handoff template requests failing fixtures/tests before prose-only findings;
- integration report separates implementation-green, conformance-green, review-green, and native-validation-green;
- optional CI target for reducer conformance if runtime remains reasonable.

Acceptance:

- a new reducer issue can be assigned cold without the coder inventing global semantics;
- shared-contract change requests route to the Contract Agent;
- unresolved false-story cases block merge even when normal CI is green.

## Agent execution sequence per reducer lane

```text
CEO / Contract Agent
-> Evidence phase: evidence card
-> Normalizer phase: typed observations + normalization tests
  -> Reducer Agent: red-first reducer scenario + implementation
  -> Adversary Agent: counterexample fixtures/property cases
  -> Reducer Agent: resolve valid failures
  -> Contract Agent: semantic conformance review
  -> Integration Agent: restack + exact-head gates
  -> CEO: merge recommendation
```

The Evidence and Normalizer stages may overlap only when source contracts are already established. Adversarial review should not wait until a giant PR is otherwise considered complete; run it once the first meaningful reducer behavior exists and again on the final diff.

## Evidence card template

Every new reducer lane should answer before implementation:

```text
Workload:
Sources:
Validated versions/builds:
Authoritative identity keys:
Secondary/weak identity keys:
Source-native ordering guarantees:
Timestamp semantics:
Terminal signals:
Retry/session semantics:
Coverage gaps that prevent conclusions:
Sensitive/restricted fields:
Cross-artifact correlation allowed:
Cross-artifact correlation forbidden:
Known unknowns:
Real/sanitized fixture anchors:
```

Unknown fields remain unknown; agents must not fill them by inference.

## Reducer review checklist

A reducer is not merge-ready until the reviewer can answer yes to each applicable item:

- Does every terminal outcome come from assessable evidence?
- Are identities explicit enough for the claimed correlation strength?
- Can input vector ordering change the answer accidentally?
- Can timestamp proximity create causality?
- Can duplicate evidence inflate confidence?
- Can unrelated evidence alter another entity/session?
- Are retries explicitly linked rather than guessed?
- Are installer/workload families isolated where semantics differ?
- Are contradictory authoritative signals represented conservatively?
- Do coverage gaps remain coverage gaps?
- Does every finding cite supporting evidence/coverage from the actual input?
- Does redaction preserve intended semantics while respecting privacy policy?
- Are unsupported versions/builds prevented from driving unsupported terminal semantics?

## Immediate first move

Do not begin with a broad code refactor. Land the governance slice with the four ADRs and Store inventory. Then create a separate Phase 2 Store branch for typed-intent authority and input-order independence RED tests, followed by the concrete Store fixes and targeted adversarial pilot. Do not build a generic conformance or semantic runtime layer until that pilot proves the smallest reusable shape.
