# ADR-001: Evidence strength constrains finding confidence

- **Status:** Accepted for Framework v1
- **Context:** Reducers currently expose conclusion confidence, while source authority and evidence quality are separate concerns. Repetition cannot promote weak evidence into authoritative evidence.
- **Decision:** Keep `IntuneFindingConfidence` as the public conclusion projection. The five evidence-strength levels — `Authoritative`, `Strong`, `Corroborating`, `Weak`, and `Untrusted` — are a conceptual vocabulary for reasoning and review, not a requirement for a shared enum, envelope, or runtime representation. Workload contracts may express the distinctions in workload-appropriate types or tests. Evidence strength may constrain confidence, but confidence must never be used as a substitute for source authority. Non-assessable evidence cannot produce a terminal conclusion.
- **Consequences:** Workload reducers retain domain-specific confidence rules. Framework v1 adds no numeric score, universal reducer, or mandatory shared evidence-strength type. A later shared helper is justified only by a concrete Store test and must preserve this separation.
- **Executable invariants:** Weak evidence cannot become authoritative through duplication; untrusted or non-assessable evidence cannot produce high-confidence terminal success/failure; coverage gaps cannot raise confidence.

## Addendum: the directional doctrine is shared prose, not shared code

Added during the Framework v1 thin extraction, after an inspection found the same
sentence implemented two structurally different ways.

**The doctrine, stated once:** non-assessable evidence cannot *prove* a
conclusion, but a *recorded* non-assessable failure must still *block* a success.
"Absence proves nothing" is not "presence proves nothing". Any record strong
enough to fail an operation when readable is strong enough to block that
operation's success when unreadable.

**The mechanism is deliberately per-workload, because "recorded failure" is a
workload fact, not a framework one.** The two lanes that implement it do not
gate on the same thing and must not be merged:

| Lane | What is unreadable | What it gates on |
|---|---|---|
| Autopilot | the artifact or section itself (envelope not `Available` + `Parsed`) | the envelope **plus** a failure-shaped signal: `!is_assessable(observation)` AND `observation.signal.is_terminal_failure()` |
| Configuration | nothing about the envelope; the *result token inside a readable record* | a readable, device-side `CommandFailure` event whose disposition never reached terminal. "The direction is evidence; the code is not." |

Sites:

- Autopilot: `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/reducer.rs`
  - `recorded_non_assessable_failure_sections` and
    `recorded_non_assessable_failure_observations` (~650-707) define the predicate.
  - Enforced at ~1668-1688, where the pair short-circuits an otherwise clean
    `profile.applied && handoff.esp_observed` into `InsufficientEvidence`.
  - The envelope predicate itself is
    `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/models.rs`
    ~248-256 (`is_assessable` = `Available` + `Parsed`).
- Configuration: `crates/cmtraceopen-parser/src/intune/device/windows/configuration/sources.rs`
  ~163-174 (`is_unassessable_failure`), enforced in
  `.../configuration/reducer.rs` ~246-263, which turns `Applied`/`Removed` into
  `Contested` rather than into an outcome-free state.

**Consequence for future work:** a PR that "unifies the ADR-001 gate" across
these two lanes is unifying an English sentence with a code path. Autopilot's
predicate reads the envelope; Configuration's reads a payload token in a record
whose envelope is fine. Neither predicate can express the other's case. Extract
the prose (this addendum) and leave the mechanisms alone. The catalogue of every
other divergence in this family, and why each is protected, is
`docs/architecture/shared-vs-workload-invariants.md`.
