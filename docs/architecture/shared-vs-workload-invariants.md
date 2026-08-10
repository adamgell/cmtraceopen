# Shared vs workload-specific invariants (Intune Windows reducers)

## Why this file exists

Framework v1 asked what the Intune Windows workload reducers have in common. The
answer, after inspection, was: much less than it looks. Four lanes (Win32,
Microsoft Store, Autopilot, Configuration, plus Compliance) use the same
vocabulary and the same doc-comment idioms, so their rules *read* alike while
deciding different things about different evidence.

This is a catalogue of what is genuinely shared and what is deliberately not.
Everything in the "protected divergences" section is **tested** and
**intentional**. Each entry exists because a reasonable person reading two lanes
side by side would conclude one of them is wrong, and would be mistaken.

**If you are here because you are writing a consistency PR: the entries below are
the answer to "why is this inconsistent?". Do not delete them to make the lanes
match. If you believe one is genuinely wrong, that is a RED-first behavior-change
PR with its own issue, not a refactor.**

## Actually shared

| Concern | Owner | Notes |
|---|---|---|
| Evidence envelope types (`IntuneObservationContext`, `IntuneEvidenceRef`, `IntuneProvenance`, `IntuneArtifactCoverage`, `IntuneFinding`, ...) | `crates/cmtraceopen-parser/src/intune/evidence.rs` | Additive-only. Append variants and `Option<T>` fields at the end. |
| `IntuneAccessState` <-> `IntuneArtifactStatus` mapping, both directions | `intune/evidence.rs` (`artifact_status_for_access_state`, `access_state_for_artifact_status`) | A total 7-arm bijection. Exhaustive `match`, no `_` arm, so a new variant is a compile error rather than a silently defaulted status. Was three byte-identical copies before Framework v1 PR 4. |
| Redaction **grammar** (which byte patterns are masked and how) | `intune/apps/windows/common/redaction.rs` (`redact_text`) | One owner. A local fork previously reintroduced a fixed JSON-escaped-path bug; see `win32/redaction.rs` lines 9-15. |
| Fixture corpus envelope: manifest version, path safety, byte-count truth, file/manifest closure, synthetic marker, privacy scan | `crates/cmtraceopen-parser/tests/support/mod.rs` | Every Intune corpus. |
| Fixture `captureState` -> library vocabulary | `tests/support/mod.rs` (`artifact_status_for_capture_state`, `access_state_for_capture_state`) | The collector boundary the fixtures stand in for. The access-state form is the status form composed with the crate's own mapping, so a fixture can never disagree with the crate about what `parseFailed` means. |
| The ADR-001 *directional doctrine* as prose | `docs/architecture/decisions/ADR-001-evidence-strength-confidence.md` (addendum) | The sentence is shared. The mechanism is not; see below. |

## Protected divergences

### 1. A `Capped` artifact may still prove a terminal outcome (Win32 only)

- **Win32:** truncation removes records, it does not corrupt the ones that framed
  completely. A complete framed record inside a capped artifact is authentic
  evidence and may prove a terminal outcome, including `Succeeded`. What capping
  costs is *confidence*: `High` is demoted to `Medium`, never more.
  - `intune/apps/windows/win32/reducer.rs` ~1687-1716 (`confidence_for`).
  - Test: `a_capped_artifact_proves_a_terminal_outcome_only_at_demoted_confidence`,
    same file ~2262-2286.
- **Autopilot / Compliance:** the opposite. Assessability is an allowlist
  (`access_state == Available && parse_state == Parsed`), so `Capped` is simply
  not assessable and proves nothing.
  - `.../autopilot/models.rs` ~248-256; `.../device/windows/compliance/sources.rs`
    ~447-455.
- **Why both are right:** Win32 evidence is CCM-framed log records with explicit
  record boundaries, so "this record is complete" is a checkable property of the
  bytes. Autopilot and Compliance reduce documents and reports where a truncated
  input has no per-record completeness signal at all. The predicate differs
  because the *evidence* differs, not because one lane is sloppier.

### 2. Autopilot: `time_basis` is deliberately ungated

Every reduction path in the Autopilot reducer passes through `is_assessable`.
`time_basis` is the one deliberate exception, and the exception is the
conservative direction: an unfiltered scan lets a non-assessable record with an
unnormalized timestamp *downgrade* the basis. Gating it would remove that record
from consideration and thereby **upgrade** the reported basis on thinner
evidence.

- `.../autopilot/reducer.rs` ~534-559 (the unfiltered scan), with the rationale
  stated at ~595-606 on `is_assessable` itself.
- Adding the gate here for symmetry would be a behavior regression that no
  compile error would catch.

### 3. Autopilot: `AutopilotKeyGate::Detecting` reads every observation

Key linkage runs two passes with different admission rules, on purpose:

- `Proving` (assessable observations only): these keys may establish a link, the
  confident `Linked` state, and the `Completed` outcome behind it.
- `Detecting` (every observation): these keys may only *detect conflicts* and can
  never upgrade a linkage on their own.

More evidence is the conservative direction for conflict detection, and the
restrictive direction for proof. Collapsing the two passes into one gate breaks
whichever half it is collapsed toward.

- `.../autopilot/reducer.rs` ~1311-1327 (enum + doc), applied ~1349-1352, both
  passes ~1426-1452.

### 4. Configuration admits `IntuneParseState::Raw` as interpretable

Configuration's `is_uninterpretable` excludes only `Malformed` and `Unsupported`
(plus partially-read sources); `Raw` falls through as interpretable. Autopilot
and Compliance both require `Parsed` exactly.

- Configuration: `.../device/windows/configuration/sources.rs` ~146-151.
- Autopilot: `.../autopilot/models.rs` ~253-256.
- Compliance: `.../device/windows/compliance/sources.rs` ~447-455.
- **Why:** Configuration's `Raw` retains a record whose typed fields were not
  modelled but whose structure was read. For that lane, a retained raw setting
  report is usable input. For Autopilot, `Raw` means the document never declared
  what it was, which is exactly the case the explicit-schema-detection rule
  exists to refuse.

### 5. Store and Win32 disagree about what degradation costs, by contract

| | What degrades | Degraded confidence |
|---|---|---|
| Microsoft Store | only `IntuneParseState::Malformed` (with a non-`Available` access state as a separate contributor) | `Low` |
| Win32 | degraded coverage generally | `Medium` (demotion from `High` only) |

- Store: `.../apps/windows/microsoft_store/reducer.rs` ~857-858 (contributors),
  ~905-909 (call site), ~956-972 (`degraded` forces `Low`).
- Win32: `.../apps/windows/win32/reducer.rs` ~1711-1715.

Both are correct against their own contract. Store transactions are assembled
from OS event channels where a malformed contributor means the channel itself is
suspect; Win32 transactions are assembled from framed log records where a
degraded artifact still yields intact records (see divergence 1). Making the two
constants agree would silently rewrite one lane's contract.

### 6. Linkage and supersession: four different source contracts, never unify

| Lane | Contract |
|---|---|
| Microsoft Store | asymmetric `activity_id`; no cross-artifact linkage; pairwise only |
| Autopilot | orderless `activity_id` **sets** |
| Win32 | two grammars plus transitive closure |
| Configuration | refuses to link and returns `Contested` |

These are not four implementations of one idea. They are four different answers
to "what does the source actually guarantee about correlation identifiers",
grounded in ADR-002. A shared linkage helper would have to be the loosest of the
four, which would let Store observations merge across artifacts and let
Configuration produce a link its evidence does not support.

### 7. Redaction: the grammar is shared, the projection is not

The masking grammar has exactly one owner
(`intune/apps/windows/common/redaction.rs::redact_text`). What each lane
*classifies as sensitive*, and what its redacted-export equality scope is, is a
property of that analyzer's contract and is not shared.

The dividing line is stated in `intune/apps/windows/win32/redaction.rs` lines
9-15: the module "owns only the *projection*: which Win32 fields are classified
sensitive is a property of this analyzer's contract, not of the shared grammar."
The same file records why the grammar has one owner: a local fork of the rules
previously reintroduced an already-fixed JSON-escaped-path bug.

### 8. Test helpers: `evidence_ids` ordering is per-corpus

`tests/support/mod.rs` provides `sorted_evidence_ids`, named for what it does,
for consumers whose contract is the *set* of citations. Compliance uses it and
sorts both sides of every such assertion.

Microsoft Store keeps its own insertion-ordered, panicking version in
`tests/intune_windows_microsoft_store.rs`, because that leaf asserts citation
*order*: a transaction's `evidence` is positionally in step with its
`observations`. Forcing both corpora onto one helper would retire that pairing
without any test failing.

Autopilot likewise keeps its own `capture_state` helper: its input type is the
lane-local `AutopilotCaptureState`, and the mapping is serde's own
`rename_all = "camelCase"` rather than a hand-written table.

## Extraction test

Before proposing that something move into shared code, it must pass all three:

1. **Byte-identical today** across every copy, verified arm by arm rather than by
   shape.
2. **Identical for the same reason**, not by coincidence. Two lanes that agree
   because neither has met the disagreeing case yet are not shared.
3. **A future divergence would be a bug, not a contract**, so that making the
   shared version harder to diverge from is a feature rather than an obstacle.

The `IntuneAccessState` <-> `IntuneArtifactStatus` mapping passes all three. Most
of what looks shared in this family fails test 2.
