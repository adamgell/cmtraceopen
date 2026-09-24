# Shared vs workload-specific invariants (Intune Windows reducers)

## Why this file exists

Framework v1 asked what the Intune Windows workload reducers have in common. The
answer, after inspection, was: much less than it looks. Five lanes (Win32,
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
| Evidence envelope types (`IntuneObservationContext`, `IntuneEvidenceRef`, `IntuneProvenance`, `IntuneArtifactCoverage`, `IntuneFinding`, ...) | `crates/cmtraceopen-parser/src/intune/evidence.rs` | Two separate compatibility questions, and only one of them has an "additive" answer. **Wire format:** exactly as `INTUNE_EVIDENCE_SCHEMA_VERSION` states at `crates/cmtraceopen-parser/src/intune/evidence.rs:23-24` — only an optional field, or a variant on an `intune_raw_preserving_string_enum!` type, is additive. The plain `#[derive(Deserialize)]` enums (`IntuneTimestampKind`, `IntuneSensitivity`, `IntuneParseState`, `IntuneAccessState`, `IntuneArtifactStatus`) have no `#[serde(other)]` arm, so an unknown variant is a hard decode error: adding one breaks older readers and bumps the schema version. **Rust API:** no additive guarantee at all. None of these types are `#[non_exhaustive]` and `cmtraceopen-parser` is published, so a new variant or public field breaks downstream `match` arms and struct literals and needs a semver-major release, or `#[non_exhaustive]` first. |
| `IntuneAccessState` <-> `IntuneArtifactStatus` mapping, both directions | `crates/cmtraceopen-parser/src/intune/evidence.rs` (`artifact_status_for_access_state`, `access_state_for_artifact_status`) | A total 7-arm bijection. Exhaustive `match`, no `_` arm, so a new variant is a compile error rather than a silently defaulted status. Was three byte-identical copies before Framework v1 PR 4. |
| The citation **verdict**: is a finding backed by anything at all | `crates/cmtraceopen-parser/src/intune/evidence.rs:355` (`IntuneFinding::is_evidence_backed`) | One owner, called by all five Windows lanes. The predicate reads two emptiness bits and no lane-specific state, so its input space is four cells; Autopilot and Compliance each restated its De Morgan negation inline until they were converted to call it. Where each lane asks the question is *not* shared; see divergence 9. |
| Redaction **grammar** (which byte patterns are masked and how) | `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs` (`redact_text`) | One owner. A local fork previously reintroduced a fixed JSON-escaped-path bug; see `crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs` lines 9-15. |
| Fixture corpus envelope: manifest version, path safety, byte-count truth, file/manifest closure, synthetic marker, privacy scan | `crates/cmtraceopen-parser/tests/support/mod.rs` | Every Intune corpus. |
| Fixture `captureState` -> library vocabulary | `crates/cmtraceopen-parser/tests/support/mod.rs` (`artifact_status_for_capture_state`, `access_state_for_capture_state`) | The collector boundary the fixtures stand in for. The access-state form is the status form composed with the crate's own mapping, so a fixture can never disagree with the crate about what `parseFailed` means. |
| The ADR-001 *directional doctrine* as prose | `docs/architecture/decisions/ADR-001-evidence-strength-confidence.md` (addendum) | The sentence is shared. The mechanism is not; see below. |

## Protected divergences

### 1. A `Capped` artifact may still prove a terminal outcome (Win32 only)

- **Win32:** truncation removes records, it does not corrupt the ones that framed
  completely. A complete framed record inside a capped artifact is authentic
  evidence and may prove a terminal outcome, including `Succeeded`. What capping
  costs is *confidence*: `High` is demoted to `Medium`, never more.
  - `crates/cmtraceopen-parser/src/intune/apps/windows/win32/reducer.rs` ~1687-1716 (`confidence_for`).
  - Test: `a_capped_artifact_proves_a_terminal_outcome_only_at_demoted_confidence`,
    same file ~2262-2286.
- **Autopilot / Compliance:** the opposite. Assessability is an allowlist
  (`access_state == Available && parse_state == Parsed`), so `Capped` is simply
  not assessable and proves nothing.
  - `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/models.rs` ~248-256; `crates/cmtraceopen-parser/src/intune/device/windows/compliance/sources.rs`
    ~447-455.
- **Why both are right:** Win32 evidence is CCM-framed log records with explicit
  record boundaries, so "this record is complete" is a checkable property of the
  bytes. Autopilot and Compliance reduce documents and reports where a truncated
  input has no per-record completeness signal at all. The predicate differs
  because the *evidence* differs, not because one lane is sloppier.

### 2. Autopilot: `time_basis` is deliberately ungated

Assessability is the admission rule for the Autopilot reducer's status-bearing
paths, but it is not applied uniformly, and the departures are deliberate:

- **Gated** (the default): status, phase, and signal reduction filter on
  `is_assessable` / `is_assessable_section` before reading an observation.
- **Deliberately inverted:** the coverage-gap paths select on
  `!is_assessable_section` and `!is_assessable` precisely so unusable input is
  reported as a gap rather than silently dropped.
- **Deliberately ungated:** `time_basis` (this section) and
  `AutopilotKeyGate::Detecting` (section 3).

`time_basis` is ungated in the conservative direction: an unfiltered scan lets a
non-assessable record with an unnormalized timestamp *downgrade* the basis.
Gating it would remove that record from consideration and thereby **upgrade**
the reported basis on thinner evidence.

- `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/reducer.rs:541`
  (the unfiltered `all_normalized` scan), with the rationale stated at
  `:604` on `is_assessable` itself, and the inverted coverage-gap
  filters at `:672` and `:705`.
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

- `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/reducer.rs` ~1311-1327 (enum + doc), applied ~1349-1352, both
  passes ~1426-1452.

### 4. Configuration admits `IntuneParseState::Raw` as interpretable

Configuration's `is_uninterpretable` excludes only `Malformed` and `Unsupported`
(plus partially-read sources); `Raw` falls through as interpretable. Autopilot
and Compliance both require `Parsed` exactly.

- Configuration: `crates/cmtraceopen-parser/src/intune/device/windows/configuration/sources.rs` ~146-151.
- Autopilot: `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/models.rs` ~253-256.
- Compliance: `crates/cmtraceopen-parser/src/intune/device/windows/compliance/sources.rs` ~447-455.
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

- Store: `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/reducer.rs` ~857-858 (contributors),
  ~905-909 (call site), ~956-972 (`degraded` forces `Low`).
- Win32: `crates/cmtraceopen-parser/src/intune/apps/windows/win32/reducer.rs` ~1711-1715.

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
(`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs`, `redact_text`). What each lane
*classifies as sensitive*, and what its redacted-export equality scope is, is a
property of that analyzer's contract and is not shared.

The dividing line is stated in `crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs` lines
9-15: the module "owns only the *projection*: which Win32 fields are classified
sensitive is a property of this analyzer's contract, not of the shared grammar."
The same file records why the grammar has one owner: a local fork of the rules
previously reintroduced an already-fixed JSON-escaped-path bug.

**This has now happened twice.** Compliance also carried a private copy of the
grammar, and by the time it was found the copy had drifted in nine places, every
one of them in the leaking direction: a SID with the minimum identifying
sub-authority count, the legacy `Documents and Settings` profile root,
JSON-escaped profile paths, and the device-name, UNC-server, account, tenant,
inline-credential and MSI-property rules were all absent or weaker, so each was
exported verbatim. A fork does not announce itself; it simply stops receiving
the owner's fixes. `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs` now
re-exports the owner, and
`crates/cmtraceopen-parser/tests/intune_windows_compliance.rs::the_compliance_lane_and_the_shared_grammar_agree_byte_for_byte`
asserts equal *output*, not merely equal masking decisions, so a future fork
fails rather than drifts.

Lanes outside this family (`esp`, and the Apple and Company Portal lanes) mask a
different vocabulary against different evidence and are not covered by this
owner. Their relationship to it is unsettled and is not a licence to fork within
the Windows family.

### 8. Test helpers: `evidence_ids` ordering is per-corpus

`crates/cmtraceopen-parser/tests/support/mod.rs` provides `sorted_evidence_ids`, named for what it does,
for consumers whose contract is the *set* of citations. Compliance uses it and
sorts both sides of every such assertion.

Microsoft Store keeps its own insertion-ordered, panicking version in
`crates/cmtraceopen-parser/tests/intune_windows_microsoft_store.rs`, because that leaf asserts citation
*order*: a transaction's `evidence` is positionally in step with its
`observations`. Forcing both corpora onto one helper would retire that pairing
without any test failing.

Autopilot likewise keeps its own `capture_state` helper: its input type is the
lane-local `AutopilotCaptureState`, and the mapping is serde's own
`rename_all = "camelCase"` rather than a hand-written table.

### 9. The citation verdict is shared; the finding constructors around it are not

The verdict is one predicate with one owner (see "Actually shared" above).
The constructor that asks it is per-lane, in three different shapes, and the
next consistency PR should stop at the predicate rather than continue into the
constructors.

| Lane | Shape | Where the verdict is asked | What else the constructor owns |
|---|---|---|---|
| Autopilot | `fn finding(...) -> Option<IntuneFinding>` | `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/rules.rs:912` | Sorts and de-duplicates **both** citation sets first (`normalized_evidence` plus `sort`/`dedup` on the gap ids); takes `recommended_checks: &[String]` |
| Compliance | `fn finding(...) -> Option<IntuneFinding>` | `crates/cmtraceopen-parser/src/intune/device/windows/compliance/rules.rs:697` | Keeps citations verbatim; takes a single `check: &str` and wraps it |
| Win32 | build always, gate in `push` | `crates/cmtraceopen-parser/src/intune/apps/windows/win32/findings.rs:191` | Runs the shared redaction grammar over `summary` **after** the gate, so an uncited finding is never redacted-and-dropped |
| Microsoft Store | build inside `push_finding`, gate there | `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/findings.rs:187` | Takes `recommended_checks: &[&str]` |
| Configuration | build always, gate in `push_finding` | `crates/cmtraceopen-parser/src/intune/device/windows/configuration/rules.rs:152` | Nothing beyond the gate |

**Why the verdict could be shared:** every lane's own doc comment already named
`IntuneFinding::is_evidence_backed` as the invariant it was enforcing, so the
five agreed for the same stated reason rather than by coincidence, and a lane
that emitted an uncited finding would be violating the invariant declared on
`IntuneFinding` itself. That is the extraction test below, all three parts.

**Why the constructors cannot be:** they disagree on normalization and on the
arity of `recommended_checks`, and Win32 additionally has a side effect ordered
against the gate. A single shared constructor would have to pick one
normalization policy, which would either impose Autopilot's byte-identical
ordering contract on Compliance or retire it from Autopilot.

Autopilot's normalization runs *before* it asks the verdict. That is safe
rather than lucky: `sort` never changes a vector's length and `dedup` never
empties a non-empty one, so normalization preserves both emptiness bits and
cannot move the answer. Pinned by
`the_constructor_sorts_and_dedupes_both_citation_sets`
(`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/rules.rs:983`) against
`the_constructor_preserves_citation_order_and_duplicates_verbatim`
(`crates/cmtraceopen-parser/src/intune/device/windows/compliance/rules.rs:835`), with the four-cell input space asserted
in both lanes by `the_citation_guard_agrees_with_the_shared_invariant_on_every_input`
(`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/rules.rs:956`, `crates/cmtraceopen-parser/src/intune/device/windows/compliance/rules.rs:803`).

The ESP lane carries the same constructor shape at `crates/cmtraceopen-parser/src/esp/rules.rs:669`
over `EspDiagnosticFinding` and `EspEvidenceRef`, a separate type family that
cannot call this predicate at all. It is out of this owner's scope for the same
reason it is out of the redaction owner's scope (divergence 7), and its
similarity is not evidence that the shapes should converge.

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
