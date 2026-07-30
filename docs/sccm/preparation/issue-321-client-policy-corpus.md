# Issue #321 client policy corpus preparation

## Purpose and dependency boundary

This document and its synthetic fixtures prepare Task 5 of the SCCM Client
intake/core plan. They define behavior-first policy workflow cases without
implementing a reducer, parser interface, or production schema. Every fixture
uses `contractState: proposedPending318`; field names under this preparation
contract are review labels until #318 publishes the shared artifact, evidence,
key, phase, finding, coverage, and request types.

#321 also depends on #319 for the final physical artifact/manifest contract.
The fixtures therefore follow #319's reviewed design shape now: a physical
`artifactId` is distinct from `designOnlyCatalog.entryId`; group memberships
are sorted; capture provenance is exact; and a physical file is referenced
rather than copied once per logical consumer. No production code, native
collection behavior, or speculative #318 interface is part of this slice.

The policy reducer must remain independently callable. It consumes policy
artifacts and their normalized evidence directly. It never consumes the output
of the health, deployment, update, or future correlation reducer. A bounded
request for `client-location` in the request-auth scenario is a coverage
dependency only, not health-reducer input and never evidence of an MP cause.

## Policy state contract

```text
Request -> Download -> Persist -> Schedule -> Evaluate -> Report
```

- `Request` is an evidenced client policy request/authentication outcome.
- `Download` is an evidenced policy transfer outcome for the same exact key.
- `Persist` is an evidenced client-side policy persistence outcome.
- `Schedule` is an evidenced scheduler disposition. `Deferred` is a first
  class state, not a failure or an evaluation result.
- `Evaluate` is an evidenced policy evaluation outcome.
- `Report` is an evidenced state/report outcome.

The last successful phase is the latest phase supported by coherent evidence,
not the phase before the newest line by filename or ingestion order. Absence
cannot prove success or failure.

## Source-family and physical identity design

| Catalog entry | Physical basenames used here | Policy responsibility |
| --- | --- | --- |
| `client-policy-agent` | `PolicyAgent.log`, `Scheduler.log`, supported `PolicyAgent.lo_` rollover | Request, Download, Persist, Schedule |
| `client-policy-state` | `CIAgent.log`, `StateMessage.log` | Evaluate, Report |
| `client-location` | absent `ClientLocation.log` only in request-auth coverage | Bounded missing client-side context; no policy phase and no MP conclusion |

Each artifact retains a globally unique synthetic physical ID, one catalog
entry, one sorted membership, a synthetic path handle, a distinct path
fingerprint, and exact basename/rotation metadata. Captured artifacts also
retain one relative evidence path. `captured` and `capped` artifacts declare
`encoding: utf-8`, an explicit
`collectionLimit`, and a `bytesCopied` value equal to the physical file.
Noncapture artifacts use zero bytes and a null relative path without invented
encoding or limit provenance.

Complete evidence files are forced through the existing CCM grammar. The
literal `SYNTHETIC FIXTURE` appears inside the first semantic CCM record and is
never a marker-only line. A split rotation sets `fragmentComplete: false`; no
individual fragment can yield a complete record, key, phase, or terminal
finding. A syntactically complete record may still carry an invalid offset.
Valid offsets normalize to UTC and must be no later than the artifact's
`capturedUtc`; the original display and offset remain cited. Invalid or unknown
offsets remain raw, non-comparable ordering evidence with no normalized UTC
instant and cannot raise confidence.

## Version-profiled key contract

The selected preparation profile is
`policy-client-5.00.test-v1`, scoped only to the synthetic version prefix
`5.00.TEST.` and the declared policy source families. This is not a claim about
an observed production ConfigMgr version.

A keyed transaction requires normalized `assignmentId` and `policyId` UUIDs
extracted as `exact` under that profile. When a complete profile-recognized
Request record directly supplies them, its counterpart-ready fact also carries
an exact `requestId`, correlation-safe client handle, three-character
`siteCode`, selected/observed management-point host handle, selection kind, and
the Request evidence reference. These optional fields remain absent when the
source cannot prove them. Filename, bundle capture host, component, message
proximity, and timestamp alone never create or fill a transaction key. An
unvalidated version, malformed key, or rotation-split key remains a
source-local observation with:

- no transaction key;
- `keyConfidence: none`;
- `confidence: low`;
- `confidenceCeiling: low`; and
- `correlationEligible: false`.

Such evidence cannot be attached later by time or by some other reducer.

## Reducer and false-causality rules

1. Reduce one exact assignment/policy key at a time and stable-sort the final
   transactions, findings, observations, and evidence references.
2. Preserve repeated observations. An ordered, explicit terminal success may
   prove recovery from an earlier terminal-looking result only with the same
   exact key and coherent timestamp/source ordering.
3. Same-key success/failure facts at the same resolved instant across
   independent physical sources remain contradictory when no trusted ordering
   resolves them. The confidence ceiling is low.
4. Normalize valid offsets before ordering. An invalid/unknown offset cannot
   order evidence across artifacts, and matching display time alone cannot
   create causality or raise confidence.
5. Same-minute facts with different exact keys remain separate transactions.
   They never qualify or overwrite one another.
6. `Deferred` maps to `blockedOrDeferred`, never `confirmedFailure`.
7. A terminal failure names only the client phase evidenced. It does not infer
   management-point authentication, availability, or server root cause.
8. An incomplete path requests the smallest catalog group:
   `client-policy-agent` for Request through Schedule and
   `client-policy-state` for Evaluate/Report.
9. Reordering manifest artifacts or evidence inputs must produce byte-equal
   normalized analysis after #318 supplies the normalizer.

## Scenario matrix

| Scenario | Expected result | Last successful phase | Bounded next artifact |
| --- | --- | --- | --- |
| `complete` | Clean success through Report with no failure or recovery branch. | Report | None |
| `recovery` | Success through Report after an ordered same-exact-key Download failure then explicit later Download success. | Report | None |
| `request-auth-failure` | Client Request failure with missing location coverage; no MP cause. | None | `client-location` |
| `download-failure` | Confirmed client Download failure. | Request | None |
| `persist-failure` | Confirmed client Persist failure. | Download | None |
| `scheduler-deferred` | Blocked/deferred scheduler disposition, not failure. | Persist | `client-policy-agent` |
| `evaluation-failure` | Confirmed client Evaluate failure. | Schedule | None |
| `reporting-failure` | Confirmed client Report failure. | Evaluate | None |
| `rotation-split` | Keyless low-confidence insufficient evidence. | None | `client-policy-agent` |
| `malformed` | Keyless low-confidence symptom under an unvalidated version. | None | `client-policy-agent` |
| `incomplete` | Exact transaction stops at Schedule because policy-state coverage is absent. | Schedule | `client-policy-state` |
| `multiline` | Clean success with Request framed as one complete logical CCM record across two physical lines. | Report | None |
| `contradictory-offset` | Assignment A orders valid offsets by normalized UTC despite reversed display order; assignment B stays low/contradictory because one offset is invalid and non-comparable. Same-display-time different keys remain isolated. | A: Report; B: Schedule | A: none; B: `client-policy-state` |
| `gate-c-contradictory` | Assignment A retains an unresolved same-normalized-instant Evaluate contradiction across independent physical artifacts with no source-local or lineage order; unrelated assignment B remains a separate Report failure. | A: Schedule; B: Evaluate | A: `client-policy-state`; B: none |

The repaired corpus contains 14 scenarios, 41 artifacts (39 captured and 2
noncapture), 39 evidence files, 69 complete CCM records, 2 deliberately
incomplete rotation fragments, 14 exact transactions, 12 nonsuccess findings,
and 2 keyless source-local observations. The 39 evidence files total exactly
21,396 bytes. The focused byte coordinator's path-and-artifact-qualified
aggregate SHA-256 is
`15acfe9cf467b64a2ebcb0896a6e8e6cb12400e37eb448ec8de6200938e0d387`.

## Expected-output preparation labels

Each `expected.json` includes:

- the full state chain and independent-reducer contract;
- extraction-profile selection or explicit unvalidated-version state;
- stable transactions and/or keyless source-local observations;
- exact phase, state, last successful phase, classification, confidence, and
  confidence ceiling;
- exact physical artifact/line-range evidence references;
- a bounded `nextArtifact` object or explicit `null`;
- one finding per nonsuccess subject;
- capture-provenance assertions by physical artifact ID;
- full physical-line spans for complete multiline logical records;
- preserved display/offset plus normalized or explicitly non-comparable
  ordering provenance;
- deterministic reordered-input expectation; and
- prohibited management-point/server, #333, and device-wide merge claims.

These labels describe the behavior that future #318-backed tests must assert;
they are not proposed final public field names.

## Privacy and evidence limits

All host/site/path/version/key values are deterministic synthetic labels.
Declared ConfigMgr site codes are exactly three alphanumeric characters.
Allowed identities are `LAB-CLIENT-01`, the synthetic site code `LAB`,
correlation-safe handles such as `safe:client:policy-11` and
`safe:mp:lab-mp-01`, synthetic UUIDs, and `SYNTHETIC://` opaque path handles.
Fixtures contain no customer path, hostname, user, SID, tenant, token,
certificate, serial, deployment name, or copied production log text.
Error-looking codes are synthetic workflow facts, not external error-database
conclusions.

## #333 handoff

#321 exposes exact, profile-qualified assignment/policy keys and, only when a
recognized Request record directly proves them, request ID, correlation-safe
client handle, three-character site code, selected/observed MP host handle,
client-side phase, ordering provenance, and evidence references. The declared
counterpart-ready key kinds are `requestId`, `policyId`, `clientSafeHandle`,
`siteCode`, and `managementPointHostHandle`. Missing or unvalidated Request
evidence emits no counterpart-ready fact; neither `LAB-CLIENT-01` nor capture
time may be repurposed as MP-selection evidence.

#333 owns topology compatibility and the adversarial exact-key/different-site
or different-MP classification. It must independently require compatible
server evidence, topology, ordering, and coverage before correlating
policy-to-MP behavior. This corpus performs no topology match, cross-side
matching, or server claim.

## Replay and acceptance gates

Before implementation, map these design labels to the published #318/#319
contracts. Then load each fixture through the public reader, run only the
independent policy reducer, repeat with reversed/shuffled input, and compare
normalized output. Validate JSON, exact bytes, paths/references/no orphans,
privacy, forced CCM grammar, multiline framing, partial boundaries, valid
offset normalization, invalid-offset non-comparability, chronology,
key/profile ceilings, parser regression tests, strict Clippy, wasm32, and
TypeScript.

#318 and #319 remain explicit blockers for compiled policy tests. #333 is a
later correlation handoff, not a blocker that authorizes cross-side behavior
inside #321.
