# Issue #327 server site-core/status corpus contract

Status: preparation only

This document freezes the synthetic scenario contract for issue #327 without
selecting speculative Rust interfaces. Production reducers remain blocked on
the reviewed #318 diagnostic spine and #335 server-intake contracts. The
fixtures define observable behavior that those later implementations must
satisfy.

## Scope

Issue #327 consumes only the catalogued `server-sitecomp` and `server-status`
source groups for an observed site-server role. It may describe site-core
component and status-processing evidence local to that role.

It must not:

- infer client impact;
- infer that a downstream Management Point, Distribution Point, SUP, WSUS,
  Provider, or other role is absent or unhealthy;
- create a transaction from a component name, source basename, host name, site
  code, or timestamp alone;
- turn an absent, access-denied, capped, skipped, unsupported, malformed, or
  partial source into a failure fact;
- join a logical CCM record across rotation files; or
- treat an error-looking record without a profile-recognized terminal status
  as `ConfirmedFailure`.

## State contract

```text
ComponentStart
  -> ComponentWork
  -> InboxOrQueue
  -> StatusOrStateProcessing
  -> HealthyOrTerminal
```

Phases advance only from complete logical records admitted by the versioned
profile. A positive fact entering a phase can become the last successful
phase. An error observed while attempting a phase does not make that phase a
success. Consequently:

- a terminal component failure after `ComponentWork` leaves
  `ComponentWork` as the last success;
- a terminal status-processing failure after a positive processing-start fact
  leaves `StatusOrStateProcessing` as the last success;
- a profile-recognized `SC_INBOX_BACKLOG` leaves `ComponentWork` as the last
  success and deterministically yields `BlockedOrDeferred`; it remains
  non-terminal and never becomes a root-cause finding;
- a later recovery reaches `HealthyOrTerminal` only for the same exact
  transaction key and usable source-local ordering; and
- a split or malformed rotation contributes a parse/coverage gap, never a
  phase or terminal fact.

## Versioned identity and signal admission

The fixture corpus names the experimental extraction profile
`sccm-site-core` version `1`. The profile is deliberately synthetic; it is not
evidence that these message patterns are accepted against a live ConfigMgr
version.

A transaction key is the exact tuple:

```text
(profile id, profile version, site handle, component id, work-item id)
```

The profile must validate both the component ID and the status ID before a fact
can advance the state machine. Version 1 admits these synthetic component IDs:

- `SMS_EXECUTIVE`
- `SMS_DISTRIBUTION_MANAGER`

Version 1 admits these synthetic status IDs:

- `SC_COMPONENT_START_OK`
- `SC_COMPONENT_WORK_OK`
- `SC_INBOX_ACCEPTED`
- `SC_INBOX_BACKLOG`
- `SC_STATUS_PROCESSING_OK`
- `SC_COMPONENT_HEALTHY`
- `SC_COMPONENT_TERMINAL_FAILURE`
- `SC_STATUS_TERMINAL_FAILURE`
- `SC_COMPONENT_RECOVERED`

An unknown component, status ID, profile ID, or profile version is retained as
an unlinked raw-safe observation. At most it can support a low-confidence
`Symptom`; it cannot create a keyed transaction or high-confidence terminal
result.

## Terminality, recovery, and confidence

`ConfirmedFailure` with `High` confidence requires a complete,
profile-recognized, source-specific terminal fact with the exact transaction
key. `SC_INBOX_BACKLOG` is always `BlockedOrDeferred`, never terminal or a
root-cause finding. Low-confidence `Symptom` is reserved for generic or
unrecognized errors. Missing downstream evidence is non-terminal.

Recovery requires all of the following:

1. the earlier failure and later success use the same profile ID and version;
2. site, component, and work-item keys match exactly;
3. the later record is the profile-recognized recovery or healthy terminal
   status;
4. timestamp provenance permits source-local ordering; and
5. both records are complete logical records.

A healthy record for another component in the same minute cannot recover,
qualify, suppress, or merge with a failing component transaction.

## Manifest draft boundaries

Each scenario `manifest.json` follows the plan's additive SCCM server manifest
shape:

- `sccmManifestVersion` is `1`;
- `bundleRole` is `server`;
- topology records only synthetic capture host, observed role, and site code;
- every `artifactId` is non-empty and unique within its scenario
  manifest/bundle. It is authoritative for physical evidence, coverage
  references, and deterministic artifact ordering;
- artifacts retain artifact ID, role, source group/kind, redacted original
  path, basename, configured-path observation, rotation, capture state,
  synthetic source version, collection time, encoding, relative path, and
  copied bytes;
- `captured` and `capped` artifacts have a non-null relative path and exact
  local evidence;
- every referenced physical artifact whose expected evidence identifies an
  incomplete logical record declares `rotation.fragmentComplete: false`,
  whether its capture state is `captured` or `capped`; capture success never
  implies parse completeness;
- `absent`, `accessDenied`, `skipped`, `unsupported`, and `parseFailed`
  artifacts have no relative path, zero copied bytes, and no physical
  line-ranged evidence; and
- artifacts are sorted by `artifactId`.

This preparation corpus does not make the manifest fields a public Rust API.
#335 owns that decision and must either map this draft losslessly or document a
reviewed fixture migration.

## Expected-result contract

Each `expected.json` uses `expectedContractVersion: 1` and records:

- the exact profile;
- zero or more component-keyed results;
- state and last-success semantics;
- `findingClass` and confidence ceiling;
- exact physical evidence references using artifact ID plus physical line
  range;
- explicit coverage-only references that may contain only the artifact ID;
- an exact, bounded next-artifact request or an empty request list;
- unlinked observations where applicable;
- deterministic result/evidence/request ordering; and
- prohibited client-impact, absent-role, and cross-side causal claims.

Evidence references never use a basename as artifact identity. Every physical
reference contains its own manifest `artifactId` plus exact `lineStart` and
`lineEnd`; logical entry IDs use the fixture-stable form
`<artifactId>:<lineStart>-<lineEnd>`. Coverage-only references may stop at the
manifest `artifactId`. An artifact whose manifest `captureState` is `absent`,
`accessDenied`, `skipped`, `unsupported`, or `parseFailed` cannot carry
physical lines. A physically present capped or malformed fragment may be cited
by exact lines inside a coverage gap, but it remains coverage/nonterminal
evidence.

## Scenario matrix

| Scenario | Required behavior | Maximum diagnosis |
| --- | --- | --- |
| `healthy` | All five phases complete for one exact component/work item. | Healthy result; no finding. |
| `component-failure` | Recognized terminal component failure after work; status source absent is a coverage fact only. | `ConfirmedFailure` / `High`, last success `ComponentWork`. |
| `inbox-backlog` | Recognized queue backlog without terminal evidence; status source absent. | `BlockedOrDeferred` / `Low`, never root cause. |
| `status-processing-failure` | Positive processing start then recognized status terminal failure for the same key. | `ConfirmedFailure` / `High`, last success `StatusOrStateProcessing`. |
| `recovery` | Recognized failure followed by a later recognized recovery for the exact same key. | Historical `Symptom` / `High`; no current confirmed failure. |
| `contradictory` | One component fails while an independent component succeeds in the same minute. | Two independent results; no cross-component merge or recovery. |
| `malformed` | A terminal-looking status candidate is an unclosed logical record, so its visible component/work-item/status tokens are not admitted. | `Symptom` / `Low` plus parse coverage; no transaction, key, phase, or terminal state. |
| `rotation-boundary` | Opening and closing fragments are split across `.lo_` and current files. | `InsufficientEvidence` / `None`; no phase or terminal fact. |
| `incomplete` | Site-component source is capped, status source is access denied, state source is absent. | `InsufficientEvidence` / `None`; coverage only. |

## Minimal bounded requests

Requests use a catalog logical source name, the `siteServer` role, declared
basenames, declared rotations, and the exact component/work-item scope when
available. No fixture requests a drive, arbitrary directory, unrestricted IIS
tree, database, registry, WMI, event log, network query, or live collection.

## Synthetic and privacy rules

Every complete evidence file begins with a profile-validated semantic CCM
record whose message starts `# SYNTHETIC FIXTURE - NOT LIVE DATA` and then
contains the actual profile/component/work-item/status tokens. There is no
separate marker-only record, because unknown raw records must be preserved as
symptoms and would make the fixture non-minimal. Fixture identifiers use only
`LAB-CM01`, site code `LAB`, `SMS_*` synthetic component IDs, and `SC-*`
synthetic work-item IDs. Paths in manifests are `REDACTED`; evidence contains
no customer host, user, domain, URL, certificate, database, package, client,
credential, or live log content.

The marker prefix does not replace or suppress the first semantic signal. The
standalone malformed scenario puts the marker inside its unclosed candidate,
sets `rotation.fragmentComplete: false`, and requests exactly one fresh
`statmgr.log` current artifact. Visible key and terminal-looking tokens inside
that incomplete candidate remain unadmitted. The rotation-boundary exception
marks each manifest artifact with `syntheticFixture: true` and
`rotation.fragmentComplete: false`, puts the literal marker inside the opening
malformed fragment, and leaves the closing-fragment file untouched by any
artificial comment or complete marker record. Reducers must not concatenate
those physical rotation files; expected coverage names both unique physical
artifact IDs.

## Future reducer assertions

When #318 and #335 are reviewed, the production test for each scenario must:

1. deserialize and normalize the SCCM-specific manifest without changing
   generic collection-manifest semantics;
2. parse only complete CCM logical records;
3. admit only source/profile/component/status combinations listed above;
4. compare the serialized reducer result to `expected.json`;
5. rerun after reversing input artifact order and require byte-identical
   normalized output;
6. prove manifest artifact IDs are unique within the scenario/bundle and are
   the authoritative deterministic ordering key;
7. validate every physical evidence reference by exact artifact ID and line
   range while permitting artifact-ID-only coverage references;
8. prove nonphysical capture states never carry physical evidence;
9. prove `ConfirmedFailure` / `High` always cites its terminal record;
10. prove coverage states do not become success or failure facts;
11. prove every expected evidence reference with
   `completeLogicalRecord: false` maps to a manifest artifact with
   `rotation.fragmentComplete: false`; and
12. prove no client-impact, downstream-role-absence, or cross-side causal claim
   escapes the role-local analyzer.
