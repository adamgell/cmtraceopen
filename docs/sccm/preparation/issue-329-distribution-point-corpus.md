# Issue #329 Distribution Point/content corpus preparation

## Scope and dependency boundary

This slice prepares the role-local source and behavior contract for Issue
`#329`. It intentionally contains only synthetic CCM evidence, versioned
manifest/expected-output labels, and a focused Rust fixture-contract test.
It does not add a production reducer, native collector, parser family, public
wire type, database dependency, or cross-side correlator.

The preparation contract is `proposedPendingReviewed318And335`:

- the reviewed #318 artifact, logical-record, evidence, timestamp, key,
  coverage, redaction, signal, and finding contracts are the implementation
  boundary;
- #335 supplies the producer-role, workflow-subject, configured-path,
  physical identity, rotation, and coverage handoff;
- #322 remains independently callable and does not feed this role-local
  preparation corpus; and
- #333 may later consume exact #322/#329 counterpart facts, but this slice
  performs no correlation and makes no client-impact or causal claim.

All `.log` files remain raw CCM transport. The corpus calls the existing
`normalize_ccm_artifact` logical-record path and does not introduce
`ParserKind::Sccm` or a second CCM parser.

## Producer and workflow-subject contract

A physical producer is not inferred from the workflow it describes.

| Source ID | Basename | Allowed producer role | Workflow subject | Use |
| --- | --- | --- | --- | --- |
| `server-dp-distribution` | `distmgr.log` | `siteServer` | DP role scope; exact handle on each record | Receive and distribute |
| `server-dp-distribution` | `PkgXferMgr.log` | `siteServer` | DP role scope; exact handle on each record | Transfer and retry |
| `server-dp-distribution` | `SMSDPProv.log` | `distributionPoint` | same exact DP handle | Validate and make available |
| `server-dp-distribution` | `PullDP.log` | `distributionPoint` | same exact pull-DP handle | Pull transfer when a reviewed fixture proves it |
| `server-dp-serve` | `SMSdpmon.log` | `distributionPoint` | same exact DP handle | Optional, explicitly catalogued serving/status evidence |
| `client-content-control` | `DataTransferService.log` | `client` | selected DP only as an ignored control | Must never enter the server reducer |

`server-dp-serve` is supplemental and bounded. It is not permission to scan
an IIS tree, content library, filesystem root, or arbitrary DP directory.
The existing IIS W3C parser may later support an explicitly catalogued
artifact, but this corpus neither requires nor fabricates one.

Each manifest preserves:

- a synthetic site code and one or more approved opaque DP handles;
- producer role and producer handle separately from workflow-subject role and
  either an exact handle or the bounded `manifestTopology` basis used by one
  site-server file that contains records for multiple declared DPs;
- source ID, exact basename, source grammar, synthetic version, path
  fingerprint, and `SYNTHETIC://` provenance;
- rotation kind, lineage, and fragment completeness;
- capture state, collection timestamp, encoding, byte policy, exact copied
  byte count, and bounded relative evidence path; and
- deterministic artifact identity and ordering.

The two DPs in `content-version-mismatch` remain separate transaction subjects
even though one physical `distmgr.log` and one physical `PkgXferMgr.log`
contain records for both. A physical site-server source is captured once;
changing its path fingerprint or destination cannot duplicate it merely to
attach another workflow-subject handle. Each admitted logical record must
carry an exact DP handle from the bounded manifest topology.

## State and exact-key contract

The proposed role-local state chain is:

```text
ReceiveContent -> Distribute -> Transfer -> Validate -> MakeAvailable -> ServeOrReport
```

A transaction is admitted only when every cited logical record repeats the
same exact profile-valid tuple:

```text
packageId
+ contentId
+ contentVersion
+ siteCode
+ distributionPointHandle
+ extractionProfileId
```

The synthetic profile is `dp-server-5.00.test-v1`, limited to
`5.00.TEST.*` fixture evidence. It is not a claim that a real ConfigMgr build
has been validated.

The focused contract parses semicolon-delimited synthetic fields as unique
`Name=Value` pairs. Substring lookalikes, duplicate fields, missing fields,
case aliases, a changed version, or a changed DP handle cannot satisfy an
exact transaction. Observation order uses the additive normalized SCCM
timestamp provenance, not the legacy public `LogEntry.timezone_offset`.
Evidence later than the canonical bundle capture is rejected.

The outcome rules are conservative:

- success requires a cited terminal successful `ServeOrReport`;
- confirmed failure requires cited source-specific terminal failure evidence;
- retry remains `blockedOrDeferred`;
- incomplete coverage remains `insufficientEvidence` with exact physical gap
  IDs and a bounded source ID;
- rotation fragments and malformed evidence remain noncorrelatable
  source-local observations whose classification is bound to exact physical
  role, capture state, lineage, rotation kind, and fragment completeness; and
- a client-only download record cannot become a DP transaction or DP failure.

## Coverage and request contract

`captured`, `absent`, `accessDenied`, `capped`, `skipped`, `unsupported`, and
`parseFailed` remain distinct physical manifest states. The expected coverage
array is an exact, sorted projection of physical artifact IDs and states.

Artifact requests contain only a catalogued source ID and one versioned reason
code:

- `coverageAbsent`
- `coverageAccessDenied`
- `coverageCapped`
- `coverageMalformed`
- `coverageRotationSplit`

There is no free-form collection request in the preparation labels. A reason
code must have matching noncomplete physical coverage. An absent default path
is a source gap; it cannot change an observed DP role to absent, broken,
uninstalled, unavailable, healthy, or failed.

## Scenario matrix

| Scenario | Required behavior |
| --- | --- |
| `healthy-package` | Exact six-phase successful distribution |
| `distribution-failure` | Terminal distribution failure with Receive as the last success |
| `transfer-retry` | Retry/backlog remains deferred, not failed |
| `validation-failure` | Terminal provider validation failure after exact transfer evidence |
| `content-version-mismatch` | Same package/content stays separate across versions and two DPs |
| `serve-observed` | Optional bounded serving source supplies the terminal observed outcome |
| `client-only-looking-request` | Same-time client content failure remains ignored server-side evidence |
| `rotation-boundary` | Current/`.lo_` fragments and malformed provider bytes form no transaction |
| `absent-dp` | Missing source candidates do not erase or diagnose an observed DP role |
| `incomplete` | Exact early phases survive while absent/denied downstream coverage requests the bounded source |

The contract test also mutates exact versions, DP topology, terminal evidence,
coverage states, role provenance, causal fields, rotations, and transaction
cardinality. Each mutation must fail closed.

## Deferred implementation and validation

After the #318 API gate and required restack/review, the production reducer may
map these labels onto the reviewed public contracts. It must remain pure Rust
and wasm32-compatible. Native capture remains a separate Windows adapter and
must retain configured paths, producer/subject topology, rotation, byte caps,
access results, and collision-safe identities.

No committed fixture contains customer data, real hostnames, raw filesystem
paths, credentials, or live SCCM evidence. No live Windows or SCCM Server
acceptance is claimed by this preparation slice.
