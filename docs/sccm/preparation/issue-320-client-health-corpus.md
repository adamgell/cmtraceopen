# Issue #320 client health corpus preparation

## Purpose and dependency boundary

This is a synthetic, preparation-only corpus for the client-only health
workflow in issue #320. It specifies evidence, expected conservative outcomes,
and future direct test assertions. It does not add a reducer, public Rust API,
Tauri surface, Cargo dependency, or compiled test while the reviewed #318 and
#319 interfaces are unavailable in this worktree.

The intended workflow is strictly:

```text
Setup -> Service -> Identity -> SiteAssignment -> ManagementPoint -> Transport
```

Each hop needs source-local, complete, profile-validated evidence. A captured
file, a hostname-shaped string, a timestamp coincidence, or an absent artifact
does not prove a hop. Findings remain client-side observations: this corpus
never asserts a site-server, management-point, DNS, proxy, or network root
cause.

## Synthetic fixture wire shape

Every scenario contains `manifest.json`, `expected.json`, and only the minimum
referenced `evidence/` files. The manifests deliberately retain the #319
preparation shape and set both `proposalOnly` and `syntheticFixture` to true.
All evidence uses valid CCM logical-record syntax except the explicit malformed
or rotation-boundary cases. The `fragmentComplete` marker is a proposed #319
capture detail: an incomplete fragment is coverage only and is never supplied
to a semantic reducer as a complete logical record.

Expected records are future-test contracts, not current serialized API claims:

- `contractState` remains `proposedPending318And319`.
- Every physical candidate has a globally unique `artifactId`; the logical
  #319 design-only catalog identity is separately preserved as
  `designOnlyCatalog.entryId`.
- `LocationServices.log` is captured once per scenario as
  `client-location-services-shared`, with sorted `groupMemberships` of
  `client-content` and `client-location`. Health consumes only the
  `client-location` membership.
- Captured artifacts record exact `bytesCopied`, `encoding: "utf-8"`, and a
  `collectionLimit`; non-captures use zero bytes and null capture-only fields.
  Every usable record timestamp is at or before `capturedUtc`.
- `fixtureEvidence` uses the physical artifact ID plus an exact fixture-local
  entry ID and physical line range. #318/#319 must define the public reader and
  evidence-ID projection before these become compiled assertions.
- `nextArtifacts` is always the smallest logical client source that can answer
  the unresolved hop. An absence or coverage gap creates only
  `insufficientEvidence`, never a client failure.
- All arrays are pre-sorted by stable finding ID, artifact ID, then entry ID.

## Scenario matrix

| Scenario | Evidence focus | Required future assertion |
| --- | --- | --- |
| `success` | Complete keyed setup, service, identity, site, MP, and request/response sequence. | `lastSuccessfulPhase = transport`; no finding. |
| `setup-failure` | Profile-validated terminal setup record with no later matching recovery. | High `confirmedFailure` at `setup`; do not infer later hops. |
| `identity-failure` | Setup and service succeed, then identity registration has a terminal record. | High `confirmedFailure` at `identity`, never an MP failure. |
| `no-site-or-mp` | Setup/service/identity succeed; captured location source has no complete site/MP response. | Low `insufficientEvidence` at `siteAssignment`; request only `client-location`. |
| `transport-failure` | Same validated request ID and MP host connect a request to a terminal client transport error. | High client-side `confirmedFailure` at `transport`; never claim MP cause. |
| `contradictory` | Terminal setup error and later success have different validated bootstrap keys. | Low `symptom`; do not treat the later record as recovery. |
| `rotation-boundary` | A terminal-looking setup record is split across two incomplete rotations. | No phase advance or failure; low `insufficientEvidence` at `setup`. |
| `malformed` | Setup is valid but service source is an unclosed CCM record. | Low `symptom` at `service`; request only `client-evaluation`. |
| `incomplete` | Setup/service are valid; identity capture is access-denied and location is absent. | `lastSuccessfulPhase = service`; low `insufficientEvidence` at `identity`; request only `client-identity`. |

## Future reducer and test specification

Once #318/#319 publish reviewed contracts, add a dedicated
`sccm_client_health` test target that loads each manifest through the public
bundle reader and makes direct assertions (not permissive snapshots):

1. Normalize complete CCM logical records source-locally and reject records
   from `fragmentComplete: false` or malformed fragments before key extraction.
2. Classify only the #319 health memberships: `client-ccmsetup`,
   `client-evaluation`, `client-identity`, and `client-location`. The shared
   `client-location-services-shared` catalog entry is one physical capture,
   not a second health-specific copy.
3. Apply only a reviewed ConfigMgr/artifact-family extraction profile. Unknown
   versions or message patterns retain low-confidence safe evidence and cannot
   establish a terminal state or validated correlation key.
4. Advance each phase only from positive evidence for that phase. Site and MP
   need their own location evidence; a hostname in unrelated text is not an MP
   success.
5. Permit a later recovery to supersede a terminal-looking record only when
   the same validated key is present and the ordering is usable (valid resolved
   UTC ordering, or a reviewed safe source-local order). The `contradictory`
   case proves a different key cannot recover the earlier record; add a
   focused mutation of that case with the same key and ordered success to prove
   permitted recovery.
6. A transport failure needs a validated request/host context linking the
   terminal response to the request. An unkeyed same-minute network error is a
   low-confidence `symptom` only, as in `no-site-or-mp`.
7. Keep alternative evidence cited. Do not collapse it into a mutable global
   client-health state, and sort output deterministically regardless of input
   artifact order.

Required direct assertions per `expected.json` are workflow name, last proven
phase, finding ID/class/phase/confidence, fixture evidence references, coverage
gap IDs, and ordered next logical artifacts. Tests must also assert every
finding summary/title is client-side and contains none of `server`,
`management point caused`, `DNS caused`, or equivalent causal language.

## Exact unresolved #318/#319 mappings

| Proposed corpus field or rule | Must be supplied/reviewed by | Status before implementation |
| --- | --- | --- |
| `manifest.json` reader, `sccmManifestVersion`, artifact grouping, and stable artifact ordering | #319 intake/bundle contract | Unresolved; #319 preparation is not a public reader. |
| `captureState`, `relativePath`, `pathFingerprint`, `fragmentComplete`, `unsafePath`, and legacy capture details | #319 manifest contract mapped to #318 coverage | Unresolved; current #318 coverage enum cannot by itself preserve all proposed distinctions. |
| Normalized complete logical records, source-local entry IDs, safe evidence redaction, and bundle evidence ordering | #318 evidence ingest/export contract | Unresolved. |
| `SccmPhase`, `SccmConfidence`, finding builder validation, evidence refs, artifact requests, and workflow analysis serialization | #318 shared finding/workflow contract | Unresolved. |
| Versioned health message profiles and validated client/site/MP/request/bootstrap key extraction | #318 key/profile contract plus #320 review | Unresolved; no regex or heuristic is frozen by this corpus. |
| Recognition of the four client health logical memberships, including the shared `client-location-services-shared` entry, and their coverage projection | #319 client catalog/intake contract | Unresolved. |

The currently visible #318 work establishes coverage/rotation model beginnings
only; it does not authorize assumptions about the items above. Until all rows
are mapped, no production reducer or compiling test may deserialize these
proposed manifests against speculative APIs.

## Privacy and replay rules

- Every identifier is synthetic: `LAB-CLIENT-01`, `CONTOSO`, RFC-style UUIDs,
  `.invalid` hosts, `BOOT-TEST-*`, and `REQ-TEST-*` are fixture tokens only.
- `SYNTHETIC://` is opaque provenance. No real endpoint path, user, SID,
  certificate, token, tenant, serial, deployment, or customer log content is
  permitted.
- The synthetic marker is embedded in the first semantic CCM record, never a
  marker-only line. A closing rotation fragment intentionally has no standalone
  marker or invented semantic record.
- Fixed timestamps and byte counts are intentional. A future reader must not
  add dynamic IDs, current time, temporary paths, or external error-database
  wording to expected output.
- Replay JSON validation, referenced-file validation, artifact ordering,
  privacy-marker validation, and `git diff --check` are valid now. Native
  Windows collection, ACL, reparse, and rotation acceptance remain separate
  #319/Windows gates.
