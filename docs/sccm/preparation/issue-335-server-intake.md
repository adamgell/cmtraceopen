# Issue #335 preparation: role-aware server intake

## Scope and dependency boundary

This is an implementation-ready preparation package for #335, not a parser or
collector implementation. It freezes synthetic fixture intent while #318 owns
the common serialized SCCM types, coverage vocabulary, evidence identifiers,
redaction handles, and logical-record API. No fixture asserts a Rust type or
function name before those contracts are public.

The intake contract is role-aware: a source is classified only from declared
role/topology provenance plus a catalogued basename and rotation. A missing
default candidate is `Absent` for that candidate only. It never proves that a
role is missing, broken, uninstalled, or healthy.

## Source catalog (pre-#318 declaration)

Producer role is the topology that emitted/stored the artifact. Workflow
subject is the role or instance whose work the artifact describes. They are
separate facts: a site-server `distmgr.log` record can describe distribution
to a DP, and a site-server `wsyncmgr.log` record can describe SUP sync, without
turning either file into a DP- or SUP-produced artifact.

| Source ID | Candidate basename(s) | Allowed producer role | Workflow subject | Grammar | Collection rule / consumer |
| --- | --- | --- | --- | --- | --- |
| `server-sitecomp` | `sitecomp.log`, `hman.log` | `siteServer` | site core | CCM | current + rotations; #327 |
| `server-status` | `statmgr.log`, `statesys.log` | `siteServer` | site status | CCM | current + rotations; #327 |
| `server-mp-auth` | `MP_GetAuth.log` | observed MP/site-system producer | management point | CCM | current + rotations; retain observed placement; #328 |
| `server-mp-auth` | `MP_CliReg.log`, `MP_RegistrationManager.log` | observed MP/site-system producer | management point | CCM | current + rotations; native placement must be retained; #328 |
| `server-mp-policy` | `MP_GetPolicy.log`, `MP_Location.log` | observed MP/site-system producer | management point | CCM | current + rotations; retain observed placement; #328 |
| `server-mp-policy` | `mpcontrol.log` | `siteServer` | management point | CCM | current + rotations; #328 |
| `server-mp-iis` | explicitly captured W3C export | observed IIS site-system producer | management point | IIS W3C | optional, scoped; #328 |
| `server-dp-distribution` | `distmgr.log`, `PkgXferMgr.log` | `siteServer` | distribution point/content | CCM | current + rotations; #329 |
| `server-dp-distribution` | `SMSDPProv.log` | observed DP producer | distribution point/content | CCM | current + rotations; #329 |
| `server-dp-distribution` | `PullDP.log` | observed pull-DP producer | distribution point/content | CCM | current + rotations; #329 |
| `server-dp-serve` | explicitly catalogued serving/status export | observed DP producer | distribution point/content | profile-defined | optional supplemental; #329 |
| `server-sup-sync` | `WCM.log`, `wsyncmgr.log` | `siteServer` | software update point | CCM | current + rotations; #330 |
| `server-sup-sync` | `SUPSetup.log`, `WSUSCtrl.log` | observed site-system producer | software update point | CCM | current + rotations; #330 |
| `server-sup-wsus` | explicitly scoped WSUS health/sync export | observed WSUS producer | software update point | profile-defined | optional, bounded; #330 |
| `server-iis-status` | curated IIS/status export | observed IIS site-system producer | discovered role only | IIS W3C | optional; skipped by default |

Microsoft's ConfigMgr documentation places `distmgr.log` and
`PkgXferMgr.log` on the site server while identifying `smsdpprov.log` on the
DP ([content-library troubleshooting](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/the-content-library) and
[Package Transfer Manager](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/package-transfer-manager)).
The official [log-file reference](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files)
likewise places `WCM.log` and `wsyncmgr.log` on the site server, and
`SUPSetup.log`/`WSUSCtrl.log` on a site-system server. Those references justify
the producer/subject split; they do not prove a lab's configured path, host
identity, co-located roles, or version-specific placement. Native discovery
must retain the observed producer topology and record unresolved placement
rather than broadening an allowed producer set.

The same reference separates MP/site-system-produced `MP_GetAuth.log`,
`MP_GetPolicy.log`, and `MP_Location.log` candidates from the
site-server-produced `mpcontrol.log`. They are deliberately separate catalog
rows. A co-located or otherwise ambiguous deployment retains its observed
producer handle plus unresolved placement provenance until native Windows
validation; basename or workflow ownership never resolves that ambiguity.

An overlapping basename or workflow subject is never enough to infer a server
source or producer role. Artifacts with undeclared source IDs, basenames,
rotations, or producer combinations remain `Unsupported`/unclassified evidence
and cannot enter a role reducer.

## Manifest and provenance handoff

The synthetic manifests use a stable, intentionally provisional JSON shape.
`sccmManifestVersion: 1` is the proposed server manifest version; actual
serde field names and tolerant-reader behavior are deferred to #318.

- `syntheticFixture: true` and `proposalOnly: true` make the committed safety
  and pre-#318 schema boundary machine-readable.
- `topology.rolesObserved` is a list of observed facts, never path guesses.
- Each artifact retains `producerRole`, a privacy-safe producer host handle,
  optional `workflowSubject`, `sourceId`, `configuredPathProvenance`,
  `originalBasename`, `rotation`, `captureState`, nullable `relativePath`,
  byte/count provenance, and collection time. Within one manifest/bundle,
  `artifactId` is unique across every artifact, including non-captured states.
  Reusing the same deterministic ID in an independent bundle is valid; there
  is no corpus-global namespace.
- `artifactId` is derived from the canonical producer role/host, source,
  workflow-subject role/instance, path fingerprint, basename, and rotation
  identity. Discovery position, task completion order, and a mutable counter
  are never inputs. A duplicate canonical identity or ID inside one manifest
  is rejected before any evidence write.
- Every `Captured`/`Capped` artifact carries explicit `encoding` and
  `collectionLimit` (`byteLimit`, `limitApplied`) provenance. A completed
  capture models its policy even when the limit was not reached. Non-captured
  artifacts omit these fields unless a future contract explicitly represents
  them as unavailable/null.
- Capture limits apply inclusively to raw file bytes before decoding. A capped
  artifact is the exact prefix of the source through byte `byteLimit`; the
  collector neither decodes first nor splits, repairs, or replaces bytes to
  form text. It records `bytesCopied == file size == byteLimit`,
  `truncated: true`, and `fragmentComplete: false`.
- `originalPath` is always a privacy marker in committed fixtures. The opaque
  `pathFingerprint` distinguishes configured roots without publishing them.
- `rotation.lineageId` joins current and rotated members of a source only; it
  is not a cross-role identifier. `relativePath` includes producer/source and,
  when needed, deterministic workflow-subject instance and configured-root
  discriminators so colliding basenames cannot overwrite or merge. The
  preparation key segment is the first 16 lowercase hexadecimal characters of
  SHA-256 over the UTF-8 NFC approved opaque handle; duplicate destinations
  are rejected during preflight rather than disambiguated by discovery order.
- Evidence retains `artifactId`, a full logical `lineRange`, and a synthetic
  text payload. Evidence payloads are raw and bundle-internal. Any public
  evidence projection and any derived field must pass the #318 redaction
  boundary and may retain only approved opaque handles/statuses. The future
  normalizer must frame before extraction.

## Native capture adapter design (deferred implementation)

1. A Windows-only discovery boundary returns observed role facts and configured
   candidate roots with discovery method and failure detail. A default path may
   be added as a candidate but may not create `rolesObserved`.
2. The engine selects only catalogued roles/sources, canonicalizes each path,
   rejects reparse/symlink escapes outside the allow-listed configured root,
   and enforces per-source file and inclusive raw-byte caps. The byte count and
   prefix copy occur before text decoding; the collector never repairs a
   truncated encoding boundary.
3. Before opening any destination, capture canonicalizes every artifact
   identity, workflow-subject/root collision key, and final bundle-relative
   path for the full batch. Duplicate identity/path preflight fails the batch.
   Each accepted destination is created atomically with create-new/no-overwrite
   semantics; a concurrent or pre-existing path is an explicit capture error,
   never a replacement.
4. Collision-safe paths include deterministic opaque subject-instance and
   configured-root segments when either can vary, for example
   `evidence/sccm/server/site-server/server-sup-sync/subject-software-update-point/instance-17eae15500d8968f/root-b11afca548220198/current/wsyncmgr.log`.
   The raw path or instance value must not be recoverable from those segments.
   Two roots or instances remain distinct IDs/evidence references and cannot
   overwrite or normalize-merge. Partial copies remain `Capped`; they do not
   become success.
5. The writer projects server fields into a versioned manifest without changing
   generic `ArtifactStatus`. Access, cap, skipped, unsupported, absent, and
   parse failure stay distinct. Raw evidence stays internal to the bundle. A
   public export runs both evidence and derived values through #318 redaction,
   removes raw host/path/content values, and retains only
   source/producer/workflow-subject/rotation, approved opaque handles, and
   allowed statuses.
6. Native acceptance needs Windows CI temp-path tests plus an authorized SCCM
   lab. The lab is not a prerequisite for parser corpus work and is currently
   pending; this package makes no live-capture claim.

Deferred native tests must make the write/privacy boundaries observable:

- a fake batch with colliding roots/instances must fail during preflight with
  zero destination files created; a pre-existing destination must remain
  byte-identical after atomic create-new fails;
- a capped source whose next byte crosses a decoding boundary must retain the
  exact raw prefix and size without replacement/repair before the parser sees
  it; and
- a protected bundle may contain sentinel raw host/path/evidence/derived
  values, but its serialized public projection must contain none of those
  sentinels while preserving only the expected approved opaque
  handles/statuses.

## Intake assessment rules

- Classify by `(producer role/topology, source ID/basename, supported rotation,
  provenance)`, not filename, workflow subject, or default path alone.
- Stable-normalize artifacts by producer role/host handle, source ID,
  workflow-subject role/instance/basis, path fingerprint, explicit rotation
  family rank, within-family value, lineage ID, basename, capture state,
  relative path, then artifact ID. Equality through the final ID is a rejected
  duplicate identity, so no input-order tie remains.
- Rotation family rank is timestamped, numbered, `.lo_`, current,
  provider-defined, then none. Timestamped values sort ascending by valid
  `YYYYMMDD-HHMMSS`; numbered values sort by descending integer; remaining
  ties use lineage ID, basename, capture state, relative path, and artifact ID
  in binary-stable lexical order. Canonical spellings are replacement-extension
  `.lo_`, numbered `.log.N`, and `.log.YYYYMMDD-HHMMSS`. This is serialization
  order only: intended lineage/record chronology is evaluated separately and
  is never inferred from array position.
- For every admitted complete record, its authoritative UTC instant is derived
  only from a syntactically valid date/time/offset and must be less than or
  equal to `collectedUtc` with zero synthetic tolerance. A timestamped
  rotation's filename/value instant must be less than or equal to the earliest
  admitted record instant in that member. Invalid/unknown offsets are
  non-comparable coverage gaps: they receive no invented UTC, reordering, or
  correlation.
- Missing required evidence yields a role-scoped coverage gap and a minimal
  next artifact request. It does not yield a role-health finding.
- `AccessDenied`, `Capped`, `Skipped`, `Unsupported`, and `ParseFailed` are
  preserved exactly. A partial, malformed, or unframed rotation boundary can
  create only coverage/parse gaps or a low-confidence symptom.
- Legacy generic records are eligible only through an explicit adapter that
  supplies role/source provenance. A generic `Failed` status must not be
  rewritten as `AccessDenied`, `Capped`, or `ParseFailed`.

## Fixture test matrix

| Scenario | Primary proof | Expected conservative result |
| --- | --- | --- |
| `complete-multi-role` | Site/MP plus site-produced DP/SUP control evidence with explicit subjects | producer topology and workflow subject stay separate; no health conclusion |
| `configured-nondefault-path` | observed MP configured root has opaque non-default provenance | source retained; absent default remains candidate-only |
| `collision-same-basename-configured-roots` | two current `MP_GetPolicy.log` files from distinct configured roots | distinct fingerprints/opaque path segments/IDs/references; neither overwrite nor merge |
| `rotations` | current, `.lo_`, numbered, timestamped files share lineage | unique collision-safe artifacts in stable rotation order |
| `multiline` | two physical lines form one complete CCM record | one logical evidence record with full `1-2` range |
| `absent-dp` | DP candidate absent and no observed DP role | DP coverage gap; never `DP broken` |
| `access-denied-mp` | MP policy candidate cannot be read | access coverage plus bounded reread request; no terminal MP result |
| `capped-sup` | site-server `wsyncmgr.log` for an SUP workflow is retained only to a byte cap | capped coverage and no terminal SUP health conclusion |
| `skipped-iis` | optional IIS supplemental source intentionally skipped | skip preserved; no required-source failure |
| `unsupported-db-supplement` | unknown DB export has explicit unsupported metadata | retained outside reducers; no inferred database/role state |
| `unsorted-manifest` | source order differs from canonical order | canonical source order and byte-identical normalized output |
| native fake-discovery (future) | role facts/configured roots are explicit | no default-path role inference; documented discovery failure state |
| native collision/cap/unsafe-path (future) | same basename, caps, and reparse escape | no overwrite; `Capped`; unsafe candidate rejected/skipped with provenance |
| legacy adapter (future) | generic artifact lacks SCCM fields | incomplete server bundle only when explicit provenance is supplied |

## #318 field-mapping blockers

The following are deliberately unresolved and must be mapped against #318
before implementation or compiling tests are added:

| Preparation field | Needed #318 contract | Decision required |
| --- | --- | --- |
| `captureState` | serialized coverage/capture enum | exact wire strings and unknown form |
| `producerRole` / `producerHostHandle` / `workflowSubject` | producer/subject topology model | canonical roles, safe host/instance handles, and non-inference rules |
| `configuredPathProvenance` | privacy/redaction and provenance model | safe handle/fingerprint representation |
| `encoding` / `collectionLimit` | capture provenance model | encoding enum/string and limit-policy wire shape |
| `rotation` | rotation and source identity model | rotation ordering and accepted syntax |
| `topology` / `rolesObserved` | role/topology model | canonical role enum and additive fields |
| `evidence` / `lineRange` | evidence reference and logical-record model | evidence ID derivation and line range schema |
| `expected` coverage entries | coverage gap/finding/result model | stable snapshot schema and next-artifact request form |
| legacy mapping | generic artifact adapter | explicit incomplete/unknown status behavior |

Until #318 lands, the JSON files are design fixtures only. They must not be
compiled as tests or used to imply native collection, server discovery, role
health, client impact, or client/server causality.
