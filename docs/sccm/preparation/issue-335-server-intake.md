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
| `server-mp-auth` | `MP_GetAuth.log` | `siteServer` | management point | CCM | current + rotations; #328 |
| `server-mp-auth` | `MP_CliReg.log`, `MP_RegistrationManager.log` | observed MP/site-system producer | management point | CCM | current + rotations; native placement must be retained; #328 |
| `server-mp-policy` | `MP_GetPolicy.log`, `MP_Location.log`, `mpcontrol.log` | observed MP producer | management point | CCM | current + rotations; native placement still requires validation; #328 |
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
  byte/count provenance, and collection time. `artifactId` is unique across
  every manifest artifact, including non-captured states.
- Every `Captured`/`Capped` artifact carries explicit `encoding` and
  `collectionLimit` (`byteLimit`, `limitApplied`) provenance. A completed
  capture models its policy even when the limit was not reached. Non-captured
  artifacts omit these fields unless a future contract explicitly represents
  them as unavailable/null.
- `originalPath` is always a privacy marker in committed fixtures. The opaque
  `pathFingerprint` distinguishes configured roots without publishing them.
- `rotation.lineageId` joins current and rotated members of a source only; it
  is not a cross-role identifier. `relativePath` includes producer/source and,
  when needed, workflow-subject and deterministic opaque configured-root
  segments so colliding basenames cannot overwrite or merge.
- Evidence retains `artifactId`, a full logical `lineRange`, and a synthetic
  text payload. The future normalizer must frame before extraction.

## Native capture adapter design (deferred implementation)

1. A Windows-only discovery boundary returns observed role facts and configured
   candidate roots with discovery method and failure detail. A default path may
   be added as a candidate but may not create `rolesObserved`.
2. The engine selects only catalogued roles/sources, canonicalizes each path,
   rejects reparse/symlink escapes outside the allow-listed configured root,
   and enforces per-source file and byte caps.
3. Capture writes collision-safe paths. If a logical source/basename is
   collected from more than one configured root or instance, the writer must
   include the deterministic opaque root/instance segment before rotation, for
   example
   `evidence/sccm/server/management-point/server-mp-policy/root-7d4a9c2e/current/MP_GetPolicy.log`.
   The raw path must not be recoverable from that segment. Two roots remain two
   artifact IDs/evidence references and cannot overwrite or normalize-merge.
   Partial copies remain `Capped`; they do not become success.
4. The writer projects server fields into a versioned manifest without changing
   generic `ArtifactStatus`. Access, cap, skipped, unsupported, absent, and
   parse failure stay distinct. A public export redacts raw host/path values
   while retaining source/producer/workflow-subject/rotation and approved
   opaque handles.
5. Native acceptance needs Windows CI temp-path tests plus an authorized SCCM
   lab. The lab is not a prerequisite for parser corpus work and is currently
   pending; this package makes no live-capture claim.

## Intake assessment rules

- Classify by `(producer role/topology, source ID/basename, supported rotation,
  provenance)`, not filename, workflow subject, or default path alone.
- Stable-normalize artifacts by producer role/host handle, source ID, workflow
  subject role/instance, path fingerprint, rotation order, basename, then
  artifact ID. Reordered input must produce byte-identical normalized output
  and deterministic evidence IDs once #318 supplies them.
- The preparation rotation order is oldest timestamped member, descending
  numbered member, `.lo_`, then current; #318 may replace this only with a
  documented stable shared ordering. Canonical spellings are `.log.lo_`,
  `.log.N`, and `.log.YYYYMMDD-HHMMSS`; the `rotations` fixture locks this
  intent with valid calendar/time fields.
- A complete record's parsed UTC instant must be less than or equal to its
  `collectedUtc`. Timestamped rotation filename/value and record time must
  agree and preserve the intended chronology. Only a syntactically valid
  offset may be normalized; invalid/unknown offsets are explicit coverage
  gaps and never receive an invented UTC instant.
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
