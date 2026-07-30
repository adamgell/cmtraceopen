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

| Source ID | Allowed role(s) | Candidate basenames | Grammar | Rotation | Requiredness / consumers |
| --- | --- | --- | --- | --- | --- |
| `server-sitecomp` | `siteServer` | `sitecomp.log`, `hman.log` | CCM | current, `.lo_`, numeric, timestamp | required incident group; #327 |
| `server-status` | `siteServer` | `statmgr.log`, `statesys.log` | CCM | current, `.lo_`, numeric, timestamp | required incident group; #327 |
| `server-mp-auth` | `managementPoint` | `MP_GetAuth.log`, `MP_CliReg.log`, `MP_RegistrationManager.log` | CCM | current, `.lo_`, numeric, timestamp | required incident group; #328 |
| `server-mp-policy` | `managementPoint` | `MP_GetPolicy.log`, `MP_Location.log`, `mpcontrol.log` | CCM | current, `.lo_`, numeric, timestamp | required incident group; #328 |
| `server-mp-iis` | `managementPoint` | explicitly captured W3C export | IIS W3C | provider-defined | optional supplemental; #328 |
| `server-dp-distribution` | `distributionPoint`, `siteServer` | `distmgr.log`, `PkgXferMgr.log`, `SMSDPProv.log`, `PullDP.log` | CCM | current, `.lo_`, numeric, timestamp | required incident group when DP is in scope; #329 |
| `server-dp-serve` | `distributionPoint` | explicitly catalogued serving/status export | profile-defined | provider-defined | optional supplemental; #329 |
| `server-sup-sync` | `softwareUpdatePoint` | `wsyncmgr.log`, `wcm.log`, `WSUSCtrl.log`, `SUPSetup.log` | CCM | current, `.lo_`, numeric, timestamp | required incident group when SUP is in scope; #330 |
| `server-sup-wsus` | `softwareUpdatePoint` | explicitly scoped WSUS health/sync export | profile-defined | provider-defined | optional supplemental, bounded; #330 |
| `server-iis-status` | `managementPoint`, `softwareUpdatePoint` | curated IIS/status export | IIS W3C | provider-defined | optional; skipped by default |

An overlapping basename is never enough to infer a server source. Artifacts
with undeclared source IDs, basenames, rotations, or role combinations remain
`Unsupported`/unclassified evidence and cannot enter a role reducer.

## Manifest and provenance handoff

The synthetic manifests use a stable, intentionally provisional JSON shape.
`sccmManifestVersion: 1` is the proposed server manifest version; actual
serde field names and tolerant-reader behavior are deferred to #318.

- `topology.rolesObserved` is a list of observed facts, never path guesses.
- Each artifact retains `role`, `sourceId`, `configuredPathProvenance`,
  `originalBasename`, `rotation`, `captureState`, `relativePath`, byte/count
  provenance, and collection time. `artifactId` is unique per captured file.
- `originalPath` is always a privacy marker in committed fixtures. The opaque
  `pathFingerprint` distinguishes configured roots without publishing them.
- `rotation.lineageId` joins current and rotated members of a source only; it
  is not a cross-role identifier. `relativePath` includes role/source/rotation
  so colliding basenames cannot overwrite one another.
- Evidence retains `artifactId`, a full logical `lineRange`, and a synthetic
  text payload. The future normalizer must frame before extraction.

## Native capture adapter design (deferred implementation)

1. A Windows-only discovery boundary returns observed role facts and configured
   candidate roots with discovery method and failure detail. A default path may
   be added as a candidate but may not create `rolesObserved`.
2. The engine selects only catalogued roles/sources, canonicalizes each path,
   rejects reparse/symlink escapes outside the allow-listed configured root,
   and enforces per-source file and byte caps.
3. Capture writes collision-safe paths such as
   `evidence/sccm/server/management-point/server-mp-policy/numbered-2/MP_GetPolicy.log.2`.
   It records partial copies as `Capped`; it does not convert them to success.
4. The writer projects server fields into a versioned manifest without changing
   generic `ArtifactStatus`. Access, cap, skipped, unsupported, absent, and
   parse failure stay distinct. A public export redacts raw host/path values
   while retaining source/role/rotation and an approved opaque handle.
5. Native acceptance needs Windows CI temp-path tests plus an authorized SCCM
   lab. The lab is not a prerequisite for parser corpus work and is currently
   pending; this package makes no live-capture claim.

## Intake assessment rules

- Classify by `(observed or declared role, source ID/basename, supported
  rotation, provenance)`, not filename alone.
- Stable-normalize artifacts by role, source ID, path fingerprint, rotation
  order, basename, then artifact ID. Reordered input must produce byte-identical
  normalized output and deterministic evidence IDs once #318 supplies them.
- The preparation rotation order is oldest timestamped member, descending
  numbered member, `.lo_`, then current; #318 may replace this only with a
  documented stable shared ordering. The `rotations` fixture locks this intent.
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
| `complete-multi-role` | Site/MP/DP/SUP source groups captured with declared topology | all listed groups covered; no health conclusion |
| `configured-nondefault-path` | observed MP configured root has opaque non-default provenance | source retained; absent default remains candidate-only |
| `rotations` | current, `.lo_`, numbered, timestamped files share lineage | unique collision-safe artifacts in stable rotation order |
| `multiline` | two physical lines form one complete CCM record | one logical evidence record with full `40-41` range |
| `absent-dp` | DP candidate absent and no observed DP role | DP coverage gap; never `DP broken` |
| `access-denied-mp` | MP policy candidate cannot be read | access coverage plus bounded reread request; no terminal MP result |
| `capped-sup` | SUP log is retained only to a byte cap | capped coverage and no terminal SUP health conclusion |
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
| `configuredPathProvenance` | privacy/redaction and provenance model | safe handle/fingerprint representation |
| `rotation` | rotation and source identity model | rotation ordering and accepted syntax |
| `topology` / `rolesObserved` | role/topology model | canonical role enum and additive fields |
| `evidence` / `lineRange` | evidence reference and logical-record model | evidence ID derivation and line range schema |
| `expected` coverage entries | coverage gap/finding/result model | stable snapshot schema and next-artifact request form |
| legacy mapping | generic artifact adapter | explicit incomplete/unknown status behavior |

Until #318 lands, the JSON files are design fixtures only. They must not be
compiled as tests or used to imply native collection, server discovery, role
health, client impact, or client/server causality.
