# Issue #319 client intake preparation

## Purpose and dependency boundary

This document began as the bounded source inventory and synthetic fixture
design for issue #319. The pure parser intake is now implemented against the
published #318 artifact, coverage, rotation, and schema contracts; its public
assessment is executable and validated on both serialization and
deserialization. The native manifest reader/writer, bounded discovery/capture,
legacy adapter, and Windows acceptance described below remain pending and do
not become delivered merely because the pure projection is available.

The proposed native adapter consumes the catalog below and writes an additive,
versioned SCCM extension (for example `sccm-manifest.json`). The generic bundle
manifest and generic `ArtifactStatus` remain unchanged: their meanings are
only `Collected`, `Missing`, and `Failed`. SCCM capture detail is an extension,
not a reinterpretation of a generic failure.

## Bounded client source catalog

| Catalog entry | Allowed basenames | Stable group memberships | Workflow consumer | Default requiredness | Rotations |
| --- | --- | --- | --- | --- | --- |
| `client-ccmsetup` | `ccmsetup.log`, `client.msi.log` | `client-ccmsetup` | health | incident core | current, `.lo_`, numbered, timestamped when explicitly captured |
| `client-evaluation` | `CcmEval.log`, `CcmExec.log`, `CcmRestart.log` | `client-evaluation` | health | incident core | same |
| `client-identity` | `ClientIDManagerStartup.log` | `client-identity` | health | incident core | same |
| `client-location` | `ClientLocation.log`, `CcmMessaging.log` | `client-location` | health | incident core | same |
| `client-location-services-shared` | `LocationServices.log` | `client-content`, `client-location` | health, deployment | incident core | same |
| `client-policy-agent` | `PolicyAgent.log`, `PolicyAgentProvider.log`, `PolicyEvaluator.log`, `Scheduler.log` | `client-policy-agent` | policy | policy bundle | same |
| `client-policy-state` | `CIAgent.log`, `CIDownloader.log`, `StateMessage.log`, `StatusAgent.log` | `client-policy-state` | policy | policy bundle | same |
| `client-app-intent` | `AppIntentEval.log`, `AppDiscovery.log` | `client-app-intent` | deployment | deployment bundle | same |
| `client-app-enforce` | `AppEnforce.log`, `ExecMgr.log` | `client-app-enforce` | deployment | deployment bundle | same |
| `client-content` | `CAS.log`, `ContentTransferManager.log`, `DataTransferService.log` | `client-content` | deployment | deployment bundle | same |
| `client-updates` | `ScanAgent.log`, `WUAHandler.log`, `UpdatesDeployment.log`, `UpdatesHandler.log`, `UpdatesStore.log` | `client-updates` | updates | update bundle | same |
| `client-windows-update-supplemental` | `ReportingEvents.log`, explicitly captured CBS/DISM export | `client-windows-update-supplemental` | updates | optional supplemental | declared separately only |

`ccmsetup` is separate from operational CCM logs. A basename is eligible only
when a declared source, client role/provenance, and supported rotation agree;
it cannot be classified by pathname or extension alone. `CustomVendorHook.log`
and `PolicyAgent.log.backup` remain unsupported. Current source candidates are
native concerns only: `%WINDIR%\\CCM\\Logs`, `%WINDIR%\\ccmsetup\\Logs`, and
explicitly configured roots. Pure intake must never reconstruct a path.

Catalog matching is set-valued and single-capture. A physical candidate is
matched once by client role/provenance, exact declared basename, and supported
rotation to exactly one catalog entry. That entry supplies an already-sorted,
immutable set of logical group memberships. The collector creates one stable
physical artifact identity from the configured-root handle/path fingerprint,
basename, and rotation lineage, then the intake projection references that same
artifact from each membership; it does not copy or reclassify the file.
Consequently `LocationServices.log` is captured once through
`client-location-services-shared` and contributes to both `client-content` and
`client-location`. Catalog validation must reject a basename/role/rotation
tuple owned by more than one entry, rather than selecting the first matching
row. Input or catalog iteration order therefore cannot change classification.

## Proposed manifest v1 adapter

The fixture manifests are a reviewable proposed wire shape, not a claim that
the #318 reader accepts it. Before implementation, map each proposed field to
the published #318 field or remove it. Unknown future fields must be preserved
where #318 permits; unavailable detail must lower coverage/confidence rather
than being guessed.

```json
{
  "sccmManifestVersion": 1,
  "proposalOnly": true,
  "syntheticFixture": true,
  "bundle": {
    "role": "client",
    "captureHost": "LAB-CLIENT-01",
    "siteCode": "LAB",
    "artifactOrder": "designOnlyCatalog.entryId,pathFingerprint,rotationRank,originalBasename,artifactId",
    "rotationOrder": "current,lo,numeric-ascending,timestamp-ascending"
  },
  "artifacts": [{
    "artifactId": "fixture-app-enforce-root-a-current",
    "designOnlyCatalog": {
      "entryId": "client-app-enforce",
      "groupMemberships": ["client-app-enforce"]
    },
    "role": "client",
    "kind": "ccmLog",
    "captureState": "captured",
    "encoding": "utf-8",
    "collectionLimit": {"byteLimit": 4096, "limitApplied": false},
    "originalBasename": "AppEnforce.log",
    "sanitizedSourcePath": "SYNTHETIC://root-a/CCM/Logs/AppEnforce.log",
    "pathFingerprint": "synthetic-root-a-app-enforce-current",
    "rotation": {"kind": "current", "fragmentComplete": true},
    "sourceVersion": "5.00.TEST.0000",
    "capturedUtc": "2026-07-30T00:00:00Z",
    "bytesCopied": 177,
    "relativePath": "evidence/client-app-enforce/current/AppEnforce.log"
  }]
}
```

`designOnlyCatalog.entryId` and `designOnlyCatalog.groupMemberships` are
fixture-design labels, not proposed final #318 field names. They make the
single-capture/multi-consumer invariant reviewable until #318 provides the
actual representation. `artifactId` denotes one physical candidate/fragment
record and must be unique within a bundle; it is not a logical group ID.
For captured and capped artifacts, `bytesCopied` is the exact copied-file byte
length, `encoding` is explicit, and `collectionLimit` distinguishes the
configured limit from whether it actually truncated the file. Expected
fixtures mirror those fields by physical artifact ID. Noncapture states carry
zero bytes and a null relative path without invented encoding/limit
provenance.

An applied byte cap is inclusive and counts raw source bytes before decoding.
The captured payload is the exact source prefix through `byteLimit`, even when
the boundary splits a multibyte sequence, physical line, or logical CCM
record. The collector does not append a textual truncation marker, decode and
repair the prefix, or replace boundary bytes. It records
`bytesCopied == file size == byteLimit`, `fragmentComplete: false`, and an
exact digest suitable for fixture verification. Any decoding or parse failure
remains a coverage state and cannot turn error-looking retained text into a
terminal finding.

Capture states in this proposed SCCM extension are `captured`, `absent`,
`accessDenied`, `capped`, `skipped`, `unsafePath`, `unsupported`, and
`legacyUnknownDetail`. They must be projected to the eventual #318 coverage
contract without changing generic `ArtifactStatus`. `Failed` from a legacy
generic manifest maps only to `legacyUnknownDetail`, never to `accessDenied`,
`capped`, `skipped`, or a parser failure. A legacy `collected` or `missing`
value may be mapped only when its provenance explicitly identifies a declared
client source; otherwise it remains incomplete/unclassified.

The native adapter is deliberately small: `discover_client_sources` evaluates
allow-listed basenames under configured roots; `capture_client_bundle` applies
per-source file/byte caps and collision-safe destinations; and
`write_sccm_manifest_v1` serializes sorted extension records. It must
canonicalize a configured root, reject a symlink/reparse target outside that
root, use a testable access-status provider, and retain original paths only as
privacy-classified provenance. There is no Tauri command, UI, direct parser
filesystem access, globbing in the pure crate, or redefinition of CCM.

## Determinism, collision, and rotation rules

- Sort manifest artifacts by catalog entry ID, normalized path fingerprint,
  rotation rank, original basename, then physical artifact ID. Group memberships
  are sorted independently. `expected.json` preserves the public group,
  physical-artifact, unsupported-artifact, and coverage-gap order exactly; its
  deduplicated fragment table and pending native provenance are sorted by
  physical artifact ID.
- Use the declared `current, lo, numeric ascending, timestamp ascending`
  capture order. Parsing may later use valid normalized timestamps for evidence
  order; it may not infer a cross-artifact relationship from rotation order.
- Store each fragment under its catalog entry and physical identity. Same
  basenames from distinct allowed roots receive distinct artifact IDs,
  fingerprints, and relative paths; neither overwrites nor merges into the
  other by basename.
- `.lo_`, `.N`, and a documented timestamp suffix are rotations only of an
  explicit allowed basename. `.backup` and arbitrary suffixes are unsupported.
- Complete record timestamps must be valid and no later than `capturedUtc`.
  Canonical evidence basenames retain replacement-extension `.lo_` and
  numbered `.log.N` spellings.
- A rotation split at either logical-record boundary carries
  `fragmentComplete: false`; it can provide raw-safe coverage but cannot create
  a key, phase transition, or terminal finding by itself.
- An unknown source is retained as unsupported metadata, outside workflow
  reducers. Reordering an input manifest must serialize to identical assessed
  output after the public #318 normalizer exists.

## Scenario matrix and expected test design

| Scenario | Primary assertion | Conservative result |
| --- | --- | --- |
| `complete` | Every curated group is captured with an explicitly synthetic record. | Baseline intake coverage only; no workflow diagnosis. |
| `rotations` | Current, `.lo_`, and `.2` `AppEnforce` fragments group together in declared order. | Captured group; no inferred deployment state. |
| `collision` | Two current `AppEnforce.log` candidates from distinct roots retain unique IDs, fingerprints, and paths. | Both physical artifacts survive; basename does not overwrite or merge them. |
| `missing-root` | No configured client root was discovered. | Every curated source is absent coverage; never “client not installed.” |
| `access-denied` | `client-policy-agent` has denied access while all other represented sources remain distinct. | Policy readiness requests only `client-policy-agent`; no policy failure. |
| `capped` | `client-content` retains exactly 128 bytes of a marker-bearing, incomplete fragment containing error-looking text. | Deployment readiness is insufficient; the fragment cannot parse as a complete record or establish a terminal condition. |
| `skipped` (design-only) | An optional supplemental source is intentionally disabled. | Preserve an intentional skip, distinct from absence/failure. |
| `unsafe-path` (design-only) | A reparse/symlink escapes an allow-listed root. | Reject capture, record `unsafePath`, and request a safe configured root. |
| `legacy-mapping` (design-only) | Generic legacy `collected`/`missing` have explicit client provenance; `failed` has none. | Map only the first two; retain `legacyUnknownDetail` for failed. |

The six committed fixture directories are intentionally the smallest corpus
for first intake tests. `skipped`, `unsafe-path`, and `legacy-mapping` remain
test-design cases until the additive native manifest and test-double boundary
exist; they must be added before #319 reaches its exit gate. Every production
behavior must begin with a focused red test. Required pure tests use typed,
unknown-field-denying expectations and exact normalized comparison across all
groups, fragments, physical artifacts, unsupported artifacts, and coverage
gaps. Mutation tests cover omissions, reordering, forged provenance, unknown
basenames, unsupported suffixes, source collisions, and every supported pure
coverage state. Native temp-directory tests cover caps, access-provider
results, escape rejection, and legacy mapping. Windows client collection
remains a separate acceptance gate.

## Fixture privacy and sanitization

- Fixtures use only `LAB-CLIENT-01`, the exact synthetic site code `LAB`,
  RFC-style test UUIDs, and fake `APP-TEST-001`, `CONTENT-TEST-001`, and
  `KB0000000` tokens.
- `SYNTHETIC://` paths are opaque fixture provenance, never real Windows paths.
  No customer hostname, user, SID, tenant, certificate, token, serial, actual
  deployment name, or customer log line is permitted.
- All timestamps, exact byte counts, encodings, collection limits, and record
  text are fixed. Evidence is minimal, deterministic, and has no semantic
  assertion beyond stated coverage.
- Each manifest has `proposalOnly: true` and `syntheticFixture: true`. The first
  line of every evidence file contains the literal `SYNTHETIC FIXTURE` plus
  scenario-specific coverage text: complete CCM fixtures place it inside the
  first CCM record, the capped fixture retains it in an intentionally
  incomplete 128-byte fragment, and non-CCM supplemental fixtures use it as
  plain text. A production collector must not treat the marker as a real SCCM
  file format.
- `expected.json` uses `contractState: pureIntakeImplementedNativePending`.
  `pureAssessment` is the complete typed
  executable oracle. `nativeDesignPending` holds byte/limit/digest facts that
  remain outside the pure projection, and `downstreamDesignPending` labels
  request wording and prohibited claims that are not intake output. Native
  manifest emission, discovery/capture, and Windows acceptance remain
  design-only gates rather than delivered claims.

## Remaining delivery blockers

1. The additive SCCM native manifest reader/writer and bounded client
   discovery/capture adapter are not implemented. The committed
   `proposalOnly` manifest shape is test design, not a native wire acceptance
   claim.
2. Pure coverage already keeps `captured`, `absent`, `accessDenied`, `capped`,
   `skipped`, `unsupported`, and `parseFailed` distinct. Native `unsafePath`
   and `legacyUnknownDetail` mapping still need their own additive manifest
   and test-double contracts rather than being guessed into an existing state.
3. The public legacy generic-manifest adapter and tolerant unknown-field/enum
   behavior remain unresolved; only provenance-backed `collected`/`missing`
   may map forward.
4. A Windows SCCM development client and Windows CI are required to accept
   actual canonicalization/reparse/ACL/rotation collection semantics. macOS
   proves the pure projection, JSON, ordering, synthetic privacy, and future
   native test doubles only.
