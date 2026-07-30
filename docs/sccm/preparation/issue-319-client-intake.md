# Issue #319 client intake preparation

## Purpose and dependency boundary

This preparation artifact defines the bounded source inventory and synthetic
fixture design for issue #319. It is deliberately not production code and does
not freeze an API, Rust type, Tauri feature, Cargo dependency, or the #318
serialized contract. #319 may start implementation only after #318 publishes
and tests its public artifact, evidence, coverage, signal, key, timestamp,
redaction, finding, and bundle-reader contracts.

The proposed native adapter consumes the catalog below and writes an additive,
versioned SCCM extension (for example `sccm-manifest.json`). The generic bundle
manifest and generic `ArtifactStatus` remain unchanged: their meanings are
only `Collected`, `Missing`, and `Failed`. SCCM capture detail is an extension,
not a reinterpretation of a generic failure.

## Bounded client source catalog

| Logical source | Allowed basenames | Workflow consumer | Default requiredness | Rotations |
| --- | --- | --- | --- | --- |
| `client-ccmsetup` | `ccmsetup.log`, `client.msi.log` | health | incident core | current, `.lo_`, numbered, timestamped when explicitly captured |
| `client-evaluation` | `CcmEval.log`, `CcmExec.log`, `CcmRestart.log` | health | incident core | same |
| `client-identity` | `ClientIDManagerStartup.log` | health | incident core | same |
| `client-location` | `ClientLocation.log`, `LocationServices.log`, `CcmMessaging.log` | health, deployment | incident core | same |
| `client-policy-agent` | `PolicyAgent.log`, `PolicyAgentProvider.log`, `PolicyEvaluator.log`, `Scheduler.log` | policy | policy bundle | same |
| `client-policy-state` | `CIAgent.log`, `CIDownloader.log`, `StateMessage.log`, `StatusAgent.log` | policy | policy bundle | same |
| `client-app-intent` | `AppIntentEval.log`, `AppDiscovery.log` | deployment | deployment bundle | same |
| `client-app-enforce` | `AppEnforce.log`, `ExecMgr.log` | deployment | deployment bundle | same |
| `client-content` | `CAS.log`, `ContentTransferManager.log`, `DataTransferService.log`, `LocationServices.log` | deployment | deployment bundle | same |
| `client-updates` | `ScanAgent.log`, `WUAHandler.log`, `UpdatesDeployment.log`, `UpdatesHandler.log`, `UpdatesStore.log` | updates | update bundle | same |
| `client-windows-update-supplemental` | `ReportingEvents.log`, explicitly captured CBS/DISM export | updates | optional supplemental | declared separately only |

`ccmsetup` is separate from operational CCM logs. A basename is eligible only
when a declared source, client role/provenance, and supported rotation agree;
it cannot be classified by pathname or extension alone. `CustomVendorHook.log`
and `PolicyAgent.log.backup` remain unsupported. Current source candidates are
native concerns only: `%WINDIR%\\CCM\\Logs`, `%WINDIR%\\ccmsetup\\Logs`, and
explicitly configured roots. Pure intake must never reconstruct a path.

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
    "siteCode": "CONTOSO",
    "artifactOrder": "logicalArtifactId,pathFingerprint,rotationRank,originalBasename",
    "rotationOrder": "current,lo,numeric-ascending,timestamp-ascending"
  },
  "artifacts": [{
    "artifactId": "client-app-enforce",
    "role": "client",
    "kind": "ccmLog",
    "captureState": "captured",
    "originalBasename": "AppEnforce.log",
    "sanitizedSourcePath": "SYNTHETIC://root-a/CCM/Logs/AppEnforce.log",
    "pathFingerprint": "synthetic-root-a-app-enforce-current",
    "rotation": {"kind": "current", "fragmentComplete": true},
    "sourceVersion": "5.00.TEST.0000",
    "capturedUtc": "2026-07-30T00:00:00Z",
    "bytesCopied": 128,
    "relativePath": "evidence/client-app-enforce/current/AppEnforce.log"
  }]
}
```

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

- Sort manifest artifacts by logical artifact ID, normalized path fingerprint,
  rotation rank, then original basename. Expected arrays use stable IDs.
- Use the declared `current, lo, numeric ascending, timestamp ascending`
  capture order. Parsing may later use valid normalized timestamps for evidence
  order; it may not infer a cross-artifact relationship from rotation order.
- Store each fragment under its logical source and fragment identity. Same
  basenames from distinct allowed roots receive distinct fingerprints and paths;
  neither overwrites the other.
- `.lo_`, `.N`, and a documented timestamp suffix are rotations only of an
  explicit allowed basename. `.backup` and arbitrary suffixes are unsupported.
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
| `rotations` | Current, `.lo_`, and `.2` `AppEnforce` fragments group together, in declared order, with two roots retained separately. | Captured group; no collision or inferred deployment state. |
| `missing-root` | No configured client root was discovered. | Every curated source is absent coverage; never “client not installed.” |
| `access-denied` | `client-policy-agent` has denied access while all other represented sources remain distinct. | Policy readiness requests only `client-policy-agent`; no policy failure. |
| `capped` | `client-content` retains a capped tail containing error-looking text. | Deployment readiness is insufficient; tail cannot establish a terminal condition. |
| `skipped` (design-only) | An optional supplemental source is intentionally disabled. | Preserve an intentional skip, distinct from absence/failure. |
| `unsafe-path` (design-only) | A reparse/symlink escapes an allow-listed root. | Reject capture, record `unsafePath`, and request a safe configured root. |
| `legacy-mapping` (design-only) | Generic legacy `collected`/`missing` have explicit client provenance; `failed` has none. | Map only the first two; retain `legacyUnknownDetail` for failed. |

The five committed fixture directories are intentionally the smallest corpus
for first intake tests. `skipped`, `unsafe-path`, and `legacy-mapping` remain
test-design cases until #318 publishes compatible public types and a native
test-double boundary; they must be added before #319 reaches its exit gate.
Every production behavior must begin with a focused red test. Required pure
tests deserialize through the published #318 bundle reader, use direct field
assertions (not permissive snapshots), and cover unknown basenames, unsupported
suffixes, deterministic reordered input, source collisions, and each capture
state above. Native temp-directory tests cover caps, access provider results,
escape rejection, and legacy mapping. Windows client collection remains a
separate acceptance gate.

## Fixture privacy and sanitization

- Fixtures use only `LAB-CLIENT-01`, `CONTOSO`, RFC-style test UUIDs, and fake
  `APP-TEST-001`, `CONTENT-TEST-001`, and `KB0000000` tokens.
- `SYNTHETIC://` paths are opaque fixture provenance, never real Windows paths.
  No customer hostname, user, SID, tenant, certificate, token, serial, actual
  deployment name, or customer log line is permitted.
- All timestamps, byte counts, and record text are fixed. Evidence is minimal,
  deterministic, and has no semantic assertion beyond stated coverage.
- Each manifest has `proposalOnly: true` and `syntheticFixture: true`; each
  evidence file begins with `# SYNTHETIC FIXTURE`. A production collector must
  not treat these markers as a real SCCM file format.
- `expected.json` asserts explicit coverage and requests. Its `contractState`
  is `proposedPending318`, so no fixture suggests that interface names, enum
  spellings, or schema fields are final.

## Exact dependency blockers

1. #318 has not yet supplied a stable public `SccmArtifact`, evidence,
   coverage, rotation, redaction, key/timestamp, finding, and bundle-reader
   contract in this worktree. No parser source, test compiled against an
   invented interface, or Cargo change is authorized here.
2. The final mapping from the proposed SCCM extension states to #318 coverage
   variants is unresolved. In particular `accessDenied`, `capped`, `skipped`,
   `unsafePath`, and `legacyUnknownDetail` must remain distinct.
3. The public legacy generic-manifest adapter and tolerant unknown-field/enum
   behavior are unresolved; only provenance-backed `collected`/`missing` may
   map forward.
4. A Windows SCCM development client and Windows CI are required to accept
   actual canonicalization/reparse/ACL/rotation collection semantics. macOS
   can validate only JSON, ordering, synthetic privacy, and later pure/native
   test doubles.
