# Issue #330 Software Update Point and WSUS corpus preparation

## Scope and dependency boundary

This slice prepares the server-local source, fixture, key, coverage, and
behavior contract for issue `#330`. It contains only synthetic CCM evidence,
versioned manifest/expected-output labels, and a focused Rust fixture-contract
test. It does not add a production reducer, native collector, parser family,
public wire type, database or network dependency, or cross-side correlator.

The preparation contract is `proposedPendingReviewed318And335`:

- reviewed #318 artifact, logical-record, timestamp, evidence, key, coverage,
  signal, redaction, and finding contracts remain the implementation boundary;
- #335 supplies role/topology, configured-path, physical identity, rotation,
  collection-limit, and coverage handoff;
- #323 remains independently callable and does not feed this server-local
  preparation corpus; and
- #333 owns any later client update/SUP correlation. This slice performs none
  and emits no client-impact or causal claim.

All `.log` files remain raw CCM transport. The focused contract consumes the
existing `normalize_ccm_artifact` path and does not add `ParserKind::Sccm` or a
second CCM parser. The parser crate remains pure Rust and wasm32-compatible.

## Bounded source and role contract

Producer identity stays separate from the Software Update Point workflow
subject.

| Source ID | Basename | Producer role | Workflow subject | Use |
| --- | --- | --- | --- | --- |
| `server-sup-sync` | `WCM.log` | `siteServer` | exact SUP handle | SUP configuration |
| `server-sup-sync` | `wsyncmgr.log` | `siteServer` | exact SUP handle | synchronization, metadata, and publish facts |
| `server-sup-sync` | `SUPSetup.log` | `softwareUpdatePoint` | same exact SUP handle | setup/configuration facts |
| `server-sup-sync` | `WSUSCtrl.log` | `softwareUpdatePoint` | same exact SUP handle | WSUS validation and terminal health facts |
| `server-sup-wsus` | `WsusHealth.json` | `wsUs` | exact SUP handle | optional profile-defined supplemental health |
| `client-updates-control` | `WUAHandler.log` | `client` | exact SUP handle only as ignored control | must not enter the server reducer |

`server-sup-wsus` is optional and bounded. It is not permission to inspect an
arbitrary WSUS database, IIS tree, update catalog, filesystem root, registry,
WMI surface, or network endpoint. The `WsusHealth.json` label is a synthetic
profile-defined contract, not a supported native collector.

Every manifest preserves the site code, opaque SUP and WSUS handles, observed
roles, producer role and host handle, workflow subject, exact source and
basename, grammar, synthetic source version, sanitized path/fingerprint,
rotation lineage, collection timestamp, and capture state. Physical artifact
records additionally preserve encoding, fragment completeness, byte cap, exact
copied-byte count, and a collision-safe evidence destination. Nonphysical
states omit encoding, byte, limit, relative-path, and fragment completion
facts.

Rotation provenance is structural rather than self-asserted. A canonical
rotation kind/value must agree with the sanitized source basename and with the
collision-safe destination segment (`current`, `lo_`, `numbered-N`, or
`timestamped-YYYYMMDD-HHMMSS`). Numbered values are nonzero, timestamps are
canonical calendar values, lineage IDs are bounded safe tokens, and physical
source identity does not become unique merely because an artifact declares a
different rotation.

An absent or access-denied default candidate is source coverage only. It cannot
erase an observed SUP role or prove the role healthy, failed, broken,
uninstalled, or unavailable.

## State, key, and terminal-evidence contract

The proposed role-local state chain is:

```text
Configure -> Synchronize -> ImportOrProcessMetadata -> ValidateWsus
          -> PublishAvailability -> HealthyOrTerminal
```

A proposed transaction admits only a profile-valid exact tuple:

```text
syncRunId
+ siteCode
+ softwareUpdatePointHandle
+ optional exact updateId and KB pair
+ extractionProfileId
```

The synthetic profile is `sup-server-5.00.test-v1`, bounded to
`5.00.TEST.*` fixtures. It makes no claim about a real ConfigMgr build.
Structured fields are unique, closed `Name=Value` pairs. Duplicate fields,
nested CCM-like text, aliases, unknown fields, partial update/KB pairs, or a
key not repeated by every cited record fail closed.

The reducer contract is conservative:

- success requires a cited terminal `HealthyOrTerminal` success;
- confirmed failure requires cited source-specific terminal failure evidence;
- `retrying` remains `blockedOrDeferred`, never inferred failure;
- incomplete manifest coverage remains `insufficientEvidence`, retains exact
  gap IDs, and requests only a bounded source ID/reason code;
- skipped optional WSUS coverage lowers the confidence ceiling without
  converting a cited terminal success to failure;
- rotation fragments and malformed bytes remain low-confidence,
  noncorrelatable source-local observations; and
- a same-time client record, shared KB, or client-only update ID cannot enter a
  server transaction or establish causality.

Observation order uses normalized timestamp provenance plus artifact/bundle
capture chronology. Time alone is not a join key.

## Coverage and bounded requests

`captured`, `absent`, `accessDenied`, `capped`, `skipped`, `unsupported`, and
`parseFailed` remain distinct manifest states. Expected coverage is the exact
sorted projection of all manifest artifact IDs and states, including
nonphysical coverage outcomes.

Requests use only a catalogued source ID and one of:

- `coverageAbsent`
- `coverageAccessDenied`
- `coverageCapped`
- `coverageMalformed`
- `coverageRotationSplit`

A reason code must be backed by matching noncomplete manifest coverage. There
is no free-form collection request in the preparation labels.

## Scenario matrix

| Scenario | Required behavior |
| --- | --- |
| `sync-success` | Six distinct phases end in cited terminal success |
| `wcm-configuration-failure` | WCM terminal failure has no invented prior success |
| `wsus-health-failure` | WSUS validation terminal failure retains metadata as the last success |
| `sync-retry` | Retry is deferred with configuration as the last success |
| `metadata-failure` | Metadata terminal failure remains distinct from WSUS health |
| `sup-setup-failure` | SUP setup terminal configuration failure stays role-local |
| `supplemental-wsus-skipped` | Optional skipped WSUS coverage lowers confidence only |
| `unrelated-update-key` | Same-time client failure with another update ID stays ignored |
| `rotation-boundary` | Split rotations plus malformed WSUS bytes form no transaction |
| `incomplete` | Early configuration survives while denied/absent downstream sources remain gaps |

Permanent adversarial tests mutate exact keys, terminality, producer handles,
capture chronology, physical/nonphysical provenance, source-local
classifications, observation order, transaction cardinality, destination
collisions, unknown causal fields, and client update identity borrowing. Every
mutation must fail closed.

Scenario `evidence/` trees are recursively closed against their physical
manifest artifacts, and every such artifact must appear in expected coverage.
Mutation-only byte sequences are stored outside all scenario trees under the
explicit versioned `software_update_point_mutation_assets/manifest.json`
test-only contract with exact byte counts and purposes.

## Deferred implementation and validation

Production `software_update_point.rs` implementation waits for the #318 API
gate and mandatory restack/review. It may then map the preparation labels onto
the reviewed public contracts without weakening this corpus. Native Windows
capture is a separate adapter concern and must retain configured paths,
producer/subject topology, rotation, access results, byte caps, and
collision-safe identities.

No committed fixture contains customer data, real hostnames, raw filesystem
paths, credentials, tokens, live SCCM logs, or actual update metadata. No live
Windows, ConfigMgr, SUP, or WSUS acceptance is claimed by this preparation
slice.
