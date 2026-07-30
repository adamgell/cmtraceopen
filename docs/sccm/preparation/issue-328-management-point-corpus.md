# Issue #328 Management Point corpus preparation

## Purpose and dependency boundary

This document and its synthetic fixtures prepare Task 4 of the SCCM Server
intake/core plan. They define the behavior required from a future
Management Point analyzer without implementing a reducer, native adapter,
parser family, or public wire schema.

The preparation contract is explicitly `proposedPending318And335`:

- #318 must publish the shared artifact, evidence, timestamp, key, phase,
  finding, coverage, request, redaction, and confidence contracts.
- #335 must publish the role-aware server catalog, physical artifact identity,
  topology manifest, tolerant reader, and deterministic coverage projection.
- #327 may later contribute independently cited site-core context, but #328
  must remain callable without consuming #327 output.
- #333 may later consume counterpart-ready #321/#328 facts. This corpus does
  not correlate a client and server or make a client-side causal claim.

Every field in `manifest.json` or `expected.json` is therefore a review label,
not a speculative production interface. The future implementation must map
these behaviors onto the reviewed #318/#335 public types.

## Role-local state contract

```text
ReceiveRequest
  -> Authenticate
  -> RegisterOrIdentify
  -> ResolveLocationOrPolicy
  -> Respond
  -> RecordOutcome
```

The chain is one role-local Management Point transaction. It is not a client
transaction and does not imply that a nearby client symptom reached this
server.

- `ReceiveRequest` requires an explicit, profile-valid MP receive fact.
- `Authenticate` records a server-side authentication disposition.
- `RegisterOrIdentify` records the MP registration or identity disposition.
- `ResolveLocationOrPolicy` records a location or policy resolution fact.
- `Respond` records an explicit response attempt or terminal disposition.
- `RecordOutcome` records a coherent final server-side outcome.

A last-success value is the latest coherent phase evidenced for the same exact
key and compatible topology. Filename, component, source proximity, or
timestamp proximity cannot advance the state.

## Curated source contract

| Catalog group | Physical producer and basename | Responsibility |
| --- | --- | --- |
| `server-mp-auth` | `MP_GetAuth` / `MP_GetAuth.log` | Receive and Authenticate |
| `server-mp-auth` | `MP_CliReg` / `MP_CliReg.log` | Register or identify |
| `server-mp-auth` | `MP_RegistrationManager` / `MP_RegistrationManager.log` | Registration disposition |
| `server-mp-policy` | `MP_Location` / `MP_Location.log` | Location resolution |
| `server-mp-policy` | `MP_GetPolicy` / `MP_GetPolicy.log` | Policy resolution, response, and outcome |
| `server-mp-policy` | `SMS_MP_CONTROL_MANAGER` / `mpcontrol.log` | Role-local MP context only; never a keyed request by itself |
| `server-mp-iis` | `IIS-W3C` / explicitly catalogued `u_ex*.log` | Optional supplemental request evidence; never an arbitrary IIS tree |

All CCM sources reuse the existing CCM logical-record parser. The source
catalog and workflow analyzer must not add a Management Point `ParserKind` or
duplicate CCM framing. A catalogued IIS source uses the existing IIS W3C
parser and remains optional.

The source producer, captured artifact basename, and CCM `file=` code-origin
attribute are three distinct provenance fields. None may be substituted for
another.

Microsoft's [Configuration Manager log-file
contract](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/about-log-files)
specifies that standard rollover replaces the active `.log` suffix with
`.lo_`. For example, `MP_GetAuth.log` rolls to `MP_GetAuth.lo_`; the rollover
is not named `MP_GetAuth.log.lo_`. A physical manifest must retain that
observed basename exactly.

## Physical artifact, topology, and path provenance

Every manifest represents a synthetic server bundle with:

- `bundleRole: server` and `workflow: managementPoint`;
- observed role `managementPoint`;
- synthetic capture host `LAB-MP01`;
- synthetic site label `LAB`;
- public correlation-safe MP handle `safe:mp:lab-mp-01`;
- a corpus-unique physical `artifactId`;
- exactly one design-only catalog group membership;
- explicit role, producer, source kind, basename, and rotation lineage;
- configured/catalogued/optional path provenance plus an opaque path
  fingerprint;
- an obvious `SYNTHETIC://` source handle for captured files;
- explicit capture state, ConfigMgr profile label, collection time, encoding,
  byte limit, and exact copied byte count; and
- a collision-safe relative evidence path.

`LAB` also satisfies Microsoft's [site-code
contract](https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/setup-wizard-central-primary):
an exact ConfigMgr site code is three alphanumeric characters from `A` through
`Z` and `0` through `9`. The profile validator applies `^[A-Z0-9]{3}$` to
every exact topology and transaction-key claim.

`Captured`, `Absent`, `AccessDenied`, `Capped`, `Skipped`, `Unsupported`, and
`ParseFailed` remain distinct. A noncapture has zero bytes and no invented
encoding or collection-limit result. Its rotation kind and lineage retain the
candidate's deterministic identity, but `fragmentComplete` is omitted because
no physical fragment exists. Only a captured or capped physical artifact may
declare fragment completeness.

The manifest records an observed MP role independently from source coverage.
An absent candidate or missing default path is a source gap only. It never
means the role is absent, uninstalled, unavailable, or unhealthy. Configured
non-default paths must survive through the same opaque path provenance rather
than being replaced by a failed default-path probe.

## Synthetic evidence mechanics

Complete CCM evidence is forced through the existing CCM grammar. The literal
`SYNTHETIC FIXTURE` appears inside the first semantic record of every complete
artifact and is never a marker-only line. Every record retains:

- the physical artifact and exact line range;
- the declared producer/component;
- the distinct CCM `file=` code-origin value;
- original timestamp text and numeric offset;
- normalized UTC only when that offset is valid; and
- record-before-collection chronology.

The two physical files in the rotation-boundary split have
`fragmentComplete: false`. Neither is a logical record, neither exposes a key
or authentication fact, and joining their text is not an analyzer behavior.
A separate complete record in that scenario uses an unknown synthetic version
and malformed request key. It remains keyless and cannot borrow a key from
either adjacent fragment.

## Exact synthetic key profile

The selected preparation profile is `mp-server-5.00.test-v1`, scoped only to
synthetic source versions beginning `5.00.TEST.` and to the declared
`server-mp-auth` and `server-mp-policy` families for the Management Point
role. It is not a claim about an observed production ConfigMgr build.

Two phase-appropriate exact key shapes are allowed:

1. `requestClientTopology`: exact request UUID, correlation-safe client
   handle, site code, and MP host handle. `policyId` is explicitly null.
2. `requestPolicyClientTopology`: the same values plus an exact policy UUID.

Every source fact admitted to an exact transaction repeats the complete
selected key shape. In the expected-output labels, `transaction.key` is the
single authoritative key and every contained observation declares
`observationKeyBinding.mode: inheritImmutableParentTransactionKey`. An
observation has no independent `key` field and cannot override, borrow, or
conflict with its immutable parent key. Its one cited source line must repeat
every parent-key token, so a phase fact remains counterpart-ready for Issue
`#333` without duplicating the serialized key.

An assignment-looking token, raw client-looking token, message neighborhood,
same host label, component, or timestamp is insufficient. Unknown versions,
malformed keys, physical fragments, and incompatible client-style tokens
remain keyless source-local observations with:

- `keyConfidence: none`;
- low confidence and a low confidence ceiling;
- `correlationEligible: false`; and
- `borrowedKeys: false`.

## Reducer and causality rules

1. Reduce one exact key and compatible MP topology at a time.
2. Preserve every observation and stable-sort artifacts, transactions,
   observations, findings, context facts, and evidence references.
3. A deferred response is `blockedOrDeferred`, not a terminal failure. A later
   same-key explicit success may complete the transaction when source ordering
   is coherent.
4. Same-key success and failure at the same resolved instant remain
   contradictory when no trusted ordering resolves them. Their confidence
   ceiling is low.
5. An isolated contradictory control transaction cannot upgrade, qualify, or
   overwrite a different exact key's terminal finding.
6. A source-specific terminal record plus coherent preceding same-key phases
   may support a role-local confirmed failure. A red-looking record alone is a
   symptom.
7. Missing coverage requests the smallest group:
   `server-mp-auth` for Receive/Authenticate/Register and
   `server-mp-policy` for Resolve/Respond/Outcome.
8. Missing optional `server-mp-iis` coverage never creates a failure or lowers
   a coherent main-source result.
9. `mpcontrol.log` may add separately cited role-local context but cannot form
   a request transaction.
10. Client-looking values or adjacent client timestamps cannot attach to a
    server transaction. No client root cause or impact is emitted.

## Exact scenario matrix

The directory set remains exactly the nine scenarios prescribed by Task 4.
Program Gate C controls are isolated inside those scenarios rather than
creating unplanned top-level directories.

| Scenario | Primary outcome | Last successful phase | Bounded next artifact | Embedded control |
| --- | --- | --- | --- | --- |
| `healthy-policy` | Successful policy response and recorded outcome | RecordOutcome | None | A same-key deferred Respond observation is followed by explicit success |
| `auth-failure` | Confirmed role-local authentication failure | ReceiveRequest | None | None |
| `registration-failure` | Confirmed role-local registration failure | Authenticate | None | None |
| `location-failure` | Confirmed role-local location-resolution failure | RegisterOrIdentify | None | None |
| `policy-failure` | Confirmed role-local response failure | ResolveLocationOrPolicy | None | A separate exact key retains a same-instant Respond contradiction at low confidence |
| `iis-supplemental` | Successful main-source policy response with optional IIS intentionally skipped | RecordOutcome | None | `mpcontrol` context cannot enter the request transaction |
| `unrelated-client-like-key` | No MP transaction; incompatible client-like values remain source-local | None | `server-mp-auth` | Time proximity and client-looking tokens are explicitly unused |
| `rotation-boundary` | No MP transaction; split fragments are coverage-only | None | `server-mp-auth` | Separate unknown-version malformed key remains non-correlatable |
| `incomplete` | Exact transaction stops after registration because MP policy coverage is absent | RegisterOrIdentify | `server-mp-policy` | Missing source does not imply a missing MP role |

Together these fixtures cover the Program Gate C completed, confirmed
terminal, blocked/deferred, contradictory, incomplete, rotation, and malformed
classes while preserving the Task 4 directory contract.

## Expected-output preparation labels

Each `expected.json` declares:

- the exact state chain and role-local reducer boundary;
- synthetic profile selection and phase-appropriate exact key shape;
- observed role/topology without a default-path inference;
- physical artifact provenance and source-group coverage;
- transactions and observations with deterministic IDs;
- immutable parent-transaction key inheritance for every exact observation,
  with observation-level key fields and overrides forbidden;
- original timestamp, offset, normalized UTC, producer, and exact evidence
  ranges;
- phase, state, last successful phase, classification, confidence, and
  confidence ceiling;
- one cited finding per nonsuccess subject;
- a bounded next artifact or explicit null;
- keyless/non-correlatable local observations;
- deterministic reordered-input behavior;
- Program Gate C coverage tags; and
- prohibited role-absence, IIS-required, client-cause, time-only, and
  cross-side claims.

These are behavior labels for future compiled tests, not proposed final public
field names.

## Privacy limits

The corpus uses only deterministic synthetic values: `LAB-MP01`, `LAB`,
synthetic UUIDs, correlation-safe handles, and `SYNTHETIC://` path handles.
It contains no customer logs, real hosts, domains, users, SIDs, URLs,
certificates, database names, credentials, package identifiers, or raw client
identities. Error-looking values are synthetic terminal markers, not external
error-database diagnoses.

## Focused validation and future test specification

Preparation validation must fail before the document/corpus exists, then pass
only when the exact scenario set, byte/path/reference closure, privacy,
logical-record boundary, chronology, topology, producer, key, confidence,
coverage, Gate C, and false-causality contracts are satisfied.

After #318 and #335 publish the reviewed types, create
`sccm_server_management_point.rs`, load these fixtures through the public
server reader, run only the independently callable MP analyzer, reverse and
shuffle inputs, and compare normalized serialized results.

Run the plan-prescribed commands:

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_management_point
cargo test --locked -p cmtraceopen-parser --test sccm_server_site_core
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
```

Repository policy also requires `npx tsc --noEmit`. Until #318/#335 land, the
two focused SCCM server test targets are expected blockers rather than
permission to invent a private interface. The aggregate parser, strict Clippy,
wasm32, TypeScript, JSON, exact-byte, forced-parser, and diff gates remain
meaningful for this preparation slice.

Native Windows collection acceptance is explicitly pending. Future acceptance
must record the lab ConfigMgr version, observed role topology, configured path
provenance, capture time zone, synthetic scenario, byte limits, and redaction
procedure. macOS parser proof is not native role discovery or capture proof.

## Issue #333 contractual handoff

Issue `#328` may expose exact profile-qualified request/policy keys, a
correlation-safe client handle, site and MP topology handles, role-local
phases, source ordering provenance, and evidence references. That is the
entire handoff.

Issue `#333` must independently require compatible keys from Issue `#321`,
compatible role topology, usable timestamp offsets whenever ordering is
asserted, sufficient counterpart coverage, and terminal/corroborating facts.
A time-only, filename-only, error-code-only, client-ID-looking, or same-host
join is never a high-confidence cause. This corpus performs no link and makes
no client-side claim.
