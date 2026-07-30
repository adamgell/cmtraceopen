# SCCM Client Intake and Core Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver issues #319, #320, #321, #322, and #323 as a deterministic SCCM Client intake bundle plus evidence-backed health/location, policy, application/content, and software-update diagnoses.

**Architecture:** The pure parser crate owns client source classification, normalized evidence consumption, workflow transactions, and findings. The native crate owns bounded Windows source discovery and capture into an SCCM-specific manifest. CCM remains the one raw record grammar; no client workflow reparses physical log lines or introduces a `ParserKind::Sccm`. Every analyzer returns its last proven phase, cited evidence, coverage gaps, and the smallest useful next artifact request instead of a causal guess.

**Tech Stack:** Rust 1.88, Cargo workspace, `cmtraceopen-parser`, `cmtrace-open` Tauri backend, serde/serde_json, regex, chrono, existing CCM parser, existing native ESP discovery only as an implementation pattern, Windows SCCM Client development host for final collection validation.

## Global Constraints

- #318 is a hard dependency. This plan must consume its public `SccmArtifact`, `SccmEvidence`, coverage, signal, key, timestamp, redaction, and finding contracts rather than defining client-private replacements.
- This plan owns #319 through #323 only. Do not add Task Sequence, inventory, compliance, co-management, scripts, notification, Software Center, server-role rules, cross-side correlation, or workspace UI here.
- `cmtraceopen-parser` remains pure and `wasm32-unknown-unknown` compatible. It cannot read paths, glob, copy files, inspect a registry, invoke WMI, query a service, or communicate over the network.
- Keep raw CCM parsing in `crates/cmtraceopen-parser/src/parser/ccm.rs`. Workflow extraction starts from complete logical records supplied through the SCCM spine; `parse_lines` is never a semantic evidence input.
- Do not add `ParserKind::Sccm`, a parser kind per client log, or a second CCM regular expression. Source names map to SCCM workflow catalog entries above the shared `ParserKind::Ccm` transport grammar.
- Preserve current generic collection-bundle behavior. `ArtifactStatus` currently represents only `Collected`, `Missing`, and `Failed`; do not silently overload it to mean access denied, capped, skipped, unsupported, or partial SCCM coverage.
- The SCCM Client native bundle gets an additive, versioned SCCM manifest/extension. Its reader must tolerate a generic legacy manifest and map only unambiguous legacy states; no existing generic bundle consumer may break.
- An absent source means only absent coverage. It must create an `InsufficientEvidence`/coverage result, never an assertion that the client is healthy, targeted, not targeted, or failing.
- Unknown client version, unknown message pattern, malformed logical record, or split rotation must lower confidence and retain raw-safe evidence rather than extrapolating a workflow state.
- Use only synthetic fixture identities: `LAB-CLIENT-01`, `CONTOSO`, RFC-style UUIDs, fake package/content IDs, and no customer paths, users, SIDs, tokens, certificates, tenant IDs, serials, or real deployment names.
- Windows SCCM Client collection behavior is accepted only on Windows CI and the development client. macOS validates deterministic pure parser and native test-double behavior, not Windows filesystem/ACL semantics.

---

## Scope, Dependencies, and Ship Order

| Issue | Deliverable | Starts after | May run in parallel with | Blocks |
| --- | --- | --- | --- | --- |
| #319 | Curated client source catalog, versioned bundle manifest, deterministic current/rotation intake | #318 | #335 server intake | #320–#326 |
| #320 | Setup/service/identity/location transaction | #319 source contract | #321–#323 analyzer implementation | Reliable prerequisite findings |
| #321 | Policy request-to-report transaction | #319 and #320 vocabulary | #322/#323 | First policy-to-MP correlation in #333 |
| #322 | App/package/content deployment transaction | #319 | #320/#321/#323 | First content-to-DP correlation in #333 |
| #323 | Software-update transaction | #319 | #320–#322 | Future SUP correlation after #330 |

Land #319 before invoking any analyzer against a live client. After #319, parser-only analyzer PRs may proceed independently provided they use the frozen shared fixture schema and public #318 contracts. Do not make #322 wait for #321 implementation: it may receive an absent policy artifact as explicit coverage and request it. Do not start #333 implementation from this plan; it only emits stable keys/evidence needed by #333.

## File Structure and Ownership

The exact directories are deliberately split by pure semantics versus native I/O:

```text
crates/cmtraceopen-parser/
├── src/sccm/
│   ├── mod.rs                         # #318 public façade; add client re-export only
│   ├── models.rs                      # #318 shared models; do not add workflow-local wire types
│   ├── catalog.rs                     # #318 filename/role primitives; extend catalog ownership here
│   └── client/
│       ├── mod.rs                     # public client bundle/analyzer façade
│       ├── intake.rs                  # expected client source groups + coverage projection
│       ├── health.rs                  # #320 setup/service/identity/location state machine
│       ├── policy.rs                  # #321 policy transaction state machine
│       ├── deployment.rs              # #322 app/package/content transaction state machine
│       └── updates.rs                 # #323 software-update transaction state machine
├── tests/
│   ├── sccm_client_intake.rs          # pure catalog/coverage/ordering contract
│   ├── sccm_client_health.rs          # #320 behavior contract
│   ├── sccm_client_policy.rs          # #321 behavior contract
│   ├── sccm_client_deployment.rs      # #322 behavior contract
│   ├── sccm_client_updates.rs         # #323 behavior contract
│   └── fixtures/sccm/client/
│       ├── README.md                  # schema, sanitization, replay instructions
│       ├── intake/<scenario>/         # manifest + current/rotation source evidence
│       ├── health/<scenario>/         # setup/location cases
│       ├── policy/<scenario>/         # policy state-machine cases
│       ├── deployment/<scenario>/     # app/content cases
│       └── updates/<scenario>/        # update cases

src-tauri/
├── Cargo.toml                         # add an opt-in sccm-diagnostics feature and test target
├── src/lib.rs                         # compile-gated native SCCM module declaration
├── src/sccm/
│   ├── mod.rs                         # native-only surface, not a UI/workspace feature
│   ├── intake.rs                      # bounded client discovery/candidate evaluation
│   ├── bundle.rs                      # SCCM bundle layout + manifest reader/writer adapter
│   └── manifest.rs                    # SCCM manifest schema v1 serialization and legacy mapping
└── tests/
    └── sccm_client_intake.rs          # temp-directory native discovery/capture/manifest tests
```

Do not put native capture code under `crates/cmtraceopen-parser/src/sccm`. Do not put client analyzers under `src-tauri/src/esp`, reuse ESP code as a narrow private implementation reference only after tests show it does not carry ESP state/session assumptions.

## Shared Client Contracts Consumed from #318

The spine owns serialized types. This plan adds only client workflow enums and behavior that use those types. The public client façade should be small and deterministic:

~~~rust
// crates/cmtraceopen-parser/src/sccm/client/mod.rs
pub fn analyze_client_bundle(
    bundle: &SccmNormalizedBundle,
) -> SccmBundleAnalysis;

pub fn assess_client_intake(
    artifacts: &[SccmArtifact],
) -> SccmClientIntakeAssessment;
~~~

Each per-workflow analyzer remains independently callable for tests and future dedicated Client workspace views:

~~~rust
pub fn analyze_client_health(
    bundle: &SccmNormalizedBundle,
) -> SccmWorkflowAnalysis;

pub fn analyze_client_policy(
    bundle: &SccmNormalizedBundle,
) -> SccmWorkflowAnalysis;

pub fn analyze_client_deployment(
    bundle: &SccmNormalizedBundle,
) -> SccmWorkflowAnalysis;

pub fn analyze_client_updates(
    bundle: &SccmNormalizedBundle,
) -> SccmWorkflowAnalysis;
~~~

`SccmWorkflowAnalysis` must contain the workflow name, stable sorted transactions, stable sorted findings, workflow-scoped coverage gaps, and artifact requests. It must not contain a private copy of evidence, a filesystem path, a raw execution context, or a mutable global cache.

Client workflow transaction models should use domain phases, but findings use the shared `SccmPhase`/`SccmFinding` contract. The enum values below are intentionally explicit so reviewers can reject a skipped phase rather than infer behavior from a message name:

| Workflow | Transaction phases | Minimum stable keys |
| --- | --- | --- |
| Health/location | Setup, Service, Identity, SiteAssignment, ManagementPoint, Transport | client GUID, site code, management-point host |
| Policy | Request, Download, Persist, Schedule, Evaluate, Report | policy/assignment ID, client GUID, site code, policy request ID |
| Deployment | Intent, Requirements, LocateContent, Transfer, Cache, Enforce, Detect, Report | assignment ID, CI ID, package/content ID, DP host, BITS job ID, product/exit code |
| Updates | Scan, Evaluate, LocateSup, Download, MaintenanceWindow, Install, Reboot, Report | update/KB, CI ID, content ID, SUP host, update job/result ID |

No timestamp alone can create a transaction key. An exact key can associate records only after the #318 extraction profile has identified the client version/artifact-family rule as validated. A time-only neighborhood may order a single artifact's local timeline but cannot establish a high-confidence relationship between separate artifacts or hosts.

## Fixture Schema and Sanitization Contract

Every client fixture directory contains exactly these committed inputs unless a scenario deliberately tests missing input:

```text
manifest.json              # schemaVersion, bundle metadata, all expected artifacts/states
evidence/<artifact>/<fragment>.log    # current and rotation fragments named by manifest relative paths
expected.json              # expected transactions, findings, evidence refs, coverage, requests
README.md                  # only when scenario needs a specific explanation beyond directory name
```

`manifest.json` must declare, for every expected artifact: `artifactId`, `role: "client"`, `kind`, capture state, original basename, sanitized source path or `null`, rotation lineage, source ConfigMgr version or `null`, capture timestamp, and bounded byte count. `expected.json` must assert full output, not merely a title substring:

```json
{
  "workflow": "policy",
  "transactions": [{
    "transactionId": "policy:assignment:11111111-1111-1111-1111-111111111111",
    "phase": "persist",
    "state": "failed",
    "lastSuccessfulPhase": "download",
    "evidence": [{"artifactId": "client-policy-agent", "entryId": "entry-000001"}]
  }],
  "findings": [{
    "class": "confirmedFailure",
    "confidence": "high",
    "phase": "persist",
    "coverageGapArtifactIds": [],
    "nextArtifacts": []
  }]
}
```

Expected fixture outputs must be sorted by stable IDs. Never include a dynamically generated timestamp, random UUID, host identity, absolute temporary path, or an error description that comes from an unstable external database. When a fixture intentionally has incomplete coverage, it must assert the gap and bounded next-artifact request explicitly.

## Source Bundle Contract for #319

### Initial client source groups

The following source groups are the first curated client intake contract. The list is deliberately bounded; presence in a default directory is a candidate, not evidence that every client/version has that source.

| Logical artifact ID | Candidate basenames | Primary purpose | Required for | Rotation behavior |
| --- | --- | --- | --- | --- |
| `client-ccmsetup` | `ccmsetup.log`, `client.msi.log` where documented | bootstrap/setup | health | current + `.lo_` + numbered/timestamped when captured |
| `client-evaluation` | `CcmEval.log`, `CcmExec.log`, `CcmRestart.log` | service/evaluation/restart | health | all recognized rotations |
| `client-identity` | `ClientIDManagerStartup.log` | client identity/registration | health | all recognized rotations |
| `client-location` | `ClientLocation.log`, `LocationServices.log`, `CcmMessaging.log` | site/MP/location/transport | health | all recognized rotations |
| `client-policy-agent` | `PolicyAgent.log`, `PolicyAgentProvider.log`, `PolicyEvaluator.log`, `Scheduler.log` | policy lifecycle | policy | all recognized rotations |
| `client-policy-state` | `CIAgent.log`, `CIDownloader.log`, `StateMessage.log`, `StatusAgent.log` | policy evaluation/reporting supplemental | policy | all recognized rotations |
| `client-app-intent` | `AppIntentEval.log`, `AppDiscovery.log` | app intent/requirements/detection | deployment | all recognized rotations |
| `client-app-enforce` | `AppEnforce.log`, `ExecMgr.log` | enforcement/result | deployment | all recognized rotations |
| `client-content` | `CAS.log`, `ContentTransferManager.log`, `DataTransferService.log`, `LocationServices.log` | location/content/transfer/cache | deployment | all recognized rotations |
| `client-updates` | `ScanAgent.log`, `WUAHandler.log`, `UpdatesDeployment.log`, `UpdatesHandler.log`, `UpdatesStore.log` | update lifecycle | updates | all recognized rotations |
| `client-windows-update-supplemental` | `ReportingEvents.log`, CBS/DISM artifact only when explicitly captured | OS update corroboration | updates | declared separately; never assume present |

Paths for candidate discovery are platform/native concerns. Current client operational candidate roots include `%WINDIR%\\CCM\\Logs`, `%WINDIR%\\ccmsetup\\Logs`, and explicitly supplied alternate/cached paths. The pure catalog sees only artifact metadata and a basename; it does not reconstruct or assume a path.

### Deterministic artifact/rotation rules

- Capture order must be `(logical artifact ID, original path normalized for comparison, rotation rank, basename)` so bundle manifests are byte-stable for identical inputs.
- Rotation rank is `current`, then `.lo_`, then numeric/timestamped historical rotations in an explicitly documented oldest-to-newest or newest-to-oldest order. Choose one order, record it in the manifest, and normalize to chronological evidence ordering only after parsing timestamps.
- A same-basename collision from separate candidate roots must preserve a distinct `artifactId`/source-path fingerprint; it must never overwrite a file because the generic collector destination is filename-only.
- If a rotated fragment begins or ends mid-logical record, represent its coverage/parse boundary. It cannot emit a key, phase transition, or terminal finding by itself.
- Candidate access denied, cap reached, decoding failure, unsafe reparse point, or user-disabled optional source maps to a distinct SCCM capture state. It must not be recast as generic `Failed` without detail.
- A missing default root can only prove that this discovery attempt did not find it. It cannot prove the ConfigMgr role/client is absent or unhealthy.

## Task 1: Establish #319's pure client intake catalog and fixture schema

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Create: `crates/cmtraceopen-parser/src/sccm/client/intake.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/mod.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/catalog.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_intake.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/README.md`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/intake/{complete,rotations,missing-root,access-denied,capped}/manifest.json`
- Create: matching `expected.json` and sanitized `evidence/` files for each nonempty scenario

**Consumes:** The #318 public artifact, coverage, source classification, evidence-ref, timestamp, and schema-version contracts.

**Produces:** A pure `assess_client_intake` API that describes what an already-supplied bundle covers; it neither reads from disk nor diagnoses a workflow.

- [ ] **Step 1: Write the five intake fixture tests before creating client code**

Write focused tests that deserialize the fixture manifest through the public SCCM bundle reader and assert these exact outcomes:

  - `complete`: all baseline health/policy/deployment/update source groups are `Captured`; output has zero absence-caused finding requests.
  - `rotations`: `AppEnforce.log`, `AppEnforce.log.lo_`, and `AppEnforce.log.2` map to one logical client-app-enforce group with three ordered fragments and no filename collision.
  - `missing-root`: no client root is discovered; every expected source group gets `Absent` and only an intake/coverage assessment, never "client not installed".
  - `access-denied`: `client-policy-agent` is `AccessDenied`; policy readiness reports a bounded request for that group and does not emit a policy-failure diagnosis.
  - `capped`: `client-content` is `Capped`; deployment readiness remains insufficient even when a retained tail contains an error-looking record.

Use direct assertions rather than snapshots that silently bless new fields:

~~~rust
#[test]
fn rotated_client_artifacts_have_one_logical_group_and_stable_lineage() {
    let intake = load_client_intake_fixture("rotations");
    let group = intake.group("client-app-enforce").expect("group is catalogued");
    assert_eq!(group.coverage, SccmCoverageState::Captured);
    assert_eq!(group.fragments.len(), 3);
    assert_eq!(group.fragments[0].rotation, SccmRotation::Current);
    assert_eq!(group.fragments[1].rotation, SccmRotation::LoUnderscore);
    assert_eq!(group.fragments[2].rotation, SccmRotation::Numbered(2));
}
~~~

- [ ] **Step 2: Run only the new test target and record its red failure**

Run:

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
~~~

Expected: FAIL because the `sccm::client` module, client-source groups, and fixture loader support do not exist. Do not implement any native discovery to make this green; the test must remain pure.

- [ ] **Step 3: Add the pure catalog and intake projection**

Define the client catalog in one location, preferably a table of `SccmSourceCatalogEntry` values extended in `sccm/catalog.rs`. Each entry declares logical artifact ID, role, artifact family, accepted basenames, workflow consumers, capture requiredness, and supported rotation names. `client/intake.rs` must:

  1. normalize a supplied artifact basename and rotation without inspecting a path;
  2. match only catalogued client basenames;
  3. group captured fragments by logical artifact ID;
  4. retain unknown artifact entries as unknown/unsupported evidence rather than dropping them;
  5. compute group coverage as the most limiting meaningful state, while preserving every fragment state in the result;
  6. return stable sorted groups and coverage gaps.

Do not implement source discovery, filename globbing, or a new parser in this step. The source catalog must map `ccmsetup` separately from operational `CCM\\Logs` sources; `ccmsetup` is not a substitute for client operational logs.

- [ ] **Step 4: Make tests green and add negative contract tests**

Add assertions that:

  - `CustomVendorHook.log` is represented as unsupported/unknown and does not become a client-policy log;
  - a `.lo_` suffix is recognized only as a rotation of its explicit base name;
  - a file named `PolicyAgent.log.backup` is not silently treated as a known rotation;
  - different source paths containing an identical basename remain separate fragments;
  - reordering manifest artifacts gives byte-identical serialized assessment output.

Run:

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
~~~

Expected: PASS.

- [ ] **Step 5: Commit the pure intake contract in isolation**

~~~bash
git add crates/cmtraceopen-parser/src/sccm crates/cmtraceopen-parser/tests/sccm_client_intake.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client
git commit -m "feat(sccm): define client intake coverage contract"
~~~

Do not include `src-tauri` changes in this commit. Link the exact fixture matrix and test command in #319 after review.

## Task 2: Implement #319 native bounded client discovery and SCCM manifest v1

**Files:**

- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/lib.rs`
- Create: `src-tauri/src/sccm/mod.rs`
- Create: `src-tauri/src/sccm/intake.rs`
- Create: `src-tauri/src/sccm/bundle.rs`
- Create: `src-tauri/src/sccm/manifest.rs`
- Create: `src-tauri/tests/sccm_client_intake.rs`
- Modify only if a proven shared helper is necessary: `src-tauri/src/esp/discovery.rs`

**Consumes:** The pure #319 catalog/coverage contract and native bounded discovery primitives in `src-tauri/src/esp/discovery.rs` as an internal reference.

**Produces:** A native, feature-gated client capture adapter that writes a versioned SCCM manifest without changing generic collection semantics or creating a Tauri UI command.

- [ ] **Step 1: Write temp-directory discovery/manifest failures first**

Add `[[test]]` to `src-tauri/Cargo.toml`:

~~~toml
[[test]]
name = "sccm_client_intake"
required-features = ["sccm-diagnostics"]
~~~

Add the feature as an opt-in native feature (`sccm-diagnostics = []` initially; add dependencies only when a tested implementation requires them). Test with a fake discovery input rooted in a temporary directory, never `C:\\Windows`:

  1. captures current, `.lo_`, and numeric rotated files into collision-safe relative bundle paths;
  2. serializes `sccmManifestVersion: 1`, host/role/source path/rotation/capture state/byte count for every expected artifact;
  3. emits `Absent`, `AccessDenied`, `Capped`, and `Skipped` in the SCCM extension with deterministic ordering;
  4. rejects a symlink/reparse target escaping the supplied discovery root;
  5. maps a legacy generic manifest's `collected`, `missing`, and `failed` values only to documented legacy-compatible views, preserving an "unknown detail" gap for failed.

- [ ] **Step 2: Prove the tests fail before adding native module code**

Run:

~~~bash
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
~~~

Expected: FAIL due to missing feature/test/module surface. If the test cannot compile because the feature is unknown, add only the Cargo feature/test registration, rerun, and retain the next missing-symbol failure as the red state.

- [ ] **Step 3: Add narrowly-scoped native discovery and writing APIs**

Implement the following native-only responsibilities:

~~~rust
pub fn discover_client_sources(
    input: &SccmClientDiscoveryInput,
) -> SccmClientDiscoveryResult;

pub fn capture_client_bundle(
    request: &SccmClientCaptureRequest,
) -> Result<SccmClientCaptureResult, AppError>;

pub fn write_sccm_manifest_v1(
    bundle_root: &Path,
    manifest: &SccmBundleManifestV1,
) -> Result<(), AppError>;
~~~

`SccmClientDiscoveryInput` must expose candidate roots, a maximum file count/bytes per logical source, an allow-listed source catalog view, and a testable access-status provider. It must not read arbitrary paths passed from the frontend. Resolve/canonicalize each candidate root before enumerating it, reject a path outside the approved root, and preserve the original configured path only as privacy-classified manifest provenance.

The writer must use a dedicated file such as `sccm-manifest.json` or an additive namespaced object recognized by a versioned reader. Do not modify `src-tauri/src/collector/manifest.rs` to add new enum meanings unless a separate compatibility PR first expands generic result models and all existing consumers. The SCCM bundle's evidence layout must preserve logical source ID and unique fragment identity, for example:

```text
evidence/sccm/client/client-app-enforce/current/AppEnforce.log
evidence/sccm/client/client-app-enforce/lo/AppEnforce.log.lo_
evidence/sccm/client/client-app-enforce/numbered-2/AppEnforce.log.2
```

- [ ] **Step 4: Verify deterministic capture and existing native regression behavior**

Run:

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test esp_diagnostics_sources --all-features
cargo test --locked -p cmtrace-open --test parser_expanded_corpus --all-features
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
git diff --check
~~~

Expected: PASS on the development host for temp-directory behavior. The ESP suite remains a regression signal; do not move SCCM tests into its large source file.

- [ ] **Step 5: Commit native intake separately and write the live-lab validation checklist**

~~~bash
git add src-tauri/Cargo.toml src-tauri/src/lib.rs src-tauri/src/sccm src-tauri/tests/sccm_client_intake.rs
git commit -m "feat(sccm): capture bounded client diagnostic bundles"
~~~

Before a Windows client run, record in #319 or its linked validation checklist: ConfigMgr client version, Windows version, client install path if non-default, selected candidate roots, capture limit, time zone, intentionally generated lab workflow, and redaction proof. Do not capture production/customer evidence just to make a fixture.

## Task 3: Validate #319 on a Windows SCCM Client without making the lab a blocker

**Files:**

- Create: `docs/sccm/validation/client-intake-lab-checklist.md`
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/README.md` only with sanitized observed-version notes
- Modify: GitHub issue #319 after validation evidence exists

**Consumes:** #319 pure and native passing tests, an authorized development SCCM Client, and a consciously selected synthetic scenario.

**Produces:** Reproducible collection validation evidence; no parser behavior change unless a sanitized, independently reproducible discrepancy warrants a follow-up issue.

- [ ] **Step 1: Create a checklist before connecting to the lab**

The checklist must require confirmation of these read-only facts before capture:

  - client host is a development/test machine and not a customer endpoint;
  - ConfigMgr client version and site code are recorded in a sanitized form;
  - expected client root(s) and alternate paths are observed, not assumed;
  - no credentials, enrollment tokens, certificates, live user context, or secret-bearing command output are in the selected bundle;
  - bundle size/file limits and the rationale are recorded;
  - a synthetic policy, deployment, or update workflow is chosen only if it is safe in the lab;
  - temporary captured evidence location and retention/disposal owner are documented.

- [ ] **Step 2: Run the native capture in dry-run/discovery mode first**

Use the native API or a narrowly scoped test harness to list discovered candidates and predicted coverage without copying files. Compare candidate names and rotations to the catalog. A source missing from its expected default root is a discovery result to record, not a code defect until a configured/observed path proves it should be captured.

- [ ] **Step 3: Capture one bounded synthetic scenario and verify manifest facts**

Assert manually and with a test harness that the written manifest retains source group, role `client`, relative path, original basename, coverage state, rotation, byte count, collection time, and redacted/no-sensitive provenance. Confirm distinct same-name files do not overwrite one another. Confirm a deliberately unreadable test path yields `AccessDenied` or a documented simulation outcome rather than `Missing`.

- [ ] **Step 4: Convert only sanitized minimal evidence into fixtures**

Copy no lab log wholesale. Reduce each approved scenario to the smallest synthetic records that demonstrate the contract. Preserve line/rotation/timestamp relationships, replace identity values consistently, and add a fixture README stating that all values are synthetic. Rerun the parser suite after the fixture is committed.

- [ ] **Step 5: Report the gate outcome accurately**

Post a #319 comment with OS/ConfigMgr version family, source catalog confirmation, test commands, manifest schema version, coverage states exercised, redaction result, and any unvalidated path/rotation behavior. If native Windows validation cannot run yet, leave #319 open with pure/native temp-directory tests green; do not claim real capture acceptance.

## Task 4: Implement #320 client setup, health, identity, and location analysis

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/health.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_health.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/health/{success,setup-failure,identity-failure,no-site-or-mp,transport-failure,rotation-boundary,incomplete}/manifest.json`
- Create: matching `evidence/` and `expected.json` assets

**Consumes:** #318 normalized evidence/signals/keys/findings and #319 source groups `client-ccmsetup`, `client-evaluation`, `client-identity`, and `client-location`.

**Produces:** A health/location state machine that identifies the last evidenced good hop and requests the next smallest client artifact when setup, identity, site assignment, MP location, or transport evidence is absent.

### Health state contract

```text
Setup -> Service -> Identity -> SiteAssignment -> ManagementPoint -> Transport
```

`Setup` means the client installation/bootstrap record is evidenced, not merely that `ccmsetup.log` exists. `Service` means a service/evaluation/restart observation is evidenced. `Identity` means a client identity/registration outcome is evidenced. `SiteAssignment` and `ManagementPoint` require their own client-location evidence. `Transport` requires a completed request/response or a terminal transport error for the same validated key/context. Do not infer site/MP success from a hostname-shaped string in unrelated message text.

- [ ] **Step 1: Add behavior-first health tests**

Create one test per fixture and assert exact phase/class/confidence/evidence/next request. Minimum cases:

  - a complete setup-to-transport sequence returns no failure finding and records `Transport` as last successful;
  - a setup terminal error creates `ConfirmedFailure` only if terminal evidence is present and no later successful bootstrap proves recovery;
  - identity registration failure is not mislabeled as MP failure;
  - missing/empty `ClientLocation.log` after an evidenced identity requests the location artifact and yields `InsufficientEvidence`;
  - no site/MP evidence returns a bounded `SiteAssignment` or `ManagementPoint` gap, not an assertion that the client is unassigned;
  - a same-minute generic network error with no validated request/host key creates only a low-confidence symptom;
  - a record split across rotations cannot advance or fail the state machine.

Use a failing public call first:

~~~rust
let result = analyze_client_health(&load_bundle("health/no-site-or-mp"));
assert_eq!(result.last_successful_phase, Some(SccmPhase::Identity));
assert_eq!(result.findings[0].class, SccmFindingClass::InsufficientEvidence);
assert_eq!(result.findings[0].next_artifacts[0].logical_artifact_id, "client-location");
~~~

- [ ] **Step 2: Run the health target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_health
~~~

Expected: FAIL because `health.rs` and its state transitions do not exist.

- [ ] **Step 3: Implement a finite, evidence-first reducer**

Use a private ordered reducer over `SccmEvidence` that accepts catalogued source groups only. It may advance a phase on a positive, profile-validated record; it may mark a terminal failure only on a profile-validated terminal record; it must keep alternative/contradictory records as evidence. Do not use a single mutable global "client health" state across artifacts. Sort records by resolved UTC only when timestamp provenance permits it; otherwise retain source-local order and lower cross-artifact confidence.

- [ ] **Step 4: Make the test target and general parser suite green**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_health
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
~~~

- [ ] **Step 5: Commit #320 without folding policy/deployment logic into it**

~~~bash
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/tests/sccm_client_health.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/health
git commit -m "feat(sccm): analyze client health and location evidence"
~~~

## Task 5: Implement #321 policy acquisition, evaluation, and reporting analysis

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/policy.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_policy.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/policy/{complete,request-auth-failure,download-failure,persist-failure,scheduler-deferred,evaluation-failure,reporting-failure,rotation-split,malformed,incomplete}/{manifest.json,expected.json,evidence/}`

**Consumes:** Client policy source groups, #318 versioned assignment/client/site/request keys, #320 health/location findings only as a cited prerequisite—not as a replacement for policy evidence.

**Produces:** Per-policy/assignment transaction analysis across request, download, persist, schedule, evaluate, and report phases.

### Policy state contract

```text
Request -> Download -> Persist -> Schedule -> Evaluate -> Report
```

An assignment transaction exists only with an exact/validated assignment or policy key, or a deliberately declared keyless single-artifact local observation that is forced to low confidence and cannot be correlated later. Do not collapse all policy messages into one device-wide transaction. The analyzer must preserve a `Deferred` state separately from terminal failures—for example, a scheduler wait is not a failed evaluation.

- [ ] **Step 1: Write failing transaction tests for all policy terminal classes**

For each scenario, assert transaction ID, last success, state, class, evidence refs, and next artifact request. Include:

  - complete policy flow with no failure;
  - request authentication/transport failure with a requested `client-location` artifact if location coverage is missing;
  - transfer/download failure with no unsupported inference about MP behavior;
  - persistence failure with a terminal client record;
  - scheduler deferred / maintenance or retry state as `BlockedOrDeferred`, not `ConfirmedFailure`;
  - evaluation failure after an evidenced schedule;
  - reporting failure after successful evaluation;
  - rotation-split correlation key that cannot create a policy transaction;
  - malformed or unknown-version policy message that retains a low-confidence symptom and requests a bounded source;
  - missing state/report artifact produces explicit coverage rather than "policy succeeded".

- [ ] **Step 2: Run #321 tests red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_policy
~~~

Expected: FAIL before `analyze_client_policy` exists.

- [ ] **Step 3: Implement keyed, isolated policy reducers**

Group evidence by `AssignmentId`/policy ID only when `SccmKeyConfidence` satisfies the profile's exact/strong threshold. For each group, order the safe evidence timeline, advance the phase monotonicly, preserve retries as repeated observations, and emit a single final transaction state. A later explicit success may supersede an earlier terminal-looking record only when it has the same validated key and coherent evidence ordering; otherwise produce contradictory/low-confidence evidence, not silent recovery.

Construct findings through the #318 builder. A high-confidence failure needs terminal or corroborating evidence. Any partial group must generate the smallest source request from the policy source catalog: `client-policy-agent` for missing request/download/persist/schedule records; `client-policy-state` for missing evaluate/report state.

- [ ] **Step 4: Add deterministic and false-causality regression cases**

Assert that reordering artifacts produces identical serialized analysis; an unrelated client policy error with an unrelated assignment does not affect the target transaction; same timestamps with different keys stay separate; client-only output never claims an MP-side root cause; and absent ConfigMgr version cannot create an exact extracted key.

Run:

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_policy
cargo test --locked -p cmtraceopen-parser --test sccm_client_health
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
~~~

- [ ] **Step 5: Commit the policy slice and document the #333 handoff**

~~~bash
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/tests/sccm_client_policy.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/policy
git commit -m "feat(sccm): analyze client policy transactions"
~~~

In #321, record the validated policy keys/version profile and explicitly link its output contract as a prerequisite for #333 policy-to-MP correlation. Do not implement MP rules here.

## Task 6: Implement #322 application, package, and content deployment analysis

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/deployment.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_deployment.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/deployment/{success,not-targeted,requirements-failure,dependency-failure,location-missing,dp-content-missing,bits-transfer-failure,cache-failure,enforcement-exit,detection-false-negative,rotation-boundary,incomplete}/{manifest.json,expected.json,evidence/}`

**Consumes:** Client app/content groups, versioned assignment/CI/package/content/DP/BITS/product/exit keys, and shared signal extraction. Existing MSI/PSADT/Burn parser outputs may be attached only as separately classified supplemental artifacts.

**Produces:** Per-deployment transaction analysis that distinguishes target/intent, requirements/dependencies, location/content, transfer/cache, enforcement, detection, and state reporting.

### Deployment state contract

```text
Intent -> Requirements -> LocateContent -> Transfer -> Cache -> Enforce -> Detect -> Report
```

The transaction key priority is: exact assignment+CI, then exact package/content with a corroborating assignment/CI, then a bounded local candidate with low confidence. Do not key a deployment by filename, `AppEnforce` component, deployment display name, or time alone. `NotTargeted` is a classification only when explicit policy/intent evidence says the assignment is not applicable; a missing intent log is insufficient evidence.

- [ ] **Step 1: Write the deployment fixture tests before the reducer**

Assert these outcomes:

  - success retains final detected/reported evidence and no failure;
  - explicit not-targeted is not a failure and does not request DP evidence;
  - requirement/dependency failure stops before location and does not call it a download issue;
  - missing content location request is client-side insufficient evidence unless an exact client content error is terminal;
  - an exact content/DP request with a missing client content response is a `LocateContent` gap, not a DP diagnosis;
  - BITS/transfer failure cites transfer evidence and preserves the BITS signal/key;
  - cache failure remains distinct from transfer failure;
  - enforcement nonzero exit code is a symptom until terminal app-enforcement/result record corroborates it;
  - a detected-state mismatch after enforcement is a detection result, not an installation root cause;
  - malformed/rotation-split or incomplete source coverage yields low confidence/next artifacts;
  - an MSI, PSADT, or Burn supplemental artifact may enrich a same-key client deployment but cannot override the SCCM phase absent a stable key.

- [ ] **Step 2: Run the focused target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_deployment
~~~

Expected: FAIL because deployment source grouping and reducer do not exist.

- [ ] **Step 3: Implement source-local facts, then keyed reducer composition**

In `deployment.rs`, make small private functions that extract facts from each source family (intent, discovery, enforcement, content location, transfer, cache, supplemental installer). Each fact retains `SccmEvidenceRef`, exact keys, phase candidate, and terminality. Compose facts into transactions only after the #318 key/profile check succeeds. Do not allow a generic error token from `DataTransferService.log` to attach to every app deployment.

Use stable sorted `BTreeMap`/sort keys. Preserve parallel deployments as separate transactions. When an artifact has only an unsafe candidate key, expose it as a low-confidence unlinked symptom and request the minimum related source, not a broad "collect all SCCM logs" request.

- [ ] **Step 4: Verify independent and shared contracts**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_deployment
cargo test --locked -p cmtraceopen-parser --test sccm_client_policy
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
~~~

- [ ] **Step 5: Commit #322 and preserve the server handoff boundary**

~~~bash
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/tests/sccm_client_deployment.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/deployment
git commit -m "feat(sccm): analyze client deployment and content evidence"
~~~

Update #322 with its client-only limitations. The only #333 handoff is stable cited client content/DP keys plus phase facts; no statement about a distribution point cause belongs in #322.

## Task 7: Implement #323 software-update analysis

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/updates.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_updates.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/updates/{success,no-sup,scan-failure,evaluation-failure,content-failure,maintenance-window,reboot-pending,install-failure,reporting-failure,supplemental-conflict,incomplete}/{manifest.json,expected.json,evidence/}`

**Consumes:** Client update sources, shared versioned update/KB/CI/content/SUP/job keys, and optional separately captured CBS/DISM/ReportingEvents artifacts.

**Produces:** Per-update transaction analysis that identifies the last proven stage from scan through report, while keeping ConfigMgr client evidence separate from Windows servicing supplemental evidence.

### Update state contract

```text
Scan -> Evaluate -> LocateSup -> Download -> MaintenanceWindow -> Install -> Reboot -> Report
```

`LocateSup` means the client has an evidenced SUP/location interaction; it does not prove the SUP server was healthy. `MaintenanceWindow` and `Reboot` are blocked/deferred outcomes unless terminal evidence proves a failure. CBS/DISM/ReportingEvents can corroborate an install/reboot outcome only when source provenance and a stable update/KB/CI key permit it. Their presence cannot turn a client-only update flow into a server diagnosis.

- [ ] **Step 1: Write failing fixture tests for each update branch**

Required scenarios:

  - full success with report;
  - no SUP/location evidence after scan/evaluate requests the appropriate client source and returns insufficient evidence;
  - scan failure;
  - evaluation failure;
  - content/download failure;
  - maintenance-window delay is `BlockedOrDeferred` with its next time/context evidence requested only if absent;
  - reboot-pending is `BlockedOrDeferred`, not install failure;
  - terminal install failure with exact update key;
  - reporting failure after install success;
  - contradictory CBS/DISM supplemental evidence with no exact key remains a low-confidence symptom;
  - incomplete/malformed rotation coverage produces no cause.

- [ ] **Step 2: Run the update test target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_updates
~~~

Expected: FAIL before the update reducer exists.

- [ ] **Step 3: Implement keyed update fact extraction and phase reduction**

Use source-specific fact extractors for `ScanAgent`, `WUAHandler`, `UpdatesDeployment`, `UpdatesHandler`, and `UpdatesStore`. Only attach supplemental windows-servicing facts after the update/KB/CI key match and source/version profile requirements have passed. Model overlapping updates separately. A signal code alone can describe a terminal error only when the source-specific update fact recognizes a terminal status; the generic #318 signal extractor cannot decide this for the reducer.

- [ ] **Step 4: Add conservative ordering/coverage regressions and run gates**

Add tests that invalid/missing offset disallows cross-artifact high confidence, multiple updates in the same minute do not merge, an absent SUP-log counterpart does not blame a server, and artifact input order does not alter JSON output.

Run:

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_updates
cargo test --locked -p cmtraceopen-parser --test sccm_client_deployment
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
~~~

- [ ] **Step 5: Commit #323 independently**

~~~bash
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/tests/sccm_client_updates.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/updates
git commit -m "feat(sccm): analyze client software update transactions"
~~~

The #323 completion comment must list the validated client-only update keys and note that server SUP correlation remains deferred until #330 and #333 validate a pairwise contract.

## Task 8: Run the client-core release gate and issue evidence pass

**Files:**

- Modify: `crates/cmtraceopen-parser/README.md` only if the implemented public API requires a concise SCCM Client usage example
- Modify: GitHub issues #319–#323 with completion/test/fixture evidence

**Consumes:** All prior tasks in this plan, the #318 contract suite, and available development client validation information.

**Produces:** Review-ready individual issue evidence with a clear list of unvalidated live-Windows behaviors.

- [ ] **Step 1: Execute focused parser and native suites**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
cargo test --locked -p cmtraceopen-parser --test sccm_client_health
cargo test --locked -p cmtraceopen-parser --test sccm_client_policy
cargo test --locked -p cmtraceopen-parser --test sccm_client_deployment
cargo test --locked -p cmtraceopen-parser --test sccm_client_updates
cargo test --locked -p cmtraceopen-parser
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test esp_diagnostics_sources --all-features
cargo test --locked -p cmtrace-open --test parser_expanded_corpus --all-features
~~~

- [ ] **Step 2: Execute compilation, style, and compatibility gates**

~~~bash
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
cargo fmt --check --all
git diff --check
~~~

- [ ] **Step 3: Inspect the shipped JSON contracts deliberately**

For one success, one terminal failure, one deferred, and one incomplete fixture per workflow, serialize the public analysis and inspect: camelCase names; schema version; deterministic array order; bounded requested artifacts; evidence IDs; no raw context/user/path beyond approved redaction; no server causal wording; and no unknown signal loss. Remove any temporary debug output before committing.

- [ ] **Step 4: Post issue-specific evidence rather than a generic program update**

For #319, post catalog version, manifest schema, rotation/collision/access/cap scenarios, Windows validation state, and exact tests. For #320–#323, post source groups, state phases, fixture scenario names, version profiles/keys, expected conservative behavior, exact tests, and the next correlation prerequisite. Leave an issue open whenever its Windows/native acceptance gate or an explicit required fixture remains incomplete.

- [ ] **Step 5: Use review boundaries, not a mega-PR**

Keep one PR/commit series per issue (or split pure/native portions of #319). Request review of #318 contract compatibility before #319; request a separate false-causality review for #321/#322/#323 transactions. Never close #319–#323 merely because the code compiles: every closure needs the linked test corpus and the defined exit conditions below.

## Per-Issue Exit Criteria

### #319 Client intake

- [ ] Pure catalog handles all listed client groups, unknown source names, current/.lo_/numbered/timestamped rotations, and deterministic ordering.
- [ ] Native SCCM manifest v1 preserves group/role/path/host/rotation/state/size provenance without changing generic manifest semantics.
- [ ] Collision, absent, access-denied, capped, skipped, unsafe-path, and legacy mapping tests pass.
- [ ] Windows client validation is either recorded passing with a sanitized lab artifact or explicitly listed as pending; no false claim of native acceptance.

### #320 Health/location

- [ ] Every phase has success, terminal failure, contradictory, and incomplete evidence tests.
- [ ] Findings cite exact evidence and last known good phase; no failure classification based solely on absence.
- [ ] Location/MP claims are client-side observations only until #333 validates cross-side evidence.

### #321 Policy

- [ ] Transactions are keyed conservatively and handle deferred/retry/contradictory/rotation cases.
- [ ] Request/download/persist/schedule/evaluate/report gaps request the smallest specific artifact group.
- [ ] Client-only policy findings do not assert an MP cause.

### #322 Deployment/content

- [ ] Intent/requirements/location/transfer/cache/enforce/detect/report phases remain distinct.
- [ ] Same-minute/multi-deployment/unkeyed installer cases do not merge or establish high confidence.
- [ ] Output contains the exact client keys/evidence #333 needs for future content-to-DP correlation, and no DP-side cause claim.

### #323 Updates

- [ ] Scan/evaluate/SUP-location/download/MW/install/reboot/report phases are distinct with all branch fixtures.
- [ ] Supplemental Windows servicing logs are strictly provenance/key gated.
- [ ] Client-only evidence does not assert SUP/server health; it names missing counterpart evidence when appropriate.
