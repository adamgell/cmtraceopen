# SCCM Server Intake and Core Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Deliver issues #335, #327, #328, #329, and #330 as a role-aware SCCM Server evidence bundle plus site-core/status, Management Point, Distribution Point/content, and Software Update Point/WSUS diagnostics.

**Architecture:** The parser crate classifies supplied server artifacts and reduces role-local evidence into transactions/findings using the shared #318 contracts. The native backend discovers configured/observed server roles and bounded candidate sources, writes a versioned SCCM server manifest, and preserves role/topology/provenance. No analyzer assumes a default server path proves a role exists; no client/server causality is claimed until #333 consumes validated pairs.

**Tech Stack:** Rust 1.88, cmtraceopen-parser, cmtrace-open, serde/serde_json, existing CCM parser and IIS parser, current generic collector only as a compatibility reference, Windows Server SCCM development environment for native capture acceptance, synthetic fixture corpus.

## Global Constraints

- #318 is the parser/API prerequisite. #335 is the intake prerequisite for #327–#330. #319 client intake may proceed in parallel but is not a substitute for server evidence.
- This plan covers server intake/site core/MP/DP/SUP only. It does not cover hierarchy/replication, Provider/Admin Service, advanced roles, UI workspaces, or cross-side diagnosis.
- SCCM server log formats still use raw parser families such as CCM and IIS W3C. Do not add an SCCM ParserKind, duplicate CCM framing, or make every server role a parser implementation.
- The pure parser crate stays free of filesystem, registry, WMI, IIS configuration, SQL, service-control, event-log, network, and Tauri dependencies. Those belong exclusively in the native collector adapter.
- Existing generic ArtifactStatus has three serialized values. Do not change it or overload it with server role/coverage semantics in this plan; use an additive, versioned SCCM server manifest schema/extension and a documented tolerant reader.
- Capture state must preserve Captured, Absent, AccessDenied, Capped, Skipped, Unsupported, and ParseFailed separately. A default candidate root not found is Absent for that candidate—not proof that the role is absent, unhealthy, or uninstalled.
- Preserve server host, role, configured source path, source version, rotation lineage, collection time, encoding, and byte limit provenance. Artifact basename and CCM file= code-origin attribute are distinct and must stay distinct.
- Collections must preserve distinct log/rotation paths; the generic collector's filename-only destination cannot be used where two role logs could collide.
- Analyze only complete logical records. A partial first/last rotation record, malformed record, unknown profile version, or invalid timestamp offset may create a coverage/parse gap or low-confidence symptom, never a terminal role diagnosis.
- Findings name the last evidenced good hop and a bounded next artifact request. An error-looking server record alone cannot establish a root cause for a client.
- The new SCCM Server dev environment is a validation source, not a blocker. Parser/corpus work proceeds against synthetic inputs. Native acceptance remains pending until the lab is authorized and exercised.
- Never commit live site names, host names, users, domain names, certificates, URLs, database names, package IDs, client identifiers, credentials, or customer logs. Use LAB-CM01, LAB-MP01, LAB-DP01, the three-character site code LAB, and synthetic keys.

---

## Issue Sequencing

| Issue | Deliverable | Must follow | Can proceed in parallel with | Unlocks |
| --- | --- | --- | --- | --- |
| #335 | Server source catalog, role/topology manifest, bounded capture, pure intake | #318 | #319 | #327–#334 |
| #327 | Site core/component/status transactions | #335 | #328/#329 analysis implementation after source contract | Server role health vocabulary |
| #328 | MP request/auth/registration/policy/location transactions | #335; #327 findings may enrich but do not block | #329 | #333 policy-to-MP pair after #321 |
| #329 | DP/package/content distribution transactions | #335 | #328/#330 | #333 content-to-DP pair after #322 |
| #330 | SUP/WSUS synchronization/health transactions | #335 | #327–#329 | later update/SUP pair after #323 |

Land #335 as pure catalog/manifest reader first, then native capture in a separate commit if possible. #327 establishes site/role status vocabulary and should be reviewed before declaring a downstream role unavailable. #328 and #329 may develop from frozen server intake fixtures in parallel. #330 is server-local: do not force it to wait for client update analysis or server correlation.

## File Structure and Ownership

~~~text
crates/cmtraceopen-parser/
├── src/sccm/
│   ├── mod.rs
│   ├── models.rs                    # #318 shared wire models only
│   ├── catalog.rs                   # shared source/role catalog primitive
│   └── server/
│       ├── mod.rs                   # server public façade
│       └── windows/
│           ├── mod.rs
│           ├── catalog.rs           # server role/source/bundle declaration; no I/O
│           ├── intake.rs            # manifest/artifact classification + coverage
│           ├── site_core.rs         # #327
│           ├── management_point.rs  # #328
│           ├── distribution_point.rs# #329
│           └── software_update_point.rs # #330
├── tests/
│   ├── sccm_server_intake.rs
│   ├── sccm_server_site_core.rs
│   ├── sccm_server_management_point.rs
│   ├── sccm_server_distribution_point.rs
│   ├── sccm_server_software_update_point.rs
│   └── fixtures/sccm/server/
│       ├── README.md
│       ├── intake/<scenario>/{manifest.json,evidence/,expected.json}
│       ├── site_core/<scenario>/{manifest.json,evidence/,expected.json}
│       ├── management_point/<scenario>/{manifest.json,evidence/,expected.json}
│       ├── distribution_point/<scenario>/{manifest.json,evidence/,expected.json}
│       └── software_update_point/<scenario>/{manifest.json,evidence/,expected.json}

src-tauri/
├── Cargo.toml
├── src/sccm/
│   ├── mod.rs
│   ├── bundle.rs                    # shared SCCM bundle layout/types from #319
│   ├── manifest.rs                  # schema v1 reader/writer; extend compatibly
│   └── collector/
│       ├── mod.rs
│       ├── discovery.rs             # Windows/configured-role discovery only
│       ├── engine.rs                # bounded capture/collision-safe layout
│       └── manifest.rs              # server manifest projection, not generic manifest mutation
├── tests/sccm_server_collection.rs
scripts/collection/
└── sccm-server-evidence-profile.json             # only if a script profile is shipped
references/collection/
└── sccm-server-evidence-profile.json             # byte-for-byte parity with scripts copy
~~~

If #319 has already created src-tauri/src/sccm/{intake.rs,bundle.rs,manifest.rs}, reuse those stable types instead of creating a parallel client/server manifest representation. Put Windows-only server role discovery in collector/discovery.rs, behind the same sccm-diagnostics feature or a carefully additive sccm-server-diagnostics feature. Do not wire a desktop command or dedicated workspace in this plan unless the issue explicitly requires a tested callable capture entry point; a native library function is sufficient for the first server capture contract.

## Server Bundle/Manifest Contract

The server manifest needs enough information to interpret evidence without querying the lab again. The top-level schema is versioned independently from generic collection manifests:

~~~json
{
  "sccmManifestVersion": 1,
  "bundleRole": "server",
  "topology": {
    "captureHost": "LAB-CM01",
    "rolesObserved": ["siteServer", "managementPoint"],
    "siteCode": "LAB"
  },
  "artifacts": [{
    "artifactId": "server-mp-get-policy",
    "role": "managementPoint",
    "sourceKind": "ccmLog",
    "originalPath": "REDACTED",
    "originalBasename": "MP_GetPolicy.log",
    "configuredPath": true,
    "rotation": {"kind": "current"},
    "captureState": "captured",
    "sourceVersion": "5.00.TEST",
    "collectedUtc": "2026-07-30T00:00:00Z",
    "relativePath": "evidence/sccm/server/management-point/mp-get-policy/current/MP_GetPolicy.log",
    "bytesCopied": 1024
  }]
}
~~~

A redacted public export may omit/transform captureHost/paths but must retain role, source ID, capture state, rotation, artifact identity, and an opaque stable handle when correlation needs it. The pure reader must deserialize manifest fields in stable order and map legacy generic artifacts only when their role/source provenance is explicitly supplied; it must not invent a management-point role from a filename alone.

## Initial Source Catalog and Requiredness

These are curated candidate groups—not promises that a role or source exists in every installation. Each entry carries role, source parser family, workflow consumers, default requiredness for an incident bundle, rotation behavior, and whether it is an optional supplemental source.

| Logical artifact | Candidate basenames | Role | Workflow use | Collection rule |
| --- | --- | --- | --- | --- |
| server-sitecomp | sitecomp.log, hman.log, component manager status sources | site server | #327 | current + known rotations; role candidate |
| server-status | statmgr.log, statesys.log, curated status/state sources | site server | #327 | current + known rotations |
| server-mp-auth | MP_GetAuth.log, MP_CliReg.log, MP_RegistrationManager.log | MP | #328 | current + known rotations |
| server-mp-policy | MP_GetPolicy.log, MP_Location.log, mpcontrol.log | MP | #328 | current + known rotations |
| server-mp-iis | catalogued IIS W3C logs or explicitly captured MP web logs | MP | #328 supplemental | optional; no broad IIS tree |
| server-dp-distribution | distmgr.log, PkgXferMgr.log, SMSDPProv.log, PullDP.log when observed | DP/site server | #329 | current + known rotations |
| server-dp-serve | explicitly catalogued DP serving/status source | DP | #329 supplemental | optional until fixture proven |
| server-sup-sync | wsyncmgr.log, wcm.log, WSUSCtrl.log, SUPSetup.log | SUP/WSUS | #330 | current + known rotations |
| server-sup-wsus | explicitly scoped WSUS health/sync log source | SUP/WSUS | #330 supplemental | optional, bounded/capped |
| server-iis-status | curated IIS/status export when role discovery proves scope | MP/SUP/other | supplemental | skipped by default unless incident bundle asks |

The catalog must accept only declared basenames/rotations for a role. An artifact whose basename overlaps a client log is not a server artifact without role/provenance. Unknown artifacts are retained as unclassified/unsupported manifest evidence; they are not silently discarded or misclassified.

## Task 1: Implement #335 pure server catalog, manifest reader, and coverage assessment

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/mod.rs
- Create: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Create: crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs
- Create: crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs
- Modify: crates/cmtraceopen-parser/src/sccm/mod.rs
- Modify only for common catalog primitives: crates/cmtraceopen-parser/src/sccm/catalog.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_intake.rs
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/server/README.md
- Create: intake fixtures complete-multi-role, configured-nondefault-path, rotations, multiline, absent-dp, access-denied-mp, capped-sup, skipped-iis, unsupported-db-supplement, and unsorted-manifest

**Consumes:** #318 shared models, coverage/rotation/time/redaction/key contracts, and the public CCM logical-record path.

**Produces:** A pure assess_server_intake and normalize_server_bundle contract which classifies supplied artifacts by declared role/source and yields deterministic coverage. It does not enumerate server paths.

- [ ] **Step 1: Write the intake fixture tests before adding server code**

Test all fixture cases explicitly:

  - complete-multi-role recognizes site/MP/DP/SUP groups, their roles, paths, and all captured states;
  - configured-nondefault-path retains the configured/observed source provenance and never converts it to a missing default path;
  - rotations maps current, .lo_, numeric, and timestamped rotations with stable lineage and collision-safe source IDs;
  - multiline proves one framed CCM record produces one evidence record with a full line range/rotation provenance;
  - absent-dp emits DP coverage gaps but no “DP broken” finding;
  - access-denied-mp exposes MP access coverage and a bounded next request without a terminal MP diagnosis;
  - capped-sup prevents a truncated log tail from yielding terminal SUP health;
  - skipped-iis preserves an intentional optional source skip;
  - unsupported-db-supplement preserves unknown/unsupported metadata but cannot enter a role reducer;
  - unsorted-manifest results in byte-identical normalized intake output when artifacts are reordered.

- [ ] **Step 2: Run red before implementation**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
~~~

Expected: FAIL because server modules/catalog/manifest intake APIs do not exist.

- [ ] **Step 3: Add server source declarations and pure intake logic**

Create a declarative source table. Each entry must state logical ID, allowed role(s), candidate basenames, parser family, rotation parser, requiredness, incident bundles, and workflow consumers. intake.rs must:

1. verify SccmRole and artifact metadata compatibility;
2. classify known basename plus supported rotation, never a filename alone;
3. preserve configured-path and host/topology evidence;
4. group fragments by logical source and role;
5. retain every individual capture state and calculate workflow coverage without collapsing errors;
6. preserve unknown/unsupported sources separately;
7. call only shared logical-record normalization to construct evidence;
8. stable-sort by role/logical source/path fingerprint/rotation/basename.

Do not build a role health model or source discovery yet.

- [ ] **Step 4: Add backward/forward compatibility tests**

Add tests that a legacy generic manifest is accepted only as an explicitly incomplete server bundle when supplied through an adapter; absent SCCM fields remain gaps. Test unknown external enum strings/fields survive tolerant deserialization via a documented unknown form, where the #318 schema permits it. Test a Failed generic status does not falsely become AccessDenied, Capped, or ParseFailed.

- [ ] **Step 5: Make pure server intake green and commit it separately**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm crates/cmtraceopen-parser/tests/sccm_server_intake.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server
git commit -m "feat(sccm): define server intake coverage contract"
~~~

## Task 2: Implement #335 native role discovery, bounded capture, and server manifest writing

**Files:**

- Modify: src-tauri/Cargo.toml
- Modify: src-tauri/src/sccm/mod.rs
- Extend/reuse: src-tauri/src/sccm/bundle.rs, src-tauri/src/sccm/manifest.rs
- Create: src-tauri/src/sccm/collector/mod.rs
- Create: src-tauri/src/sccm/collector/discovery.rs
- Create: src-tauri/src/sccm/collector/engine.rs
- Create: src-tauri/src/sccm/collector/manifest.rs
- Create: src-tauri/tests/sccm_server_collection.rs
- Create only if a supported command-line collection profile is intentionally shipped: paired scripts/collection/sccm-server-evidence-profile.json and references/collection/sccm-server-evidence-profile.json

**Consumes:** Task 1 pure catalog/manifest schema plus current native sccm-diagnostics feature/bundle code. Existing ESP discovery can be reused only as a private bounded-path primitive after targeted tests.

**Produces:** A native library-level server capture adapter which discovers observed/configured roles safely, captures a bounded incident bundle, and writes deterministic SCCM server manifest v1.

- [ ] **Step 1: Write temporary-directory/native fake-discovery tests first**

Do not require the real lab to test behavior. Use a fake discovery provider and temp paths to prove:

  - role discovery returns an observed role/configured source candidate without asserting roles that were not observed;
  - configured non-default roots are collected when allow-listed;
  - current/.lo_/numbered/timestamped rotations map to unique bundle-relative paths;
  - two sources sharing a basename cannot overwrite one another;
  - file/byte caps produce Capped with a retained partial artifact record and no unsafe success claim;
  - access/provider failures produce AccessDenied or documented discovery error state;
  - reparse/symlink paths outside the allowed root are rejected;
  - results/manifests are deterministic despite concurrent collection;
  - server bundle writing does not alter existing generic manifest.json behavior or ESP tests;
  - if script profiles are shipped, scripts/ and references/ copies compare byte-for-byte.

- [ ] **Step 2: Run native test red**

~~~bash
cargo test --locked -p cmtrace-open --test sccm_server_collection --features sccm-diagnostics
~~~

Expected: FAIL because no server collector/test target/module exists. Add feature/test registration only as required to reach a missing-symbol test failure.

- [ ] **Step 3: Implement an explicit role-discovery boundary**

Define a testable provider interface or function boundary for read-only role/configuration discovery. It may read safe Windows role/configuration evidence where available, but must return observed facts/candidates with provenance and failure detail. It may not use a default path alone to set an observed role. The engine selects catalogued incident bundles (site core, MP, DP, SUP) and copies only allow-listed files under explicit per-artifact count/byte limits.

Use a collision-safe layout such as:

~~~text
evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log
evidence/sccm/server/management-point/server-mp-policy/current/MP_GetPolicy.log
evidence/sccm/server/distribution-point/server-dp-distribution/numbered-2/distmgr.log.2
~~~

The manifest writer owns role/topology/configuredPath/original basename/rotation/capture state fields. It must not mutate generic ArtifactResult meanings. Preserve original source path only through the approved redaction/provenance field, never in a public unsafe export.

- [ ] **Step 4: Run regressions and compile gates**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtrace-open --test sccm_server_collection --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test esp_diagnostics_sources --all-features
cargo test --locked -p cmtrace-open --test parser_expanded_corpus --all-features
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
git diff --check
~~~

- [ ] **Step 5: Commit native server capture separately and add the Windows lab checklist**

~~~bash
git add src-tauri/Cargo.toml src-tauri/src/sccm src-tauri/tests/sccm_server_collection.rs scripts/collection/sccm-server-evidence-profile.json references/collection/sccm-server-evidence-profile.json
git commit -m "feat(sccm): capture role-aware server evidence"
~~~

Only include script/reference files if they were actually added. Create docs/sccm/validation/server-intake-lab-checklist.md in its own documentation commit. It must record server version, site version, observed roles, configured paths, incident bundle chosen, capture limits, time zone, redaction method, and disposal/retention—not credentials or customer identifiers.

## Task 3: Implement #327 site core and status analysis

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/windows/site_core.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_site_core.rs
- Create fixtures: healthy, component-failure, inbox-backlog, status-processing-failure, recovery, contradictory, rotation-boundary, incomplete

**Consumes:** #335 server source groups server-sitecomp and server-status, #318 signals/keys/findings, and server topology provenance.

**Produces:** Role-local site component/status transactions and findings. It may qualify a later MP/DP/SUP observation but cannot diagnose an absent downstream role.

### State contract

~~~text
ComponentStart -> ComponentWork -> InboxOrQueue -> StatusOrStateProcessing -> HealthyOrTerminal
~~~

The concrete component identity is key/profile data; do not aggregate every site component into one device-wide health result. A backlog means observed pending work, not a root cause. A later successful status record can show recovery only for the same profile-validated component/transaction context.

- [ ] **Step 1: Write failing #327 fixtures**

Required outcomes: healthy completion; terminal component failure; inbox/queue backlog as symptom/deferred until terminal evidence; status/state processing failure; same-component recovery; unrelated same-minute component error; a rotation boundary that cannot form a terminal record; and missing site/status coverage. Each asserts last success, class/confidence, exact evidence, and bounded next artifact.

- [ ] **Step 2: Run target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_site_core
~~~

- [ ] **Step 3: Implement source-specific facts and component-keyed reducer**

Only profile-validated component/status IDs create component transactions. Persist unknown raw signals/evidence as symptoms. Require source-specific terminal facts for ConfirmedFailure; otherwise a backlog/error remains a symptom or likely contributor. Do not give #327 a client request ID or infer a client impact.

- [ ] **Step 4: Verify and commit**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_site_core
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server crates/cmtraceopen-parser/tests/sccm_server_site_core.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/site_core
git commit -m "feat(sccm): analyze site core status evidence"
~~~

## Task 4: Implement #328 Management Point analysis

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/windows/management_point.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_management_point.rs
- Create fixtures: healthy-policy, auth-failure, registration-failure, location-failure, policy-failure, iis-supplemental, unrelated-client-like-key, rotation-boundary, incomplete

**Consumes:** #335 MP source groups; #318 request/client/site/policy/host keys; optional #327 site-core result only as an independently cited context fact.

**Produces:** Server-local MP request/auth/registration/location/policy transactions, ready for but not performing #333 policy-to-MP matching.

### State contract

~~~text
ReceiveRequest -> Authenticate -> RegisterOrIdentify -> ResolveLocationOrPolicy -> Respond -> RecordOutcome
~~~

The transaction needs an exact profile-validated request/policy/client key and compatible MP topology. A server error near a client timestamp is not an MP transaction. IIS records are supplemental—the main MP implementation cannot require an arbitrary IIS log tree to return a conservative result.

- [ ] **Step 1: Write red fixture tests**

Test full healthy policy response; terminal auth failure; terminal registration failure; location failure; policy generation/response failure; missing optional IIS has no failure; a matching-looking but incompatible client ID/key does not attach; partial source coverage returns a precise MP artifact request; rotation physical fragment cannot create an authentication outcome.

- [ ] **Step 2: Run target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_management_point
~~~

- [ ] **Step 3: Implement facts/reducer with no client-cause claim**

Extract facts separately from MP_GetAuth, MP_CliReg/registration, MP_Location, MP_GetPolicy, mpcontrol, and catalogued supplemental IIS records. Group only exact validated keys. Use bounded role-local findings and surface counterpart-ready keys/evidence refs. If client identity is privacy-classified, use the #318 safe handle in a key only when its correlation rules permit it.

- [ ] **Step 4: Verify and commit**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_management_point
cargo test --locked -p cmtraceopen-parser --test sccm_server_site_core
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server crates/cmtraceopen-parser/tests/sccm_server_management_point.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/management_point
git commit -m "feat(sccm): analyze management point evidence"
~~~

Document #328's exact profile/key scope as the contractual handoff to #333; do not add correlation code in this issue.

## Task 5: Implement #329 Distribution Point/content analysis

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/windows/distribution_point.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_distribution_point.rs
- Create fixtures: healthy-package, distribution-failure, transfer-retry, validation-failure, content-version-mismatch, serve-observed, client-only-looking-request, rotation-boundary, absent-dp, incomplete

**Consumes:** #335 DP source groups; #318 package/content/version/DP/server keys and signals.

**Produces:** Role-local package/content distribution/validation/serving analysis, with counterpart-ready exact content/version/DP keys.

### State contract

~~~text
ReceiveContent -> Distribute -> Transfer -> Validate -> MakeAvailable -> ServeOrReport
~~~

A content package may have multiple versions and multiple DPs. The transaction key must include exact content/package identifier plus version/DP topology when applicable. Do not report a client download failure as a DP failure; that belongs to #333 only if a compatible client-to-DP pair is later proven.

- [ ] **Step 1: Write failing DP fixture tests**

Cover healthy package; terminal distribution/transfer/validation failure; retry/backlog; exact same content with mismatching version; observed serving outcome; source coverage absent; unrelated client-style requests; malformed/rotation boundary; and deterministic sorting of multiple DPs/content versions.

- [ ] **Step 2: Run target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_distribution_point
~~~

- [ ] **Step 3: Implement content/version/topology reducer**

Extract source-local distribution, transfer, provider, pull-DP, and optional serving facts. Key by normalized content/package/version plus DP host only under a validated profile. Preserve retry/backlog as a state/symptom, and require terminal source-specific evidence for failure. If DP role coverage is absent, return an InsufficientEvidence artifact request rather than a role diagnosis.

- [ ] **Step 4: Verify and commit**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_distribution_point
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server crates/cmtraceopen-parser/tests/sccm_server_distribution_point.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/distribution_point
git commit -m "feat(sccm): analyze distribution point content evidence"
~~~

## Task 6: Implement #330 Software Update Point and WSUS analysis

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/windows/software_update_point.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_software_update_point.rs
- Create fixtures: sync-success, wcm-configuration-failure, wsus-health-failure, sync-retry, metadata-failure, sup-setup-failure, supplemental-wsus-skipped, unrelated-update-key, rotation-boundary, incomplete

**Consumes:** #335 SUP/WSUS groups, #318 source/version/key/finding contracts, and optional catalogued WSUS supplemental sources.

**Produces:** Server-local synchronization/configuration/WSUS health transactions. It does not diagnose a client scan/install path without #333 counterpart evidence.

### State contract

~~~text
Configure -> Synchronize -> ImportOrProcessMetadata -> ValidateWsus -> PublishAvailability -> HealthyOrTerminal
~~~

ValidateWsus is not presumed merely because WSUSCtrl.log exists. A sync retry is not terminal failure. A client update/KB token cannot attach to a server sync run unless a validated shared key/profile supports it; client/SUP causality remains outside #330.

- [ ] **Step 1: Add red fixture tests**

Require success, configuration failure, terminal WSUS health failure, retry/deferred sync, metadata processing failure, SUP setup failure, intentionally skipped supplemental WSUS evidence, unrelated update token, malformed rotation fragment, and incomplete required group scenarios. Assert class/confidence/evidence/next artifact exactly.

- [ ] **Step 2: Run target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_software_update_point
~~~

- [ ] **Step 3: Implement source-local facts and SUP reducer**

Use distinct extractors for WCM configuration, sync, WSUS control/health, setup, and catalogued supplemental logs. Reduce by validated sync/run/update metadata keys only. Retain unknown signal codes losslessly. A terminal ConfirmedFailure needs source-specific terminal evidence and sufficient coverage; a skipped/capped supplemental source lowers confidence rather than becoming a failure.

- [ ] **Step 4: Verify and commit**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_software_update_point
cargo test --locked -p cmtraceopen-parser --test sccm_server_distribution_point
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server crates/cmtraceopen-parser/tests/sccm_server_software_update_point.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/software_update_point
git commit -m "feat(sccm): analyze software update point evidence"
~~~

## Task 7: Run server release gates and lab validation

**Files:**

- Create: docs/sccm/validation/server-intake-lab-checklist.md
- Create: docs/sccm/validation/server-core-workflows-lab-checklist.md
- Modify: GitHub issues #335, #327–#330 with exact test/fixture/native validation evidence
- Modify CI workflow files only after a targeted Windows SCCM test job is designed/reviewed

**Consumes:** All preceding parser/native changes and the development SCCM Server when available.

**Produces:** An evidence-backed statement of what is parser-proven, native test-double-proven, and Windows-server-proven.

- [ ] **Step 1: Execute all focused parser suites**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser --test sccm_server_site_core
cargo test --locked -p cmtraceopen-parser --test sccm_server_management_point
cargo test --locked -p cmtraceopen-parser --test sccm_server_distribution_point
cargo test --locked -p cmtraceopen-parser --test sccm_server_software_update_point
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
~~~

- [ ] **Step 2: Execute native regression suites**

~~~bash
cargo test --locked -p cmtrace-open --test sccm_server_collection --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test esp_diagnostics_sources --all-features
cargo test --locked -p cmtrace-open --test parser_expanded_corpus --all-features
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
~~~

- [ ] **Step 3: Execute the development-server validation safely**

Before capture, the checklist requires: confirmed development-only host; ConfigMgr/site version; exact observed server roles; configured/actual paths; chosen synthetic incident; source group selection; capture caps; local time/offset; redaction strategy; secure storage and disposal. Run discovery first, compare observed roles/candidates to catalog, then capture a bounded bundle. Treat any unobserved candidate/source semantic as a validation result, not an automatic coding failure.

- [ ] **Step 4: Create sanitized fixture deltas only after independent review**

Never add full lab logs. Extract the minimum synthetic record sequence necessary to recreate an observed parser contract, replace every identifier consistently, retain timestamp/rotation/line relationships, verify redaction, and rerun focused parser tests. If a live finding requires additional server behavior not already catalogued, create a dedicated #334-style source-contract issue rather than widening #327–#330 blindly.

- [ ] **Step 5: Add Windows acceptance to CI only once source contracts are stable**

Design a dedicated Windows SCCM collection/contract job analogous to the existing Windows-targeted diagnostics checks. It must test manifest/collision/rotation/provenance behavior using synthetic temp paths; it must not depend on a live lab server or credentials. Native configured-path discovery receives final acceptance on Windows CI plus the dev server, not macOS.

## Per-Issue Exit Criteria

### #335 Server intake

- [ ] Pure source catalog and manifest reader cover multi-role, configured-path, rotation, multiline, absent/access/cap/skipped/unsupported, and deterministic ordering scenarios.
- [ ] Native capture preserves host/role/topology/path/rotation/state/size without changing generic bundle meanings.
- [ ] Filename collisions/reparse escape/legacy mapping/script-profile parity tests pass.
- [ ] Windows Server validation is recorded as passing or pending, with no false live-acceptance claim.

### #327 Site core

- [ ] Component/status transactions use validated component context and keep backlog/deferred separate from terminal failure.
- [ ] Healthy/recovery/terminal/contradictory/rotation/incomplete fixtures pass.
- [ ] No client impact/root-cause assertion escapes this role-local analyzer.

### #328 Management Point

- [ ] Auth/registration/location/policy phases remain distinct and key/topology-gated.
- [ ] Optional IIS coverage does not force failure; client-looking timestamps/keys cannot create a transaction by proximity.
- [ ] Output exposes exact, cited counterpart-ready evidence for #333 without performing correlation.

### #329 Distribution Point

- [ ] Content/package/version/DP topology prevents merges across multiple DPs or versions.
- [ ] Retry/backlog, distribution/validation failure, absence, and rotation boundaries are distinct.
- [ ] Output makes no client download/DP causality claim before #333.

### #330 SUP/WSUS

- [ ] Configure/sync/metadata/WSUS validation/publish phases are distinct, with retries/deferred separate from failure.
- [ ] Supplemental WSUS coverage is explicitly optional/capped/skipped and cannot create false terminal health.
- [ ] No client update causal statement is made before a validated future correlation pair.
