# SCCM Shared Diagnostic Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #318: a pure, serializable SCCM diagnostic contract that turns classified raw records into evidence, signals, stable keys, transactions, coverage, and conservative findings.

**Architecture:** Add a new parser-owned sccm module without changing public CCM parsing behavior or ParserKind. Factor CCM logical framing behind an internal enriched record envelope so SCCM ingest can retain context, physical line range, timestamp-parse validity, and source-code file metadata while ordinary callers continue to receive unchanged LogEntry values. SCCM models own serialization and privacy semantics; catalog/classification, signal extraction, key normalization, and finding construction stay in focused files with no I/O.

**Tech Stack:** Rust 1.88, serde, serde_json, chrono, regex, cmtraceopen-parser, standard Rust tests.

## Global Constraints

- This plan implements #318 only. It creates no client/server source discovery, no Tauri command, no workspace UI, and no workflow-specific SCCM rules.
- The API consumes content/provenance supplied by callers. It cannot open files, enumerate folders, read registry, run commands, query WMI, or call a network service.
- Reuse parser::ccm for framing and timestamp parsing. No SCCM-specific ParserKind or duplicate record parser.
- Preserve a raw artifact identity separately from LogEntry.source_file, because source_file is the component source-code attribute while the artifact identity names the captured log.
- Existing LogEntry serialization must not change. Factor an internal CCM logical-record envelope and let SCCM ingest consume it; do not add a SCCM-only context field to public LogEntry or require downstream callers to update struct literals. SCCM evidence may carry a privacy-classified/redacted context handle only after the envelope/redaction tests pass.
- Signal extraction is diagnostic metadata, not error_db UI highlighting. Preserve unknown tokens, numeric form, original text, and span even when error_db has no description.
- New models use serde camelCase, derive Debug/Clone/PartialEq, and use Unknown(String) for externally supplied enum values that can evolve.
- Use UTC epoch milliseconds only for ordering. Retain original timestamp display and offset in evidence.
- Never output raw user names, credential-like text, client tokens, or user context in public evidence. Preserve a deterministic redacted handle only when a downstream correlation need is explicit and reviewed.

---

## File Structure

- Create: crates/cmtraceopen-parser/src/sccm/mod.rs — public SCCM façade and focused re-exports.
- Create: crates/cmtraceopen-parser/src/sccm/models.rs — schema version, enums, artifact/evidence/transaction/finding models.
- Create: crates/cmtraceopen-parser/src/sccm/catalog.rs — filename-to-role/workload catalog and artifact classification.
- Create: crates/cmtraceopen-parser/src/sccm/signals.rs — known/unknown HRESULT, Win32, GLE, status, exit-code, and return-code extraction.
- Create: crates/cmtraceopen-parser/src/sccm/keys.rs — stable-key normalization and version-aware extractor metadata.
- Create: crates/cmtraceopen-parser/src/sccm/ingest.rs — artifact-content to SCCM evidence normalization using the internal CCM logical-record envelope.
- Create: crates/cmtraceopen-parser/src/sccm/evidence.rs — evidence IDs, timestamp/provenance projection, context redaction, and public export boundary.
- Create: crates/cmtraceopen-parser/src/sccm/findings.rs — conservative finding builder/validation and next-artifact request models.
- Create: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs — public JSON/schema, catalog, signal, key, privacy, framing, and finding contracts.
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/spine/multiline-policy.log — sanitized logical CCM record split across physical lines.
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/spine/artifact-manifest.json — sanitized artifact provenance/coverage scenario.
- Modify: crates/cmtraceopen-parser/src/lib.rs — publish the new sccm module.
- Modify: crates/cmtraceopen-parser/src/parser/ccm.rs — factor the existing logical-record scanner into a crate-private envelope without changing the public parse_content or LogEntry contract.

## Public Interfaces

All types below are new public parser-crate types. Do not relocate ESP types or make SCCM depend on esp.

~~~rust
pub const SCCM_DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;

pub enum SccmCoverageState {
    Captured,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    ParseFailed,
}

pub enum SccmRole {
    Client,
    SiteServer,
    ManagementPoint,
    DistributionPoint,
    SoftwareUpdatePoint,
    WsUs,
    Provider,
    Unknown(String),
}

pub enum SccmFindingClass {
    Symptom,
    ConfirmedFailure,
    BlockedOrDeferred,
    LikelyContributor,
    InsufficientEvidence,
}

pub enum SccmConfidence {
    None,
    Low,
    Moderate,
    High,
}

pub struct SccmArtifact {
    pub artifact_id: String,
    pub display_name: String,
    pub original_path: Option<String>,
    pub host: Option<String>,
    pub role: SccmRole,
    pub configmgr_version: Option<String>,
    pub collected_at_utc: Option<String>,
    pub rotation: SccmRotation,
    pub coverage: SccmCoverageState,
    pub encoding: Option<String>,
}

pub struct SccmEvidenceRef {
    pub artifact_id: String,
    pub entry_id: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
}

pub struct SccmEvidence {
    pub evidence_id: String,
    pub reference: SccmEvidenceRef,
    pub role: SccmRole,
    pub component: Option<String>,
    pub ccm_source_file: Option<String>,
    pub message: String,
    pub timestamp: SccmTimestamp,
    pub signals: Vec<SccmSignal>,
    pub keys: Vec<SccmCorrelationKey>,
    pub execution_context: Option<SccmSensitiveHandle>,
}

pub struct SccmFinding {
    pub finding_id: String,
    pub class: SccmFindingClass,
    pub phase: SccmPhase,
    pub role: SccmRole,
    pub severity: Severity,
    pub confidence: SccmConfidence,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub correlation_keys: Vec<SccmCorrelationKey>,
    pub next_artifacts: Vec<SccmArtifactRequest>,
}
~~~

### Task 1: Create the empty public SCCM module and compile-only API boundary

**Files:**
- Create: crates/cmtraceopen-parser/src/sccm/mod.rs
- Create: crates/cmtraceopen-parser/src/sccm/models.rs
- Modify: crates/cmtraceopen-parser/src/lib.rs
- Create: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs

**Consumes:** Existing crate root conventions, serde, models::log_entry::Severity.

**Produces:** A compilable sccm module with schema version and the smallest stable model set.

- [ ] **Step 1: Write the failing public-import test**

Create the test file with a compile-use contract:

~~~rust
use cmtraceopen_parser::sccm::{
    SccmArtifact, SccmCoverageState, SccmFindingClass, SccmRole,
    SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};

#[test]
fn sccm_contract_is_public_and_versioned() {
    assert_eq!(SCCM_DIAGNOSTICS_SCHEMA_VERSION, 1);
    let artifact = SccmArtifact::missing(
        "client-policy-agent",
        "PolicyAgent.log",
        SccmRole::Client,
        SccmCoverageState::Absent,
    );
    assert_eq!(artifact.coverage, SccmCoverageState::Absent);
    assert_eq!(SccmFindingClass::InsufficientEvidence.as_str(), "insufficientEvidence");
}
~~~

- [ ] **Step 2: Run the focused test before implementation**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract sccm_contract_is_public_and_versioned -- --exact
~~~

Expected: FAIL because the sccm module and its public types do not exist.

- [ ] **Step 3: Add the module declaration and exact minimum types**

Add to the crate root:

~~~rust
pub mod sccm;
~~~

Create sccm/mod.rs with:

~~~rust
pub mod models;

pub use models::*;
~~~

In sccm/models.rs, derive Serialize and Deserialize for public types, apply serde rename_all = "camelCase", and define the missing constructor:

~~~rust
impl SccmArtifact {
    pub fn missing(
        artifact_id: impl Into<String>,
        display_name: impl Into<String>,
        role: SccmRole,
        coverage: SccmCoverageState,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            display_name: display_name.into(),
            original_path: None,
            host: None,
            role,
            configmgr_version: None,
            collected_at_utc: None,
            rotation: SccmRotation::Current,
            coverage,
            encoding: None,
        }
    }
}
~~~

- [ ] **Step 4: Run format, focused test, and public API compile test**

Run:

~~~bash
cargo fmt --check --all
cargo test -p cmtraceopen-parser --test sccm_spine_contract sccm_contract_is_public_and_versioned -- --exact
~~~

Expected: PASS.

- [ ] **Step 5: Commit the empty-but-usable contract boundary**

~~~bash
git add crates/cmtraceopen-parser/src/lib.rs crates/cmtraceopen-parser/src/sccm crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
git commit -m "feat(sccm): add diagnostic contract boundary"
~~~

### Task 2: Define complete artifact provenance and coverage semantics

**Files:**
- Modify: crates/cmtraceopen-parser/src/sccm/models.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/spine/artifact-manifest.json

**Consumes:** SccmArtifact from Task 1.

**Produces:** Round-trippable artifact provenance with explicit coverage and rotation semantics.

- [ ] **Step 1: Add failing JSON round-trip and coverage tests**

~~~rust
#[test]
fn artifact_round_trip_preserves_capture_and_rotation_provenance() {
    let artifact = SccmArtifact {
        artifact_id: "client-content-transfer".into(),
        display_name: "ContentTransferManager.log.2".into(),
        original_path: Some(r"C:\Windows\CCM\Logs\ContentTransferManager.log.2".into()),
        host: Some("LAB-CLIENT-01".into()),
        role: SccmRole::Client,
        configmgr_version: Some("5.00.9128.1007".into()),
        collected_at_utc: Some("2026-07-30T15:00:00Z".into()),
        rotation: SccmRotation::Numbered(2),
        coverage: SccmCoverageState::Captured,
        encoding: Some("utf-8".into()),
    };

    let json = serde_json::to_value(&artifact).unwrap();
    assert_eq!(json["rotation"]["kind"], "numbered");
    assert_eq!(json["coverage"], "captured");
    assert_eq!(serde_json::from_value::<SccmArtifact>(json).unwrap(), artifact);
}

#[test]
fn coverage_states_are_distinct_and_never_deserialize_as_captured() {
    for state in [
        SccmCoverageState::Absent,
        SccmCoverageState::AccessDenied,
        SccmCoverageState::Capped,
        SccmCoverageState::Skipped,
        SccmCoverageState::Unsupported,
        SccmCoverageState::ParseFailed,
    ] {
        assert_ne!(state, SccmCoverageState::Captured);
    }
}
~~~

- [ ] **Step 2: Run the coverage tests and confirm red**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract artifact_round_trip_preserves_capture_and_rotation_provenance -- --exact
~~~

Expected: FAIL until SccmRotation has a stable tagged representation and all coverage states exist.

- [ ] **Step 3: Implement exact enum behavior**

Use a tagged rotation representation so a JSON consumer can distinguish current, CMTrace .lo_, dated history, and numeric history:

~~~rust
pub enum SccmRotation {
    Current,
    LoUnderscore,
    Numbered(u32),
    Timestamped(String),
    Unknown(String),
}
~~~

Serialize it as a tagged object with kind and value fields. Ensure coverage state names are the lower camelCase values listed in the epic. Do not collapse AccessDenied, Capped, Skipped, or ParseFailed into Absent.

- [ ] **Step 4: Add a fixture-backed manifest test**

Create artifact-manifest.json with one captured current artifact, one numbered rotation, one absent log, and one access-denied registry export. Deserialize it in a test and assert every artifact retains its own state.

- [ ] **Step 5: Verify and commit**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract artifact_
cargo fmt --check --all
git diff --check
~~~

Then commit:

~~~bash
git add crates/cmtraceopen-parser/src/sccm/models.rs crates/cmtraceopen-parser/tests
git commit -m "feat(sccm): model artifact coverage and rotation"
~~~

### Task 3: Classify artifacts by filename and role without parsing a record

**Files:**
- Create: crates/cmtraceopen-parser/src/sccm/catalog.rs
- Modify: crates/cmtraceopen-parser/src/sccm/mod.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs

**Consumes:** SccmArtifact, SccmRole, normalized display name.

**Produces:** Deterministic SccmSourceCatalogEntry and classify_artifact_name.

- [ ] **Step 1: Write failing catalog tests for raw grammar reuse**

~~~rust
#[test]
fn catalog_classifies_client_policy_without_changing_ccm_parser_kind() {
    let class = classify_artifact_name("PolicyAgent.log", SccmRole::Client);
    assert_eq!(class.family, SccmArtifactFamily::ClientPolicy);
    assert_eq!(class.logical_name, "policyAgent");
    assert!(class.uses_ccm_records);
}

#[test]
fn catalog_recognizes_rotated_client_log_by_base_name() {
    let class = classify_artifact_name("AppEnforce.log.3", SccmRole::Client);
    assert_eq!(class.family, SccmArtifactFamily::ClientApplication);
    assert_eq!(class.rotation, SccmRotation::Numbered(3));
}

#[test]
fn catalog_leaves_unrecognized_sources_explicitly_unknown() {
    let class = classify_artifact_name("CustomVendorHook.log", SccmRole::Client);
    assert_eq!(class.family, SccmArtifactFamily::Unknown("customVendorHook".into()));
    assert!(!class.supported_for_diagnosis);
}
~~~

- [ ] **Step 2: Run the catalog tests before implementation**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract catalog_ -- --nocapture
~~~

Expected: FAIL because classifier symbols do not exist.

- [ ] **Step 3: Implement a small immutable catalog**

Define SourceCatalogEntry values for only the shared initial names: CCMSetup, CcmEval, CcmExec, CcmRestart, ClientIDManagerStartup, ClientLocation, LocationServices, CcmMessaging, PolicyAgent, PolicyAgentProvider, PolicyEvaluator, Scheduler, CAS, ContentTransferManager, DataTransferService, AppIntentEval, AppDiscovery, AppEnforce, ScanAgent, WUAHandler, UpdatesDeployment, UpdatesHandler, UpdatesStore, smsts, sitecomp, hman, statmgr, statesys, MP_CliReg, MP_GetAuth, MP_GetPolicy, MP_Location, MP_RegistrationManager, mpcontrol, distmgr, PkgXferMgr, SMSDPProv, PullDP, WCM, WSUSCtrl, wsyncmgr, SUPSetup, replmgr, rcmctrl, sender, despool, Smsprov, and AdminService.

The catalog must return unsupported or unknown for every entry outside its declared list. It must never infer a workflow from a message alone.

- [ ] **Step 4: Verify catalog behavior**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract catalog_
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
~~~

Expected: PASS.

- [ ] **Step 5: Commit**

~~~bash
git add crates/cmtraceopen-parser/src/sccm/catalog.rs crates/cmtraceopen-parser/src/sccm/mod.rs crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
git commit -m "feat(sccm): classify diagnostic artifact families"
~~~

### Task 4: Preserve logical-record evidence and timestamp provenance

**Files:**
- Modify: crates/cmtraceopen-parser/src/parser/ccm.rs
- Create: crates/cmtraceopen-parser/src/sccm/ingest.rs
- Create: crates/cmtraceopen-parser/src/sccm/evidence.rs
- Modify: crates/cmtraceopen-parser/src/sccm/mod.rs
- Modify: crates/cmtraceopen-parser/src/sccm/models.rs
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/spine/multiline-policy.log
- Modify: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs

**Consumes:** parser::ccm internal logical-record framing, unchanged public parse_content/LogEntry behavior, SccmArtifact, and catalog classification.

**Produces:** normalize_ccm_artifact(artifact, content) and deterministic SCCM evidence references with complete logical line ranges and safe provenance.

- [ ] **Step 1: Add a multiline-framing regression test**

Use a fixture containing a PolicyAgent message split across physical lines:

~~~text
<![LOG[Policy request completed for assignment
{11111111-1111-1111-1111-111111111111}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="NT AUTHORITY\SYSTEM" type="1" thread="42" file="policyagent.cpp">
~~~

Test the raw parser and evidence conversion:

~~~rust
#[test]
fn evidence_uses_one_logical_record_and_normalized_utc_ordering() {
    let text = include_str!("fixtures/sccm/spine/multiline-policy.log");
    let (entries, errors) = cmtraceopen_parser::parser::ccm::parse_content(text, "PolicyAgent.log", None);
    assert_eq!(errors, 0);
    assert_eq!(entries.len(), 1, "ordinary public CCM output stays unchanged");

    let evidence = normalize_ccm_artifact(client_policy_artifact(), text);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].reference.line_start, Some(1));
    assert_eq!(evidence[0].reference.line_end, Some(2));
    assert_eq!(evidence[0].ccm_source_file.as_deref(), Some("policyagent.cpp"));
    assert_eq!(evidence[0].timestamp.original_display.as_deref(), Some("07-30-2026 10:00:00.000"));
    assert_eq!(evidence[0].timestamp.offset_minutes, Some(-240));
    assert!(evidence[0].timestamp.utc_millis.is_some());
}
~~~

- [ ] **Step 2: Run the framing test before implementation**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract evidence_uses_one_logical_record_and_normalized_utc_ordering -- --exact
~~~

Expected: FAIL because the evidence conversion API does not exist.

- [ ] **Step 3: Factor CCM framing into an internal rich envelope before SCCM ingest**

Introduce a crate-private envelope in parser/ccm.rs that holds the unchanged LogEntry projection plus raw metadata required by SCCM:

~~~rust
pub(crate) struct CcmLogicalRecord {
    pub entry: LogEntry,
    pub context: Option<String>,
    pub line_start: u32,
    pub line_end: u32,
    pub timestamp: CcmTimestampParse,
}
~~~

Move the existing whole-content logical scanner into a shared private function that returns CcmLogicalRecord values. Public parse_content and parse_lines_with_specialization must project only record.entry exactly as they do today. SCCM ingest may call the crate-private shared scanner, never reproduce the CCM regex or physical-line loop.

Before adding SCCM ingest, add regression tests proving that existing public CCM entries and parse-error counts are byte-for-byte/equivalence unchanged for: a single record; the multiline fixture; malformed continuation; no timestamp offset; and existing CCM unit fixtures. Run the focused public parser tests to green, then commit the internal refactor separately:

~~~bash
cargo test --locked -p cmtraceopen-parser parser::ccm
git add crates/cmtraceopen-parser/src/parser/ccm.rs crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
git commit -m "refactor(ccm): retain internal logical record metadata"
~~~

- [ ] **Step 4: Implement SccmTimestamp, provenance, and evidence construction**

Define:

~~~rust
pub struct SccmTimestamp {
    pub original_display: Option<String>,
    pub offset_minutes: Option<i32>,
    pub utc_millis: Option<i64>,
    pub ordering_state: SccmTimeOrderingState,
}

pub enum SccmTimeOrderingState {
    NormalizedUtc,
    OffsetMissing,
    OffsetInvalid,
    TimestampMissing,
}
~~~

Use the rich envelope's parsed timestamp state together with the existing LogEntry timestamp, timestamp_display, and timezone_offset projection. Do not call chrono::Local or infer a missing client/server offset. A missing or invalid offset leaves utc_millis unset for cross-host ordering and sets the correct state. Keep the artifact basename/original-path handle separate from ccm_source_file, and use line_start/line_end from the envelope rather than inventing line numbers after parsing.

- [ ] **Step 5: Handle context and privacy compatibility explicitly**

Add tests proving the public LogEntry API still does not expose a new context field, while the SCCM path can receive the envelope context. First test the redacted export projection: a fixture context such as NT AUTHORITY\\SYSTEM or LAB\\SyntheticUser must not appear raw in public SCCM JSON; only an approved deterministic sensitive handle may appear when a reviewed correlation rule needs it. Test that the raw internal snapshot is not mutated by export redaction.

Do not add context to LogEntry, change its serde shape, or update external struct literals. If a future public raw-parser context API is genuinely needed, open a separate compatibility issue with a public-versioning review; it is explicitly out of #318.

- [ ] **Step 6: Verify SCCM ingest and commit**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract evidence_
cargo test -p cmtraceopen-parser
cargo fmt --check --all
~~~

Commit:

~~~bash
git add crates/cmtraceopen-parser/src/sccm crates/cmtraceopen-parser/tests
git commit -m "feat(sccm): normalize framed evidence provenance"
~~~

### Task 5: Extract diagnostic signals without losing unknown codes

**Files:**
- Create: crates/cmtraceopen-parser/src/sccm/signals.rs
- Modify: crates/cmtraceopen-parser/src/sccm/mod.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs

**Consumes:** Reassembled SccmEvidence.message and existing error_db lookup result only as optional enrichment.

**Produces:** extract_signals(message) -> Vec<SccmSignal>.

- [ ] **Step 1: Add failing known and unknown signal tests**

~~~rust
#[test]
fn signal_extractor_preserves_known_hresult_and_error_db_metadata() {
    let signals = extract_signals("Download failed with hr=0x80070005");
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].kind, SccmSignalKind::HResult);
    assert_eq!(signals[0].raw, "0x80070005");
    assert_eq!(signals[0].numeric, Some(0x80070005));
    assert!(signals[0].error_description.is_some());
}

#[test]
fn signal_extractor_preserves_unknown_exit_and_gle_values() {
    let signals = extract_signals("exit code 1603; [gle=0xDEADBEEF]; status=71");
    assert_eq!(
        signals.iter().map(|signal| (&signal.kind, signal.raw.as_str())).collect::<Vec<_>>(),
        vec![
            (&SccmSignalKind::ExitCode, "1603"),
            (&SccmSignalKind::Gle, "0xDEADBEEF"),
            (&SccmSignalKind::Status, "71"),
        ]
    );
    assert!(signals.iter().all(|signal| signal.error_description.is_none() || !signal.raw.is_empty()));
}
~~~

- [ ] **Step 2: Run the signal tests and confirm red**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract signal_extractor_ -- --nocapture
~~~

Expected: FAIL because signal extractor types and function do not exist.

- [ ] **Step 3: Implement focused regexes with deterministic precedence**

Extract, in message order, only exact structured forms:

~~~text
hr=0xNNNNNNNN
HRESULT 0xNNNNNNNN
[gle=0xNNNNNNNN]
exit code N
exitCode = N
return code N
status=N
~~~

Record UTF-8 byte-independent span positions using character offsets or clear source indexes. Do not consume GUIDs as codes. Deduplicate only identical kind/raw/span triples; preserve repeated tokens at different positions.

- [ ] **Step 4: Enrich known values but retain unknown values**

Use error_db only after a token is captured. If lookup resolves, add description/category to the signal. If not, keep numeric/raw data and leave enrichment None. No signal extractor may discard an unknown code.

- [ ] **Step 5: Verify and commit**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract signal_
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git diff --check
~~~

Commit:

~~~bash
git add crates/cmtraceopen-parser/src/sccm/signals.rs crates/cmtraceopen-parser/src/sccm/mod.rs crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
git commit -m "feat(sccm): retain diagnostic signal tokens"
~~~

### Task 6: Normalize version-aware correlation keys conservatively

**Files:**
- Create: crates/cmtraceopen-parser/src/sccm/keys.rs
- Modify: crates/cmtraceopen-parser/src/sccm/models.rs
- Modify: crates/cmtraceopen-parser/src/sccm/mod.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs

**Consumes:** SccmEvidence, SccmArtifact.configmgr_version, signal/source metadata.

**Produces:** extract_keys(evidence, extraction_profile) and normalized key evidence.

- [ ] **Step 1: Add failing key-normalization tests**

~~~rust
#[test]
fn key_normalization_is_stable_across_case_and_brace_variants() {
    let left = normalize_key(SccmCorrelationKeyKind::AssignmentId, "{ABCDEFAB-0000-0000-0000-000000000001}");
    let right = normalize_key(SccmCorrelationKeyKind::AssignmentId, "abcdefab-0000-0000-0000-000000000001");
    assert_eq!(left.normalized, right.normalized);
    assert_eq!(left.confidence, SccmKeyConfidence::Exact);
}

#[test]
fn unvalidated_version_cannot_emit_exact_extracted_key() {
    let result = extract_keys(
        &evidence_with_message("Policy id={ABCDEFAB-0000-0000-0000-000000000001}"),
        &SccmExtractionProfile::for_version(Some("unobserved-version")),
    );
    assert!(result.keys.is_empty());
    assert_eq!(result.gaps[0].kind, SccmExtractionGapKind::UnvalidatedVersion);
}
~~~

- [ ] **Step 2: Run and confirm red**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract key_ -- --nocapture
~~~

Expected: FAIL because the key contract does not exist.

- [ ] **Step 3: Implement key kinds, confidence, and versioned profiles**

Start with normalized lexical rules for assignment ID, client GUID, package ID, content ID, site code, server host, CI ID, update/KB, BITS job ID, task-sequence execution ID, request/topic ID, and state message ID. Profile selection must declare:

~~~rust
pub struct SccmExtractionProfile {
    pub profile_id: String,
    pub configmgr_version_prefixes: Vec<String>,
    pub validated_artifact_families: Vec<SccmArtifactFamily>,
}
~~~

Unknown version has no validated profile by default. It may still preserve candidate raw text inside a gap record but must not emit an Exact or Strong key.

- [ ] **Step 4: Add two-version fixture gates**

For every profile promoted to stable, add fixture cases with at least two observed version labels or keep the profile experimental with low-confidence-only output. Test version-prefix selection and normalized equality.

- [ ] **Step 5: Verify and commit**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract key_
cargo test -p cmtraceopen-parser
cargo fmt --check --all
~~~

Commit:

~~~bash
git add crates/cmtraceopen-parser/src/sccm/keys.rs crates/cmtraceopen-parser/src/sccm/models.rs crates/cmtraceopen-parser/tests
git commit -m "feat(sccm): add versioned correlation keys"
~~~

### Task 7: Enforce conservative finding construction

**Files:**
- Create: crates/cmtraceopen-parser/src/sccm/findings.rs
- Modify: crates/cmtraceopen-parser/src/sccm/mod.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_spine_contract.rs

**Consumes:** SccmEvidenceRef, SccmCorrelationKey, SccmCoverageState, Severity.

**Produces:** SccmFindingBuilder::build and validation errors for unsound findings.

- [ ] **Step 1: Add failing finding-safety tests**

~~~rust
#[test]
fn confirmed_failure_requires_terminal_evidence() {
    let result = SccmFindingBuilder::new("app-enforcement-failed")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![single_nonterminal_error_ref()])
        .build();

    assert_eq!(result.unwrap_err(), SccmFindingValidationError::MissingTerminalEvidence);
}

#[test]
fn insufficient_evidence_requires_next_artifact_request() {
    let result = SccmFindingBuilder::new("missing-policy-log")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap("client-policy-agent")
        .build();

    assert_eq!(result.unwrap_err(), SccmFindingValidationError::MissingNextArtifactRequest);
}
~~~

- [ ] **Step 2: Run and confirm red**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract confirmed_failure_requires_terminal_evidence -- --exact
~~~

Expected: FAIL because SccmFindingBuilder does not exist.

- [ ] **Step 3: Implement the validation rules**

Require:

- ConfirmedFailure with High confidence: at least one evidence reference marked terminal or two corroborating references with the same exact/strong key.
- LikelyContributor: confidence no higher than Moderate unless corroborated by a terminal transaction record.
- InsufficientEvidence: one or more coverage gaps plus one or more next artifact requests.
- Any finding with no evidence and no coverage gap: reject.
- Any request for an artifact: use catalog logical name, role, and reason; never ask for an unbounded entire drive.

- [ ] **Step 4: Add JSON and ordering contracts**

Serialize a valid blocked/deferred finding, deserialize it, and assert evidence/correlation-key arrays preserve deterministic sorted order. Add a test that same-minute but keyless evidence cannot construct a High confidence finding.

- [ ] **Step 5: Verify and commit**

Run:

~~~bash
cargo test -p cmtraceopen-parser --test sccm_spine_contract finding_
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git diff --check
~~~

Commit:

~~~bash
git add crates/cmtraceopen-parser/src/sccm/findings.rs crates/cmtraceopen-parser/src/sccm/mod.rs crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
git commit -m "feat(sccm): enforce evidence-backed findings"
~~~

### Task 8: Run the shared-contract regression suite and document the exact boundary

**Files:**
- Modify: crates/cmtraceopen-parser/README.md
- Modify: docs/superpowers/specs/2026-07-29-parser-family-architecture-design.md only if code names diverge from the approved design
- Modify: GitHub issue #318 with verification evidence after local tests pass

**Consumes:** All Task 1 through Task 7 APIs and tests.

**Produces:** A reviewable contract release gate with documented non-goals.

- [ ] **Step 1: Add a concise README SCCM contract section**

Document that SCCM diagnostics classify and correlate supplied artifacts over CCM records, retain unknown signals, represent coverage gaps, and do not perform on-device collection in the parser crate.

- [ ] **Step 2: Run all parser-only tests**

Run:

~~~bash
cargo test -p cmtraceopen-parser
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
~~~

Expected: PASS.

- [ ] **Step 3: Inspect public JSON manually**

Run an existing test with --nocapture or add a temporary non-committed debug serialization in the test. Check camelCase fields, no raw execution context, and expected coverage-state names. Remove all debug output before commit.

- [ ] **Step 4: Commit documentation separately**

~~~bash
git add crates/cmtraceopen-parser/README.md docs/superpowers/specs/2026-07-29-parser-family-architecture-design.md
git commit -m "docs(sccm): describe diagnostic contract boundary"
~~~

- [ ] **Step 5: Update issue #318 with completion evidence**

Post the exact test commands, commit IDs, fixture names, versioned profiles supported, and any explicitly deferred raw-context compatibility work. Do not close #318 until reviewers approve the contract and a native-independent CI run is green.

## Final #318 Review Checklist

- [ ] No new platform-specific dependency in cmtraceopen-parser.
- [ ] No raw SCCM ParserKind added.
- [ ] Artifact name and source-code file are distinct.
- [ ] Unknown signals survive extraction.
- [ ] Unvalidated key/version cannot become Exact or Strong.
- [ ] Invalid/missing offset cannot establish cross-host order.
- [ ] High-confidence cause cannot exist without terminal/corroborating evidence.
- [ ] Insufficient-evidence finding names a bounded next artifact request.
- [ ] Every added serialized type has deterministic fixtures and round-trip tests.
