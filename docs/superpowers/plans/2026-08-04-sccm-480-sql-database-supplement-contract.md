# SCCM Site-Database Export Supplement Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deliberately invoked, schema-v1 SCCM site-database export contract that accepts at most one data-minimized, operator-authorized snapshot and emits coverage-only status, never semantic evidence.

**Architecture:** Keep the contract outside `assess_server_intake`: its input is explicit operator-supplied JSON bytes, not a discovered server artifact or a database connection. A small standalone validator owns duplicate-key detection, strict schema/version/authorization/provenance/privacy/cap checks, and an integrity binding over the canonical payload; it returns a bounded coverage assessment whose evidence disposition is permanently `coverageOnly`. The existing SQL source card remains `deferred` under the frozen CAPTURE-MORE audit because synthetic contract tests are not sanitized production observation and the contract has no parser, reducer, transaction, finding, native Windows, credential, or SQL-execution path.

**Tech Stack:** Rust 1.88+, `serde`, `serde_json`, `sha2`, `chrono`, `thiserror`, JSON Schema Draft 2020-12; no new dependency.

---

## Decision record and non-goals

- The public entry point is `assess_sccm_site_database_export(input: &[u8])`. No caller may reach it through server-log discovery, `assess_server_intake`, a collector, a connection string, a credential, or a query argument. This makes supplying the bytes itself the explicit operator action.
- The v1 document contains one `snapshot` object at most, never an array. A captured or partial export has exactly one snapshot; an access-denied export has `snapshot: null`. The raw input cap is **1,048,576 bytes (1 MiB)** before JSON parsing; no retained string, array, row, or result-set surface exists.
- The only accepted query provenance is the literal export profile ID `sccm-site-database-export-v1`; raw SQL, table names, connection strings, parameter values, credentials, and arbitrary query identifiers are not schema fields and are rejected by `deny_unknown_fields`/`additionalProperties: false`.
- All identity-bearing values are fixed-prefix, lowercase SHA-256 handles. The public result contains only the contract ID, schema version, coverage state, coarse gate code, and `coverageOnly` disposition. It does not serialize handles, counts, query profile, timestamps, integrity digest, or payload bytes.
- A successful v1 envelope is **coverage-only**, not eligible evidence. Its API has no `SccmEvidence`, finding, transaction, parser, reducer, correlation key, request, or promotion output. Partial, denied, malformed, duplicate-key, oversized, integrity-mismatched, and unknown-version inputs cannot become eligible evidence either.
- Delete the obsolete generic `unknown-db-supplement` intake fixture and its closed synthetic allow-list entries. Do not retain it as a fallback, alias, or compatibility branch. The explicit v1 API replaces that proposed-only fixture rather than treating unknown server-manifest artifacts as database exports.

## File structure and scope map

| Path | Action | Responsibility |
| --- | --- | --- |
| `crates/cmtraceopen-parser/src/sccm/json_contract.rs` | Create | Reusable duplicate-preserving JSON preflight used by existing server intake and the new contract. |
| `crates/cmtraceopen-parser/src/sccm/mod.rs` | Modify | Declare the crate-private JSON preflight module. |
| `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs` | Modify | Consume the extracted preflight utility; remove only the obsolete database fixture vocabulary. |
| `crates/cmtraceopen-parser/src/sccm/server/windows/site_database_export.rs` | Create | v1 wire types, gate errors, canonical integrity material, and coverage-only assessment API. |
| `crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs` | Modify | Declare and publicly re-export the standalone explicit contract. |
| `crates/cmtraceopen-parser/tests/sccm_server_intake.rs` | Modify | Delete assertions for the retired generic `unknown-db-supplement` path while retaining all other intake coverage behavior. |
| `crates/cmtraceopen-parser/tests/sccm_site_database_export_contract.rs` | Create | Red/green contract suite: schema, gates, privacy, canonical integrity, and public-output boundary. |
| `crates/cmtraceopen-parser/tests/fixtures/sccm/server/site_database_export/v1/{captured,partial,denied,malformed,unknown-version,duplicate,oversized}/export.json` | Create | Seven synthetic input fixtures; `oversized` is exactly 1,048,577 bytes. |
| `crates/cmtraceopen-parser/tests/fixtures/sccm/server/site_database_export/v1/{captured,partial,denied}/expected.json` | Create | Inspectable public coverage-only oracles; rejected inputs assert exact error codes in Rust tests. |
| `docs/sccm/contracts/sccm-site-database-export-v1.schema.json` | Create | Normative Draft 2020-12 data-minimized wire schema. |
| `docs/sccm/contracts/sccm-site-database-export-v1.md` | Create | Operator contract, privacy/redaction matrix, integrity rule, stop conditions, and no-live-DB boundary. |
| `crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/source-cards/sql-database-export.json` | Modify | Keep the card deferred; point it at #480, v1 cap/fixture IDs, and the exact remaining promotion evidence. |
| `docs/sccm/source-catalog/advanced-roles.md` | Modify | State that v1 is a separate coverage contract, never an intake fallback or semantic source. |
| `crates/cmtraceopen-parser/tests/fixtures/sccm/server/intake/unsupported-db-supplement/{manifest.json,expected.json}` | Delete | Remove the retired proposed-only generic database artifact. |

### Schema-v1 fields and validation

The normative schema and the Rust deserializer use camelCase fields and reject every field not listed below. `opaqueHandle(prefix)` means exactly `prefix` followed by 64 lowercase hexadecimal characters. All `...Utc` values are RFC 3339 UTC values normalized to `Z`; `exportCompletedUtc` must be greater than or equal to `exportStartedUtc`.

| Object | Required fields | Rule |
| --- | --- | --- |
| Root | `schemaVersion`, `contractId`, `intent`, `captureState`, `authorization`, `provenance`, `snapshot`, `integrity` | `schemaVersion` is `1`; `contractId` is `sccm-site-database-export`; `intent` is `captureMore`; `captureState` is `captured`, `partial`, or `accessDenied`. |
| `authorization` | `authorizationId`, `authorizerHandle`, `authorizedAtUtc`, `decision`, `scope` | Both handles use `cmtraceopen.sccm.dbexport.authorization.sha256.v1:` and `cmtraceopen.operator.sha256.v1:`; `scope` is `coverageOnlySccmSiteDatabaseExport`; `decision` is `granted` for captured/partial and `denied` for accessDenied. |
| `provenance` | `siteHandle`, `databaseHandle`, `exporterHostHandle`, `exportProfileId`, `exportStartedUtc`, `exportCompletedUtc` | Handles use site/database/host v1 prefixes; `exportProfileId` is exactly `sccm-site-database-export-v1`. It is the only query provenance admitted. |
| `snapshot` | `snapshotId`, `capturedAtUtc`, `complete`, `summary` when non-null | Non-null exactly for captured/partial; `snapshotId` uses `cmtraceopen.sccm.dbexport.snapshot.sha256.v1:`; `complete` is true only for captured. |
| `snapshot.summary` | `activeClientCount`, `managedDeviceCount`, `packageCount`, `deploymentCount` | Unsigned integers from 0 through 1,000,000,000; no device, user, package, collection, deployment, or site rows/identifiers exist. |
| `integrity` | `algorithm`, `canonicalPayloadSha256` | `algorithm` is `sha256`; the digest is 64 lowercase hex characters and equals the SHA-256 of the canonical serialization of every root field except `integrity`, in declaration order. |

The canonical integrity material is a dedicated `#[derive(Serialize)]` struct with fields in this exact order: `schemaVersion`, `contractId`, `intent`, `captureState`, `authorization`, `provenance`, `snapshot`. It is serialized with `serde_json::to_vec`; `Sha256::digest` is encoded as lowercase hex and compared in constant time by byte equality after syntax validation. The integrity object is intentionally excluded from its own material, preventing a self-reference. Duplicate keys are rejected before normal deserialization, so a later duplicate cannot alter the digest input or override a validated field.

### Privacy/redaction matrix

| Sensitive class | Input rule | Retained/public output rule |
| --- | --- | --- |
| Database identity | Accept only `databaseHandle`; reject database name, server name, instance, connection string, and path fields. | Never serialize the handle. |
| Query identity/text | Accept only the fixed `exportProfileId`; reject SQL, query text, table/view names, parameters, query file/path, and connection metadata. | Do not serialize the profile ID or a query digest. |
| User identity | Do not provide a user field, user rows, account names, SIDs, or affinity details. Numeric aggregate counts are not included for users. | Never available. |
| Device identity | Do not provide device rows, resource IDs, names, GUIDs, MACs, or IPs. `managedDeviceCount` and `activeClientCount` are bounded aggregates only. | Counts are omitted from the public assessment. |
| Package/deployment identity | Do not provide package/application/deployment IDs, names, content paths, or collection IDs. `packageCount` and `deploymentCount` are bounded aggregates only. | Counts are omitted from the public assessment. |
| Site identity | Accept only `siteHandle`; reject site code/name, hierarchy links, hostnames, and paths. | Never serialize the handle. |

### Promotion and stop conditions

The card remains `deferred` after this issue. Contract acceptance means only a specific submitted envelope produced a coverage row; it does not move the source card to `observed`, `fixtureValidated`, `ruleValidated`, or semantic admission. A later promotion must separately provide all of the following: reviewed schema-v1 fixture evidence, a sanitized real operator authorization/provenance observation ID, privacy review sign-off, an approved source-version policy, exact correlation keys, incomplete/error scenarios, a named implementation issue, and a named reducer with its own production tests. Until then, unknown version and failed gates are `unsupported`/rejected, partial and denied inputs are coverage gaps, and every accepted export remains coverage-only.

Stop immediately and return a non-semantic contract error or coverage gap when the input is over 1 MiB; not valid JSON; has duplicate keys; has an unknown schema/profile/version; has a missing, denied, malformed, or inconsistent authorization envelope; has raw identity/query fields; has an invalid handle/timestamp/count; has more than one snapshot representation; has a captured/partial/denied state inconsistent with `snapshot`; or has an integrity mismatch. Do not query SQL Server, discover a database, retry through logs, request credentials, or invoke Windows APIs.

### Task 1: Extract duplicate-key preflight without changing server-intake behavior

**Files:**
- Create: `crates/cmtraceopen-parser/src/sccm/json_contract.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/mod.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [ ] **Step 1: Add regression tests before moving the utility**

Add focused server-intake tests that submit duplicate keys at the root, `privacy`, `topology`, an artifact, and an artifact nested object; each must still return the existing scoped intake error. Add an exact no-duplicate control using the current `complete-multi-role` fixture.

```rust
assert_eq!(
    assess_server_intake(&duplicate_manifest, &payloads),
    Err(SccmServerIntakeError::MalformedManifest)
);
```

- [ ] **Step 2: Run the regression test red**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_server_intake duplicate`

Expected: FAIL because the new regression cases have not been added.

- [ ] **Step 3: Move the duplicate-preserving document representation**

Create `json_contract.rs` with `PreservedJsonValue`, its Serde visitor, `parse_preserved_json`, `object_fields`, `field`, and recursive `has_duplicate_object_keys`. Return a small `JsonContractPreflightError::{Malformed, DuplicateKey}`; retain field values so `intake.rs` can continue validating its opaque extensions. Declare it crate-private in `sccm/mod.rs`, replace the private `PreservedJsonValue`/visitor in `intake.rs`, and map errors back to the current `SccmServerIntakeError` variants. Do not change intake limits, extension handling, or its serialized assessment.

- [ ] **Step 4: Run intake tests green**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_server_intake`

Expected: PASS, including all existing extension and duplicate-key cases.

- [ ] **Step 5: Commit the mechanical extraction**

```bash
git add crates/cmtraceopen-parser/src/sccm/json_contract.rs \
  crates/cmtraceopen-parser/src/sccm/mod.rs \
  crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs \
  crates/cmtraceopen-parser/tests/sccm_server_intake.rs
git commit -m "refactor: share SCCM duplicate-key JSON preflight"
```

### Task 2: Commit the normative v1 schema and operator privacy contract

**Files:**
- Create: `docs/sccm/contracts/sccm-site-database-export-v1.schema.json`
- Create: `docs/sccm/contracts/sccm-site-database-export-v1.md`
- Test: `crates/cmtraceopen-parser/tests/sccm_site_database_export_contract.rs`

- [ ] **Step 1: Write the failing schema/fixture contract test**

Create the test target with a fixture loader rooted at `tests/fixtures/sccm/server/site_database_export/v1`. Assert the successful, partial, and denied fixtures have exactly the schema fields and that fixture data contains none of these case-insensitive markers: `select `, `from `, `password`, `connectionstring`, `server=`, `uid=`, `resourceid`, `deviceid`, `username`, `packageid`, `sitecode`.

```rust
for scenario in ["captured", "partial", "denied"] {
    let bytes = std::fs::read(fixture_root(scenario).join("export.json"))?;
    assert!(bytes.len() <= 1_048_576);
    assert_no_raw_identifier_markers(&bytes);
}
```

- [ ] **Step 2: Run the schema/fixture test red**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_site_database_export_contract schema_and_fixture_contract`

Expected: FAIL because the schema, fixture root, and test target do not exist.

- [ ] **Step 3: Define the exact Draft 2020-12 document and guide**

Create the schema with `$schema: "https://json-schema.org/draft/2020-12/schema"`, `$id: "https://cmtraceopen.dev/schemas/sccm-site-database-export-v1.schema.json"`, root `additionalProperties: false`, and the field table above as `const`, `enum`, `required`, `pattern`, `format`, and numeric `maximum` constraints. Model `snapshot` as `oneOf` a strict object or `null`, then use root `allOf` conditionals to require captured/partial object states and denied `null` state. The operator guide must include the privacy matrix, the canonical payload formula, exact size/snapshot caps, the CAPTURE-MORE boundary, and the stop conditions above.

- [ ] **Step 4: Add the seven synthetic fixtures and public oracles**

Use handles composed only of the prescribed prefixes plus deterministic lowercase hexadecimal digests. `captured` is complete with a matching digest; `partial` is `captureState: "partial"` and `complete: false`; `denied` is `captureState: "accessDenied"`, `authorization.decision: "denied"`, and `snapshot: null`; `malformed` is invalid JSON; `unknown-version` changes `schemaVersion` to `2`; `duplicate` repeats `authorizationId`; and `oversized` is a syntactically valid captured document padded with whitespace to exactly 1,048,577 bytes. Create expected public JSON only for captured, partial, and denied.

- [ ] **Step 5: Run the schema/fixture test green**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_site_database_export_contract schema_and_fixture_contract`

Expected: PASS with a checked-in 1,048,577-byte oversize fixture and no raw sensitive markers in accepted-fixture bytes.

- [ ] **Step 6: Commit the normative contract**

```bash
git add docs/sccm/contracts/sccm-site-database-export-v1.schema.json \
  docs/sccm/contracts/sccm-site-database-export-v1.md \
  crates/cmtraceopen-parser/tests/sccm_site_database_export_contract.rs \
  crates/cmtraceopen-parser/tests/fixtures/sccm/server/site_database_export/v1
git commit -m "docs: define SCCM database export v1 contract"
```

### Task 3: Implement the isolated coverage-only validator

**Files:**
- Create: `crates/cmtraceopen-parser/src/sccm/server/windows/site_database_export.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_site_database_export_contract.rs`

- [ ] **Step 1: Write red public-API and successful-admission tests**

Add tests that feed `captured/export.json` through the new API and require an exact coverage-only result, a private digest binding, and no semantic result surfaces:

```rust
let assessment = assess_sccm_site_database_export(&captured_bytes)
    .expect("captured v1 export is assessable");
assert_eq!(assessment.coverage().state(), SccmSiteDatabaseExportCoverageState::Captured);
assert_eq!(assessment.evidence_disposition(), SccmSiteDatabaseExportEvidenceDisposition::CoverageOnly);
assert!(!serde_json::to_string(&assessment)?.contains("cmtraceopen.site.sha256.v1:"));
```

Also assert that serializing the assessment contains `coverageOnly` and does not contain `findings`, `transactions`, `evidence`, `authorization`, `provenance`, `snapshot`, or `integrity`.

- [ ] **Step 2: Run the success test red**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_site_database_export_contract captured_export_is_coverage_only`

Expected: FAIL because the API and types do not exist.

- [ ] **Step 3: Add strict wire types, public result types, and gates**

Implement `assess_sccm_site_database_export(input: &[u8]) -> Result<SccmSiteDatabaseExportAssessment, SccmSiteDatabaseExportError>` in the new module. Use `#[serde(deny_unknown_fields, rename_all = "camelCase")]` for every root and nested wire struct, `json_contract::parse_preserved_json` for duplicate rejection before `serde_json::from_slice`, `chrono` for timestamp normalization/order, and existing `sha2` for integrity. Expose only these public result concepts:

```rust
pub enum SccmSiteDatabaseExportCoverageState { Captured, Partial, AccessDenied }
pub enum SccmSiteDatabaseExportEvidenceDisposition { CoverageOnly }
pub struct SccmSiteDatabaseExportCoverage { /* state and non-sensitive gate code */ }
pub struct SccmSiteDatabaseExportAssessment { /* schema version, coverage, disposition */ }
```

Keep parsed authorization, provenance, summary, payload bytes, and computed digest private. Validate raw size first; schema version and literal profile next; then handles, timestamps, capture-state/snapshot consistency, count caps, and the canonical integrity digest. Map an intentional denied envelope to `AccessDenied` coverage and an intentional incomplete envelope to `Partial` coverage. There is no `Eligible` disposition and no route to the server intake, source catalog, or a semantic analyzer.

- [ ] **Step 4: Run the successful-admission test green**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_site_database_export_contract captured_export_is_coverage_only`

Expected: PASS; the only admitted disposition is `coverageOnly`.

- [ ] **Step 5: Commit the isolated API**

```bash
git add crates/cmtraceopen-parser/src/sccm/server/windows/site_database_export.rs \
  crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs \
  crates/cmtraceopen-parser/tests/sccm_site_database_export_contract.rs
git commit -m "feat: add SCCM database export coverage contract"
```

### Task 4: Prove every failed gate stays non-semantic

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/sccm_site_database_export_contract.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/site_database_export.rs`
- Test: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/site_database_export/v1/{partial,denied,malformed,unknown-version,duplicate,oversized}/export.json`

- [ ] **Step 1: Add the negative matrix before refining gate errors**

Add a table-driven test with exact expectations: partial -> `Partial` plus `CoverageOnly`; denied -> `AccessDenied` plus `CoverageOnly`; malformed -> `MalformedDocument`; unknown-version -> `UnsupportedSchemaVersion`; duplicate -> `DuplicateJsonKey`; oversized -> `InputLimitExceeded`; mutated captured `canonicalPayloadSha256` -> `IntegrityMismatch`; raw `queryText`/`databaseName`/`deviceId`/`packageId`/`userName`/`siteCode` fields -> `UnexpectedField`; a second snapshot object -> `SnapshotContractViolation`.

```rust
assert!(matches!(
    assess_sccm_site_database_export(&fixture_bytes),
    Err(SccmSiteDatabaseExportError::UnsupportedSchemaVersion { found: 2 })
));
```

- [ ] **Step 2: Run the negative matrix red**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_site_database_export_contract rejects_or_preserves_only_coverage_for_failed_gates`

Expected: FAIL until every error variant and state transition is explicitly implemented.

- [ ] **Step 3: Make failure classification deterministic and bounded**

Add the exact error enum variants used above. Do not place potentially identifying source values in `Display`, `Debug` assertions, or serialized public coverage. Ensure duplicate detection is recursive; `duplicate` must fail even though normal `serde_json` would accept the last occurrence. Keep the raw input unretained after parsing, never allocate based on supplied count fields, and verify the input cap before the duplicate preflight or deserialization.

- [ ] **Step 4: Run the negative matrix green**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_site_database_export_contract rejects_or_preserves_only_coverage_for_failed_gates`

Expected: PASS; no failed gate yields semantic evidence, a transaction, a finding, a collection request, or a database action.

- [ ] **Step 5: Commit the gate matrix**

```bash
git add crates/cmtraceopen-parser/src/sccm/server/windows/site_database_export.rs \
  crates/cmtraceopen-parser/tests/sccm_site_database_export_contract.rs \
  crates/cmtraceopen-parser/tests/fixtures/sccm/server/site_database_export/v1
git commit -m "test: harden SCCM database export contract gates"
```

### Task 5: Retire the generic intake placeholder and document deferred catalog status

**Files:**
- Delete: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/intake/unsupported-db-supplement/manifest.json`
- Delete: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/intake/unsupported-db-supplement/expected.json`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/source-cards/sql-database-export.json`
- Modify: `docs/sccm/source-catalog/advanced-roles.md`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_advanced_roles_catalog.rs`

- [ ] **Step 1: Write the red retirement/catalog assertions**

Change the intake fixture inventory assertion to require that `unsupported-db-supplement` is absent. Add source-card assertions requiring `ownerIssue == "#480"`, `promotion.state == Deferred`, `rawParserFamily == Unsupported`, `capture.maxBytes == 1_048_576`, `rotationPolicy.kinds == ["snapshot"]`, `rotationPolicy.maxFiles == 1`, and semantic policy flags all false.

- [ ] **Step 2: Run the retirement tests red**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_server_intake unsupported_db`

Expected: FAIL because the proposed-only fixture and synthetic vocabulary still exist.

- [ ] **Step 3: Remove the obsolete generic path and update the card**

Delete the old fixture, remove `unknown-db-supplement` and `synthetic:path:unsupported-db` from the closed synthetic acceptance lists, and remove only the tests that load that fixture. Update the card to version `1.1.0`, owner `#480`, fixture IDs for all seven v1 scenarios, and a deferred reason that states: synthetic v1 gates exist but sanitized observed operator provenance, source-version policy, and semantic admission evidence do not. Update the catalog prose to identify the explicit API and reiterate that generic server intake and database fallback remain unsupported.

- [ ] **Step 4: Run retirement/catalog tests green**

Run: `cargo test --locked -p cmtraceopen-parser --test sccm_server_intake && cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog`

Expected: PASS; the SQL card remains deferred and no generic intake artifact is recognized as a database export.

- [ ] **Step 5: Commit the clean scope transition**

```bash
git add -A crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs \
  crates/cmtraceopen-parser/tests/sccm_server_intake.rs \
  crates/cmtraceopen-parser/tests/fixtures/sccm/server \
  docs/sccm/source-catalog/advanced-roles.md
git commit -m "docs: defer SCCM database source behind v1 gates"
```

### Task 6: Run the final contract gates and hand off the evidence pack

**Files:**
- Verify: every file in the scope map

- [ ] **Step 1: Run focused contract and catalog suites**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_site_database_export_contract
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
```

Expected: PASS. The fixture suite demonstrates captured/partial/denied coverage and all malformed, duplicate, unknown-version, oversized, raw-field, snapshot, and integrity rejections.

- [ ] **Step 2: Run parser and cross-target quality gates**

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
```

Expected: PASS. No Windows runtime or live SCCM/SQL acceptance command is part of this plan.

- [ ] **Step 3: Inspect the final public boundary**

```bash
rg -n 'SccmEvidence|SccmFinding|transaction|reducer|sqlx|odbc|tiberius|password|connectionString|queryText' \
  crates/cmtraceopen-parser/src/sccm/server/windows/site_database_export.rs \
  docs/sccm/contracts/sccm-site-database-export-v1.schema.json
```

Expected: no semantic/database-client symbols and no raw query/credential field names; documentation may contain the prohibition prose but schema/code must not admit those fields.

- [ ] **Step 4: Commit the verified implementation**

```bash
git add crates/cmtraceopen-parser docs/sccm
git commit -m "test: verify SCCM database export contract"
```

## Implementation handoff evidence pack

Before requesting review, attach:

| Field | Required evidence |
| --- | --- |
| Target | Commit SHA plus `sccm-site-database-export-v1.schema.json`, the operator guide, and the fixture directory. |
| Viewing conditions | Run the three focused tests, then the formatter/parser/clippy/WASM commands from Task 6. Inspect captured, partial, denied, malformed, duplicate, unknown-version, and oversized fixture outcomes. |
| Claims | One bounded v1 JSON envelope; explicit authorization/provenance; 1 MiB and one-snapshot cap; deterministic integrity binding; coverage-only public result; deferred source card; deleted generic placeholder. |
| Reproduce | Use the exact commands in Task 6 from the repository root. |
| Out of scope | Live database access, SQL/query execution, credentials, collection, parser/reducer/findings, correlation, native Windows acceptance, and compatibility aliases. |

**Decision:** Keep CAPTURE-MORE frozen. Accept this issue only when the v1 contract passes its gates and remains coverage-only; do not promote the catalog card or authorize semantic analysis in this change.
