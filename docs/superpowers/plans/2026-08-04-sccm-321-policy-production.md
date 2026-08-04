# SCCM Client Policy Production Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the #321 client policy/assignment analyzer as a deterministic production reducer over the accepted #318/#319 intake, admission, key, and finding authority.

**Architecture:** A new `sccm::client::policy` reducer owns policy workflow semantics but accepts only the public canonical bundle, its reassessed intake projection, and bytes-only admission payloads. The existing admission capability remains the sole source of normalized CCM evidence and extraction profiles; the reducer groups only exact assignment/policy keys, treats time as ordering evidence rather than identity, and emits shared validated findings plus explicit coverage/profile gaps.

**Tech Stack:** Rust, serde, existing CCM scanner, SCCM client intake/admission, shared SCCM key extraction, shared SCCM finding builder, SHA-256 fixture oracles.

---

### Task 1: Register policy key authority

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/models.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/keys.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/findings.rs`
- Test: `crates/cmtraceopen-parser/src/sccm/client/authority_contract_tests.rs`

- [ ] Add `PolicyId` to `SccmCorrelationKeyKind` and register `policy-client-5.00.test-v1` as the stable `ClientPolicy` profile for canonical version `5.00.TEST.0000`.
- [ ] Make stable policy extraction emit exact `AssignmentId`, `PolicyId`, `RequestId`, `StateMessageId`, and `SiteCode` keys with their admitted evidence references; a caller-assembled profile with the same label must still fail the built-in profile-shape check.
- [ ] Register only that canonical profile with finding validation and update exhaustive key ordering.
- [ ] Run the SCCM spine and client authority tests; expected result is all green with stable policy keys exact and non-policy behavior unchanged.

### Task 2: Add the sealed policy reducer

**Files:**
- Create: `crates/cmtraceopen-parser/src/sccm/client/policy.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/admission.rs`

- [ ] Export `analyze_client_policy(bundle, assessment, payloads) -> Result<SccmPolicyAnalysis, SccmPolicyError>`; do not accept normalized evidence, profiles, keys, or findings from callers.
- [ ] Call `admit_client_evidence` before reduction and use only its sealed evidence/key accessors for facts. Permit sealed non-comparable timestamp provenance to remain evidence, but never use it for causal ordering.
- [ ] Parse the closed phases `Request`, `Download`, `TransferAuth`, `Persist`, `Schedule`, `Evaluate`, and `Report` only from admitted CCM records containing one exact assignment/policy pair. Treat request IDs as optional transaction metadata and never synthesize unresolved values.
- [ ] Reduce exact-key facts deterministically: later comparable same-phase success may recover an earlier failure; equal/non-comparable opposing outcomes are contradictory; phase inversion fails closed; time alone never joins records.
- [ ] Emit last confirmed phase, exact terminal evidence, bounded next artifacts, explicit absent/capped/profile gaps, and collision-resistant observation identities containing artifact and physical line provenance.
- [ ] Use `SccmFindingBuilder` for every finding. Confirmed failures include `SccmTerminalEvidence::observed_failure`; incomplete findings include shared coverage gaps and requests; successful cycles emit no finding.

### Task 3: Drive the complete preparation corpus through production

**Files:**
- Create: `crates/cmtraceopen-parser/tests/sccm_client_policy.rs`
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/policy/*/manifest.json`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/policy/production-oracles.json`

- [ ] Build canonical intake bundles from every committed policy preparation manifest, bind each retained complete payload to its exact byte length and SHA-256, assess it, and invoke the exported analyzer.
- [ ] Compare the complete serialized production output for every fixture to `production-oracles.json`; also reverse artifact and payload order and require byte-for-byte identical JSON.
- [ ] Assert the acceptance states: completed cycle, request/transfer authentication failure, download/persist/evaluate/report terminal failures, scheduler deferral, recovery, missing policy-state coverage, contradictory outcomes/offsets, multiline framing, rotation split, and unvalidated malformed input.
- [ ] Add focused no-assignment, stale-assignment, and corrupt-processing coverage without expanding into application enforcement or update-install outcomes.

### Task 4: Add adversarial authority gates

**Files:**
- Test: `crates/cmtraceopen-parser/tests/sccm_client_policy.rs`

- [ ] Mutate a canonical post-intake assessment, payload digest/bytes, profile version, evidence ordering, exact keys, and physical line identity; each authority mutation must fail closed or remain source-local.
- [ ] Prove two exact-key transactions at the same instant remain separate and two observations on the same artifact/line cannot collide.
- [ ] Prove unkeyed records at matching timestamps never enter a transaction and public JSON contains neither raw paths nor client/management-point handles.

### Task 5: Verify and freeze

**Files:**
- Verify only the issue-scoped files above.

- [ ] Run the focused policy suite and the committed policy preparation contract.
- [ ] Run client intake, admission, authority/spine, and full parser tests.
- [ ] Run `cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown`.
- [ ] Run `cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings`.
- [ ] Run scoped `rustfmt --check`, JSON validation, and `git diff --check`.
- [ ] Commit exactly one clean issue-scoped production slice and return its frozen SHA and evidence pack without claiming acceptance.
