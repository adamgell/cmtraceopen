# SCCM Cross-Side Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Deliver issue #333 as a conservative client/server correlation layer. The first shipped pairs are policy to Management Point and content to Distribution Point. A later updates to SUP pair is gated rather than assumed.

**Architecture:** Correlation consumes normalized, role-classified SCCM evidence and workflow outputs from #318, #321/#322, and #328/#329. It builds deterministic links only when versioned exact keys, compatible topology, usable timestamp provenance, and corroborating phase or terminal evidence justify them. It returns cited links, last-known-good hops, coverage requests, and symptoms or diagnoses; it never overwrites a source analyzer, calls the network, or converts adjacent timestamps into a root cause.

**Tech Stack:** Rust 1.88, cmtraceopen-parser pure crate, serde/serde_json, BTreeMap/stable sorting, shared SCCM evidence/finding models, synthetic client/server fixture bundles. No Windows/native collection code is required beyond manifest provenance preserved by #319 and #335.

## Global Constraints

- #318 is required. Policy to MP starts only after #321 and #328 have stable public facts, keys, and fixtures. Content to DP starts only after #322 and #329 have the same. Do not make #333 wait for #330 or advanced-role work.
- This plan implements pairwise correlation only. It does not replace client/server source analyzers, add raw parsers, add a ParserKind, implement a graph database, perform live server queries, or create a workspace UI.
- Correlation must consume complete logical records and existing evidence references. It never reparses physical lines or extracts keys from a rotation fragment rejected by #318.
- Use exact profile-validated keys plus compatible topology for high-confidence joining. Time-only, filename-only, generic error-code, component-name, or same-host-name joins are not causal proof.
- A valid UTC value requires valid source offset/provenance. Missing/invalid offsets prevent cross-host causal ordering; they may only support a low-confidence local-time observation if the pair rule explicitly allows one.
- Link source artifact identity, source code file attribute, role, host/topology, path class, and capture state remain distinct. A matching CCM file= attribute never means matching captured artifact.
- Client/server keys that could carry identity or sensitive path/URL/context values must use the #318 redacted stable handle. Raw values must never appear in public link/finding/export JSON.
- A client-only or server-only bundle is a supported input. The result must identify what it can prove and request the minimum counterpart artifact/role, not return an empty result or assert a cause.
- A direct client finding and a server finding continue to exist independently. Correlation adds links and higher-confidence cross-side findings only when strict requirements pass; it must not silently rewrite source-side confidence.
- Any new pair after policy-MP/content-DP requires a source contract, pair-specific fixture matrix, and separate issue/PR or clearly scoped #333 subtask. Do not generalize from one pair to every SCCM workflow.
- Output order, link IDs, candidate explanations, coverage requests, and redacted projection must be deterministic under artifact/evidence input reordering.

---

## Dependency and Rollout Map

~~~text
#318 normalized evidence + versioned keys + coverage + redaction
  |
  +--> #321 policy client facts ----+
  |                                 +--> #333 policy <-> MP pair
  +--> #328 MP server facts --------+
  |
  +--> #322 deployment/content facts -+
  |                                    +--> #333 content <-> DP pair
  +--> #329 DP server facts ----------+
  |
  +--> #323 updates + #330 SUP ----> future pair only after a new reviewed subplan
~~~

The first two pairs are deliberately independent. Land a generic topology/link contract first, then policy-MP and content-DP as separate commits/tests. Each pair receives a false-causality review on its own. If #321/#328 or #322/#329 changes a public key/provenance contract, amend that upstream plan before implementing a workaround in #333.

## File Structure and Ownership

~~~text
crates/cmtraceopen-parser/
├── src/sccm/
│   ├── models.rs                          # shared correlation wire types only if #318 owns them
│   ├── findings.rs                        # shared validation; do not duplicate it here
│   └── correlation/
│       ├── mod.rs                         # public correlation facade
│       ├── topology.rs                    # role/host/site/path compatibility checks
│       ├── link.rs                        # generic deterministic link candidate builder/ranker
│       ├── rules.rs                       # common evidence/coverage/confidence guards
│       ├── policy_management_point.rs     # #321 + #328 pair rules
│       └── content_distribution_point.rs  # #322 + #329 pair rules
├── tests/
│   ├── sccm_correlation_contract.rs
│   ├── sccm_correlation_policy_management_point.rs
│   ├── sccm_correlation_content_distribution_point.rs
│   └── fixtures/sccm/correlation/
│       ├── README.md
│       ├── shared/<scenario>/
│       ├── policy_management_point/<scenario>/
│       └── content_distribution_point/<scenario>/
~~~

No files in src-tauri are needed for semantic correlation. Native work merely preserves manifest topology, role, host, path, and coverage needed by these pure inputs. Do not add cross-side logic to the client or server intake modules; source modules expose safe facts and correlation owns joins.

## Public Correlation Contract

Expose one small public entry point and a serializable result. Exact field names belong to the #318 schema review, but the behavior contract is fixed here:

~~~rust
pub fn correlate_client_server(
    bundle: &SccmNormalizedBundle,
) -> SccmCorrelationResult;

pub struct SccmCorrelationResult {
    pub schema_version: u32,
    pub links: Vec<SccmCorrelationLink>,
    pub findings: Vec<SccmFinding>,
    pub coverage_gaps: Vec<SccmCoverageGap>,
    pub artifact_requests: Vec<SccmArtifactRequest>,
}

pub struct SccmCorrelationLink {
    pub link_id: String,
    pub workflow: SccmCorrelationWorkflow,
    pub strength: SccmLinkStrength,
    pub topology: SccmTopologyCompatibility,
    pub matched_keys: Vec<SccmCorrelationKey>,
    pub client_evidence: Vec<SccmEvidenceRef>,
    pub server_evidence: Vec<SccmEvidenceRef>,
    pub ordering: SccmCorrelationOrdering,
    pub reason: String,
}
~~~

Required link strengths and their maximum conclusions:

| Link strength | Minimum proof | Maximum output |
| --- | --- | --- |
| ExactCorroborated | exact validated keys, compatible topology, usable ordering when order is asserted, terminal/corroborating facts | high-confidence cross-side diagnosis or confirmed last good hop |
| ExactPartial | exact validated keys but missing coverage/terminal/ordering evidence | linked symptom, low/medium contributor, specific counterpart request |
| Candidate | compatible role plus low-confidence candidate key or time neighborhood | low-confidence candidate/symptom only; never root cause |
| Incompatible | conflicting keys/topology/version/role | no causal link; optional diagnostic explanation/coverage request |
| Unlinked | no safe association | source-local analysis remains; bounded counterpart request only when it resolves a concrete question |

The code must prevent a caller from constructing a high-confidence cross-side finding from Candidate, Incompatible, or Unlinked strength. This is a testable validation invariant, not reviewer convention.

## Pairwise Evidence Requirements

### Policy to Management Point

Client #321 emits validated policy/assignment/request/client/site/MP facts with phase and evidence refs. Server #328 emits validated request/policy/client/site/MP facts with phase and evidence refs. A high-confidence link requires:

1. exact common policy/assignment/request key according to a shared profile;
2. compatible site/MP topology, including selected/observed MP where evidence permits;
3. client request/response and server receive/auth/policy/response facts that do not contradict each other;
4. valid ordering provenance whenever the finding claims first failed hop or client-before-server sequence;
5. sufficient required client and MP source coverage;
6. terminal/corroborating evidence for a cross-side confirmed failure.

If an exact policy key matches but the MP host/site is incompatible, emit Incompatible and explain topology mismatch without blaming either host. If the client has a request failure and no MP capture, return client-side fact plus a request for the named MP artifact group, not an MP failure.

### Content to Distribution Point

Client #322 emits validated assignment/CI/package/content/version/DP/transfer facts. Server #329 emits package/content/version/DP distribution/validation/serve facts. A high-confidence link requires:

1. exact normalized content/package identity plus version where the profile says version is significant;
2. compatible DP topology/host or explicit distribution mapping;
3. client location/transfer and server content availability/serve facts that belong to the same content/DP;
4. usable ordering when sequencing is asserted;
5. required client-content and DP coverage;
6. terminal/corroborating evidence for a cross-side confirmed failure.

Matching content ID but a different version or DP is Incompatible, not a weak success/failure. A client BITS/cache/enforcement failure with no compatible DP fact stays client-local. A DP distribution error with no client request stays server-local.

## Task 1: Add cross-side models and negative-contract tests

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/correlation/mod.rs
- Create: crates/cmtraceopen-parser/src/sccm/correlation/rules.rs
- Modify: crates/cmtraceopen-parser/src/sccm/mod.rs
- Modify: crates/cmtraceopen-parser/src/sccm/models.rs only when #318 has approved shared correlation wire types
- Create: crates/cmtraceopen-parser/tests/sccm_correlation_contract.rs
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/README.md
- Create shared fixtures client-only, server-only, same-time-no-key, conflicting-key, invalid-offset, unknown-profile, rotation-split, reordered-input, and redaction

**Consumes:** #318 public evidence/coverage/key/timestamp/finding/redaction contracts and stable upstream workflow fact interfaces.

**Produces:** Correlation model/API skeleton and non-negotiable safety validation before any workflow pair logic exists.

- [ ] **Step 1: Write failing public-import and safety tests**

Test that public API/result types exist, carry a schema version, and preserve deterministic ordering. More importantly, write tests that must fail until guards exist:

  - Candidate, Incompatible, and Unlinked links cannot build a High confidence ConfirmedFailure;
  - a link with missing/invalid timestamp offset cannot claim causal ordering;
  - an exact key from an unknown/unvalidated extraction profile cannot be promoted to ExactCorroborated;
  - raw user/context/path/token-like test markers do not appear in redacted result JSON;
  - client-only and server-only inputs produce coverage/artifact request output with no fabricated cross-side finding;
  - reordering artifact/evidence input produces identical serialized output.

- [ ] **Step 2: Run the contract target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract
~~~

Expected: FAIL because correlation modules/types/validation do not exist.

- [ ] **Step 3: Implement minimal types, facade, and validation invariants**

Create private generic constructors/rules in rules.rs and public re-exports in mod.rs. The initial correlation function may return source-independent coverage/no-link results, but it must not add pair behavior. Use shared SccmFindingBuilder validation or extend it in one controlled shared change; do not copy finding validation into the correlation directory.

Use deterministic identifiers based on schema version, workflow, sorted safe keys, stable evidence IDs, and topology handles. Do not use wall clock/random UUIDs. Make a public redacted export projection immutable: projection must not mutate the original result/snapshot.

- [ ] **Step 4: Make contract tests green**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
~~~

- [ ] **Step 5: Commit cross-side safety boundary**

~~~bash
git add crates/cmtraceopen-parser/src/sccm crates/cmtraceopen-parser/tests/sccm_correlation_contract.rs crates/cmtraceopen-parser/tests/fixtures/sccm/correlation
git commit -m "feat(sccm): add correlation safety contract"
~~~

## Task 2: Implement topology compatibility and generic link construction

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/correlation/topology.rs
- Create: crates/cmtraceopen-parser/src/sccm/correlation/link.rs
- Modify: crates/cmtraceopen-parser/src/sccm/correlation/mod.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_correlation_contract.rs
- Add shared fixtures matching-topology, missing-topology, incompatible-mp, incompatible-dp, same-content-different-version, and same-minute-unrelated

**Consumes:** #318 artifact role/host/site/provenance, shared key profile metadata, upstream workflow facts.

**Produces:** A generic, pair-agnostic compatibility/link mechanism that reports why a potential join is exact, partial, candidate, or incompatible.

### Compatibility ordering

Evaluate joins in this deterministic order:

1. verify client/server roles are eligible for the requested pair;
2. verify source/profile version compatibility;
3. compare exact normalized required keys;
4. compare topology constraints: site, selected server/role, DP host, content version as pair requires;
5. examine capture/coverage/rotation completeness;
6. examine timestamp ordering only if both sides supply valid UTC provenance;
7. classify strength and reason;
8. produce deterministic link/finding/request ordering.

A later step can lower a strength but may never repair a failed earlier key/topology requirement through time proximity.

- [ ] **Step 1: Add red compatibility tests**

Assert exact key plus compatible topology creates a candidate eligible for ExactPartial; exact key plus missing topology stays partial; exact key plus incompatible MP/DP/version is Incompatible; same time/role without key is Candidate at most; stale/unknown profile cannot receive an exact strength; and required coverage gaps lower strength/request counterpart source.

- [ ] **Step 2: Run red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract topology_and_link_strength
~~~

- [ ] **Step 3: Implement topology compatibility types and link ranker**

Use explicit topology outcomes such as Compatible, CompatibleButIncomplete, Unknown, and Incompatible with a bounded reason code. Normalize host/site identity through shared privacy-safe key facilities, not direct lowercase raw string comparisons in every pair module. Link ranker input includes workflow, roles, exact/candidate key matches, topology, coverage, ordering provenance, and source fact terminality. Use BTreeMap/sort by stable key to group/emit links.

- [ ] **Step 4: Verify and commit generic link mechanics**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/correlation crates/cmtraceopen-parser/tests/sccm_correlation_contract.rs crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/shared
git commit -m "feat(sccm): rank topology-aware evidence links"
~~~

## Task 3: Implement policy to Management Point correlation

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/correlation/policy_management_point.rs
- Modify: crates/cmtraceopen-parser/src/sccm/correlation/mod.rs
- Create: crates/cmtraceopen-parser/tests/sccm_correlation_policy_management_point.rs
- Create fixtures policy_management_point/healthy, client-request-no-server, server-auth-failure, server-policy-failure, same-time-no-key, assignment-mismatch, topology-mismatch, missing-offset, rotation-split, unknown-profile, contradictory-recovery, and reordered-input
- Modify #321/#328 fixture helpers only if a public fact contract mismatch is demonstrated; do not duplicate their private parsing rules

**Consumes:** #321 policy transactions/facts and #328 MP transactions/facts, generic link/topology contracts from Task 2.

**Produces:** Cited policy-MP links, policy-specific cross-side findings, last successful hop, and minimum counterpart artifact requests.

### Pair state contract

~~~text
ClientRequest -> MPReceive -> MPAuthenticate -> MPResolvePolicy -> MPRespond -> ClientPersistOrSchedule
~~~

The pair result may report the last proven hop only when each adjacent hop is linked by exact/common keys and compatible topology. If source coverage stops between two phases, it must state the gap rather than use the nearest error as the cause.

- [ ] **Step 1: Write full policy-MP fixture tests before rules**

Required expected outcomes:

  - healthy flow with an ExactCorroborated link and cited client/server evidence;
  - client request failure with no server capture returns client-local finding plus named MP request, not server failure;
  - MP auth failure after a proven client request and compatible exact key/topology produces high-confidence cross-side diagnosis only with terminal MP evidence;
  - MP policy response failure after successful auth preserves MP last good hop;
  - same-time/no-key logs remain a Candidate symptom and never a root cause;
  - assignment/request key mismatch, site/MP topology mismatch, missing/invalid offset, unknown profile, and rotation split cannot produce ExactCorroborated;
  - a later compatible server/client success shows recovery only for same exact pair key;
  - input order does not change serialized links/findings.

- [ ] **Step 2: Run policy-MP target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_policy_management_point
~~~

- [ ] **Step 3: Implement policy-MP fact adapter and pair rules**

Consume public source facts/transactions rather than matching raw message text. Require the shared profile to say which common key combinations are valid. Build one candidate set per exact policy/request key and topology. Derive pair phases, last successful hop, and findings via shared validation. Link to source findings/evidence instead of copying message/raw values.

When no matching server fact exists, examine MP coverage. If unavailable, request only relevant MP source group such as server-mp-auth or server-mp-policy. If server records are present but mismatch key/topology, emit an incompatibility reason—do not request generic additional server logs unless a bounded missing source would genuinely resolve it.

- [ ] **Step 4: Add false-causality and redaction checks**

Explicitly assert that a nearby MP error from a different assignment/client/site does not modify target client transaction; an unrelated IIS 500-like record cannot establish policy failure; raw context/caller/host markers are absent from exported correlation JSON; and a client-only policy success cannot be downgraded merely because server capture contains unrelated failures.

- [ ] **Step 5: Verify, commit, and issue handoff**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_policy_management_point
cargo test --locked -p cmtraceopen-parser --test sccm_client_policy
cargo test --locked -p cmtraceopen-parser --test sccm_server_management_point
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/correlation crates/cmtraceopen-parser/tests/sccm_correlation_policy_management_point.rs crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/policy_management_point
git commit -m "feat(sccm): correlate policy and management point evidence"
~~~

Update #333 and link #321/#328 with fixture/profile/key scope and an explicit no-time-only statement.

## Task 4: Implement content to Distribution Point correlation

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/correlation/content_distribution_point.rs
- Modify: crates/cmtraceopen-parser/src/sccm/correlation/mod.rs
- Create: crates/cmtraceopen-parser/tests/sccm_correlation_content_distribution_point.rs
- Create fixtures content_distribution_point/healthy, client-location-no-dp, client-transfer-failure, dp-distribution-failure, dp-validation-failure, content-version-mismatch, dp-topology-mismatch, same-time-no-key, missing-offset, rotation-split, unknown-profile, contradictory-recovery, and reordered-input

**Consumes:** #322 deployment/content facts and #329 DP content facts, generic link/topology rules.

**Produces:** Cited content-DP links, conservative last-hop outputs, and no DP root-cause claim unless a compatible exact pair supports it.

### Pair state contract

~~~text
ClientLocateContent -> DPContentAvailable -> ClientTransferStart -> DPServeOrObserve -> ClientCache -> ClientEnforce
~~~

This is a correlation view, not a replacement for either source state machine. The DP may not observe a precise client transfer/serve event in all deployments; absence of that server observation lowers confidence/creates a request. It must not force an impossible full end-to-end link.

- [ ] **Step 1: Write content-DP fixture tests first**

Test:

  - healthy compatible content/version/DP evidence produces ExactCorroborated or an explicitly defined ExactPartial if expected server confirmation is not available;
  - client location failure with absent DP evidence requests the named DP artifact and does not call it DP failure;
  - client transfer/cache failure remains client-local when DP availability is proven;
  - terminal DP distribution/validation failure plus compatible client content request yields a high-confidence server-side block only if coverage/keys/topology/order satisfy rules;
  - same content ID but different version or DP gives Incompatible;
  - same-minute generic transfer/DP errors stay Candidate;
  - missing offset, rotation split, unknown profile, conflicting recovery, and reordered input never produce a false high-confidence result.

- [ ] **Step 2: Run target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_content_distribution_point
~~~

- [ ] **Step 3: Implement content/DP fact adapter and pair rules**

Use only exact normalized content/package/version/DP keys admitted by shared profiles. Make content version requirement explicit by profile; never assume an unversioned ID is sufficient. Validate DP topology against client selected/located DP when available. Model server role availability/validation facts separately from client transfer/cache/enforce. Generate a cross-side finding only when an exact pair establishes a meaningful boundary; otherwise preserve source-local outcomes and add bounded counterpart request.

- [ ] **Step 4: Add adversarial multi-content/multi-DP tests**

Add fixture cases with two deployments using the same content name but different IDs, same content ID across versions, two DPs, two client transactions in the same minute, and an unrelated server failure. Assert no shared transaction/link/finding exists beyond exact compatible pairs.

- [ ] **Step 5: Verify, commit, and record pair limits**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_content_distribution_point
cargo test --locked -p cmtraceopen-parser --test sccm_client_deployment
cargo test --locked -p cmtraceopen-parser --test sccm_server_distribution_point
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/correlation crates/cmtraceopen-parser/tests/sccm_correlation_content_distribution_point.rs crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/content_distribution_point
git commit -m "feat(sccm): correlate content and distribution point evidence"
~~~

Update #333 with exact supported content/version/topology profile and leave client transfer/cache versus server-availability limits explicit.

## Task 5: Establish a controlled extension gate for later correlation pairs

**Files:**

- Modify: crates/cmtraceopen-parser/src/sccm/correlation/rules.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_correlation_contract.rs
- Modify: GitHub issue #333 with a subtask checklist or link individual future pair issues
- Do not create updates/SUP pair code in this task

**Consumes:** Shipping policy-MP/content-DP pair contract and #323/#330 only as future upstream contracts.

**Produces:** A repeatable pair-admission checklist that blocks accidental generic correlation expansion.

- [ ] **Step 1: Write a pair registry test**

Add a private/typed pair registry declaring supported pairs. Test that an unregistered workflow combination returns a no-link/coverage result and cannot invoke a generic all-matching-keys join. Test that every registered pair declares required client/server role, exact key types, topology constraints, source coverage requirements, ordering policy, terminal proof condition, and fixture directory.

- [ ] **Step 2: Run red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract pair_registry
~~~

- [ ] **Step 3: Implement pair registry and extension checklist**

Keep policy-MP and content-DP as the only RuleValidated pairs. Add an explicit Candidate entry for updates-SUP only if #323/#330 have defined compatible upstream facts; Candidate cannot run correlation. The checklist for promotion requires a planned pair module, success/failure/incomplete/adversarial fixtures, version/key profile, topology rules, privacy review, and independently passing source analyzers.

- [ ] **Step 4: Verify and commit**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_policy_management_point
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_content_distribution_point
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/correlation crates/cmtraceopen-parser/tests/sccm_correlation_contract.rs
git commit -m "feat(sccm): gate correlation pair expansion"
~~~

## Task 6: Run #333 release and review gates

**Files:**

- Modify: crates/cmtraceopen-parser/README.md only if public API documentation is needed after implementation
- Modify: GitHub #333 with pair-specific evidence, tests, fixtures, and known limits
- Modify CI only when existing focused tests are stable; correlation itself requires no live service

**Consumes:** All correlation tasks plus independently green upstream source analyzer suites.

**Produces:** A reviewable correlation release that is explicit about what is proven, what is merely linked, and what remains unlinked.

- [ ] **Step 1: Run every focused source/correlation suite**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_policy_management_point
cargo test --locked -p cmtraceopen-parser --test sccm_correlation_content_distribution_point
cargo test --locked -p cmtraceopen-parser --test sccm_client_policy
cargo test --locked -p cmtraceopen-parser --test sccm_server_management_point
cargo test --locked -p cmtraceopen-parser --test sccm_client_deployment
cargo test --locked -p cmtraceopen-parser --test sccm_server_distribution_point
cargo test --locked -p cmtraceopen-parser
~~~

- [ ] **Step 2: Run compatibility and static analysis gates**

~~~bash
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
~~~

- [ ] **Step 3: Perform a dedicated false-causality review**

Review adversarial fixtures before approving #333: same time/no key; exact key/different topology; exact content/different version; missing/invalid offset; unknown profile; rotation split; partial capture; unrelated terminal server error; client-only; server-only; and reordering. A reviewer must be able to point to a test that prevents each unsafe high-confidence conclusion.

- [ ] **Step 4: Inspect public JSON and redaction projection**

Serialize a healthy pair, terminal pair, incomplete pair, and incompatible pair. Check schema version, deterministic IDs/order, cited evidence, confidence ceiling, last good hop, missing counterpart request, no raw user/context/path/host secrets, and source findings unchanged by correlation. Verify redacted projection does not mutate internal result.

- [ ] **Step 5: Report issue closure evidence by pair**

For policy-MP, report exact keys/profile/topology/fixtures and coverage limits. For content-DP, report content/version/DP topology scope and client-transfer versus server-availability limits. List updates-SUP only as a gated future candidate if applicable. Keep #333 open if either first pair lacks a required adversarial fixture or a source contract has not stabilized.

## Exit Criteria

- [ ] Cross-side code uses only registered RuleValidated pairs.
- [ ] Policy-MP and content-DP outcomes have healthy, terminal, incomplete, incompatible, unknown-profile, invalid-offset, rotation, and reordering fixtures.
- [ ] Candidate/time-only/incompatible/unlinked evidence cannot generate high-confidence causal findings.
- [ ] Client-only/server-only results remain useful and request minimal counterpart evidence.
- [ ] Public JSON is deterministic, cited, redacted, and additive; source analysis remains intact.
- [ ] Future pair expansion is blocked until a dedicated source/key/topology/fixture review passes.
