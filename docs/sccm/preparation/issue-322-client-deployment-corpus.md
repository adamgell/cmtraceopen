# Issue #322 client deployment/content corpus preparation

## Purpose and dependency boundary

This slice prepares the application, package, and content behavior contract
from Task 6 of the SCCM Client intake/core plan. It contributes a direct fixture
contract plus a fully synthetic corpus; it does **not** add a production
reducer, native collector, or speculative shared model. Every expected output
is marked `proposedPending318And319` until #318 publishes the shared diagnostic
types and #319 freezes the client physical-artifact and manifest interfaces.

The future deployment reducer must be independently callable. It consumes
normalized deployment evidence, not the output of the policy reducer. The
`success` scenario deliberately records `client-policy-agent` as `absent` and
still reaches Report from its own cited evidence. Conversely, no scenario uses
missing policy coverage to manufacture a deployment conclusion.

## Deployment state and evidence contract

```text
Intent -> Requirements -> LocateContent -> Transfer -> Cache -> Enforce -> Detect -> Report
```

Each phase advances only on a complete, profile-recognized record for the same
validated transaction key. A terminal requirement or dependency record stops
before LocateContent. Transfer, cache, enforcement, detection, and reporting
remain distinct outcomes. In particular:

- a content request without a complete response is a client LocateContent gap,
  not evidence that a distribution point lacks content;
- a terminal BITS record is a client Transfer failure and retains its job key;
- a terminal cache record is a Cache failure, not a rewritten Transfer result;
- a nonzero exit is high-confidence only here because the same exact
  AppEnforce record is explicitly terminal;
- a false post-enforcement detection record is a detection symptom, not proof
  that installation or content delivery caused it; and
- an explicit not-applicable intent is `notTargeted`, not failure.

Every nonterminal gap names the smallest bounded client source family to
collect next. Missing, access-denied, capped, and partial sources remain
coverage states.

## Sources and physical identity

| Design-only catalog entry | Synthetic basenames | Responsibility |
| --- | --- | --- |
| `client-app-intent` | `AppIntentEval.log`, `AppDiscovery.log` | Intent, requirements, dependencies, detection |
| `client-content` | `CAS.log`, `CAS.lo_`, `DataTransferService.log` | Content request/topology, transfer, cache |
| `client-app-enforce` | `AppEnforce.log` | Terminal enforcement result |
| `client-policy-state` | `StateMessage.log` | Final deployment report only |
| `client-installer-supplemental` | `InstallerSupplemental.log` | Low-confidence source-local context only |
| `client-policy-agent` | absent `PolicyAgent.log` in `success` | Explicit proof that deployment output does not depend on policy-reducer output |

Physical artifacts retain distinct artifact IDs, sanitized `SYNTHETIC://`
source paths, safe relative evidence paths, exact byte counts, encoding,
collection-limit provenance, rotation kind, and source version. Noncapture
artifacts have no invented path, encoding, or collection-limit provenance.
The canonical archived suffix is `.lo_`; `.log.lo_` is forbidden.

Complete CCM evidence is passed through the existing raw CCM grammar and
contains a `SYNTHETIC FIXTURE` marker inside a semantic record. The rotation
case intentionally splits one would-be record across `CAS.lo_` and `CAS.log`.
Both physical artifacts are marked incomplete and must remain separate. The
capped AppEnforce prefix is also incomplete and source-local.

## Versioned keys and deterministic grouping

The proposed synthetic extraction profile is
`deployment-client-5.00.test-v1`, restricted to source version prefix
`5.00.TEST.` and the declared source families. It is not a claim about a live
ConfigMgr build.

Transaction priority is:

1. exact assignment ID plus CI ID;
2. exact package/content/version only when corroborated by the assignment/CI;
3. otherwise a source-local candidate capped at low confidence.

Exact content handoff facts additionally retain package ID, content ID,
content version, correlation-safe distribution-point host handle, request ID,
explicit-offset timestamp provenance, and the exact client evidence reference.
BITS job, product code, and exit code stay transaction-local where observed.
Filename, component, display name, ingestion order, and time never create or
merge a key.

Transactions, observations, findings, provenance, and evidence references have
stable IDs/order. Reordering inputs is required to produce the same normalized
future output. The `incomplete` scenario contains two assignment/CI pairs at
the same timestamp and proves they stay separate.

## Scenario matrix

| Scenario | Expected disposition | Last successful phase | Bounded next source |
| --- | --- | --- | --- |
| `success` | Success through Report with cited detection/report evidence | Report | None |
| `not-targeted` | Explicit not-applicable classification; not a failure | None | None |
| `requirements-failure` | Confirmed requirement failure | Intent | None |
| `dependency-failure` | Confirmed dependency failure | Intent | None |
| `location-missing` | Missing content coverage; insufficient evidence | Requirements | `client-content` |
| `dp-content-missing` | Exact client request without a terminal response; no DP diagnosis | Requirements | `client-content` |
| `bits-transfer-failure` | Confirmed client Transfer failure with BITS key | LocateContent | None |
| `cache-failure` | Confirmed client Cache failure after successful Transfer | Transfer | None |
| `enforcement-exit` | Confirmed terminal AppEnforce failure; unkeyed installer text remains local | Cache | None |
| `detection-false-negative` | Detection mismatch after successful enforcement | Enforce | None |
| `rotation-boundary` | Incomplete physical fragments; low-confidence gap | Requirements | `client-content` |
| `incomplete` | Two same-time exact transactions with access-denied content and capped unkeyed enforcement | Requirements | `client-content` |

The corpus has 12 scenarios, 36 artifacts, and 33 evidence files totaling
exactly 16,840 bytes. Capture states are 32 captured, one capped, one
access-denied, and two absent. The path-and-artifact-qualified evidence content
digest is SHA-256
`da2191c7c103dfd829a5b725d8a08434229a2f36670e83185a8d279123ec3f12`.

## Supplemental and unknown evidence

Supplemental MSI, PSADT, or Burn output may later enrich a transaction only
when its provenance and stable key satisfy the reviewed #318/#319 contract.
The unkeyed installer line in `enforcement-exit` is deliberately simultaneous
with the exact AppEnforce result, yet remains `keyConfidence: none`,
`confidenceCeiling: low`, and `correlationEligible: false`. It cannot override
the SCCM phase.

Likewise, an unknown extraction profile, malformed code, incomplete logical
record, or code with no reviewed semantic mapping may be retained as cited raw
source-local evidence. It cannot be promoted into a known-code diagnosis or
an exact transaction merely because it resembles a familiar code.

## #333 content-to-DP handoff

Only six scenarios emit a proposed `clientContentRequest` fact:
`success`, `dp-content-missing`, `bits-transfer-failure`, `cache-failure`,
`enforcement-exit`, and `detection-false-negative`. Each fact carries the exact
profile-qualified package/content/version/DP-handle/request key, client
LocateContent phase, usable explicit-offset provenance, and evidence.

#333 must independently require a compatible #329 server fact, compatible
topology, usable ordering, complete coverage, and corroborating or terminal
evidence. This corpus performs no topology evaluation or cross-side
correlation. Same time, a matching display label, or a client request alone
cannot establish a distribution-point or server cause.

## Privacy and acceptance limits

All identities, keys, paths, messages, codes, and versions are deterministic
synthetic values. The site code is the three-character value `LAB`; hostnames
and topology use correlation-safe synthetic handles. The corpus contains no
customer name, user profile, SID, email, token, certificate, tenant, device
serial, deployment display name, or copied production log text.

This preparation is parser-only. It does not claim native Windows collection,
live ConfigMgr compatibility, or SCCM Server lab acceptance.

## Replay gates

Run the preparation contract and exact corpus validator:

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_deployment_fixture_contract
python3 /absolute/path/to/validate_sccm_corpus.py \
  crates/cmtraceopen-parser/tests/fixtures/sccm/client/deployment \
  --exact-bytes
```

Before merging implementation against published interfaces, also run:

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
npx tsc --noEmit
git diff --check
```

The future implementation must first map these preparation labels to the
reviewed #318/#319 contracts and request a false-causality review. Passing this
corpus alone is not an issue-closure condition.
