# SCCM Diagnostics Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a pure-Rust, evidence-first SCCM diagnostic layer that explains a client or server workflow with cited evidence, explicit coverage gaps, and conservative confidence.

**Architecture:** Keep CCM as the reusable raw record grammar. Add SCCM artifact classification, normalized evidence, version-aware keys, transactions, rules, and findings in the parser crate; keep all Windows collection and workspace presentation in native/UI layers. Ship the program as independently reviewable vertical slices, then join only validated client/server pairs.

**Tech Stack:** Rust 1.88, Cargo workspace, cmtraceopen-parser, cmtrace-open Tauri backend, serde, serde_json, chrono, regex, standard Rust tests, existing collector/bundle infrastructure, native Windows test host for collection validation.

## Global Constraints

- The parser crate must remain pure Rust and compile for wasm32-unknown-unknown.
- Do not add filesystem, Windows API, Tauri, async runtime, event-log, WMI, registry, database, or network dependencies to cmtraceopen-parser.
- Reuse the CCM parser as the raw grammar. Do not add SCCM-specific ParserKind values solely because a source uses CCM syntax.
- Every diagnosis must distinguish symptom, confirmed failure, blocked/deferred state, likely contributor, and insufficient evidence.
- Every diagnosis must carry evidence references, scope/role, phase, severity, confidence, stable correlation keys, and a minimal next-artifact request.
- Missing, access-denied, capped, skipped, malformed, and unsupported sources are explicit coverage states. Absence never proves a success or a failure.
- Run identifier, signal, and correlation extraction only after logical-record framing. Never derive a finding from a physical-line fragment.
- Use UTC-normalized ordering only when the source record has a valid offset; retain original timestamp text and offset for display.
- Treat key patterns as versioned heuristics. Preserve reported ConfigMgr version where available and downgrade unknown/unvalidated patterns rather than guessing.
- Do not commit customer logs, tenant data, real hostnames, user names, SIDs, serials, secrets, deployment IDs, or private domains. Use synthetic/sanitized fixtures with obvious test values.
- Preserve public serialized field compatibility. New SCCM types are additive and use camelCase serde names.
- Make each production behavior change through a demonstrated red-green test cycle.
- Keep SCCM plans and source changes isolated on branch codex/parser-family-skeleton until a separately approved implementation branch is created.
- Native Windows is the acceptance boundary for source discovery, bundle capture, registry exports, and rotated-log collection. macOS can verify pure parser behavior only.

---

## Program File Structure

The individual plans below own the implementation detail. This file is the program contract and review sequence.

| Plan | Issues | Owns |
| --- | --- | --- |
| 2026-07-30-sccm-diagnostic-spine.md | #318 | Parser-owned common models, privacy-aware evidence, typed signals, source catalog, classification, and test corpus primitives. |
| 2026-07-30-sccm-client-intake-and-core.md | #319, #320, #321, #322, #323 | Client collection, health/location, policy, app/content, and update transaction analyzers. |
| 2026-07-30-sccm-client-extended.md | #324, #325, #326 | Task Sequence, inventory/compliance/metering, and co-management/scripts/notification analyzers. |
| 2026-07-30-sccm-server-intake-and-core.md | #335, #327, #328, #329, #330 | Server role intake plus site core, MP, DP/content, and SUP/WSUS analyzers. |
| 2026-07-30-sccm-server-extended.md | #331, #332, #334 | Hierarchy/replication, Provider/Admin Service, and advanced-role source-contract catalog. |
| 2026-07-30-sccm-cross-side-correlation.md | #333 | Pairwise client-to-MP and client-to-DP correlation, then incremental expansion. |

## Dependency and Review Graph

~~~text
#318 shared diagnostic spine
  |
  +--> #319 client intake --> #320 health/location
  |                       +--> #321 policy
  |                       +--> #322 apps/content
  |                       +--> #323 updates
  |                       +--> #324 TS / #325 inventory / #326 management
  |
  +--> #335 server intake --> #327 site core
                        +--> #328 MP
                        +--> #329 DP/content
                        +--> #330 SUP/WSUS
                        +--> #331 hierarchy
                        +--> #332 Provider/Admin Service
                        +--> #334 advanced-role contracts

validated #321 + #328 --------------> #333 policy-to-MP correlation
validated #322 + #329 --------------> #333 content-to-DP correlation
validated #323 + #330 --------------> #333 update/SUP correlation expansion
~~~

## Program-Level Review Gates

### Gate A: Shared Contract Gate

- [ ] Confirm #318 supplies serializable SCCM models without importing native dependencies.
- [ ] Confirm all required coverage states round-trip through JSON and preserve stable names.
- [ ] Confirm evidence IDs are deterministic for the same sorted artifact bundle.
- [ ] Confirm redaction maintains correlation-safe handles while withholding raw user/context values.
- [ ] Confirm unknown signal tokens are preserved as signals rather than discarded because they are absent from error_db.
- [ ] Confirm a malformed or unknown-version key extraction lowers confidence and emits a coverage/evidence gap.

### Gate B: Intake Gate

- [ ] Confirm #319 collects the named client core bundle plus current and rotated logs deterministically.
- [ ] Confirm #335 records host/role/path provenance and does not report a missing default path as a broken role.
- [ ] Confirm a deliberately incomplete captured bundle emits coverage states for every expected source.
- [ ] Confirm no collector test requires a customer environment; native validation uses an explicit developer-supplied SCCM lab.

### Gate C: Workflow Gate

- [ ] Each workflow has at least one completed, one confirmed terminal, one blocked/deferred, one contradictory, one incomplete, one rotation, and one malformed fixture scenario.
- [ ] Each high-confidence finding cites the terminal/corroborating evidence. A red log entry alone may create only a symptom.
- [ ] Each workflow returns the last confirmed successful phase and the smallest next artifact bundle when evidence stops.
- [ ] Each workflow passes pure parser tests on macOS and its native collection validation on the development SCCM server/client when that lab becomes available.

### Gate D: Cross-Side Gate

- [ ] #333 starts with independently testable policy-to-MP and content-to-DP pairs.
- [ ] Cross-side joins require stable compatible keys and role topology; time-only joins remain low confidence.
- [ ] Conflicting timestamp, invalid offset, missing source, and unrelated same-minute server-error fixtures never result in a high-confidence cause.
- [ ] The correlation output remains usable for a client-only or server-only bundle and names the missing counterpart evidence.

## Program Tasks

### Task 1: Establish the common diagnostic spine before any workflow module

**Plan:** 2026-07-30-sccm-diagnostic-spine.md

**Issue:** #318

- [ ] Execute every task in the spine plan through its parser-only verification command.
- [ ] Review serialized JSON snapshots for schema stability, redaction, and no accidental raw context export.
- [ ] Commit only files owned by #318 with a focused message such as feat(sccm): add diagnostic evidence contracts.
- [ ] Update #318 with fixture/test evidence and the exact commit after native-independent verification passes.

### Task 2: Run client and server intake foundations in parallel after the spine lands

**Plans:** 2026-07-30-sccm-client-intake-and-core.md and 2026-07-30-sccm-server-intake-and-core.md

**Issues:** #319 and #335

- [ ] Start client intake only after the artifact/coverage types from #318 are public and tested.
- [ ] Start server intake only after the same shared types are public and tested.
- [ ] Keep native collection changes segregated by client versus server artifact roots to prevent role assumptions leaking across products.
- [ ] On the development SCCM server, capture only synthetic/lab incident evidence and produce sanitized fixture manifests before committing fixture data.
- [ ] Do not close either intake issue until a deliberately incomplete bundle proves explicit coverage behavior.

### Task 3: Deliver client workflows in value order

**Plans:** 2026-07-30-sccm-client-intake-and-core.md and 2026-07-30-sccm-client-extended.md

**Issues:** #320 through #326

- [ ] Land health/location first for the clearest prerequisite vocabulary, but keep analyzer implementation dependencies at #318/#319 unless a reviewed public fact contract adds a real dependency.
- [ ] Land policy early so applications/content and updates can consume validated policy facts when present; neither #322 nor #323 may require policy output to remain conservative on a partial bundle.
- [ ] Land application/content and updates as separate transactions; share only the common models and utility extractors.
- [ ] Land Task Sequence after transaction boundaries are proven; its relocation and execution-instance contract needs separate review.
- [ ] Land inventory/compliance/metering and client-management work as scoped state machines, not catch-all parsers.

### Task 4: Deliver server workflows in role order

**Plans:** 2026-07-30-sccm-server-intake-and-core.md and 2026-07-30-sccm-server-extended.md

**Issues:** #327 through #332 and #334

- [ ] Land site core/status early so role health evidence can qualify later downstream review, but do not make MP/DP/SUP parser implementation wait unless they consume an approved public context fact.
- [ ] Land MP and DP/content as independent role analyzers so the two first #333 pairs can proceed as soon as their own client/server contracts are stable.
- [ ] Land DP/content and SUP as separate role analyzers with independent content/update identifiers.
- [ ] Land hierarchy/replication and Provider/Admin Service after the role-specific transaction model is stable.
- [ ] Keep #334 a catalog/fixture gate. Open a dedicated advanced-role implementation issue only after a verified source grammar and terminal-state contract exist.

### Task 5: Deliver cross-side correlation incrementally

**Plan:** 2026-07-30-sccm-cross-side-correlation.md

**Issue:** #333

- [ ] Begin policy-to-MP correlation after #321 and #328 are independently verified.
- [ ] Begin content-to-DP correlation after #322 and #329 are independently verified.
- [ ] Add software-update/SUP correlation only after #323 and #330 are independently verified.
- [ ] Require one review focused solely on false-causality defenses before adding any new cross-side rule family.

## Standard Verification Commands

Run the narrowest command while implementing each task, then run the relevant aggregate checks before its commit:

~~~bash
cargo test -p cmtraceopen-parser
cargo test -p cmtrace-open --test esp_diagnostics_sources
cargo test -p cmtrace-open --test parser_expanded_corpus
cargo fmt --check --all
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git diff --check
~~~

Run Windows-only collector/source checks on the SCCM lab only after the pure parser suite is green. Record the lab Configuration Manager version, role topology, capture time zone, synthetic scenario, and redaction procedure in the fixture metadata; never record credentials or live customer identifiers.

## Completion Definition

- [ ] Every issue has a committed plan-backed implementation, code review, and linked fixture/test evidence.
- [ ] Every analyzer is conservative by construction and produces evidence-backed output on incomplete bundles.
- [ ] Dedicated SCCM Client and Server workspace work starts only after the shared snapshot/finding API has at least one stable client and one stable server workflow plus a stable correlated pair.
