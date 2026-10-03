# Issue #356: canonical ownership and privacy foundation sequence

Status: implementation authorized by Adam; independent Slice A design review approved on 2026-10-03. Slice C requires its own field-level design review before code.
Base: remote main `5ab640a37b6225db271f446ae312d60d2f206d33`, verified 2026-10-03.
Owner: this isolated lane; backlog coordinator owns #645/#661 narrow fixes and all merges.

## Governing contract and scope

Follow the accepted 2026-08-29 closeout design, Phase 0 steps 5–7, and ADR-004 Revision 2. No compatibility API, raw-result convenience path, old-token reader, or dual replay schema. This program does not close #356 or establish native acceptance merely by passing parser tests.

Current source still exports flat IME modules and crate-root ESP, contains `ParsedEspEventBatch`, scans manifest-less captured bundles, and registers the ESP-only relaunch compatibility command. Those prerequisites must land before the privacy consumer. Remote open PRs and registered worktrees show no competing foundation owner; parent confirms sole ownership. #645/#661 remain held for this sequence.

## Slice A — canonical ownership and assigned deletions

Deliver a separate reviewable PR before privacy implementation. Preserve reducer behavior, existing redaction API behavior, and log entry compatibility except for the explicitly deleted bundle fallback and relaunch wire.

1. Add failing architecture tests for canonical public imports and absence of assigned obsolete modules/wires. Add an exemplar-derived native test: a directory containing the existing Autopilot configuration specimen but no manifest yields `bundle.manifest` Missing coverage and no inferred identity; it must not walk or parse undeclared artifacts. Keep malformed/denied manifests as distinct existing coverage states.
2. Move app-owned IME event tracking, downloads, policies, timeline, models and registry under `intune::apps::windows::ime`. Move ESP to `intune::enrollment::windows::esp`; update every Rust consumer, test, benchmark, rustdoc link and native re-export. Remove old root/flat declarations instead of aliases.
3. Keep raw CCM framing below workloads. Move the existing IME logical-record implementation into a shared CCM-owned module (`parser::ccm::logical`), update its pure/native consumers and the specialization dispatch, retaining its corpus-proven behavior and bounded entry contract. It remains one implementation; no new ParserKind. App IME consumers use that lower module directly.
4. Extract shared GUID/identity parsing into private `intune::common::identity`. ESP and Win32 use the lower helpers. Keep app registry aggregation at the app path. Shared helpers must not import app-owned analysis types. Keep source/name classification with its lower identity helper where needed and expose only the existing app registry's public type through the canonical app module. Preserve helper behavior with existing tests.
5. Remove `ParsedEspEventBatch` and its unused record-count-only adapter. Native acquisition continues using `ParsedEspEvtxBatch`, which preserves byte/parse-failure accounting. Remove manifest-less discovery and its allowlist, limits, and tests; use ordinary manifest-open Missing coverage. Retain valid manifest, malformed, denied, unsafe-path, and capped intake tests.
6. Delete the ESP-only relaunch command/types/error projection, Tauri registration, IPC bridge case, TypeScript invoke/decoder/type and compatibility tests. Existing UI already uses the generic elevation route; test that route remains intact. Do not change generic elevation behavior.
7. Run focused parser/native ESP tests, full parser tests, wasm, strict parser/Tauri Clippy, fmt/diff, TypeScript and frontend tests. Use CARGO_BUILD_JOBS=2 and test threads=2; coordinate the heavy-suite window. Document pre-existing baseline failures separately. Independent exact-diff review and CodeRabbit; signed commit and draft PR, exact remote signature/CI verification. Coordinator handles integration; no merge or policy bypass here.

## Slice B — provenance prerequisite

After A is integrated, rebase planning on freshly verified main. Audit the existing Phase 0A source-quality harness and all Intune manifests against the approved observed/synthetic/derived provenance classes. Deliver missing harness/audit work as its own bounded slice; remove or downgrade unsupported profile claims, and open each missing observed-anchor acquisition lane with its evidence prerequisites. Do not fabricate observations or expand public support from generated fixtures. Report any contract choices that source evidence cannot settle to the parent.

## Slice C — ESP privacy vertical (one atomic consumer)

Prepare a field-by-field independent-reviewed plan on the surviving APIs before implementation:

- `intune::redaction::RedactionContext`: internal `Zeroizing<[u8;32]>`, only fallible caller-fill constructor; no raw array constructor, Clone/Copy/Debug/Display/Default/serde. Native constructor calls existing getrandom directly into borrowed storage and returns closed diagnostic on failure. One secret per operation/session, never persisted.
- Private typed lane/domain constants, exact ADR binary frame, HMAC-SHA-256 using maintained hmac compatible with existing sha2 0.11, full URL-safe unpadded `cti1_` tag. Normalization stays explicit in each projection. No caller free-form domains.
- Private nonserializable/non-debug `Local...` reduction state; public Serialize-only projected DTOs with private fields/read-only accessors and opaque SensitiveToken/ProjectedText/RestrictedMarker. Exhaustive recursive struct construction; no clone-and-mutate, struct spread or raw public escape.
- Shared management grammar relocated byte-for-byte to lower private owner; exactly five current Windows consumers move imports. Other workload grammars remain separately owned. Do not silently migrate unrelated lane token contracts or create a second supported public API.
- Closed `PublicDiagnostic` codes/enums/counts only; map private failures before commands/events/logs. Inventory every command, session event, progress, save, clipboard, frontend store, Graph interaction and retained evidence surface.
- ESP V2 export from parser-created state; bounded native import opens one stable handle, binds identity/SHA256 and raw-byte/elapsed limits, denies unknown fields and non-V2 versions, uses fresh context and never reconstructs local state. Every imported token span is reminted once as specified. Delete all V1/bare/frontend direct readers and DTOs atomically.
- Regression matrix: exact and negative HMAC known answers; normalization/class/lane separation and cross-context unlinkability; restricted equality; entropy failure no-output; compile-fail raw construction/serialization/DTO deserialization; nested sentinel absence; stable same-context JSON; unchanged conclusions; token-shaped raw input; V2 start/middle/end/repeated spans; malformed/unknown/V1/future schemas; raw/elapsed bounds and file replacement. Preserve existing observed source anchors.
- Mandatory parser/wasm/Clippy/frontend/native tests and Windows acceptance where available, with truthful unsupported-platform results. Audit complete recursive helper list independently. Draft signed PR only after local validation and independent review; follow exact-head review/CI to terminal.

## Dependent handoff

After integrated ESP foundation, #366 is the first child consumer (existing ESP-derived grammar). Then migrate existing wired leaves, scripts/remediations separately, pure analyzers, and new leaves including #365 in ADR order. #645 is outside the numbered Intune list: prepare a separate reviewed binding to the shared context, strict intake and projected bundle output; do not make it the foundation owner. #661 keeps its narrow chronology/admission/fixture work in its coordinator-owned branch until its privacy migration turn. Scanned-service equivalence remains a separate #365 decision. No mass rebase or edits to either branch here.

## Completion evidence

For each slice retain reviewed base/head, RED/GREEN commands/results, complete projection/deletion inventory, signature verification, draft PR URL, exact-head CI and review state, and native acceptance limitations. Never treat this plan or a partial slice as completion of the shared privacy contract.
