# Reasoning-tier adversarial reducer review matrix

Use after reading the repository charter and before issuing a merge-gate report.

## Contract layer

| Question | Concrete probe | Failure signal |
|---|---|---|
| Version/assessability | Set the normalized event/schema version to an unsupported value while leaving payload fields plausible. | Terminal state or high confidence survives without an explicit coverage/degradation finding. |
| Identity | Same app/display name; vary package, product, session, or installer identity. | Weak or app-level identity joins unrelated package evidence. |
| Chronology vs linkage | Same source artifact, earlier failure and later success, but omit activity/session/retry linkage. | Later success automatically replaces failure. |
| Duplicate evidence | Duplicate provenance keys with conflicting states/errors. | Result or selected error changes with vector order. |
| Coverage | Add missing/denied/capped/skipped/unsupported artifact. | Gap raises confidence or produces success/failure. |
| Findings | Permute/duplicate observations and inspect evidence references and rendered counts. | Conclusions remain stable but citations/counts do not. |
| Redaction | Export sensitive messages, named fields, paths, findings, and transaction identity. | Restricted values leak or semantic identity changes unexpectedly. |

## Adversarial layer

Prefer a compact false-story input over prose. Record:

1. violated invariant;
2. exact constructed input;
3. expected conservative result;
4. actual result or code path;
5. severity and disposition;
6. missing regression test.

Do not infer that a source-native sequence number is also a retry/session key. Confirm the source contract or require explicit linkage.

## Mechanical layer and gate reporting

Run focused reducer tests, full parser tests, strict Clippy, formatting check, and `git diff --check` read-only. Record unrelated formatting failures separately from changed-file formatting failures. Inspect GitHub review objects directly: `CodeRabbit` status `SUCCESS` is not equivalent to an approved review. Report `approved_at_head` only when an actual approval review is present on the exact head SHA. Keep CI, local implementation tests, contract conformance, review state, and native/lab validation as separate gates.

## Store pilot review lessons

The Microsoft Store Phase 3 review exposed three durable checks:

- `NormalizedWindowsEvent.event_version` must not be bypassed by checking only `named_data["Version"]`.
- `reducer.rs` supersession must not equate same-artifact record order with explicit retry linkage.
- `resolve_state` needs a deterministic tie-break for equal artifact/record provenance, and finding evidence refs should be sorted/deduplicated before counting or rendering.

These are semantic/conformance concerns even when the happy-path and permutation suites pass.
