# Microsoft Store semantic issue inventory

**Source:** PR #518 (`lane/intune-358-store`), head `e3e328999fc4eaf7d5afa9ec12037ffa37a27298`, CodeRabbit actionable review and current reducer inspection.

This inventory groups review comments by semantic root cause. It is a pilot input, not a claim that every review comment is independently valid. Runtime fixes belong to the Store pilot, not this governance PR.

| Cluster | Semantic risk | First executable test | Phase |
|---|---|---|---|
| Typed intent authority | Caller-writable `named_data` can override assignment intent. | Typed assignment says `Required`; package/installer metadata says `NotTargeted`; intent remains `Required`. | Phase 2 RED |
| Input order and chronology | Reduction iterates group members in input-derived order; equal-ranked terminal states can change when artifacts are reordered. | Reverse equivalent artifact input; result remains identical unless source order is explicit evidence. | Phase 2 RED |
| Identity and correlation | An `app_id` match without compatible package/product identity can falsely correlate artifacts or drive a package-specific conclusion. | Match `app_id` while omitting or changing package identity; no strong correlation or package-specific terminal outcome is permitted. | Phase 2 RED / Store pilot |
| Terminal precedence and retries | Later success can replace failure without explicit retry/session linkage. | Same-identity linked retry may transition; ambiguous or unrelated success does not overwrite failure. | Store pilot |
| Installer-family isolation | AppX/UWP and Store Win32 observations can receive family-inappropriate findings or terminal semantics. | Mixed-family observations remain separate and use family-appropriate findings. | Store pilot |
| Redaction scope | Existing stable token behavior has no documented caller-controlled scope/key contract. | Define same-scope equality and cross-scope non-equality before changing token API. | ADR follow-up |
| Evidence degradation | Unknown event version and event-level mismatch are conflated, weakening confidence semantics. | Unknown version and known-event level mismatch degrade for distinct reasons. | Store pilot |
| Source classification | Channel substring matching may admit archive or unrelated channels. | Approved exact/prefix channel matches; suffixed/unrelated channels remain `Unknown`. | Store pilot |
| Fixture expectations | Some expected phase/confidence/timestamp values encode unsafe semantics. | Correct expectations only after the semantic RED tests establish the intended contract. | Store pilot |

## Duplicate/root-cause handling

- Chronology implementation and contradictory fixture timestamps are one ordering cluster.
- Unknown-event-version confidence and level-mismatch handling are one evidence-degradation cluster.
- Mixed-family finding title/ID behavior is one installer-family isolation cluster.
- Redaction hashing is not a Store-only cleanup; its equality scope is a shared ADR question.
- Observation-ID `HashSet` optimization and missing Rustdoc are valid maintenance items, not Framework v1 semantic blockers.

## Boundary

The Store reducer remains workload-specific. This inventory does not authorize a universal reducer, configurable rules engine, mandatory migration of other workloads, or runtime changes in the governance PR.
