# Issue #333 correlation-design preparation

## Status

This slice prepares adversarial fixtures and executable fixture-schema tests only. It intentionally adds no `src/sccm/correlation` module, shared SCCM model change, public correlation API, pair reducer, graph store, native collection, live query, or cross-side finding.

Production work remains blocked while:

- #318's exact shared finding/redaction/key interface is still under review;
- #321 and #328 have synthetic source corpora but no accepted public pair-fact interface;
- #322 has a synthetic deployment/content corpus but no accepted public pair-fact interface;
- #329's DP corpus is not independently accepted on the program baseline.

## Prepared pair contracts

| Pair | State | Implementation permission | Known boundary |
| --- | --- | --- | --- |
| #321 policy to #328 Management Point | `contractPrepared` | Disabled | Requires exact profile-validated policy/request keys, compatible site/MP topology, usable ordering for sequence claims, coverage, and corroborating terminal evidence |
| #322 content to #329 Distribution Point | `contractPrepared` | Disabled | Requires exact content/package identity plus required version, compatible DP topology, usable ordering for sequence claims, coverage, and corroborating terminal evidence |
| #323 updates to #330 SUP | `candidate` | Disabled | Requires a dedicated reviewed subplan after both source contracts are independently accepted |

The two first-pair matrices are independent. Policy behavior never depends on content output, and content behavior never depends on policy output.

## False-causality matrix

Each first pair instantiates all thirteen guards:

| Guard | Required conservative result |
| --- | --- |
| Missing client/server counterpart | Preserve source-local output and request only the named counterpart artifact group |
| Same-time/no-key | Candidate symptom at most; time is not a causal key |
| Conflicting exact key | Incompatible/unlinked; do not attach the terminal fact |
| Incompatible topology | Incompatible with a bounded reason; do not blame either side |
| Unknown profile | Candidate at most; unvalidated extraction cannot create an exact link |
| Version mismatch | Incompatible, including same content ID with a different required version |
| Invalid offset | No cross-host ordering claim; ExactPartial at most |
| Partial capture | Explicit coverage gap and bounded request |
| Rotation split | Explicit coverage gap; fragments cannot synthesize a logical cross-side fact |
| Unrelated terminal error | Preserve it as source-local evidence only |
| Redaction boundary | Public projection uses safe handles and excludes private markers |
| Reordered input | Identical expected result and serialization |

All adversarial scenarios set `highConfidenceCauseAllowed=false`, `exactCorroboratedAllowed=false`, and `sourceFindingsMutable=false`. A future healthy/terminal implementation matrix must be added test-first only after the corresponding upstream public fact contracts pass independent review.

## Evidence classification

The matrix uses synthetic repository fixtures where they are already merged, explicit `issue:#329:` references for pending DP scenarios, and pair-local `synthetic:` placeholders for inputs that do not yet exist. These references are design evidence, not native or live acceptance.

Client-only, server-only, missing, partial, capped, invalid-offset, rotation-split, and unknown-profile cases remain usable coverage outputs. None is proof of a server or client cause. The development SCCM Server is a future sanitized validation source and has not been exercised by this slice.
