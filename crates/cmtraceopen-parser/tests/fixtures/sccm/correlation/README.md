# SCCM production correlation contract fixtures

These fixtures are the executable production contract for issue #333. They cover exactly three independently accepted pairs:

- policy to Management Point (`#321` to `#328`);
- content to Distribution Point (`#322` to `#329`);
- updates to Software Update Point (`#323` to `#330`).

`pair-registry.json` admits only those pairs. Each is `ruleValidated`, production-enabled, owned by `sccm::correlation`, and bound to all thirteen shared guards. The registry contains no compatibility aliases, pending pair state, or undeclared blocker.

Each pair matrix is executed through the production reducer. It contains one healthy exact case and fourteen adversarial constructions covering the thirteen guards; the reordered-input guard uses opposite-order A/B cases. Every scenario pins:

- outcome, link strength, and confidence;
- sorted reason codes and triggered guards;
- the SHA-256 hash of the complete serialized analysis.

The shared guard set covers missing counterparts, same-time evidence without an exact key, conflicting exact keys, incompatible topology, version/profile mismatch, unknown profiles, invalid time ordering, partial or rotation-split capture, unrelated terminal failures, public-output redaction, and input reordering. Exact corroboration requires every guard to pass plus an exact compatible key, compatible topology, usable causal ordering, complete coverage/rotation, and a related terminal server failure.

The correlation output contains only deterministic hashed fact handles, closed enums, and bounded logical artifact requests. Raw Windows paths, live hostnames, users, tenants, tokens, evidence messages, and source-local identifiers are not part of the public projection. Source analyses are borrowed immutably and their established serialized contracts remain unchanged.
