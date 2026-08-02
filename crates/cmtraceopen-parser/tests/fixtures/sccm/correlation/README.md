# SCCM correlation adversarial contract fixtures

These fixtures prepare issue #333's false-causality contract. They do not implement correlation, expose a production API, parse raw logs, or promote either pair to RuleValidated.

`pair-registry.json` is deliberately non-executable. Policy to Management Point (`#321` to `#328`) and content to Distribution Point (`#322` to `#329`) are `contractPrepared`; their production flag, RuleValidated flag, and implementation module remain false/empty. Updates to SUP (`#323` to `#330`) is Candidate only and has no pair matrix or implementation permission.

The shared matrix defines thirteen mandatory guards. Each first-pair matrix instantiates every guard in a pair-specific adversarial scenario:

- missing client and missing server counterparts;
- same-time evidence without an exact key;
- conflicting exact keys;
- incompatible site, MP, DP, or role topology;
- content/profile version mismatch;
- unknown extraction profile;
- invalid timestamp offset;
- rotation-split and partial capture;
- unrelated terminal server failure;
- private-marker redaction;
- reordered input.

Every adversarial expected result forbids `exactCorroborated`, caps confidence below High, preserves source findings, and uses stable reason/request/result identifiers. Every declared guard must be demonstrated by the scenario's own input state, and each guard's `requiredOutputs` token is an executable predicate checked against the scenario's expected contract. Reordered input A/B cases encode one `orderedInputEvidence` manifest of side-tagged synthetic tokens, with B replaying A's multiset in opposite order, and pin identical expected public projections and result contracts.

Fixture references have explicit status and are bound to their pair side:

- `repo:` references point to already merged synthetic upstream fixture directories under the citing side's own corpus prefix;
- `issue:#329:` references mark DP scenarios whose public fact interface is not independently accepted; the #329 preparation corpus is merged on the program baseline, but until its fact interface is accepted (no production reducer exists for the #322/#329 pair) the content server side may use nothing else (or `absent`);
- `synthetic:` references describe future pair-local sanitized inputs and are only valid on merged sides;
- `absent` is an intentional missing counterpart, must agree with the declared one-sided coverage, and is never proof of failure.

No raw Windows path, live hostname, user, tenant, token, or database data belongs here. The only identity-shaped values are reserved synthetic private markers used to prove that expected public projections omit them.
