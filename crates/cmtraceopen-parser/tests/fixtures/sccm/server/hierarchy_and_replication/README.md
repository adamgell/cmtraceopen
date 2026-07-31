# Synthetic SCCM hierarchy and replication fixtures

These fixtures are invented test data. They contain no customer, production,
or lab capture. `manifest.json` records additive SCCM artifact coverage and
physical provenance; `expected.json` records the proposed #331 evidence
contract while production reducers remain dependency-blocked.

Only these raw CCM files are used as evidence:
`replmgr.log`, `sender.log` and its rotated `sender.lo_` form, `despool.log`,
and `rcmctrl.log`. Exact semantic records include the `SYNTHETIC FIXTURE`
marker and synthetic message/link/site/profile fields. The generic-message
negative contains the marker and a site-code-looking token without the exact
hierarchy grammar, so it cannot create a candidate. Partial rotation/cap
fixtures retain the marker but intentionally do not form a logical CCM record.
The healthy-link adversarial variants also freeze timestamp ordering: equal UTC
instants are usable only for forward physical lines in the same artifact, not
as ordering evidence between artifacts. Candidate facts retain the complete
shared timestamp shape and replace host/path inputs with versioned,
domain-separated SHA-256 provenance tokens before serialization.

The corpus must remain deterministic, safe to publish, and role/topology aware.
Do not replace safe handles with hostnames, add database/network collection, or
interpret missing sources as role absence or failure.
