# Synthetic SCCM hierarchy and replication fixtures

These fixtures are invented test data. They contain no customer, production,
or lab capture. `manifest.json` records additive SCCM artifact coverage and
physical provenance; `expected.json` records the proposed #331 evidence
contract while production reducers remain dependency-blocked.

Only raw CCM files from the existing hierarchy catalog are present:
`replmgr.log`, `sender.log`, `despool.log`, and `rcmctrl.log`. Every complete
record includes the semantic `SYNTHETIC FIXTURE` marker and exact synthetic
message/link/site/profile fields. Partial rotation/cap fixtures retain the
marker but intentionally do not form a logical CCM record.

The corpus must remain deterministic, safe to publish, and role/topology aware.
Do not replace safe handles with hostnames, add database/network collection, or
interpret missing sources as role absence or failure.
