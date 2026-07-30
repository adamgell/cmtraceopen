# Synthetic SCCM client intake fixtures

These are preparation-only fixtures for issue #319. They are not accepted by a
production SCCM reader until #318 publishes its stable public contracts.
`manifest.json` and `expected.json` are proposed contract inputs/outputs, not
compiled test fixtures. Every identity, path, timestamp, byte count, UUID, and
log record is deterministic and synthetic.

Privacy markers: manifests require `syntheticFixture: true` and
`proposalOnly: true`; evidence files use only `LAB-CLIENT-01`, `CONTOSO`, fake
package/content IDs, or RFC-style test UUIDs; `SYNTHETIC://` is opaque fixture
provenance. Never replace these files with a copied client log. No user, SID,
tenant, certificate, token, serial, production deployment name, customer host,
or real source path may be committed.

`complete` covers all first-pass catalog groups. `rotations` proves declared
current/`.lo_`/numbered grouping and same-basename root separation.
`missing-root`, `access-denied`, and `capped` prove coverage behavior only;
their evidence must not form workflow findings. `skipped`, `unsafe-path`, and
legacy generic-manifest mapping are intentionally documented test designs in
`docs/sccm/preparation/issue-319-client-intake.md`, pending #318 contracts.

Expected arrays are stable-sorted by `logicalArtifactId`. `contractState` must
remain `proposedPending318` until an implementation maps this design to the
published spine schema. Replay after #318: deserialize via its public reader,
assert coverage directly, reorder artifacts and compare normalized output, and
never interpret capped/split tail text as a phase or terminal diagnosis.
