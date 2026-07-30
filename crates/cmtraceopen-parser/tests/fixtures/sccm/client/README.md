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

`complete` covers all first-pass catalog groups and represents
`LocationServices.log` once with stable `client-content` and `client-location`
memberships. `rotations` proves declared current/`.lo_`/numbered grouping.
`collision` proves two current `AppEnforce.log` files from distinct roots keep
unique physical IDs, fingerprints, contents, and collision-safe relative
paths; `root-a` and `root-b` are opaque configured-root handles, not native
paths.
`missing-root`, `access-denied`, and `capped` prove coverage behavior only;
their evidence must not form workflow findings. `skipped`, `unsafe-path`, and
legacy generic-manifest mapping are intentionally documented test designs in
`docs/sccm/preparation/issue-319-client-intake.md`, pending #318 contracts.

Expected arrays are stable-sorted by `logicalArtifactId`. `contractState` must
remain `proposedPending318` until an implementation maps this design to the
published spine schema. Replay after #318: deserialize via its public reader,
assert coverage directly, reorder artifacts and compare normalized output, and
never interpret capped/split fragment text as a phase or terminal diagnosis.

Every manifest artifact has one physical `artifactId` and a
`designOnlyCatalog` object containing one catalog entry plus sorted logical
group memberships. These are preparation labels, not final #318 field names.
For every `captured` or `capped` artifact, `bytesCopied` equals the physical
evidence-file length, `encoding` is `utf-8`, and `collectionLimit` states both
the byte limit and whether it applied; `expected.json` mirrors those values in
`artifactProvenance`. Noncapture artifacts remain `bytesCopied: 0` with a null
relative path and do not invent capture provenance. The capped evidence is
exactly 128 bytes, is explicitly truncated and fragment-incomplete, retains
the marker inside those bytes, and is not a complete CCM record.

The first line of every evidence file must contain the literal
`SYNTHETIC FIXTURE` plus scenario-specific coverage text; CCM files put it
inside the first record and the plain supplemental fixture uses it directly.
