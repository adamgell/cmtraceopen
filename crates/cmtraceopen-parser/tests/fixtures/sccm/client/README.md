# Synthetic SCCM client intake fixtures

These are compiled pure-intake fixtures for issue #319. The parser test harness
maps their declared artifact fields into the published #318 spine types and
checks the executable #319 assessment. `manifest.json` remains a
`proposalOnly` native wire design: no native SCCM manifest reader, discovery,
capture, legacy adapter, or Windows acceptance is implied. Every identity,
path, timestamp, byte count, UUID, and log record is deterministic and
synthetic.

Privacy markers: manifests require `syntheticFixture: true` and
`proposalOnly: true`; issue #319 intake evidence uses only `LAB-CLIENT-01`, the
exact synthetic three-character site code `LAB`, fake package/content IDs, or
RFC-style test UUIDs; `SYNTHETIC://` is opaque fixture provenance. Workflow
corpora own their issue-scoped identifier contracts. Never replace these files
with a copied client log. No user, SID, tenant, certificate, token, serial,
production deployment name, customer host, or real source path may be
committed.

`complete` covers all first-pass catalog groups and represents
`LocationServices.log` once with stable `client-content` and `client-location`
memberships. `rotations` proves declared current/`.lo_`/numbered grouping.
`collision` proves two current `AppEnforce.log` files from distinct roots keep
unique physical IDs, fingerprints, contents, and collision-safe relative
paths; `root-a` and `root-b` are opaque configured-root handles, not native
paths.
`missing-root`, `access-denied`, and `capped` prove coverage behavior only;
their evidence must not form workflow findings. `skipped`, `unsafe-path`, and
legacy generic-manifest mapping are intentionally documented native test
designs in `docs/sccm/preparation/issue-319-client-intake.md` and remain
pending.

`contractState` is `pureIntakeImplementedNativePending`. Each `expected.json`
separates three contracts: `pureAssessment` is a typed, exact normalized view
of every public group, fragment, physical artifact, unsupported artifact, and
coverage gap; `nativeDesignPending` retains bounded byte/digest expectations
without claiming a native reader or collector exists; and
`downstreamDesignPending` labels request wording and prohibited diagnostic
claims that are not intake output. The pure arrays retain their deterministic
production order, while the deduplicated fragment table and pending native
artifact provenance are stable-sorted by artifact ID. Mutation tests reject
unknown fields, omissions, reordered output, and forged provenance. No test
interprets capped/split fragment text as a phase or terminal diagnosis.

Every manifest artifact has one physical `artifactId` and a
`designOnlyCatalog` object containing one catalog entry plus sorted logical
group memberships. These are preparation labels, not final #318 field names.
For every `captured` or `capped` artifact, `bytesCopied` equals the physical
evidence-file length, `encoding` is `utf-8`, and `collectionLimit` states both
the byte limit and whether it applied; `expected.json` mirrors those values in
`nativeDesignPending.artifactProvenance`, including an exact `bytesCopied` for
every physical fixture. Noncapture artifacts remain `bytesCopied: 0` with a
null relative path and do not invent capture provenance. An applied cap counts
inclusive raw source bytes before decoding and retains that exact source
prefix, even when the last byte splits a text or logical-record boundary. The
collector never appends a truncation marker or repairs/replaces bytes. The
capped evidence is exactly 128 bytes, is explicitly truncated and
fragment-incomplete, retains the pre-existing synthetic marker inside those
bytes, and is not a complete CCM record. Expected data locks its exact byte
count and SHA-256.

The first line of every evidence file must contain the literal
`SYNTHETIC FIXTURE` plus scenario-specific coverage text; CCM files put it
inside the first record and the plain supplemental fixture uses it directly.
