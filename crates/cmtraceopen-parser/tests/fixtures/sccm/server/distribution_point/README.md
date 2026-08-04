# Synthetic Distribution Point fixture corpus

This directory is test-only input for Issue `#329`.

Each site-server artifact has one sealed Distribution Point workflow subject.
The multi-DP scenario therefore uses separate synthetic captures per subject;
one physical artifact never becomes authority for two DPs.

- Every evidence file is authored synthetic CCM text and contains the literal
  `SYNTHETIC FIXTURE` marker.
- `manifest.json` records physical producer, workflow subject, coverage,
  rotation, bounded path, encoding, and exact byte-count provenance.
- `expected.json` is the frozen whole-output oracle from the exported analyzer.
- Exact package/content/version/DP/extraction-profile keys keep versions and DPs
  independent.
- Case-folded path fingerprints stay unique, sanitized roots and rotated
  basenames stay synthetic, and topology arrays retain only typed declared
  handles.
- Rotation lineage/fragment fields, observation IDs, evidence references, and
  coverage-gap IDs fail closed on malformed, empty, duplicate, or reused
  values.
- Every source-local observation cites a nonempty closed array of exact raw
  physical artifact/line ranges. Citing a fragment or malformed raw line does
  not promote it to a logical transaction or make it correlation-eligible.
- Missing, denied, malformed, capped, or split evidence is coverage only.
- Client records and timestamps alone never establish a DP transaction or
  cross-side cause.

The preparation manifests retain the canonical intake contract's required
`proposalOnly` synthetic marker. It is never emitted as an analyzer claim.
The focused Rust contract resolves every manifest path, runs captured CCM
files through the existing SCCM logical-record envelope, verifies normalized
timestamp/line provenance, compares every output field, and rejects
adversarial mutations.
