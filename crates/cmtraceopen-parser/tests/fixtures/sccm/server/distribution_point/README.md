# Synthetic Distribution Point fixture corpus

This directory is test-only input for Issue `#329`.

- Every evidence file is authored synthetic CCM text and contains the literal
  `SYNTHETIC FIXTURE` marker.
- `manifest.json` records physical producer, workflow subject, coverage,
  rotation, bounded path, encoding, and exact byte-count provenance.
- `expected.json` is a preparation label, not a frozen production API.
- Exact package/content/version/DP/profile keys keep versions and DPs
  independent.
- Missing, denied, malformed, capped, or split evidence is coverage only.
- Client records and timestamps alone never establish a DP transaction or
  cross-side cause.

The focused Rust contract resolves every manifest path, runs captured CCM
files through the existing SCCM logical-record envelope, verifies normalized
timestamp/line provenance, and rejects adversarial mutations.
