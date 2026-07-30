# Synthetic SCCM server intake fixtures

These fixtures prepare issue #335 while #318 owns the shared SCCM schema. They
are intentionally not connected to a Rust test target yet. Every value is
synthetic, deterministic, and privacy-safe:

- permitted topology labels are `LAB-CM01`, `LAB-MP01`, `LAB-DP01`, and
  `CONTOSO`;
- raw source paths are replaced by `REDACTED_*` markers;
- configured roots use deterministic opaque `synthetic:path:*` fingerprints;
- evidence contains no customer host, user, site, domain, identifier,
  credential, certificate, URL, database name, or client key.

Each scenario has `manifest.json`, a minimal `evidence/` file, and
`expected.json`. Manifest artifact IDs and relative paths must be unique;
expected source lists are canonicalized by role, source ID, path fingerprint,
rotation order, basename, then artifact ID. The expected data documents only
intake classification/coverage and never a role-health or client-causality
finding.

The current preparation shape is provisional:

- `captureState`, topology role names, evidence IDs, coverage output, rotation
  syntax, and legacy mapping must be reconciled to #318 before implementation.
- `defaultCandidateState: "absentCandidateOnly"` means exactly that a default
  candidate was not present. It must never be interpreted as an absent or
  broken role.
- An unsupported source remains retained manifest evidence but is ineligible
  for a role reducer. A capped/malformed rotation cannot yield terminal health.

See `docs/sccm/preparation/issue-335-server-intake.md` for the source catalog,
native capture-adapter design, matrix, and exact #318 dependency decisions.
