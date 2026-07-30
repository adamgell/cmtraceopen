# Synthetic SCCM server intake fixtures

These fixtures prepare issue #335 while #318 owns the shared SCCM schema. They
are intentionally not connected to a Rust test target yet. Every value is
synthetic, deterministic, and privacy-safe:

- permitted topology labels are `LAB-CM01`, `LAB-MP01`, `LAB-DP01`, and
  `CONTOSO`;
- raw source paths are replaced by `REDACTED_*` markers;
- configured roots use deterministic opaque `synthetic:path:*` fingerprints;
- every manifest declares `syntheticFixture: true` and `proposalOnly: true`;
- evidence contains no customer host, user, site, domain, identifier,
  credential, certificate, URL, database name, or client key.

Each scenario has `manifest.json` and `expected.json`. `Captured` and `Capped`
artifacts also have minimal evidence at the exact bundle-relative path named by
their manifest. `Absent`, `AccessDenied`, `Skipped`, and `Unsupported`
artifacts have a null/omitted `relativePath`, zero `bytesCopied`, and no
evidence placeholder. Artifact IDs are unique across every manifest artifact,
captured or non-captured; non-null relative paths are also unique. Expected
source lists are canonicalized by producer role/host, source ID, workflow
subject, path fingerprint, rotation order, basename, then artifact ID. The
expected data documents only intake classification/coverage and never a
role-health or client-causality finding.

The current preparation shape is provisional:

- `captureState`, topology role names, evidence IDs, coverage output, rotation
  syntax, and legacy mapping must be reconciled to #318 before implementation.
- `defaultCandidateState: "absentCandidateOnly"` means exactly that a default
  candidate was not present. It must never be interpreted as an absent or
  broken role.
- An unsupported source remains retained manifest evidence but is ineligible
  for a role reducer. A capped/malformed rotation cannot yield terminal health.

## Preparation validation

Validation must parse every JSON file and then walk every manifest artifact:

- `Captured`/`Capped`: `relativePath` is non-null, resolves beneath its
  scenario directory, contains a `SYNTHETIC` marker, and its file byte length
  equals `bytesCopied`.
- Every captured/capped artifact carries deterministic `encoding` and
  `collectionLimit` provenance; expected data repeats those assertions.
  Non-captured states omit those fields.
- Complete captured records use all required CCM attributes (`time`, `date`,
  `component`, `context`, `type`, `thread`, and `file`) and contain
  `SYNTHETIC FIXTURE` inside the first record message. The deliberately capped
  partial is marked non-parseable in expected data.
- `Absent`/`AccessDenied`/`Skipped`/`Unsupported`: `relativePath` is null or
  omitted and `bytesCopied` is zero.
- Every file beneath a scenario's `evidence/` tree is referenced by exactly one
  artifact. This rejects stale flat placeholders and unmanifested captures.
- Complete record timestamps never exceed `collectedUtc`; timestamped rotation
  names/values match their record instant. Unknown/invalid offsets remain
  coverage gaps rather than receiving invented UTC.
- Producer role/host topology is distinct from optional workflow subject.
  Known site-server control logs cannot be relabeled as DP/SUP producers.
- The configured-root collision scenario has two same-basename artifacts with
  distinct fingerprints, opaque root segments, IDs, contents, and references.
- Canonical artifact ordering, unique artifact IDs/paths, topology privacy
  markers, top-level synthetic/proposal markers, redacted original paths, and
  `synthetic:path:*` fingerprints remain stable.

The preparation report records the JSON/Node validation coverage and result.
These checks remain non-compiling until #318 freezes the shared Rust contract.

See `docs/sccm/preparation/issue-335-server-intake.md` for the source catalog,
native capture-adapter design, matrix, and exact #318 dependency decisions.
