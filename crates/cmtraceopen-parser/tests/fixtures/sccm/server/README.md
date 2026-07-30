# Synthetic SCCM server intake fixtures

These fixtures prepare issue #335 while #318 owns the shared SCCM schema. A
focused Rust fixture-contract test enforces their site-code, rotation-path, and
byte-integrity invariants, but no production native reader consumes them yet.
Every value is synthetic, deterministic, and privacy-safe:

- permitted topology host labels are `LAB-CM01`, `LAB-MP01`, and `LAB-DP01`;
- the exact synthetic three-character site code is `LAB`;
- raw source paths are replaced by `REDACTED_*` markers;
- configured roots use deterministic opaque `synthetic:path:*` fingerprints;
- every manifest declares `syntheticFixture: true` and `proposalOnly: true`;
- evidence contains no customer host, user, site, domain, identifier,
  credential, certificate, URL, database name, or client key.

Each scenario has `manifest.json` and `expected.json`. `Captured` and `Capped`
artifacts also have minimal evidence at the exact bundle-relative path named by
their manifest. `Absent`, `AccessDenied`, `Skipped`, and `Unsupported`
artifacts have a null/omitted `relativePath`, zero `bytesCopied`, and no
evidence placeholder. Artifact IDs are unique across every artifact in one
manifest/bundle, captured or non-captured; repeats across independent bundles
are permitted. IDs derive from canonical producer/source/subject/path/
basename/rotation identity, never discovery order. Non-null relative paths are
also unique inside a bundle. Expected source lists use producer role/host,
source ID, workflow subject, path fingerprint, explicit rotation family/value,
lineage, basename, state, relative path, and artifact ID as a total order. This
serialization order does not imply record chronology. The expected data
documents only intake classification/coverage and never a role-health or
client-causality finding.

Evidence payloads are raw and bundle-internal. Public/exported evidence and
derived values must cross the #318 redaction boundary; they may retain only
approved opaque handles and statuses, never raw paths, hosts, identifiers, or
unredacted content.

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
- A byte limit is inclusive and applies to raw source bytes before decoding.
  A capped file is the exact prefix through `byteLimit`, without decode-first
  splitting, repair, or replacement; its raw file size and `bytesCopied` both
  equal the limit, with `truncated: true` and `fragmentComplete: false`.
- Complete captured records use all required CCM attributes (`time`, `date`,
  `component`, `context`, `type`, `thread`, and `file`) and contain
  `SYNTHETIC FIXTURE` inside the first record message. The deliberately capped
  partial starts with a CCM prefix, contains the same marker, lacks terminal
  framing, and produces zero complete/successful CCM records.
- `Absent`/`AccessDenied`/`Skipped`/`Unsupported`: `relativePath` is null or
  omitted and `bytesCopied` is zero.
- Every file beneath a scenario's `evidence/` tree is referenced by exactly one
  artifact. This rejects stale flat placeholders and unmanifested captures.
- Every admitted record with a valid offset has one authoritative normalized
  UTC instant that never exceeds `collectedUtc` (zero synthetic tolerance).
  A timestamped rotation filename/value is no later than that member's
  earliest admitted record. Unknown/invalid offsets are non-comparable
  coverage gaps: they are never assigned an invented UTC, reordered, or
  correlated.
- Producer role/host topology is distinct from optional workflow subject.
  `MP_GetAuth.log`, `MP_GetPolicy.log`, and `MP_Location.log` retain observed
  MP/site-system placement; site-server-produced `mpcontrol.log` is a separate
  catalog row. Ambiguous/co-located placement remains unresolved pending
  native validation. Known site-server DP/SUP control logs cannot be relabeled
  as DP/SUP producers.
- The configured-root collision scenario has two same-basename artifacts with
  distinct fingerprints, opaque root segments, IDs, contents, and references.
  The capped SUP path also carries deterministic subject-instance and root
  discriminators. All identity keys/destinations are precomputed before
  writes; destinations use atomic create/no-overwrite, and roots/instances
  never normalize-merge.
- Rotation rank is timestamped, numbered, `.lo_`, current, provider-defined,
  then none; timestamps ascend, numbers descend, and lineage/basename/state/
  relative-path/artifact-ID tie-breakers make reordering deterministic.
- Canonical artifact ordering, manifest-scoped unique IDs/paths, topology
  privacy markers, top-level synthetic/proposal markers, redacted original
  paths, and `synthetic:path:*` fingerprints remain stable.

The local exact-byte coordinator parses all 22 JSON files, pressure-tests
within-manifest duplicate rejection and cross-bundle ID reuse, precomputes
identity/destination collisions, walks exact references/no-orphans, checks
privacy/producer/chronology/total-order contracts, and validates raw byte
counts before decoding. The ignored preparation report records its exact
command and result. These checks remain independent of the future #318 Rust
intake target.

See `docs/sccm/preparation/issue-335-server-intake.md` for the source catalog,
native capture-adapter design, matrix, and exact #318 dependency decisions.
