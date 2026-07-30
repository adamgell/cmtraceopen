# Issue #324 client Task Sequence corpus preparation

## Purpose and dependency boundary

This slice prepares the client Task Sequence source-path, execution-key, and
phase contract from Task 8 of the SCCM Client intake/core plan. It contributes
a runnable fixture contract and a fully synthetic corpus. It does **not** add a
production Task Sequence reducer, a catalog entry, native collection, or a
speculative shared model.

Every expected output is marked `proposedPending318And319`. Production work
must wait until #318 publishes the shared diagnostic types and #319 freezes the
client artifact/manifest interfaces. The future Task Sequence reducer must be
independently callable and consume normalized Task Sequence evidence directly.
It must not consume application- or policy-reducer output.

## Source paths and relocation

Microsoft documents that `smsts.log` moves as Task Sequence execution advances:

| Path class | Documented stage represented by the synthetic fixture |
| --- | --- |
| `winpe` | WinPE before the disk is formatted |
| `setup` | WinPE after format |
| `fullOs` | New operating system before the Configuration Manager client is installed |
| `client` | Client-installed path, including the final relocated `smsts.log` |
| `unknown` | Observed path that no reviewed profile recognizes |

The checked-in values are sanitized `SYNTHETIC://` handles, not copied Windows
paths. Each captured artifact pins:

- a physical artifact ID and safe repository-relative path;
- the original basename and rotation kind;
- the sanitized source path;
- the `_SMSTSLogPath` value observed in the cited record;
- a path class and relocation ordinal;
- the source version, capture timestamp, encoding, and exact byte count; and
- whether that physical fragment is a complete logical CCM record.

`_SMSTSLogPath` is the authoritative path observation. A filename, display
name, timestamp, directory name, or assumed operating-system stage cannot
invent relocation or merge two artifacts.

The `relocated-fragments` scenario pins the order:

```text
winpe -> setup -> fullOs -> client
```

All four fragments carry the same exact execution key. The order is explicit
in `relocationOrdinal`; ingestion order is irrelevant.

## Unsupported boot and recovery variants

This corpus validates only the five declared path classes and the sanitized
pre-format, post-format, pre-client, client-installed, and completed examples
in the scenario matrix. It does not validate PXE versus boot-media behavior,
standalone or prestaged media, Windows recovery/rollback environments,
alternate system-drive layouts, resumed setup paths not represented here, or
any vendor-specific recovery environment.

An unobserved boot or recovery variant is an explicit coverage/profile gap.
The `unknown` path class preserves such provenance without asserting support.
It must not be reclassified from a familiar filename, and it must not trigger
an unbounded disk search. Native Windows validation must record the ConfigMgr
and OS deployment profile, boot context, observed path class, and variants
that were not observed before support is expanded.

## Execution identity

The proposed synthetic extraction profile is
`task-sequence-client-5.00.test-v1`, restricted to the synthetic
`5.00.TEST.` source version. It is a fixture contract, not a claim about a live
ConfigMgr build.

An exact synthetic transaction key contains all of:

1. `executionId`;
2. `taskSequencePackageId`;
3. `advertisementId`; and
4. `runContext`.

Every field must be present in the transaction's cited evidence under the
recognized profile. Filename, path, timestamp, display name, component, or
ingestion order are forbidden join fields.

The `unrelated-runs` scenario gives two records the exact same normalized
timestamp. Their exact execution IDs, advertisement IDs, run contexts,
artifacts, and transactions stay separate. The
`complete-looking-unkeyed` scenario contains a success-looking terminal line
but lacks the exact key. It remains a low-confidence, non-correlatable,
source-local observation and cannot create a successful transaction.

The `unknown-profile` scenario contains key-looking fields under an
unrecognized source version. Those fields remain a low-confidence candidate;
they cannot be promoted by resemblance to the synthetic reviewed profile.

## Phase and terminal semantics

The proposed deterministic phase chain is:

```text
start -> preflight -> diskOrImage -> setupWindows -> installClient
      -> installSoftware -> postAction -> complete
```

A phase advances only on complete, profile-recognized evidence for the same
exact execution key. Expected states distinguish `inProgress`,
`blockedOrDeferred`, `failed`, and `succeeded`.

`confirmedFailure` requires a cited terminal record for the same transaction.
This requirement is pinned independently for:

- terminal preflight failure;
- disk/image failure;
- client-install failure; and
- software-install failure.

A reboot request with expected continuation is `blockedOrDeferred`, not
failure. An in-progress record is not treated as a terminal record merely
because no later fragment was collected. Each nonterminal scenario names the
smallest bounded next `client-task-sequence-smsts` path class to collect.

## Logical CCM records and rotation

Each complete synthetic file passes through the existing raw CCM grammar and
the shared SCCM normalization layer. Timestamp provenance in expected output
is derived from one complete cited CCM record. The invalid-offset scenario
retains `offsetInvalid`, the observed `9999` offset, and no normalized UTC
value; it cannot be ordered by a fabricated timestamp.

The rotation scenario stores one logical record as two physical fragments:
the archived `smsts.lo_` prefix and current `smsts.log` suffix. Each physical
fragment is deliberately incomplete and normalizes to no logical record by
itself. A controlled test-only archived-to-current concatenation produces
exactly one CCM record.

The two physical artifacts retain distinct IDs and paths, the same path
fingerprint, explicit rotation kinds, and `partial` logical coverage. Until the
final intake interfaces define controlled logical reconstruction, both remain
low-confidence, non-correlatable source-local observations.

## Coverage semantics

Capture state and execution state are independent:

- `captured` means the physical artifact was available and complete;
- `partial` means only incomplete rotation fragments are available; and
- `absent` means the logical artifact was not captured.

The `incomplete` scenario contains one absent logical artifact and no physical
evidence. Its only conclusion is `insufficientEvidence` plus a bounded request
for the active Task Sequence log. Missing `smsts` evidence is a coverage gap;
it is not proof that no Task Sequence ran.

No coverage gap is converted into application, policy, distribution-point,
management-point, or other server causality. Cross-side correlation is outside
this preparation slice.

## Scenario matrix

| Scenario | Path/identity purpose | Expected phase or disposition |
| --- | --- | --- |
| `winpe` | Before-format WinPE source | `preflight`, in progress |
| `post-format` | After-format WinPE relocation | `diskOrImage`, in progress |
| `pre-client` | New OS before client install | `setupWindows`, deferred |
| `client-installed` | Client path before terminal completion | `installClient`, in progress |
| `completed` | Final relocated keyed record | `complete`, succeeded |
| `relocated-fragments` | Same exact execution across four paths | Ordered through `complete` |
| `unrelated-runs` | Same-time adversarial executions | Two distinct transactions |
| `rotation-boundary` | One logical CCM record across two physical fragments | Partial, source-local only |
| `incomplete` | No captured `smsts` artifact | Coverage gap only |
| `terminal-preflight` | Explicit terminal record | Confirmed `preflight` failure |
| `disk-image-failure` | Explicit terminal record | Confirmed `diskOrImage` failure |
| `client-install-failure` | Explicit terminal record | Confirmed `installClient` failure |
| `software-install-failure` | Explicit terminal record | Confirmed `installSoftware` failure |
| `reboot-continuation` | Reboot with continuation expected | `postAction`, deferred |
| `invalid-offset` | Complete keyed CCM record with unusable offset | Phase retained; ordering unknown |
| `unknown-profile` | Key-looking fields under an unknown version | Low source-local candidate |
| `complete-looking-unkeyed` | Terminal-looking line without exact key | Low source-local observation |

The corpus has 17 scenarios, 22 artifacts, and 21 evidence files totaling
exactly 8,243 bytes and 21 logical file lines. Across the 22 physical artifact
rows, manifest capture states are 21 captured and one absent; of those
captured rows, 19 contain complete logical CCM records and two are partial
rotation fragments. Across the 17 scenario-level logical coverage rows, 15 are
captured, one is partial, and one is absent. The
path-and-artifact-qualified evidence content digest is SHA-256
`917df82bdf96ae4debd3e02e669669a9b564e932d7052091fb39094305593c8b`.

The Rust contract hashes every physical file, builds sorted rows as
`scenario NUL artifactId NUL relativePath NUL fileSha256 LF`, and hashes the
concatenated rows. This binds scenario, physical identity, safe path, and
bytes. It also pins unique manifest references, exact byte counts, and the
absence of orphaned or aliased evidence files.

## Determinism and fail-closed checks

The runnable contract derives manifest coverage rather than trusting expected
output, binds provenance back to physical artifacts, normalizes CCM
timestamps, and verifies exact keys against cited lines. It requires sorted,
unique transaction, observation, finding, and provenance IDs.

Adversarial mutations prove the contract rejects:

- expected output that upgrades absent coverage to captured;
- an execution ID not present in the cited evidence;
- a normalized timestamp not produced by the cited CCM record;
- two artifact IDs that alias one physical evidence path;
- escalation of an unkeyed observation above low confidence; and
- a confirmed failure with no terminal citation.

The source-local ceiling and forbidden join rules mean a plausible name or
time cannot fill an identity gap.

## Privacy and acceptance limits

All paths, IDs, versions, messages, phases, times, and codes are deterministic
synthetic values. The corpus contains no customer name, real user profile,
SID, email, token, certificate, tenant, device serial, or copied production
log text.

This is parser-side preparation only. It does not claim native Windows
collection, live ConfigMgr compatibility, task execution on a Windows client,
or SCCM lab acceptance. Passing this corpus is not an issue-closure condition.

## References

- [Microsoft: About log files in Configuration Manager](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/about-log-files)
- [Microsoft: Task sequence variables](https://learn.microsoft.com/en-us/intune/configmgr/osd/understand/task-sequence-variables)
- [Microsoft: Using task sequence variables](https://learn.microsoft.com/en-us/intune/configmgr/osd/understand/using-task-sequence-variables)

## Replay gates

Run the checked-in preparation contract:

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence_fixture_contract
```

That target validates the exact inventory/digest, physical storage,
manifest-derived coverage, CCM logical completeness, controlled rotation join,
path relocation, exact-key binding, same-time separation, timestamp
provenance, phase/terminal semantics, confidence ceilings, safe paths, and
privacy.

Before implementation is merged against the final #318/#319 interfaces, also
run:

```bash
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
npx tsc --noEmit
rustfmt --edition 2021 --check \
  crates/cmtraceopen-parser/tests/sccm_client_task_sequence_fixture_contract.rs
git diff --check
```

The future implementation must first map these preparation labels to the
reviewed #318/#319 contracts and request a false-causality review. It must not
add native-acceptance or server-causality claims based on these fixtures.
