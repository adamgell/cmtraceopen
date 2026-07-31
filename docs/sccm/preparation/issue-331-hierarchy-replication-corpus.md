# Issue #331 hierarchy and replication corpus

Status: preparation-only contract. Production extraction and reduction remain
blocked on the reviewed #318 finding boundary and the #335 native server intake
contract. This slice adds no native collection, database access, network access,
new parser family, or live Windows acceptance claim.

## Evidence boundary

Raw CCM remains the transport grammar. The corpus admits only the reviewed
site-server hierarchy family already declared by the shared catalog:

| Source | Direction | Candidate phases | Required evidence |
| --- | --- | --- | --- |
| `replmgr.log` | origin | initiate, queue or serialize | exact message, link, origin site, target site, profile |
| `sender.log` | origin | send, retry, terminal send failure | exact message, link, origin site, target site, profile |
| `despool.log` | target | receive, process, terminal receive/process outcome | exact message, link, origin site, target site, profile |
| `rcmctrl.log` | target | acknowledge, healthy or terminal | exact message, link, origin site, target site, profile |

The source name, a site-looking token, a remote host, or timestamp proximity
alone cannot create a transaction. Every transaction identity is derived from a
profile-validated message ID, link ID, origin site, and target site:

```text
hierarchy:{messageId}:{originSiteCode}:{targetSiteCode}:{linkId}
```

Unknown profiles and partial keys are source-local candidates only. They must
retain a key-extraction gap and cannot be upgraded by another source merely
because its record occurred nearby in time.

The synthetic profile `hierarchy-server-5.00.test-v1` admits only the exact
synthetic source version `5.00.TEST.0001`, the `siteServer` role, and an RFC3339
`collectedUtc` value with a usable numeric or `Z` offset. A missing, malformed,
or different source version/time value is outside that profile. Its record may
remain source-local with an extraction gap, but it cannot retain an exact key,
exact topology, or high-confidence transaction output.

## Topology and time

Origin and target direction, safe host handle, site code, source path,
rotation lineage, and physical capture identity remain attached to every
artifact. Origin artifacts must use the declared origin host. Target artifacts
must use the host declared for the exact primary or additional target site in
their profile-recognized record. Cross-host ordering is usable only when each
cited record has usable offset provenance. Missing, conflicting, or invalid
offsets prevent a high-confidence ordered diagnosis even if terminal-looking
evidence exists.

Two same-minute sender failures for different target sites are separate
transactions. The topology-mismatch fixture deliberately uses the same
message ID with different link and target-site keys; it produces no joined
transaction. The rotation fixture splits one transport record across current
and `.lo_` artifacts; neither fragment may emit a logical CCM record or a
terminal result. Candidate groups serialize in exact-key and full-provenance
order, so reversed artifact input is byte-identical while same-key facts with
different path, host, or rotation identity remain distinct. The immutable
transaction key never absorbs an artifact path, host handle, rotation, or line
range. Conversely, sharing that key never permits distinct evidence facts to be
deduplicated: every fact retains its full artifact and line provenance, and an
incompatible host, site, profile, or rotation remains source-local.

## Coverage and conclusions

The additive SCCM manifest keeps `captured`, `absent`, `accessDenied`, `capped`,
`skipped`, `unsupported`, and `parseFailed` distinct. A missing remote artifact
is a coverage state, not evidence that the remote role is absent or broken.

The gap column below applies per artifact. A non-captured artifact enters a
transaction's `coverageGapArtifactIds` only when an exact transaction candidate
already exists; otherwise it remains a source-local coverage gap.

| Coverage state | Gap mapping | Bounded request in this profile |
| --- | --- | --- |
| `captured` | No coverage gap; evidence still must parse and cite successfully | None |
| `absent` | One gap for that exact artifact ID when the source is required | `coverageAbsent` for that artifact's exact source/direction/site/host/basename basis |
| `accessDenied` | One gap for that exact artifact ID; never proof that the role failed | None until an access-remediation request reason is versioned |
| `capped` | One gap for that exact artifact ID when required evidence may be truncated | `coverageCapped` for that artifact's exact provenance basis |
| `skipped` | One gap for that exact artifact ID when the source was required | None; preserve the collection decision |
| `unsupported` | One gap for that exact artifact ID | None; do not imply that recollection can make the source supported |
| `parseFailed` | One gap for that exact physical artifact ID | None; retain the parse failure without converting it to absence |

Coverage rows aggregate by artifact identity, never only by source name or
state: each manifest artifact has exactly one coverage row, and every
transaction gap ID resolves to exactly one non-captured manifest/coverage pair.
Multiple missing artifacts therefore remain sorted, unique per-artifact gaps;
they are not collapsed into a single broad “remote coverage” gap. Missing,
duplicated, empty, malformed, or unknown identities fail closed.

`coverageRotationSplit` is not an eighth coverage state. It is permitted only
for the exact current/`.lo_` sender pair with one lineage, canonical
basename/rotation identities, one direction, and one site/host mapping.
`invalidOffset` is likewise a time-provenance request reason, not a coverage
state. Every request must equal the provenance derived from its evidence;
`both` is valid only when both origin and target evidence are actually present.
No request is synthesized for `accessDenied`, `skipped`, `unsupported`, or
`parseFailed` under this profile. Bounded follow-up requests name only the
relevant hierarchy source, exact direction, target site, mapped host, and
basenames.

The proposed state sequence is:

```text
Initiate -> QueueOrSerialize -> Send -> Receive -> Process
         -> Acknowledge -> HealthyOrTerminal
```

Retry/backlog without a terminal record remains `blockedOrDeferred`. A
high-confidence success or confirmed failure requires cited terminal evidence,
an exact validated key, compatible topology, usable time provenance, and no
coverage gap. A later success is recovery only for the same exact immutable
key. Contradictions remain visible.

No client impact, remote root cause, site-wide impact, or cross-side causal
claim is produced here. Future correlation remains owned by #333 and must use a
separately reviewed pair; time alone is never eligible.

## Scenario matrix

| Scenario | Contract |
| --- | --- |
| `healthy-link` | Complete exact-key path ends in cited acknowledgement/terminal success |
| `sender-failure` | Same-minute failures to CHD and SEC remain two terminal transactions |
| `receiver-processing-failure` | Cited send precedes a terminal target processing failure |
| `backlog-retry` | Nonterminal retry remains medium-confidence deferred evidence |
| `recovery` | Later same-key send/process success produces recovery |
| `absent-remote-source` | Missing target source is a low-confidence gap with one bounded request |
| `clock-offset-unknown` | Invalid offsets prohibit high-confidence cross-host ordering |
| `generic-site-token` | A valid generic CCM record with `CHD` but no exact hierarchy grammar creates no candidate |
| `topology-mismatch` | Same message with incompatible link/target keys remains unlinked |
| `rotation-boundary` | Partial current/`.lo_` fragments never form a record or transaction |
| `incomplete` | Capped partial origin evidence remains source-local coverage |

All committed bytes are synthetic and sanitized. The in-progress SCCM Server
lab may later validate native discovery and source semantics, but it is not an
acceptance source for this preparation slice.
