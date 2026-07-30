# Parser Family Architecture and Format Roadmap

## Status

Approved overall architecture; the SCCM end-to-end diagnostics expansion is
revised and ready for written review. This document defines the public module
skeleton, compatibility policy, and issue boundaries for the next generation
of `cmtraceopen-parser`.

The SCCM section is intentionally a diagnostic roadmap, not a claim that the
crate already interprets all Configuration Manager logs. Its proposed tracker
issues are organized around evidence-backed workflows that can eventually power
dedicated SCCM Client and SCCM Server workspaces.

## Goal

Replace the implementation-oriented public `parser::*` surface with a
discoverable, product-oriented API. A consumer should be able to find a parser
from its management workload, operating system, product, and artifact type
without knowing the current source-file layout.

The hierarchy is deliberately:

```text
<management family>::<workload>::<operating system>::<product/type>
```

The parser crate remains pure Rust and wasm-compatible. Filesystem access,
live Windows event-log access, and platform command execution remain in native
adapters in `src-tauri`.

## Current-state constraints

- The published crate currently exposes `collector`, `dsregcmd`, `error_db`,
  `esp`, `intune`, `models`, and an implementation-centric `parser` module.
- The parser dispatcher currently owns 20 detected `ParserKind` variants.
- CCM is a reusable record grammar, not an SCCM-only product parser. It is
  also used by the Intune Management Extension (IME).
- The existing ESP engine already covers both Enrollment Status Page and
  Device Preparation scenarios.
- DNS Audit EVTX and Windows Intune event-log parsing are native-only today;
  their pure model/reduction logic can move, but their file readers must not
  silently become unconditional crate dependencies.

## Canonical public tree

`[current]` means existing behavior moves or is re-exported. `[planned]`
means the path is reserved but does not promise a parser until its issue has
fixtures and an input contract. `[native]` is an existing native adapter that
must remain explicitly feature-gated or outside the pure crate.

```text
cmtraceopen_parser
├── core                                                   [current]
│   ├── types                                              # LogEntry, ParseResult, filters, selection metadata
│   ├── severity
│   ├── encoding
│   └── errors                                             # error lookup, search, and spans
├── detect                                                 [current]
├── evidence                                               [current] # profiles/contracts; no on-device I/O
│
├── ccm                                                    [current] # shared CMTrace/CCM grammar
│   ├── records
│   └── legacy                                             # $$< legacy format
├── cmtlog                                                 [current]
├── generic                                                [current]
│   ├── timestamped
│   └── plain
│
├── sccm                                                    # semantic SCCM diagnostics over CCM records
│   ├── common                                              [planned shared diagnostic contract]
│   │   ├── artifacts                                       # source catalog, paths, rotation and capture coverage
│   │   ├── evidence                                        # cited normalized records and typed signals
│   │   ├── identifiers                                     # stable correlation keys
│   │   ├── timeline
│   │   └── findings                                        # symptom, diagnosis, confidence, and next evidence
│   ├── client
│   │   └── windows
│   │       ├── intake                                      [planned]
│   │       ├── setup_and_health                            [planned]
│   │       ├── identity_and_location                       [planned]
│   │       ├── policy                                      [planned]
│   │       ├── content                                     [planned]
│   │       ├── applications                                [planned]
│   │       ├── software_updates                            [planned]
│   │       ├── inventory_and_compliance                    [planned]
│   │       ├── task_sequence                               [planned]
│   │       ├── status                                      [planned]
│   │       └── co_management                               [planned]
│   ├── server
│   │   └── windows
│   │       ├── site_core                                   [planned]
│   │       ├── management_point                            [planned]
│   │       ├── distribution_point                          [planned]
│   │       ├── software_update_point                       [planned]
│   │       ├── hierarchy_and_replication                   [planned]
│   │       ├── provider_and_admin_service                  [planned]
│   │       ├── os_deployment                               [planned]
│   │       ├── notification                                [planned]
│   │       ├── cloud_and_service_connection                [planned]
│   │       ├── reporting                                   [planned]
│   │       └── certificate_enrollment                      [planned]
│   └── correlation
│       └── client_server                                   [planned]
│
├── intune
│   ├── apps
│   │   ├── windows
│   │   │   ├── ime                                        [current]
│   │   │   │   ├── logs
│   │   │   │   ├── events
│   │   │   │   ├── policies
│   │   │   │   ├── downloads
│   │   │   │   └── timeline
│   │   │   ├── win32                                      [planned]
│   │   │   ├── microsoft_store                            [planned]
│   │   │   ├── scripts                                    [planned]
│   │   │   └── remediations                               [planned]
│   │   ├── macos
│   │   │   ├── pkg                                        [planned]
│   │   │   └── shell_scripts                              [planned]
│   │   ├── ios_ipados                                     [planned]
│   │   └── android                                        [planned]
│   │
│   ├── enrollment
│   │   ├── windows
│   │   │   ├── esp                                        [current]
│   │   │   ├── device_preparation                         [current through esp]
│   │   │   └── autopilot                                  [planned]
│   │   ├── macos
│   │   │   └── automated_device_enrollment                [planned]
│   │   ├── ios_ipados
│   │   │   └── automated_device_enrollment                [planned]
│   │   └── android
│   │       ├── work_profile                               [planned]
│   │       ├── fully_managed                              [planned]
│   │       └── dedicated                                  [planned]
│   │
│   ├── device
│   │   ├── windows
│   │   │   ├── configuration                              [planned]
│   │   │   ├── compliance                                 [planned]
│   │   │   ├── updates                                    [planned]
│   │   │   └── event_log                                  [native]
│   │   └── macos
│   │       └── mdm_daemon                                 [current]
│   │
│   └── portal                                             # a cross-workload client, not merely an app
│       ├── windows
│       │   └── company_portal
│       │       ├── logs                                   [current collection; planned parser]
│       │       ├── diagnostics                            [current collection]
│       │       └── package_state                          [current collection]
│       ├── macos
│       │   └── company_portal
│       │       ├── logs                                   [current discovery; planned parser]
│       │       ├── diagnostics                            [current import path]
│       │       └── unified_log                            [current source; planned parser]
│       ├── android
│       │   └── company_portal
│       │       └── diagnostics                            [planned imported artifact]
│       └── ios_ipados
│           └── company_portal
│               └── diagnostics                            [planned Console/imported artifact]
│
├── patchmypc
│   ├── detection                                           [current]
│   ├── ccm                                                 [planned facade]
│   └── installers                                          [planned facade]
├── psadt
│   ├── legacy                                              [current]
│   └── ccm                                                 [planned facade]
├── installers
│   ├── msi                                                 [current]
│   └── burn                                                [current]
├── windows
│   ├── servicing::{cbs, dism}                              [current]
│   ├── setup::panther                                      [current]
│   ├── update::reporting_events                            [current]
│   ├── registry                                            [current]
│   └── secure_boot::certificate_update                     [current]
├── network
│   ├── dhcp                                                [current]
│   └── dns::{debug, types, audit}                          [audit is native]
├── web::iis::w3c                                           [current]
└── identity::windows::dsregcmd                             [current]
```

## Design decisions

### CCM and SCCM are separate concepts

`ccm` owns the raw CMTrace-compatible record grammar. It remains reusable by
SCCM, IME, and any other producer of that wire format. SCCM paths must not
duplicate the raw parser or advertise a distinct ParserKind merely because a
file uses CMTrace syntax.

Instead, `sccm` owns source classification, normalization, correlation, and
findings. Today, any SCCM CMTrace log resolves to the generic CCM grammar; the
planned SCCM paths become meaningful only as each workflow gains a source
contract, fixtures, semantic analyzer, and evidence-backed output.

### Intune is workload-first

IME is one current leaf at `intune::apps::windows::ime`; it is not the Intune
namespace itself. Existing IME event, policy, download, GUID, and timeline
analysis move below that leaf. Existing ESP and Device Preparation logic moves
to `intune::enrollment::windows::esp`.

### Company Portal is a first-class cross-workload surface

Company Portal spans sign-in, enrollment, app catalog, compliance, and device
self-service. It therefore belongs at `intune::portal`, alongside—not below—
`apps`, `enrollment`, and `device`.

Current evidence is platform-specific:

- Windows Company Portal files are already collected from
  `%LOCALAPPDATA%\\Packages\\Microsoft.CompanyPortal_8wekyb3d8bbwe\\LocalState\\*`.
- macOS Company Portal files are already discovered under
  `~/Library/Logs/CompanyPortal/`; diagnostic reports and unified-log evidence
  are separate input shapes.
- Android diagnostics are user-saved or uploaded artifacts, normally from the
  work profile.
- iOS/iPadOS diagnostics are imported captures, including macOS Console
  output; the crate must not assume device filesystem access.

Each dedicated parser needs representative, sanitized fixtures before its
public API becomes non-experimental.

### Preserve compatibility deliberately

The first skeleton release adds canonical paths and re-exports existing
implementations. It does not change parsing behavior or delete source files.

For at least one minor release:

- `parser` remains as a deprecated compatibility façade.
- `models` remains as a deprecated façade to `core::types`.
- `error_db` remains as a deprecated façade to `core::errors`.
- top-level `esp` remains as a deprecated façade to
  `intune::enrollment::windows::esp`.

The root crate documentation becomes the primary docs.rs landing page: a short
quick start, the family map, stability policy, and links to product modules.

## SCCM end-to-end diagnostic architecture

### Product boundary

The SCCM feature is not a set of independently rendered log files. It turns a
bundle of supplied client and/or server artifacts into a bounded answer to
“what is wrong in this deployment or site workflow?”

The pure parser crate receives artifact contents and provenance. Native
adapters and the later workspaces discover and collect files, registry exports,
event logs, and optional database/status exports. Neither layer may infer that
a missing file proves success, absence of a role, or absence of a failure.

The intended dependency direction is:

    raw CCM records -> classified SCCM evidence -> transactions and timeline
    -> findings with cited evidence -> SCCM Client / SCCM Server workspace

The client and server products consume the same contract but never blend their
local state. A client-only bundle can make a client finding and request the
server artifact needed to raise confidence. A server-only bundle can make a
role finding and request the client transaction that would connect it to an
endpoint symptom.

### Diagnostic contract

Every SCCM analyzer emits a common, serializable diagnostic model. This is
informed by the existing ESP evidence/coverage/finding model, but must remain
SCCM-specific rather than coupling SCCM behavior to ESP.

| Contract | Required meaning |
| --- | --- |
| SccmArtifact | A supplied file or export with a stable artifact ID, original path/name, role candidate, collection time, encoding, rotation lineage, and coverage status. The log artifact name is distinct from CCM's source-code-file field. |
| SccmEvidence | A normalized record or imported status fact with an exact artifact/entry reference, timestamp, component, message, raw typed signals, and privacy-classified execution or user context. |
| SccmCorrelationKey | Stable keys such as client GUID/resource ID, site code, MP/DP/SUP host, assignment/advertisement, CI/model, package/content/version, update/KB, task-sequence execution, BITS job, request/topic, and state message ID. |
| SccmTransaction | A time-normalized workflow instance with phases, participants, terminal state, supporting evidence, and explicitly missing expected evidence. |
| SccmFinding | A symptom, confirmed terminal failure, blocked/deferred state, likely contributor, or insufficient-evidence result. It includes phase, scope/role, severity, confidence, evidence references, correlation keys, remediation-safe next checks, and required next artifacts. |

The raw parser must preserve the CCM context attribute in the SCCM evidence
model because SYSTEM versus user context can change the interpretation of an
application or task-sequence result. Exports redact that value by default.
SCCM signal extraction also preserves known and unknown HRESULT, Win32,
exit-code, return-code, hr=, status=, and [gle=] values. Highlighting a known
error code is useful UI metadata; it is not a sufficient diagnostic model.

Correlation is deterministic first: stable identifiers and explicit
request/response relationships take precedence. Time proximity alone can
produce only low-confidence linkage. A single error line is a symptom unless a
terminal outcome or corroborating chain proves the affected phase and cause.

### Evidence coverage and intake

The later collectors must model source coverage before analyzers run:

- Defaults are candidates, not universal truths. The source contract preserves
  configured path provenance for clients, site servers, management points,
  distribution points, and WSUS/SUP hosts.
- It collects a bounded, deterministic workload-priority set, then selected
  incident bundles, current files, .lo_ files, and timestamped or numbered
  rotations. The manifest records each expected source as captured, absent,
  access-denied, capped, skipped, or unsupported.
- The current embedded profile stages only CCMSetup logs and a CCM registry
  export. The SCCM intake issue must split that misleading entry into separate
  CCMSetup and client-operational roots, add the true %SystemRoot%\CCM\Logs
  source, and preserve rotations.
- Client intake includes deployment-output/CCMCache evidence and the
  phase-dependent Task Sequence log locations. Server intake treats site,
  management-point, distribution-point, and SUP paths as individually
  discoverable role sources.
- Optional status-message, site-database, registry, IIS, Windows Update,
  CBS/DISM, and deployment-output exports are first-class supplemental
  artifacts. They never become hidden local-machine requirements of the pure
  crate.

### Client diagnostic streams

Client analysis follows the actual deployment path, rather than asking users
to guess a log name:

1. Setup and health: client installation, upgrade/repair, service lifecycle,
   client evaluation, and reboot state.
2. Identity, assignment, and location: registration, certificate or Entra
   authentication, site assignment, boundary/location resolution, and MP/SUP
   selection.
3. Policy: request, download, persistence, scheduling, evaluation, and state
   reporting.
4. Content and applications: intent/requirements, DP selection, BITS/cache
   transfer, enforcement, detection, and final state message.
5. Software updates: scan/source location, compliance evaluation, download,
   maintenance-window enforcement, install, reboot, and reporting.
6. Task sequence: WinPE through post-client log relocation, exact step,
   content, command, and reboot outcomes.
7. Inventory, compliance, metering, co-management, scripts, notification, and
   Software Center: each remains a distinct state-machine contract rather than
   an “everything else” parser.

Each stream owns its representative log bundle and a sanitized multifile
corpus. For example, application diagnosis correlates intent, discovery,
content, enforcement, post-install detection, and state message rather than
declaring an AppEnforce error the root cause.

### Server diagnostic streams

Server analysis is role-first because the site server, management point,
distribution point, and SUP often live on different hosts:

1. Site core and status system: SMS Executive/site component health, hierarchy
   changes, inbox processing, component monitoring, status/state-message
   processing, and imported status-system exports.
2. Management point: client registration, authentication, location, policy,
   relay/status, and client-notification request/response paths.
3. Distribution point and content distribution: distribution jobs, package
   transfer, DP content-library/provider state, pull DP activity, and the
   existing IIS parser as supplemental HTTP evidence.
4. Software update point: WSUS/SUP install and health, synchronization,
   metadata/content processing, and the client-to-SUP location chain.
5. Hierarchy, replication, provider, and Admin Service: intersite send/receive
   and replication flow, SMS Provider/Admin Service activity, and optional
   database evidence whose provenance is explicit.
6. Later role tracks: OSD/PXE, notification, CMG/service connection,
   reporting, and certificate enrollment. These remain planned leaves until
   their input contracts and fixtures exist.

### Cross-side diagnostic rule

The correlation layer can connect a client transaction to MP, site, DP, or SUP
evidence only through stable keys and compatible role topology. It answers
questions such as “the client selected no usable DP” or “the DP content job
failed before the client attempted transfer,” with both sides cited.

It must not turn ordinary latency, an unrelated server error, missing
collection, or same-minute events into causal proof. When evidence is
incomplete, the output explicitly names the next smallest artifact bundle to
collect.

### Version, framing, and time controls

Correlation and signal extraction operate only after the raw parser has
reassembled a logical record. A physical-line split, a rotation boundary, or
unmatched tail text must never cause a partial record to become a key-bearing
event.

SCCM provenance retains the reported ConfigMgr version when the artifact
exposes it, the original local timestamp/display, and the parsed offset. The
existing raw CCM timestamp is normalized to UTC for ordering; SCCM analysis
must preserve the local form for evidence display and mark an unknown or
invalid offset as unresolved rather than inventing cross-host ordering.

Correlation-key extractors are versioned heuristics, not protocol guarantees.
Each rule declares the source/version family it was validated against. A rule
that cannot safely extract a stable key produces an evidence/coverage gap or
low-confidence candidate, never a silent guessed match. When a source family
shows release-specific wording, stable promotion requires fixtures from at
least two observed versions.

The first cross-side release is incremental: policy-to-MP and
content-to-DP pairs can ship as soon as both sides have validated contracts.
The broader correlation issue expands that graph; it does not block all
client/server value until every SCCM workflow exists.

## Skeleton PR scope

The skeleton PR will:

1. Add this architecture document and crate-level docs.
2. Add the canonical family-module structure using re-exports or minimal
   forwarding modules only.
3. Preserve all current behavior and public paths through deprecated façades.
4. Add compile-time/API tests for each new canonical current path.
5. Link the tracking issue and all concrete parser issues.

It will not implement any new format parser or SCCM semantic analyzer. Each
new parser or analyzer belongs in a separate PR that closes its own issue.

## Tracker issue policy

Create one issue per concrete input contract, not per empty namespace or
facade. An issue must identify the actual source, sample corpus, detection
signature, output model, malformed-input behavior, and platform boundary.

### SCCM diagnostic program

The SCCM work is one parent epic with workflow-oriented child issues. A child
issue owns a source bundle, classifier/normalizer rules, correlation keys,
terminal states, findings, coverage gaps, sanitized multifile fixtures, and
acceptance assertions. It is deliberately not one issue per raw .log file,
because most Windows client and many server logs reuse the CCM grammar.

The dependency gates are deliberate: shared contracts complete first; client
and server intake then proceed in parallel; each domain workflow depends on
its own intake foundation; and cross-side correlation first delivers the
validated policy-to-MP and content-to-DP pairs before expanding.

Open these SCCM issues in this dependency order:

The live checklist is [issue #317](https://github.com/adamgell/cmtraceopen/issues/317).
It links the shared contract [#318](https://github.com/adamgell/cmtraceopen/issues/318),
client intake [#319](https://github.com/adamgell/cmtraceopen/issues/319),
server intake [#335](https://github.com/adamgell/cmtraceopen/issues/335), and
the remaining workflow issues [#320](https://github.com/adamgell/cmtraceopen/issues/320)
through [#334](https://github.com/adamgell/cmtraceopen/issues/334).

1. **Epic: SCCM end-to-end diagnostics for future Client and Server
   workspaces.** Defines the product boundary and owns the child-issue
   checklist; the two workspaces consume the results later and do not
   duplicate diagnostic rules.
2. **Shared SCCM diagnostic contracts and source catalog.** Implement artifact
   provenance/coverage, normalized evidence, privacy treatment for execution
   context, typed known-and-unknown signal extraction, stable identifiers,
   transactions, timeline, and finding confidence.
3. **SCCM Client intake, collection contracts, and corpus foundation.** Split
   CCMSetup from client operational logs, capture deterministic priority
   bundles and rotations, and add sanitized multifile fixtures plus
   native-Windows validation. This issue must report partial/missing coverage
   rather than silently omitting it.
4. **SCCM Server role-aware intake, collection contracts, and corpus
   foundation.** Model role-specific site, MP, DP, SUP, provider, and hierarchy
   candidates with configured-path provenance, deterministic role bundles, and
   explicit source coverage.
5. **SCCM Client setup, health, identity, assignment, and location
   diagnostics.** Cover client install/repair/service evaluation, client
   identity and authentication, site assignment, boundary/location, and
   management-point selection.
6. **SCCM Client policy diagnostics.** Cover policy request, transfer,
   persistence, scheduling, evaluation, and state/status reporting.
7. **SCCM Client application, package, and content diagnostics.** Cover
   intent/requirements/dependencies, source/DP selection, BITS/cache transfer,
   enforcement, detection, and state reporting in a single deployment
   transaction.
8. **SCCM Client software-update diagnostics.** Cover SUP location,
   scan/evaluation, update content, maintenance windows, install/reboot, and
   reporting, with explicit CBS/DISM/Windows Update supplemental evidence.
9. **SCCM Client task-sequence diagnostics.** Cover phase-aware SMSTS/TS
   locations from WinPE through post-client operation, with step, content,
   command, and reboot terminal states.
10. **SCCM Client inventory, compliance, and metering diagnostics.** Cover
   provider collection, evaluation/remediation, report generation, and
   state-message delivery without conflating them with deployment semantics.
11. **SCCM Client co-management, scripts, notification, and Software Center
    diagnostics.** Distinguish workload hand-off, execution, user-facing
    notification, and policy/reporting outcomes.
12. **SCCM Server site-core and status-system diagnostics.** Cover site
    component health, inboxes, component monitoring, status/state-message
    processing, and optional exported status evidence.
13. **SCCM Server management-point diagnostics.** Cover client registration,
    authentication, location, policy, relay/status, and notification
    transactions; correlate with client requests only where stable keys match.
14. **SCCM Server distribution-point and content-distribution diagnostics.**
    Cover distribution jobs, package transfer, content-library/provider state,
    pull-DP behavior, and supplemental IIS evidence.
15. **SCCM Server software-update-point diagnostics.** Cover SUP/WSUS
    install/health, synchronization, metadata/content processing, and the
    client-to-SUP location chain.
16. **SCCM Server hierarchy and replication diagnostics.** Cover intersite
    transport/replication, sender/receiver state, and explicit optional
    database evidence.
17. **SCCM Server SMS Provider and Admin Service diagnostics.** Cover console,
    provider, and Admin Service paths without treating those artifacts as
    site-core or client-deployment evidence.
18. **SCCM Client-to-Server correlation and causal findings.** Build the
    deterministic client-to-MP/site/DP/SUP graph, require corroboration before
    a root-cause conclusion, and return the next minimal requested artifact
    when confidence is insufficient.
19. **SCCM advanced server role contracts.** Establish independently
    testable OSD/PXE, notification, CMG/service connection, reporting, and
    certificate-enrollment subtracks. It may create separate implementation
    issues only after each role's actual source bundle is verified.

The later SCCM Client workspace and SCCM Server workspace are explicitly
downstream consumers of this program. Their future UI issues can begin once
shared contracts and one client/server workflow provide stable fixture-backed
outputs.

Other initial tracker candidates:

1. Intune Windows Win32 app-install evidence parser.
2. Intune Windows Microsoft Store app evidence parser.
3. Intune Windows platform-script evidence parser.
4. Intune Windows remediation evidence parser.
5. Intune macOS app-management package and shell-script evidence parser.
6. Intune Windows Autopilot evidence parser.
7. Intune Windows configuration evidence parser.
8. Intune Windows compliance evidence parser.
9. Intune Windows Update for Business evidence parser.
10. Company Portal for Windows parser.
11. Company Portal for macOS parser.
12. Company Portal for Android imported-diagnostics parser.
13. Company Portal for iOS/iPadOS imported-diagnostics parser.

Existing parsers do not receive duplicates: MSI and PSADT are already tracked
by issue #23, and historic CCM/parser-location issues remain separate from
this semantic-analysis program. The current CCM, IME, ESP, CMTLOG, Patch My
PC, Windows, DNS, DHCP, IIS, Registry, and Secure Boot paths are migration
work in the skeleton PR rather than new-format work.

## Verification

The skeleton PR must pass:

```text
cargo test -p cmtraceopen-parser
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
```

For every follow-up parser issue, acceptance requires a realistic fixture,
positive detection test, negative/malformed fixture, encoding coverage where
applicable, output-contract assertions, and native Windows validation when the
source uses Windows-only APIs.

For every SCCM analyzer issue, acceptance additionally requires a multifile
transaction fixture with source-coverage assertions, deterministic ordering,
one completed workflow, one terminal or blocked workflow, one contradictory or
incomplete-evidence case, stable-correlation tests, and an assertion that the
finding cites its exact supporting entries. A high-confidence diagnosis must
not pass from a single severity/error-string match.

Key and signal extraction tests operate on logical records, not physical lines.
Cross-side tests normalize timestamps to UTC while retaining original local
evidence. A rule that encounters an unvalidated version or unresolved time
offset must lower confidence or request evidence rather than manufacture a
causal ordering.

## Non-goals

- No new parser implementation is included in the skeleton PR.
- No module claims support merely because its namespace exists.
- No native filesystem/event-log dependency is added to the default pure crate.
- No existing parser behavior is renamed or removed without a compatibility
  window and a semver-major release plan.
