# Parser Family Architecture and Format Roadmap

## Status

Approved design. This document defines the public module skeleton, compatibility
policy, and issue boundaries for the next generation of `cmtraceopen-parser`.

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
├── sccm
│   ├── client                                             [current facade over ccm]
│   ├── site_server                                        [planned]
│   │   ├── management_point
│   │   ├── distribution_point
│   │   └── software_update_point
│   └── co_management                                      [planned]
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

`ccm` owns the raw CMTrace-compatible record grammar. `sccm::client` is a
product façade over it. This avoids duplicating the parser while reserving a
truthful home for future Configuration Manager site-server logs.

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

## Skeleton PR scope

The skeleton PR will:

1. Add this architecture document and crate-level docs.
2. Add the canonical family-module structure using re-exports or minimal
   forwarding modules only.
3. Preserve all current behavior and public paths through deprecated façades.
4. Add compile-time/API tests for each new canonical current path.
5. Link the tracking issue and all concrete parser issues.

It will not implement any new format parser. Each new parser belongs in a
separate PR that closes its own issue.

## Tracker issue policy

Create one issue per concrete input contract, not per empty namespace or
facade. An issue must identify the actual source, sample corpus, detection
signature, output model, malformed-input behavior, and platform boundary.

Initial tracker candidates:

1. SCCM site-server log-family discovery and contract inventory.
2. Intune Windows Win32 app-install evidence parser.
3. Intune Windows Microsoft Store app evidence parser.
4. Intune Windows platform-script evidence parser.
5. Intune Windows remediation evidence parser.
6. Intune macOS app-management package and shell-script evidence parser.
7. Intune Windows Autopilot evidence parser.
8. Intune Windows configuration evidence parser.
9. Intune Windows compliance evidence parser.
10. Intune Windows Update for Business evidence parser.
11. Company Portal for Windows parser.
12. Company Portal for macOS parser.
13. Company Portal for Android imported-diagnostics parser.
14. Company Portal for iOS/iPadOS imported-diagnostics parser.

Existing parsers do not receive duplicates: MSI and PSADT are already tracked
by issue #23, while the current CCM, IME, ESP, CMTLOG, Patch My PC, Windows,
DNS, DHCP, IIS, Registry, and Secure Boot paths are migration work in the
skeleton PR rather than new-format work.

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

## Non-goals

- No new parser implementation is included in the skeleton PR.
- No module claims support merely because its namespace exists.
- No native filesystem/event-log dependency is added to the default pure crate.
- No existing parser behavior is renamed or removed without a compatibility
  window and a semver-major release plan.
