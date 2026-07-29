# Log Parser Hardening Design

**Date:** 2026-07-29
**Status:** Approved design; awaiting written-spec review
**Scope:** Every declared log parser kind, the IME specialization, file decoding, parser selection, structured extraction, and malformed-input recovery

## Goal

Make parser support explicit and regression-proof. Every supported log format must have a deterministic automated contract that proves the correct parser is selected and representative records are parsed into the expected `LogEntry` or dedicated structured result.

The work must harden defects exposed by those contracts without broad parser rewrites or unrelated behavior changes.

## Supported Parser Inventory

The authoritative inventory is the `ParserKind` enum in `crates/cmtraceopen-parser/src/models/log_entry.rs`. It currently contains 20 parser kinds:

1. CCM
2. Simple
3. Generic timestamped
4. Plain text
5. IIS W3C
6. Panther
7. CBS
8. DISM
9. ReportingEvents
10. MSI
11. PSADT Legacy
12. Intune macOS
13. DHCP
14. Burn
15. Patch My PC detection
16. Registry export
17. Secure Boot update log
18. DNS debug
19. DNS Audit EVTX
20. CmtLog

IME is a `ParserSpecialization` layered on the CCM implementation. It is part of the support contract and requires its own fixture even though it is not a separate `ParserKind`.

## Architecture

### Contract matrix

Add a single integration-level parser contract matrix as the visible inventory of supported formats. Each contract identifies:

- parser kind and implementation;
- representative fixture or in-memory native record;
- expected provenance, parse quality, record framing, date order, and specialization;
- expected compatibility `LogFormat`;
- format-specific output assertions;
- expected parse-error behavior.

The matrix will use an exhaustive match over `ParserKind` and assert unique coverage for every declared kind. This gives future parser additions a clear compiler/test failure until a contract is added. IME coverage is asserted separately because it is a specialization.

### Existing focused tests

Existing parser unit tests remain the place for detailed grammar cases. Existing regression and expanded-corpus tests remain valid. The new matrix does not duplicate every assertion; it proves the end-to-end contract from detection or native routing through structured output.

### Native-only formats

Registry and DNS Audit do not use the line-based dispatch in `parse_lines_with_selection`:

- Registry contracts call the dedicated registry parser and file command boundary using `.reg` content.
- DNS Audit contracts exercise provider recognition and event conversion with deterministic, synthetic serialized-event data. The existing local real-EVTX test remains an optional smoke test, but CI correctness must not depend on the ignored `Logs/` directory.

If the EVTX reader cannot be exercised deterministically without committing a large or sensitive binary, extract a small internal adapter that accepts serialized EVTX event JSON. Test the adapter and DNS provider routing with synthetic records, while retaining the real-file smoke test for the `evtx` crate boundary.

No customer, tenant, device, user, or private-domain data may be added to fixtures.

## Fixture Strategy

Text fixtures live under `src-tauri/tests/corpus/<format>/<case>/` and are intentionally small. Each clean fixture contains enough records to satisfy production detection thresholds without relying on a misleading filename unless path-based detection is itself part of the format contract.

Each format receives:

- one clean fixture proving detection and representative field extraction;
- one focused malformed or boundary fixture when the parser has logical-record framing, continuation syntax, quoting/escaping, or multi-line data;
- exact assertions on meaningful fields rather than only entry counts.

Existing fixtures are reused where they already express the contract. New fixtures are required for missing kinds rather than generating test data at runtime, except for synthetic DNS Audit serialized events.

## Required Assertions by Format

| Format | Required proof |
|---|---|
| CCM | Logical-record recovery, multiline message preservation, severity types 0-3, component, thread, source file, timezone |
| IME specialization | IME filename/content selects CCM plus `Ime`; representative IME record fields remain intact |
| Simple | Component, timestamp, thread, severity, malformed suffix fallback |
| Generic timestamped | ISO, slash-date, syslog, and time-only recognition; month/day order; continuation handling |
| Plain | Every non-empty line is preserved with stable line numbers and no invented timestamp |
| IIS W3C | `#Fields` mapping, URI/query, status/substatus, Win32 status, timing, and missing-column behavior |
| Panther | Logical records, continuation lines, component/severity, result and GLE codes, setup phase and operation |
| CBS | Logical records, continuation lines, component, severity, and mixed fallback segments |
| DISM | Logical records, DISM and CBS-style components, continuation lines, and mixed fallback segments |
| ReportingEvents | Record framing, event metadata/message, timestamp, and malformed record preservation |
| MSI | Header/action records, timestamp, component/severity, and unstructured continuation text |
| PSADT Legacy | Legacy delimiter parsing, severity mapping, component, and plain fallback |
| Intune macOS | Timestamp, process/component, severity, message, and plain fallback |
| DHCP | IPv4 and IPv6 server records, event ID, IP, host, MAC, and invalid record handling |
| Burn | Timestamp, engine/component, severity, message, and continuation/fallback behavior |
| Patch My PC detection | Detection signature, timestamp, severity, message, and false-positive boundary |
| Registry | Version 5 and REGEDIT4 headers; default/named values; string, DWORD, QWORD, binary, expand, multi-string, delete markers, continuation lines, UTF-16LE file decoding, malformed value count |
| Secure Boot update | Path/content detection, timestamp, level/severity, event fields, and plain fallback |
| DNS debug | Month-first/day-first/ISO dates, query name/type, RCODE severity, protocol/direction, IPv4/IPv6, and logical details |
| DNS Audit EVTX | DNS provider recognition, event ID dispatch, timestamp, DNS fields, severity, non-DNS filtering, malformed serialized record counting |
| CmtLog | Header/section/iteration/log kinds, inherited section color, tags, WhatIf, severity, and heuristic `.log` detection |

## Encoding and File-Boundary Coverage

The shared file reader must be covered independently from grammar tests:

- UTF-8 with and without BOM;
- UTF-16LE with BOM;
- UTF-16BE with BOM;
- Windows-1252 fallback;
- CRLF normalization where applicable;
- byte offset and file size consistency.

At least CCM and Registry must pass through the file boundary using their common Windows encodings. Encoding tests assert decoded content and parsed values so a decoder regression cannot pass by only producing valid Unicode.

## Hardening Rules

Parser changes follow test-driven development:

1. Add one focused contract or regression assertion.
2. Run it and confirm it fails for the intended behavioral reason.
3. Make the smallest parser change that satisfies the contract.
4. Re-run the focused test and relevant parser suite.
5. Refactor only after green.

Hardening priorities are:

- preserve input rather than silently drop malformed records;
- increment `parse_errors` for recoverable malformed structured input;
- prevent one format's heuristic from stealing another format's records;
- keep line numbers tied to source lines or logical-record starts;
- avoid panics on truncated input, invalid dates, invalid numerics, and incomplete continuations;
- preserve current public serialization names and frontend compatibility.

The work will not add a parser plugin architecture, replace regex-based parsers wholesale, or redesign the log viewer.

## Verification

Focused verification:

```bash
cargo test -p cmtraceopen-parser parser
cargo test -p cmtrace-open --test parser_supported_formats
cargo test -p cmtrace-open --test parser_expanded_corpus
cargo test -p cmtrace-open --test parser_regression_corpus
cargo test -p cmtrace-open --features event-log --test dns_audit_real
```

The DNS Audit real-file test may report a deliberate skip when the ignored local fixture is unavailable; synthetic DNS Audit contract tests must still execute and pass in CI.

Final verification:

```bash
cargo test -p cmtraceopen-parser
cargo test -p cmtrace-open
cargo fmt --all -- --check
cargo clippy -p cmtraceopen-parser -p cmtrace-open --all-targets --all-features -- -D warnings
```

Any platform-specific test that cannot execute on macOS must have a portable pure-parser contract and be called out explicitly rather than reported as locally verified.

## Success Criteria

- All 20 `ParserKind` variants have a deterministic contract.
- IME specialization has a deterministic contract.
- Each contract asserts parser selection and meaningful parsed fields.
- Registry and DNS Audit are tested through their dedicated architecture.
- File encodings and byte accounting are covered.
- Every hardening change has a demonstrated red-green regression test.
- Parser suites, formatting, and linting pass, with platform-specific limits reported precisely.
