# DNS Log Parser Design

**Date:** 2026-04-11
**Status:** Draft
**Scope:** Parser-only (workspace deferred to future phase)

## Overview

Add DNS log parsing to CMTrace Open, supporting three formats with a fourth stubbed for future implementation. All formats output `LogEntry` and display in the standard log viewer — no dedicated workspace.

| Format | Source | Parser | Status |
|--------|--------|--------|--------|
| DNS debug log (`dns.log`) | Text file from `dns.exe` | `dns_debug.rs` | Full implementation |
| DNS audit EVTX (Event IDs 513-582) | Standard `.evtx` event log | `dns_audit.rs` | Full implementation |
| DNS analytical ETL (Event IDs 256-280) | ETW `.etl` trace | — | Stubbed (extension detection + error message) |
| Live ETW capture | Real-time ETW subscription | — | Deferred (not in scope) |

## Architecture: Approach C — Flat Files, Unified Entry Point

Three new files in `src-tauri/src/parser/`:

```
parser/
  dns_debug.rs      — text dns.log parser (LogicalRecord framing)
  dns_audit.rs      — EVTX audit parser via evtx crate
  dns_types.rs      — shared QTYPE/RCODE maps, query name decoder
```

Both parsers return through the existing `open_log_file()` command. The frontend does not need to distinguish between DNS text and DNS EVTX — `parse_file()` handles detection and routing internally.

---

## 1. File Detection & Routing

### Debug log detection (`detect.rs`)

- **Path hints:** filename contains `dns` (case-insensitive), or path contains `\dns\` or `/dns/`
- **Content match:** `matches_dns_debug_record(line)` checks for `PACKET` keyword with surrounding DNS field structure (thread hex, UDP/TCP, Snd/Rcv, IP, XID, flags bracket)
- **Sample window:** first 50 non-empty lines when DNS path hints are present (up from default 20) to clear the ~29-line header
- **Returns:** `ResolvedParser` with `ParserKind::DnsDebug`, `ParserImplementation::DnsDebug`, `RecordFraming::LogicalRecord`, `ParseQuality::Structured`

### Binary file detection (`parse_file()` in `mod.rs`)

Early guard before text decoding:

1. Check file extension
2. If `.evtx` → open with `EvtxParser`, read first record, check for DNS provider GUID `{EB79061A-A566-4698-9119-3ED2807060E7}` or provider name `Microsoft-Windows-DNSServer`
   - DNS match → `dns_audit::parse_evtx(path)` → return `ParseResult`
   - No match → fall through to existing Sysmon path
3. If `.etl` → return error with platform-appropriate message:
   - **Windows:** "ETL analytical logs are not yet supported. Convert to XML on Windows with `tracerpt \"file.etl\" -of XML -o output.xml` and open the XML file."
   - **macOS/Linux:** "ETL files contain binary Windows event traces that require the Windows `tracerpt` tool to convert. Export to XML on a Windows machine first, then open the XML file here."
4. Otherwise → existing text decode + `detect_parser()` flow

### Date order detection (debug log)

Scan PACKET lines in the sample:
- If any date field position 1 > 12 → `DayFirst`
- If any date field position 2 > 12 → `MonthFirst`
- If all values <=12 → return ambiguous result; frontend prompts user: "This DNS log has ambiguous date formatting. Is the date format MM/DD or DD/MM?" and re-parses with the selection

---

## 2. Debug Log Parser (`dns_debug.rs`)

### Record framing: `LogicalRecord`

Each logical record is a PACKET summary line followed by detail lines until the next PACKET line or blank-line sequence. Uses the same pending-entry pattern as Panther/IME:

1. Scan each line
2. If it matches the PACKET regex → flush any pending entry, start a new one
3. If it's a detail line (indented, or starts with `UDP/TCP question/response info`) → append to pending entry
4. Header lines (before first PACKET match) → skip
5. Blank lines → skip

### PACKET line regex

```regex
^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?|\d{8}\s+\d{2}:\d{2}:\d{2})\s+([0-9A-Fa-f]{3,4})\s+PACKET\s+([0-9A-Fa-f]{8,16})\s+(UDP|TCP)\s+(Snd|Rcv)\s+([0-9a-fA-F.:]+)\s+([0-9a-fA-F]{4})\s+([R ])\s*([QNU?])\s+\[([0-9A-Fa-f]{4})\s+([ATDR ]{0,4})\s*(\w+)\]\s+(\S+)\s+(.+)$
```

Regex cached in `OnceLock<Regex>`.

### Field mapping

| Regex group | LogEntry field | Example |
|-------------|---------------|---------|
| 1 (timestamp) | `timestamp`, `timestamp_display` | `4/11/2026 3:29:17 PM` |
| 2 (thread hex) | `thread`, `thread_display` | `0294` |
| 4 (protocol) | `dns_protocol` | `UDP` |
| 5 (direction) | `dns_direction` | `Rcv` |
| 6 (remote IP) | `source_ip` | `192.168.2.9` |
| 7 (XID) | included in message | `d07e` |
| 8 (Q/R flag) | combined into `dns_flags` | `R` or space |
| 10 (flags hex) | `dns_flags` | `0x8085` |
| 12 (RCODE name) | `response_code` | `NOERROR` |
| 13 (QTYPE name) | `query_type` | `SOA` |
| 14 (QNAME raw) | `query_name` (decoded) | `home.gell.one` |

### Detail section extraction

From the multi-line detail block:
- `Remote addr X.X.X.X, port NNNNN` → port number appended to `source_ip` as `192.168.2.9:54159`
- Answer/authority/additional section presence → noted in message for context

### Message construction

- Query: `[Rcv] [UDP] home.gell.one (A) → NOERROR`
- Response: `[Snd] [UDP] home.gell.one (A) → NXDOMAIN`

### Severity mapping

| RCODE | Severity |
|-------|----------|
| NOERROR | Info |
| NXDOMAIN | Warning |
| SERVFAIL, REFUSED, FORMERR | Error |
| All other RCODEs | Warning |

### Timestamp parsing

Three locale variants detected from the PACKET line:
- **US locale:** `M/d/yyyy h:mm:ss tt` (12-hour with AM/PM)
- **EU locale:** `dd/MM/yyyy HH:mm:ss` (24-hour)
- **ISO-style:** `yyyyMMdd HH:mm:ss`

Parser detects which variant on first successful match and caches the format hint for subsequent lines (same pattern as `timestamped.rs`).

---

## 3. Audit EVTX Parser (`dns_audit.rs`)

### Entry point

`parse_evtx(path: &str) → Result<ParseResult, String>`

Uses `EvtxParser::from_path()` to iterate records as JSON. Each record dispatched by EventID to a schema group extractor.

### Schema group dispatching

| Group | Event IDs | Primary fields extracted |
|-------|-----------|------------------------|
| Record ops | 515-521 | `NAME` → `query_name`, `Type` → `query_type` (numeric→name), `RDATA` → hex in message, `Zone` → `zone_name`, `TTL`, `SourceIP` (519-520 only) |
| Zone config | 513-514, 522-537 | `Zone` → `zone_name`, `Setting`/`NewValue` in message |
| Server config | 540-560 | `Setting`, `Scope`, `Value` in message |
| DNSSEC key ops | 569-572 | Key fields in message |
| Policy ops | 577-582 | `PolicyName`, `Action`, `Criteria` in message |
| Delegation/subnet | 573-576 | Fields in message |
| Extended zone ops | 561-568 | `Zone` in message |

### Field mapping

| EVTX field | LogEntry field | Notes |
|------------|---------------|-------|
| `TimeCreated` | `timestamp`, `timestamp_display` | From System section |
| `EventID` | `dns_event_id` | Numeric |
| `NAME` / `QNAME` | `query_name` | Present in record ops |
| `Type` | `query_type` | Numeric → name via `dns_types.rs` |
| `RCODE` | `response_code` | Numeric → name |
| `Zone` | `zone_name` | Present in most events |
| `SourceIP` / `Destination` | `source_ip` | When available |

### Message construction by group

- Record ops: `[515 Record Create] home.gell.one (A) TTL=3600 Zone=home.gell.one`
- Zone config: `[514 Zone Setting] home.gell.one — Setting=AllowUpdate NewValue=1`
- Server config: `[541 Server Setting] serverlevelplugindll = ...`
- Other groups: `[EventID EventName] {available fields}`

### Severity mapping

| Condition | Severity |
|-----------|----------|
| Record delete (516, 520) | Warning |
| Zone delete (513) | Error |
| DNSSEC sign/unsign (525-527) | Warning |
| Server setting change (541) | Warning |
| Everything else | Info |

### DNS provider GUID detection

When `parse_file()` encounters a `.evtx` extension:
1. Open with `EvtxParser`
2. Read first record as JSON
3. Check `System.Provider.@Name` for `"Microsoft-Windows-DNSServer"` or `System.Provider.@Guid` for `{EB79061A-A566-4698-9119-3ED2807060E7}`
4. DNS match → `dns_audit::parse_evtx()`
5. No match → fall through to existing Sysmon path

---

## 4. Shared Types (`dns_types.rs`)

### QTYPE map (~40 entries)

Standard types (RFC 1035+): A(1), NS(2), CNAME(5), SOA(6), PTR(12), MX(15), TXT(16), AAAA(28), SRV(33), DS(43), RRSIG(46), NSEC(47), DNSKEY(48), HTTPS(65), CAA(257), etc.

Windows-specific: WINS(65281), WINSR(65282).

Meta types: AXFR(252), ANY(255).

### RCODE map (~24 entries)

NOERROR(0), FORMERR(1), SERVFAIL(2), NXDOMAIN(3), NOTIMP(4), REFUSED(5), YXDOMAIN(6), YXRRSET(7), NXRRSET(8), NOTAUTH(9), NOTZONE(10), BADVERS/BADSIG(16), BADKEY(17), BADTIME(18), BADMODE(19), BADNAME(20), BADALG(21), BADTRUNC(22), BADCOOKIE(23).

### Query name decoder

```
fn decode_query_name(raw: &str) → String
```

Handles:
- Wire-format: `(3)www(6)google(3)com(0)` → `www.google.com`
- Dotted: `.ns1.example.com.` → `ns1.example.com`
- Compression pointers: `[C00C](4)home(4)gell(3)one(0)` → strip `[XXXX]`, decode labels
- Root: `(0)` → `.`

### Severity helper

```
fn rcode_to_severity(rcode: &str) → Severity
```

Shared by both debug log and EVTX parsers.

---

## 5. LogEntry & Type System Changes

### New LogEntry fields (`models/log_entry.rs`)

Nine new optional fields, all with `#[serde(default, skip_serializing_if = "Option::is_none")]`:

```rust
pub query_name: Option<String>,
pub query_type: Option<String>,
pub response_code: Option<String>,
pub dns_direction: Option<String>,
pub dns_protocol: Option<String>,
pub source_ip: Option<String>,
pub dns_flags: Option<String>,
pub dns_event_id: Option<u32>,
pub zone_name: Option<String>,
```

### LogFormat additions

- `LogFormat::DnsDebug` → displays `"DNS Debug Log"`
- `LogFormat::DnsAudit` → displays `"DNS Audit (EVTX)"`

### ParserKind / ParserImplementation additions

- `ParserKind::DnsDebug`, `ParserKind::DnsAudit`
- `ParserImplementation::DnsDebug`, `ParserImplementation::DnsAudit`

### Routing (`parser/mod.rs`)

- `ParserImplementation::DnsDebug` → `dns_debug::parse_lines()`
- `ParserImplementation::DnsAudit` — not routed through `parse_lines()`; `parse_evtx()` returns `ParseResult` directly from the `parse_file()` early guard

---

## 6. Integration Points

### Commands (`commands/parsing.rs`, `commands/file_ops.rs`)

No changes needed. `open_log_file()` calls `parse_file()` which handles both text and EVTX DNS files. `ParseResult` returns with the appropriate `LogFormat`.

### Tailing

- DNS debug log: works through existing pipeline. `ResolvedParser` stored in `AppState`, `start_tail()` calls `parse_lines_with_selection()` with `ParserImplementation::DnsDebug` and `LogicalRecord` framing.
- DNS EVTX: no tailing (EVTX is a snapshot, not a live-appended file).

### Feature gating (`Cargo.toml`)

No new feature flag. Debug log parser has zero new dependencies. EVTX parser reuses existing `evtx` crate gated behind `event-log` feature. Add `ParserImplementation::DnsAudit` to the `event-log` feature gate.

### Frontend

- Status bar displays `format_detected` — new `LogFormat` variants render automatically.
- DNS-specific `LogEntry` fields are `Option` — `undefined` in JS for non-DNS logs. No column changes needed (workspace phase).
- **Date order prompt:** when `parse_file()` returns an ambiguous date order, frontend shows dialog: "This DNS log has ambiguous date formatting. Is the date format MM/DD or DD/MM?" Re-parses with selection.

---

## 7. Test Strategy

### Fixture location: `src-tauri/tests/fixtures/dns/`

### Debug log fixtures (hand-crafted from real data)

| Fixture | Purpose |
|---------|---------|
| `debug_basic.log` | Header + 5 PACKET lines with detail sections, US locale, Rcv+Snd pairs |
| `debug_opcodes.log` | Mix of Q (query), U (update), N (notify) opcodes |
| `debug_rcodes.log` | NOERROR, NXDOMAIN, SERVFAIL for severity mapping |
| `debug_no_detail.log` | Summary-only lines (no detail sections) — PhysicalLine fallback |
| `debug_query_names.log` | Wire-format, dotted, compression pointers, root `(0)` |
| `debug_header_only.log` | Just the header, no PACKET lines — empty result, no errors |
| `debug_ambiguous_dates.log` | All date values <=12 — triggers ambiguous date detection |

### Audit EVTX tests

**Unit tests** at the JSON extraction layer:
- Pre-built `serde_json::Value` for each of the 7 schema groups
- One test per group
- One test for unknown event ID → generic extraction
- One test for missing/null fields → graceful `None` handling

**Integration test** with real `dns-audit.evtx` fixture:
- Parses full file, asserts record count > 0
- Spot-checks known event fields

### Shared types tests

| Test | Input | Expected |
|------|-------|----------|
| Wire-format decode | `(4)home(4)gell(3)one(0)` | `home.gell.one` |
| Dotted decode | `.ns1.example.com.` | `ns1.example.com` |
| Pointer stripping | `[C00C](4)home(4)gell(3)one(0)` | `home.gell.one` |
| Root zone | `(0)` | `.` |
| QTYPE lookup known | `1` | `A` |
| QTYPE lookup unknown | `9999` | `UNKNOWN(9999)` |
| RCODE severity NOERROR | `NOERROR` | `Info` |
| RCODE severity NXDOMAIN | `NXDOMAIN` | `Warning` |
| RCODE severity SERVFAIL | `SERVFAIL` | `Error` |

### Detection tests

- DNS debug log detected correctly from path + content
- Generic timestamped file with "dns" in path does NOT false-positive as DNS
- `.evtx` with DNS provider → `ParserKind::DnsAudit`
- `.evtx` with non-DNS provider → does NOT match
- `.etl` extension → returns error with conversion instructions

---

## 8. ETL Stub (Future)

Architecture is designed for future ETL support:
- `.etl` extension detected in `parse_file()` early guard
- Future implementation: prompt user for `tracerpt` conversion, show progress indicator, parse resulting XML as `dns_analytical.rs`
- Conversion: `tracerpt "file.etl" -of XML -o output.xml` (Windows-only, `tracerpt` ships with all Windows installs)
- macOS/Linux users: error message with manual conversion instructions
- XML parsing: stream-based via `quick-xml` to handle large files
- Collection script (`Collect-DnsTestFixtures.ps1`) already collects ETL + converts to XML

---

## 9. Reference

### Source document

`docs/compass_artifact_wf-d4b3505b-8666-487c-9577-1184da86cbd6_text_markdown.md` — comprehensive reference covering all four DNS log formats, field schemas, QTYPE/RCODE tables, wire format, and ETW provider details.

### Collection script

`scripts/collection/Collect-DnsTestFixtures.ps1` — collects debug log, audit EVTX, analytical ETL (with XML conversion), and server metadata from a Windows DNS Server.

### Real test fixtures

`Logs/dns-fixtures-20260411-203254/` — collected from DNS3 server (Windows Server 2022, en-US locale):
- `DNSServer_debug.log` — 133K lines, 3,174 PACKET entries, details logging enabled, US locale
- `dns-audit.evtx` — 1.1 MB audit event log
- `server-metadata.json` — server config including locale and debug logging settings

### Key statistics from real fixtures

- Query types: A (1479), SOA (834), NS (660), PTR (606), SRV (84), CNAME (16)
- RCODEs: NOERROR (dominant), NXDOMAIN (75), SERVFAIL (25)
- Opcodes: Q (standard query), U (dynamic update)
- All UDP, single thread `0294`
- Details logging enabled on every PACKET entry
- Compression pointers present: `[C00C]`, `[C02B]`
