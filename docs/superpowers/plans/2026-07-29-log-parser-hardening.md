# Log Parser Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic contracts for every supported log parser and harden the concrete malformed-input and severity defects exposed by the parser audit.

**Architecture:** A new integration contract suite will exercise parser detection, selection metadata, file decoding, and representative structured output for all 20 `ParserKind` values plus IME specialization. Native Registry and DNS Audit formats retain their dedicated paths: Registry gets a real `.reg` file-boundary test, while DNS Audit gains a pure serialized-record adapter used by both the EVTX reader and deterministic synthetic unit tests.

**Tech Stack:** Rust 1.88, Cargo workspace, `cmtraceopen-parser`, Tauri backend crate `cmtrace-open`, `chrono`, `encoding_rs`, `evtx`, standard Rust test framework.

## Global Constraints

- Cover all 20 `ParserKind` variants and the IME specialization.
- Preserve input rather than silently dropping malformed records.
- Increment `parse_errors` for recoverable malformed structured input.
- Keep logical-record line numbers tied to the first source line.
- Do not add parser-framework or fixture-generation dependencies.
- Preserve serialized field names and frontend compatibility.
- Do not commit customer, tenant, device, user, or private-domain data in fixtures.
- Make every production change through a demonstrated red-green test cycle.
- Keep the existing unrelated changes in `src-tauri/src/commands/graph_api.rs` and `src-tauri/src/commands/system_preferences.rs` unstaged and untouched.

---

## File Structure

- Create `src-tauri/tests/parser_supported_formats.rs`: exhaustive support inventory, clean-format contracts, IME contract, and file-decoding contracts.
- Create clean fixtures under `src-tauri/tests/corpus/{timestamped,iis_w3c,psadt,intune_macos,dhcp,burn,patchmypc_detection,registry,secureboot,cmtlog}/clean/`.
- Reuse existing fixtures for CCM, Simple, Plain, Panther, CBS, DISM, ReportingEvents, MSI, DNS Debug, and IME.
- Modify `crates/cmtraceopen-parser/src/parser/plain.rs`: contiguous entry IDs across blank physical lines.
- Modify `crates/cmtraceopen-parser/src/parser/psadt.rs`: map the explicit `Success` level to `Severity::Success`.
- Modify `crates/cmtraceopen-parser/src/parser/secureboot_log.rs`: map `SUCCESS` correctly and reject impossible structured timestamps.
- Modify `crates/cmtraceopen-parser/src/parser/registry.rs`: reject malformed values and incomplete continuations instead of converting them to valid-looking values.
- Modify `src-tauri/src/parser/dns_audit.rs`: separate serialized-record conversion from EVTX iteration for deterministic tests.
- Modify `src-tauri/tests/dns_audit_real.rs`: keep the optional real-EVTX smoke test and make its skip status explicit.

---

### Task 1: Add the Exhaustive Supported-Format Contract

**Files:**
- Create: `src-tauri/tests/parser_supported_formats.rs`
- Create: `src-tauri/tests/corpus/timestamped/clean/mixed.log`
- Create: `src-tauri/tests/corpus/iis_w3c/clean/u_ex260329.log`
- Create: `src-tauri/tests/corpus/psadt/clean/Deploy-Application.log`
- Create: `src-tauri/tests/corpus/intune_macos/clean/IntuneMDMDaemon.log`
- Create: `src-tauri/tests/corpus/dhcp/clean/DhcpSrvLog-Mon.log`
- Create: `src-tauri/tests/corpus/burn/clean/bundle.log`
- Create: `src-tauri/tests/corpus/patchmypc_detection/clean/detection.log`
- Create: `src-tauri/tests/corpus/registry/clean/basic.reg`
- Create: `src-tauri/tests/corpus/secureboot/clean/SecureBootCertificateUpdate.log`
- Create: `src-tauri/tests/corpus/cmtlog/clean/basic.cmtlog`
- Reuse: `src-tauri/tests/common/mod.rs`
- Reuse: existing corpus paths named in the design spec

**Interfaces:**
- Consumes: `app_lib::parser::detect::detect_parser(path, content)`, `app_lib::parser::parse_file(path)`, `ParserKind`, `ParserImplementation`, `ParserSpecialization`, `LogFormat`.
- Produces: `const DECLARED_PARSER_KINDS: [ParserKind; 20]`, exhaustive `contract_name(ParserKind) -> &'static str`, and one field-level contract test per text format.

- [ ] **Step 1: Add the inventory test before adding new fixtures**

Create the test module with an exhaustive match and a unique 20-kind inventory:

```rust
use app_lib::models::log_entry::ParserKind;
use std::collections::BTreeSet;

const DECLARED_PARSER_KINDS: [ParserKind; 20] = [
    ParserKind::Ccm,
    ParserKind::Simple,
    ParserKind::Timestamped,
    ParserKind::Plain,
    ParserKind::IisW3c,
    ParserKind::Panther,
    ParserKind::Cbs,
    ParserKind::Dism,
    ParserKind::ReportingEvents,
    ParserKind::Msi,
    ParserKind::PsadtLegacy,
    ParserKind::IntuneMacOs,
    ParserKind::Dhcp,
    ParserKind::Burn,
    ParserKind::PatchMyPcDetection,
    ParserKind::Registry,
    ParserKind::SecureBootLog,
    ParserKind::DnsDebug,
    ParserKind::DnsAudit,
    ParserKind::CmtLog,
];

fn contract_name(kind: ParserKind) -> &'static str {
    match kind {
        ParserKind::Ccm => "ccm",
        ParserKind::Simple => "simple",
        ParserKind::Timestamped => "timestamped",
        ParserKind::Plain => "plain",
        ParserKind::IisW3c => "iis_w3c",
        ParserKind::Panther => "panther",
        ParserKind::Cbs => "cbs",
        ParserKind::Dism => "dism",
        ParserKind::ReportingEvents => "reporting_events",
        ParserKind::Msi => "msi",
        ParserKind::PsadtLegacy => "psadt",
        ParserKind::IntuneMacOs => "intune_macos",
        ParserKind::Dhcp => "dhcp",
        ParserKind::Burn => "burn",
        ParserKind::PatchMyPcDetection => "patchmypc_detection",
        ParserKind::Registry => "registry",
        ParserKind::SecureBootLog => "secureboot",
        ParserKind::DnsDebug => "dns_debug",
        ParserKind::DnsAudit => "dns_audit",
        ParserKind::CmtLog => "cmtlog",
    }
}

#[test]
fn support_inventory_names_every_parser_kind_once() {
    let names = DECLARED_PARSER_KINDS
        .into_iter()
        .map(contract_name)
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), DECLARED_PARSER_KINDS.len());
}
```

- [ ] **Step 2: Run the compile-exhaustiveness inventory test**

Run:

```bash
cargo test -p cmtrace-open --test parser_supported_formats support_inventory_names_every_parser_kind_once -- --exact
```

Expected: PASS. This is a characterization/coverage guard and requires no production change; adding a future `ParserKind` will make the exhaustive `contract_name` match fail to compile until the contract is named.

- [ ] **Step 3: Add the clean fixtures**

Use these sanitized representative records:

```text
# timestamped/clean/mixed.log
2026-07-29T09:15:30.125Z service started
07/29/2026 09:15:31 warning: retry scheduled
Jul 29 09:15:32 host daemon: request complete
09:15:33.250 final message
```

```text
# iis_w3c/clean/u_ex260329.log
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
2026-03-29 18:48:23 10.0.0.5 GET /default.htm - 443 - 203.0.113.10 Agent/1.0 200 0 0 12
2026-03-29 18:48:24 10.0.0.5 POST /api/devices id=42 443 EXAMPLE\\operator 203.0.113.11 Agent/1.1 404 7 2 35
```

```text
# psadt/clean/Deploy-Application.log
[2026-07-29 09:00:00.100] [Initialization] [Open-ADTSession] [Info] :: Session opened
[2026-07-29 09:00:01.200] [Install] [Start-ADTMsiProcess] [Success] :: Installation complete
```

```text
# intune_macos/clean/IntuneMDMDaemon.log
2026-07-29 09:10:11:888 | IntuneMDM-Daemon | I | 100 | SyncActivityTracer | Reporting results
2026-07-29 09:10:12:999 | IntuneMDM-Daemon | E | 101 | AppInstaller | Installation failed
```

```text
# dhcp/clean/DhcpSrvLog-Mon.log
Microsoft DHCP Service Activity Log
11,07/29/26,09:20:00,Renew,192.0.2.10,device.example.test,001122334455,,1,0,,,,0x00,client,,,,0
31,07/29/26,09:20:01,DNS Update Failed,2001:db8::10,device-v6.example.test,001122334466,,2,0,6,,,,,,,,,9560
```

```text
# burn/clean/bundle.log
[07A4:0CBC][2026-07-29T09:30:00]i001: Burn bundle started
[07A4:0CBC][2026-07-29T09:30:01]e000: Error 0x80070005: Access denied
```

```text
# patchmypc_detection/clean/detection.log
07/29/2026 09:40:00~[Example App 1.0]~[Found:False]~[Purpose:Detection]~[Context:TESTDEVICE$)]~[Hive:HKLM:\software\example]
07/29/2026 09:40:01~[Example App 1.0]~[Found:True]~[Purpose:Requirement]~[Context:TESTDEVICE$)]~[Hive:HKLM:\software\example]
```

```text
# registry/clean/basic.reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\CMTraceOpenTest]
@="Default"
"Enabled"=dword:00000001
"Names"=hex(7):4f,00,6e,00,65,00,00,00,54,00,77,00,6f,00,00,00,00,00
```

```text
# secureboot/clean/SecureBootCertificateUpdate.log
2026-07-29 09:50:00 [DETECT] [INFO] Detection started
2026-07-29 09:50:01 [DETECT] [SUCCESS] Secure Boot is enabled
```

```text
# cmtlog/clean/basic.cmtlog
<![LOG[Parser contract]LOG]!><time="10:00:00.000+000" date="07-29-2026" component="__HEADER__" context="" type="1" thread="0" file="" script="ParserContract.ps1" version="1.0.0" runid="test-run" mode="Normal" ps_version="7.4.0">
<![LOG[Detection]LOG]!><time="10:00:01.000+000" date="07-29-2026" component="__SECTION__" context="" type="1" thread="0" file="" color="#5b9aff">
<![LOG[Iteration 1]LOG]!><time="10:00:02.000+000" date="07-29-2026" component="__ITERATION__" context="" type="1" thread="0" file="" iteration="1/1" color="#a78bfa">
<![LOG[Policy present]LOG]!><time="10:00:03.000+000" date="07-29-2026" component="ParserContract" context="" type="0" thread="42" file="" section="detection" iteration="1/1" tag="contract:clean" whatif="1">
```

- [ ] **Step 4: Add field-level contract tests**

Add a `parse_fixture` helper that uses `CARGO_MANIFEST_DIR/tests/corpus`, then write tests named:

```rust
text_contract_ccm
text_contract_simple
text_contract_timestamped
text_contract_plain
text_contract_iis_w3c
text_contract_panther
text_contract_cbs
text_contract_dism
text_contract_reporting_events
text_contract_msi
text_contract_psadt_legacy
text_contract_intune_macos
text_contract_dhcp
text_contract_burn
text_contract_patchmypc_detection
selection_contract_registry
text_contract_secureboot
text_contract_dns_debug
selection_contract_dns_audit
text_contract_cmtlog
specialization_contract_ime
```

For every text contract, assert `selection.parser`, `selection.implementation`, `selection.provenance`, `selection.record_framing`, `result.format_detected`, `parse_errors`, and at least two format-specific fields from the design table. For Registry, assert detection returns `Registry` and defer structured values to Task 4. For DNS Audit, assert `ResolvedParser::dns_audit().to_info()` metadata and defer record conversion to Task 5. For IME, assert `ParserKind::Ccm`, `ParserImplementation::Ccm`, and `specialization == Some(ParserSpecialization::Ime)`.

- [ ] **Step 5: Run the supported-format contract**

Run:

```bash
cargo test -p cmtrace-open --test parser_supported_formats
```

Expected: PASS for all characterization and inventory contracts. Explicit `Success` severity behavior is introduced test-first in Task 3.

- [ ] **Step 6: Commit the characterization contracts**

```bash
git add src-tauri/tests/parser_supported_formats.rs src-tauri/tests/corpus
git commit -m "test(parser): cover every supported log format"
```

---

### Task 2: Harden Shared File Decoding and Plain Entry Identity

**Files:**
- Modify: `src-tauri/tests/parser_supported_formats.rs`
- Modify: `crates/cmtraceopen-parser/src/parser/plain.rs`

**Interfaces:**
- Consumes: `detect_encoding`, `decode_bytes`, `parse_file`, and plain `LogEntry.id`.
- Produces: portable encoding tests and contiguous IDs for emitted plain entries.

- [ ] **Step 1: Add failing decoding and ID tests**

```rust
#[test]
fn plain_ids_are_contiguous_across_blank_lines() {
    let lines = ["first", "", "third"];
    let (entries, errors) =
        app_lib::parser::plain::parse_lines(&lines, "plain.log");
    assert_eq!(errors, 0);
    assert_eq!(entries.iter().map(|entry| entry.id).collect::<Vec<_>>(), vec![0, 1]);
    assert_eq!(entries.iter().map(|entry| entry.line_number).collect::<Vec<_>>(), vec![1, 3]);
}
```

Add file-boundary tests that create temporary byte fixtures for UTF-8 BOM, UTF-16LE BOM, UTF-16BE BOM, and the Windows-1252 bytes for `caf\xe9`. Assert decoded messages, `file_size`, and `byte_offset`. Add a UTF-16LE Registry fixture assertion that verifies `Enabled` is parsed as DWORD `1`.

- [ ] **Step 2: Verify the contiguous-ID regression fails**

Run:

```bash
cargo test -p cmtrace-open --test parser_supported_formats plain_ids_are_contiguous_across_blank_lines -- --exact
```

Expected: FAIL with actual IDs `[0, 2]`.

- [ ] **Step 3: Use an emitted-entry counter in the plain parser**

Replace `id: i as u64` with a `next_id` initialized before the loop and incremented only after an entry is pushed. Keep `line_number: (i + 1) as u32` unchanged.

- [ ] **Step 4: Verify decoding and identity contracts**

Run:

```bash
cargo test -p cmtrace-open --test parser_supported_formats encoding_
cargo test -p cmtrace-open --test parser_supported_formats plain_ids_are_contiguous_across_blank_lines -- --exact
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cmtraceopen-parser/src/parser/plain.rs src-tauri/tests/parser_supported_formats.rs
git commit -m "fix(parser): stabilize plain entries across encodings"
```

---

### Task 3: Correct Explicit Success Severity and Secure Boot Timestamp Recovery

**Files:**
- Modify: `crates/cmtraceopen-parser/src/parser/psadt.rs`
- Modify: `crates/cmtraceopen-parser/src/parser/secureboot_log.rs`
- Modify: `src-tauri/tests/parser_supported_formats.rs`

**Interfaces:**
- Consumes: `Severity::Success`.
- Produces: explicit success labels serialize as `Success`; impossible Secure Boot dates become preserved plain fallback entries and increment `parse_errors`.

- [ ] **Step 1: Add failing severity and timestamp tests**

```rust
#[test]
fn psadt_success_is_success_severity() {
    let lines = [
        "[2026-07-29 09:00:01.200] [Install] [Start-ADTMsiProcess] [Success] :: Installation complete",
    ];
    let (entries, errors) = app_lib::parser::psadt::parse_lines(&lines, "Deploy-Application.log");
    assert_eq!(errors, 0);
    assert_eq!(entries[0].severity, app_lib::models::log_entry::Severity::Success);
}

#[test]
fn secureboot_success_is_success_severity() {
    let lines = ["2026-07-29 09:50:01 [DETECT] [SUCCESS] Secure Boot is enabled"];
    let (entries, errors) =
        app_lib::parser::secureboot_log::parse_lines(&lines, "SecureBootCertificateUpdate.log");
    assert_eq!(errors, 0);
    assert_eq!(entries[0].severity, app_lib::models::log_entry::Severity::Success);
}

#[test]
fn secureboot_invalid_timestamp_is_preserved_as_parse_error() {
    let invalid = "2026-13-40 25:61:61 [DETECT] [INFO] impossible timestamp";
    let (entries, errors) =
        app_lib::parser::secureboot_log::parse_lines(&[invalid], "SecureBootCertificateUpdate.log");
    assert_eq!(errors, 1);
    assert_eq!(entries[0].message, invalid);
    assert_eq!(entries[0].format, app_lib::models::log_entry::LogFormat::Plain);
    assert!(entries[0].timestamp.is_none());
    assert!(entries[0].timestamp_display.is_none());
}
```

- [ ] **Step 2: Verify all three tests fail for the intended values**

Run each exact test separately:

```bash
cargo test -p cmtrace-open --test parser_supported_formats psadt_success_is_success_severity -- --exact
cargo test -p cmtrace-open --test parser_supported_formats secureboot_success_is_success_severity -- --exact
cargo test -p cmtrace-open --test parser_supported_formats secureboot_invalid_timestamp_is_preserved_as_parse_error -- --exact
```

Expected: the first two report `Info` instead of `Success`; the third reports zero errors and a structured `Timestamped` entry.

- [ ] **Step 3: Implement the minimal mappings and validated timestamp branch**

In `psadt::map_severity`, map case-insensitive `success` to `Severity::Success`.

In `secureboot_log::severity_from_level`, map `SUCCESS` to `Severity::Success`.

In `secureboot_log::parse_lines`, parse the captured timestamp before constructing a structured entry. Construct the structured entry only when `NaiveDateTime::parse_from_str` succeeds; otherwise route the untouched line through the existing plain fallback branch and increment `parse_errors`. Set `timestamp_display` only from the validated timestamp.

- [ ] **Step 4: Update obsolete focused expectations**

Change the existing PSADT and Secure Boot unit tests that explicitly expect `Info` for success labels to expect `Severity::Success`. No other severity mapping changes.

- [ ] **Step 5: Verify focused and module tests**

```bash
cargo test -p cmtraceopen-parser parser::psadt
cargo test -p cmtraceopen-parser parser::secureboot_log
cargo test -p cmtrace-open --test parser_supported_formats
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/cmtraceopen-parser/src/parser/psadt.rs crates/cmtraceopen-parser/src/parser/secureboot_log.rs src-tauri/tests/parser_supported_formats.rs
git commit -m "fix(parser): preserve explicit success and invalid timestamps"
```

---

### Task 4: Make Registry Malformation Observable

**Files:**
- Modify: `crates/cmtraceopen-parser/src/parser/registry.rs`
- Modify: `src-tauri/tests/parser_supported_formats.rs`

**Interfaces:**
- Consumes: `.reg` value syntax and `RegistryParseResult.parse_errors`.
- Produces: `parse_value_line(...) -> Result<RegistryValue, RegistryValueParseError>` and `parse_hex_bytes(...) -> Result<Vec<u8>, RegistryValueParseError>`.

- [ ] **Step 1: Add failing registry tests**

Add unit tests for invalid numeric values, invalid hex tokens, unclosed strings, and incomplete continuation:

```rust
#[test]
fn malformed_values_increment_errors_without_fabricating_zeroes() {
    let content = concat!(
        "Windows Registry Editor Version 5.00\n\n",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\CMTraceOpenTest]\n",
        "\"BadDword\"=dword:nothex\n",
        "\"BadBinary\"=hex:01,GG,03\n",
        "\"BadString\"=\"unterminated\n",
        "\"BadContinuation\"=hex:01,02,\\\n",
    );
    let result = parse_registry_content(content, "bad.reg", content.len() as u64);
    assert_eq!(result.total_keys, 1);
    assert_eq!(result.total_values, 0);
    assert_eq!(result.parse_errors, 4);
}
```

Keep a clean test that proves valid zero DWORD, zero QWORD, empty binary, and quoted empty string remain valid values.

- [ ] **Step 2: Verify the malformed registry test fails**

```bash
cargo test -p cmtraceopen-parser parser::registry::tests::malformed_values_increment_errors_without_fabricating_zeroes -- --exact
```

Expected: FAIL because malformed numeric and hex data currently become valid-looking zero/partial values.

- [ ] **Step 3: Return explicit parse errors**

Add a private zero-sized `RegistryValueParseError` and change `parse_value_line` and `parse_hex_bytes` to return `Result`.

Validation rules:

- a quoted string must have a closing unescaped quote;
- DWORD requires 1-8 ASCII hex digits;
- QWORD requires exactly eight decoded bytes;
- binary/typed hex tokens must be two ASCII hex digits each;
- a trailing continuation backslash at EOF is an error;
- unsupported typed hex remains `RegistryValueKind::None` only when its bytes are syntactically valid.

In the outer loop, preserve forward progress:

```rust
let start_index = i;
match parse_value_line(trimmed, (i + 1) as u32, &lines, &mut i) {
    Ok(value) => {
        total_values += 1;
        key.values.push(value);
    }
    Err(_) => {
        parse_errors += 1;
        if i <= start_index {
            i = start_index + 1;
        }
    }
}
```

- [ ] **Step 4: Verify Registry unit and file-boundary tests**

```bash
cargo test -p cmtraceopen-parser parser::registry
cargo test -p cmtrace-open --test parser_supported_formats registry
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cmtraceopen-parser/src/parser/registry.rs src-tauri/tests/parser_supported_formats.rs
git commit -m "fix(parser): reject malformed registry values"
```

---

### Task 5: Make DNS Audit Parsing Deterministic in CI

**Files:**
- Modify: `src-tauri/src/parser/dns_audit.rs`
- Modify: `src-tauri/tests/dns_audit_real.rs`

**Interfaces:**
- Consumes: serialized JSON from `evtx::EvtxParser::records_json()`.
- Produces: private `parse_serialized_record(serialized: &str, file_path: &str, id: u64) -> Result<Option<LogEntry>, ()>` shared by production EVTX iteration and unit tests.

- [ ] **Step 1: Add failing synthetic record tests**

Inside `dns_audit.rs`, add tests with sanitized JSON:

```rust
const DNS_CREATE_RECORD: &str = r#"{
  "Event": {
    "System": {
      "Provider": {"#attributes": {"Name": "Microsoft-Windows-DNSServer"}},
      "EventID": 515,
      "TimeCreated": {"#attributes": {"SystemTime": "2026-07-29T14:00:00.000Z"}}
    },
    "EventData": {
      "NAME": "host.example.test",
      "Type": "1",
      "Zone": "example.test",
      "TTL": "3600"
    }
  }
}"#;

#[test]
fn serialized_dns_record_maps_provider_event_and_fields() {
    let entry = parse_serialized_record(DNS_CREATE_RECORD, "dns-audit.evtx", 7)
        .expect("valid JSON")
        .expect("DNS record");
    assert_eq!(entry.id, 7);
    assert_eq!(entry.dns_event_id, Some(515));
    assert_eq!(entry.query_name.as_deref(), Some("host.example.test"));
    assert_eq!(entry.query_type.as_deref(), Some("A"));
    assert_eq!(entry.zone_name.as_deref(), Some("example.test"));
    assert!(entry.timestamp.is_some());
}
```

Add one non-DNS provider test expecting `Ok(None)` and one malformed JSON test expecting `Err(())`.

- [ ] **Step 2: Verify the adapter test fails to compile**

```bash
cargo test -p cmtrace-open --features event-log parser::dns_audit::tests::serialized_dns_record_maps_provider_event_and_fields -- --exact
```

Expected: FAIL because `parse_serialized_record` does not exist.

- [ ] **Step 3: Extract the record adapter**

Move JSON decoding, provider filtering, EventID extraction, timestamp parsing, field extraction, and `LogEntry` construction from `parse_evtx` into the private adapter. Keep error-code annotation at the final result level.

Update `parse_evtx` so:

- EVTX reader errors increment `parse_errors`;
- adapter `Err(())` increments `parse_errors`;
- `Ok(None)` skips non-DNS records without error;
- IDs increment only when a DNS entry is emitted.

Update `is_dns_evtx` to reuse a small `serialized_record_is_dns_provider(&str) -> bool` helper rather than duplicating the JSON path.

- [ ] **Step 4: Clarify the optional real-file smoke test**

Rename the test to `real_dns_audit_evtx_smoke_when_local_fixture_exists` and keep the early return. The deterministic serialized-record tests are the CI contract; the smoke test verifies the `evtx` crate boundary only when the ignored local fixture is present.

- [ ] **Step 5: Verify DNS Audit paths**

```bash
cargo test -p cmtrace-open --features event-log parser::dns_audit
cargo test -p cmtrace-open --features event-log --test dns_audit_real
```

Expected: synthetic tests PASS on every machine; the real fixture test either PASSes or prints its explicit skip.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/parser/dns_audit.rs src-tauri/tests/dns_audit_real.rs
git commit -m "test(parser): make DNS audit records deterministic"
```

---

### Task 6: Run the Complete Parser Verification

**Files:**
- No planned file changes; this task is verification-only.

**Interfaces:**
- Consumes: all parser contracts and existing suites.
- Produces: fresh verification evidence with platform limitations stated exactly.

- [ ] **Step 1: Run parser-crate tests**

```bash
cargo test -p cmtraceopen-parser
```

Expected: PASS with zero failures.

- [ ] **Step 2: Run the supported-format and existing corpus suites**

```bash
cargo test -p cmtrace-open --test parser_supported_formats
cargo test -p cmtrace-open --test parser_expanded_corpus
cargo test -p cmtrace-open --test parser_regression_corpus
cargo test -p cmtrace-open --test cmtlog_parser
cargo test -p cmtrace-open --features event-log --test dns_audit_real
```

Expected: PASS; `dns_audit_real` may explicitly skip only when its ignored local fixture is absent.

- [ ] **Step 3: Run the full backend suite**

```bash
cargo test -p cmtrace-open
```

Expected: PASS with zero failures.

- [ ] **Step 4: Run formatting and lint checks**

```bash
cargo fmt --all -- --check
cargo clippy -p cmtraceopen-parser -p cmtrace-open --all-targets --all-features -- -D warnings
git diff --check
```

Expected: all commands exit zero.

- [ ] **Step 5: Inspect final scope**

```bash
git status --short
git diff --stat HEAD~5..HEAD
git log --oneline -6
```

Confirm parser commits contain only the planned parser, fixture, and test files. Confirm the pre-existing edits in `src-tauri/src/commands/graph_api.rs` and `src-tauri/src/commands/system_preferences.rs` were neither staged nor changed by this work.

- [ ] **Step 6: Request final code review**

Use `superpowers:requesting-code-review` against the complete parser diff, apply only verified actionable findings, and rerun the affected verification commands before reporting completion.
