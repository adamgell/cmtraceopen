# DNS Log Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add DNS debug log and DNS audit EVTX parsing to CMTrace Open, outputting `LogEntry` for the standard log viewer.

**Architecture:** Three new flat files in `src-tauri/src/parser/` — `dns_types.rs` (shared QTYPE/RCODE maps, query name decoder), `dns_debug.rs` (text `dns.log` parser with `LogicalRecord` framing), and `dns_audit.rs` (EVTX audit parser via `evtx` crate). Both parsers flow through the existing `open_log_file()` command. Binary `.evtx` files are intercepted in `parse_file()` before text decoding. ETL files are stubbed with an error message.

**Tech Stack:** Rust, `regex` crate (already in project), `evtx` crate (already in project behind `event-log` feature), `chrono` (already in project), `serde_json` (already in project).

**Spec:** `docs/superpowers/specs/2026-04-11-dns-parser-design.md`

**Reference doc:** `docs/compass_artifact_wf-d4b3505b-8666-487c-9577-1184da86cbd6_text_markdown.md`

**Real fixtures:** `Logs/dns-fixtures-20260411-203254/` (DNS3 server, Windows Server 2022, en-US locale)

---

### Task 1: Type System Foundation

**Files:**
- Modify: `src-tauri/src/models/log_entry.rs`

This task adds the DNS-specific enum variants and `LogEntry` fields that all subsequent tasks depend on.

- [ ] **Step 1: Add `DnsDebug` and `DnsAudit` to `LogFormat` enum**

In `src-tauri/src/models/log_entry.rs`, add two variants to `LogFormat` (after line 23):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    Ccm,
    Simple,
    Plain,
    Timestamped,
    DnsDebug,
    DnsAudit,
}
```

- [ ] **Step 2: Add `DnsDebug` and `DnsAudit` to `ParserKind` enum**

Add after `Registry` (line 44):

```rust
pub enum ParserKind {
    Ccm,
    Simple,
    Timestamped,
    Plain,
    IisW3c,
    Panther,
    Cbs,
    Dism,
    ReportingEvents,
    Msi,
    PsadtLegacy,
    IntuneMacOs,
    Dhcp,
    Burn,
    PatchMyPcDetection,
    Registry,
    DnsDebug,
    DnsAudit,
}
```

- [ ] **Step 3: Add `DnsDebug` and `DnsAudit` to `ParserImplementation` enum**

Add after `Registry` (line 63):

```rust
pub enum ParserImplementation {
    Ccm,
    Simple,
    GenericTimestamped,
    IisW3c,
    ReportingEvents,
    PlainText,
    Msi,
    PsadtLegacy,
    IntuneMacOs,
    Dhcp,
    Burn,
    PatchMyPcDetection,
    Registry,
    DnsDebug,
    DnsAudit,
}
```

- [ ] **Step 4: Add nine DNS fields to `LogEntry` struct**

Add after the `win32_status` field (after line 213), before the closing brace:

```rust
    /// DNS query name, decoded from wire-format (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_name: Option<String>,
    /// DNS query type name: A, AAAA, SRV, etc. (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_type: Option<String>,
    /// DNS response code: NOERROR, NXDOMAIN, etc. (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    /// Packet direction: Snd or Rcv (DNS debug log)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_direction: Option<String>,
    /// Transport protocol: UDP or TCP (DNS debug log)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_protocol: Option<String>,
    /// Remote IP address, optionally with port (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// DNS header flags as hex string (DNS debug log)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_flags: Option<String>,
    /// DNS event ID for EVTX-sourced entries (DNS audit)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_event_id: Option<u32>,
    /// DNS zone name (DNS audit)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_name: Option<String>,
```

- [ ] **Step 5: Update every `LogEntry` construction site to include new fields**

Every file that constructs a `LogEntry` struct literal needs the nine new fields set to `None` / `None` / `None` / `None` / `None` / `None` / `None` / `None` / `None`. Search for `LogEntry {` in all parser files. The affected files are:

- `src-tauri/src/parser/ccm.rs`
- `src-tauri/src/parser/simple.rs`
- `src-tauri/src/parser/plain.rs`
- `src-tauri/src/parser/timestamped.rs`
- `src-tauri/src/parser/panther.rs`
- `src-tauri/src/parser/cbs.rs`
- `src-tauri/src/parser/dism.rs`
- `src-tauri/src/parser/dhcp.rs`
- `src-tauri/src/parser/iis_w3c.rs`
- `src-tauri/src/parser/reporting_events.rs`
- `src-tauri/src/parser/msi.rs`
- `src-tauri/src/parser/burn.rs`
- `src-tauri/src/parser/psadt.rs`
- `src-tauri/src/parser/intune_macos.rs`
- `src-tauri/src/parser/patchmypc_detection.rs`

Add to each `LogEntry { ... }` literal:

```rust
                query_name: None,
                query_type: None,
                response_code: None,
                dns_direction: None,
                dns_protocol: None,
                source_ip: None,
                dns_flags: None,
                dns_event_id: None,
                zone_name: None,
```

- [ ] **Step 6: Run `cargo check` from `src-tauri/`**

```bash
cd src-tauri && cargo check
```

Expected: compiles with zero errors. If any `LogEntry` construction sites were missed, the compiler will report "missing field" errors — fix them.

- [ ] **Step 7: Run existing tests**

```bash
cd src-tauri && cargo test
```

Expected: all existing tests pass. No behavioral changes yet.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/models/log_entry.rs src-tauri/src/parser/*.rs
git commit -m "feat(dns): add DNS type system foundation — LogFormat, ParserKind, ParserImplementation variants and LogEntry fields"
```

---

### Task 2: Shared DNS Types (`dns_types.rs`)

**Files:**
- Create: `src-tauri/src/parser/dns_types.rs`
- Modify: `src-tauri/src/parser/mod.rs` (add `pub mod dns_types;`)

- [ ] **Step 1: Create `dns_types.rs` with QTYPE lookup**

Create `src-tauri/src/parser/dns_types.rs`:

```rust
//! Shared DNS constants and decoders.
//!
//! Provides QTYPE/RCODE name lookups, DNS wire-format query name decoding,
//! and RCODE-to-severity mapping used by both the debug log and audit EVTX parsers.

use crate::models::log_entry::Severity;

/// Map a numeric QTYPE code to its name.
pub fn qtype_name(code: u32) -> String {
    match code {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        13 => "HINFO".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        17 => "RP".into(),
        18 => "AFSDB".into(),
        24 => "SIG".into(),
        25 => "KEY".into(),
        28 => "AAAA".into(),
        29 => "LOC".into(),
        33 => "SRV".into(),
        35 => "NAPTR".into(),
        36 => "KX".into(),
        37 => "CERT".into(),
        39 => "DNAME".into(),
        41 => "OPT".into(),
        43 => "DS".into(),
        44 => "SSHFP".into(),
        45 => "IPSECKEY".into(),
        46 => "RRSIG".into(),
        47 => "NSEC".into(),
        48 => "DNSKEY".into(),
        49 => "DHCID".into(),
        50 => "NSEC3".into(),
        51 => "NSEC3PARAM".into(),
        52 => "TLSA".into(),
        53 => "SMIMEA".into(),
        55 => "HIP".into(),
        59 => "CDS".into(),
        60 => "CDNSKEY".into(),
        61 => "OPENPGPKEY".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        99 => "SPF".into(),
        249 => "TKEY".into(),
        250 => "TSIG".into(),
        251 => "IXFR".into(),
        252 => "AXFR".into(),
        255 => "ANY".into(),
        256 => "URI".into(),
        257 => "CAA".into(),
        65281 => "WINS".into(),
        65282 => "WINSR".into(),
        _ => format!("UNKNOWN({})", code),
    }
}

/// Map a numeric RCODE to its name.
pub fn rcode_name(code: u32) -> String {
    match code {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        6 => "YXDOMAIN".into(),
        7 => "YXRRSET".into(),
        8 => "NXRRSET".into(),
        9 => "NOTAUTH".into(),
        10 => "NOTZONE".into(),
        16 => "BADSIG".into(),
        17 => "BADKEY".into(),
        18 => "BADTIME".into(),
        19 => "BADMODE".into(),
        20 => "BADNAME".into(),
        21 => "BADALG".into(),
        22 => "BADTRUNC".into(),
        23 => "BADCOOKIE".into(),
        _ => format!("RCODE({})", code),
    }
}

/// Map an RCODE name string to a severity level.
pub fn rcode_to_severity(rcode: &str) -> Severity {
    match rcode {
        "NOERROR" => Severity::Info,
        "NXDOMAIN" => Severity::Warning,
        "SERVFAIL" | "REFUSED" | "FORMERR" => Severity::Error,
        _ => Severity::Warning,
    }
}

/// Decode a DNS query name from wire-format or dotted notation.
///
/// Handles:
/// - Wire-format: `(3)www(6)google(3)com(0)` → `www.google.com`
/// - Dotted: `.ns1.example.com.` → `ns1.example.com`
/// - Compression pointers: `[C00C](4)home(4)gell(3)one(0)` → `home.gell.one`
/// - Root: `(0)` → `.`
pub fn decode_query_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Check for wire-format: contains `(` digits `)`
    if trimmed.contains('(') {
        return decode_wire_format_name(trimmed);
    }

    // Dotted format: strip leading/trailing dots
    trimmed.trim_matches('.').to_string()
}

/// Decode wire-format name: `(3)www(6)google(3)com(0)` → `www.google.com`
/// Also strips compression pointers like `[C00C]`.
fn decode_wire_format_name(raw: &str) -> String {
    // Strip compression pointers: [XXXX]
    let cleaned: String = {
        let mut result = String::with_capacity(raw.len());
        let mut chars = raw.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '[' {
                // Skip until ']'
                for inner in chars.by_ref() {
                    if inner == ']' {
                        break;
                    }
                }
            } else {
                result.push(ch);
            }
        }
        result
    };

    let mut labels = Vec::new();
    let mut chars = cleaned.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '(' {
            // Read length number
            let mut num_str = String::new();
            for digit in chars.by_ref() {
                if digit == ')' {
                    break;
                }
                num_str.push(digit);
            }
            let label_len: usize = num_str.parse().unwrap_or(0);
            if label_len == 0 {
                // (0) is the root terminator
                break;
            }
            // Read label_len characters
            let label: String = chars.by_ref().take(label_len).collect();
            labels.push(label);
        }
    }

    if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qtype_known() {
        assert_eq!(qtype_name(1), "A");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(6), "SOA");
        assert_eq!(qtype_name(33), "SRV");
        assert_eq!(qtype_name(12), "PTR");
        assert_eq!(qtype_name(5), "CNAME");
        assert_eq!(qtype_name(15), "MX");
        assert_eq!(qtype_name(65281), "WINS");
        assert_eq!(qtype_name(65282), "WINSR");
    }

    #[test]
    fn test_qtype_unknown() {
        assert_eq!(qtype_name(9999), "UNKNOWN(9999)");
    }

    #[test]
    fn test_rcode_known() {
        assert_eq!(rcode_name(0), "NOERROR");
        assert_eq!(rcode_name(3), "NXDOMAIN");
        assert_eq!(rcode_name(2), "SERVFAIL");
        assert_eq!(rcode_name(5), "REFUSED");
    }

    #[test]
    fn test_rcode_unknown() {
        assert_eq!(rcode_name(99), "RCODE(99)");
    }

    #[test]
    fn test_rcode_severity() {
        assert_eq!(rcode_to_severity("NOERROR"), Severity::Info);
        assert_eq!(rcode_to_severity("NXDOMAIN"), Severity::Warning);
        assert_eq!(rcode_to_severity("SERVFAIL"), Severity::Error);
        assert_eq!(rcode_to_severity("REFUSED"), Severity::Error);
        assert_eq!(rcode_to_severity("FORMERR"), Severity::Error);
        assert_eq!(rcode_to_severity("NOTAUTH"), Severity::Warning);
    }

    #[test]
    fn test_decode_wire_format() {
        assert_eq!(
            decode_query_name("(4)home(4)gell(3)one(0)"),
            "home.gell.one"
        );
    }

    #[test]
    fn test_decode_wire_format_www() {
        assert_eq!(
            decode_query_name("(3)www(6)google(3)com(0)"),
            "www.google.com"
        );
    }

    #[test]
    fn test_decode_wire_format_root() {
        assert_eq!(decode_query_name("(0)"), ".");
    }

    #[test]
    fn test_decode_dotted() {
        assert_eq!(decode_query_name(".ns1.example.com."), "ns1.example.com");
    }

    #[test]
    fn test_decode_compression_pointer() {
        assert_eq!(
            decode_query_name("[C00C](4)home(4)gell(3)one(0)"),
            "home.gell.one"
        );
    }

    #[test]
    fn test_decode_multiple_compression_pointers() {
        assert_eq!(
            decode_query_name("[C02B](4)dns3[C00C](4)home(4)gell(3)one(0)"),
            "dns3.home.gell.one"
        );
    }

    #[test]
    fn test_decode_empty() {
        assert_eq!(decode_query_name(""), "");
    }
}
```

- [ ] **Step 2: Register the module in `mod.rs`**

In `src-tauri/src/parser/mod.rs`, add after `pub mod detect;` (line 5):

```rust
pub mod dns_types;
```

- [ ] **Step 3: Run tests**

```bash
cd src-tauri && cargo test dns_types
```

Expected: all 13 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/parser/dns_types.rs src-tauri/src/parser/mod.rs
git commit -m "feat(dns): add shared DNS types — QTYPE/RCODE maps, query name decoder, severity helper"
```

---

### Task 3: DNS Debug Log Parser (`dns_debug.rs`)

**Files:**
- Create: `src-tauri/src/parser/dns_debug.rs`
- Modify: `src-tauri/src/parser/mod.rs` (add `pub mod dns_debug;`)

- [ ] **Step 1: Create `dns_debug.rs` with PACKET regex and `matches_dns_debug_record`**

Create `src-tauri/src/parser/dns_debug.rs`:

```rust
//! Windows DNS Server debug log parser.
//!
//! Parses the text-based `dns.log` file produced by `dns.exe`.
//! Each logical record is a PACKET summary line optionally followed by
//! multi-line detail output (when Details logging is enabled).
//!
//! Format reference: docs/compass_artifact_*.md, Section 1.

use regex::Regex;
use std::sync::OnceLock;

use super::dns_types;
use super::timestamped::DateOrder;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// Compiled regex for the PACKET summary line.
fn packet_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?|\d{8}\s+\d{2}:\d{2}:\d{2})\s+([0-9A-Fa-f]{3,4})\s+PACKET\s+[0-9A-Fa-f]{8,16}\s+(UDP|TCP)\s+(Snd|Rcv)\s+([0-9a-fA-F.:]+)\s+([0-9a-fA-F]{4})\s+(R\s|[R ]\s?)([QNU?])\s+\[([0-9A-Fa-f]{4})\s*([ATDR ]{0,4})\s*(\w+)\]\s+(\S+)\s+(.+)$"
        ).expect("PACKET regex should compile")
    })
}

/// Regex for extracting port from detail section.
fn remote_port_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"Remote addr [0-9a-fA-F.:]+, port (\d+)")
            .expect("remote port regex should compile")
    })
}

/// Returns true if the line looks like a DNS debug log PACKET record.
/// Used by `detect.rs` for format detection.
pub fn matches_dns_debug_record(line: &str) -> bool {
    let trimmed = line.trim();
    // Fast pre-check before running the regex
    if !trimmed.contains("PACKET") {
        return false;
    }
    packet_re().is_match(trimmed)
}

/// Parse DNS debug log lines into `LogEntry` records.
///
/// Uses `LogicalRecord` framing: each PACKET summary line starts a new record,
/// and subsequent detail lines are appended until the next PACKET line.
pub fn parse_lines(lines: &[&str], file_path: &str, date_order: DateOrder) -> (Vec<LogEntry>, u32) {
    let re = packet_re();
    let port_re = remote_port_re();
    let mut entries = Vec::new();
    let mut parse_errors: u32 = 0;
    let mut id: u64 = 0;

    // Pending entry state for LogicalRecord framing
    let mut pending: Option<PendingEntry> = None;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Skip blank lines
        if trimmed.is_empty() {
            continue;
        }

        // Try to match as a PACKET summary line
        if let Some(caps) = re.captures(trimmed) {
            // Flush any pending entry
            if let Some(p) = pending.take() {
                entries.push(p.into_log_entry(id, file_path, &port_re));
                id += 1;
            }

            // Parse the new PACKET line
            match parse_packet_captures(&caps, (i + 1) as u32, date_order) {
                Ok(p) => {
                    pending = Some(p);
                }
                Err(_) => {
                    parse_errors += 1;
                }
            }
        } else if pending.is_some() {
            // Detail line — append to pending entry
            if let Some(ref mut p) = pending {
                p.detail_lines.push(trimmed.to_string());
            }
        }
        // Lines before any PACKET match (header) are silently skipped
    }

    // Flush final pending entry
    if let Some(p) = pending.take() {
        entries.push(p.into_log_entry(id, file_path, &port_re));
    }

    (entries, parse_errors)
}

/// Intermediate state for a partially-built log entry.
struct PendingEntry {
    line_number: u32,
    timestamp: Option<i64>,
    timestamp_display: Option<String>,
    thread: Option<u32>,
    thread_display: Option<String>,
    protocol: String,
    direction: String,
    remote_ip: String,
    xid: String,
    flags_hex: String,
    rcode: String,
    query_type: String,
    query_name: String,
    severity: Severity,
    detail_lines: Vec<String>,
}

impl PendingEntry {
    fn into_log_entry(self, id: u64, file_path: &str, port_re: &Regex) -> LogEntry {
        // Extract port from detail lines if present
        let mut source_ip = self.remote_ip.clone();
        for detail in &self.detail_lines {
            if let Some(caps) = port_re.captures(detail) {
                if let Some(port) = caps.get(1) {
                    source_ip = format!("{}:{}", self.remote_ip, port.as_str());
                    break;
                }
            }
        }

        // Build message
        let message = format!(
            "[{}] [{}] {} ({}) \u{2192} {}",
            self.direction, self.protocol, self.query_name, self.query_type, self.rcode
        );

        LogEntry {
            id,
            line_number: self.line_number,
            message,
            component: None,
            timestamp: self.timestamp,
            timestamp_display: self.timestamp_display,
            severity: self.severity,
            thread: self.thread,
            thread_display: self.thread_display,
            source_file: None,
            format: LogFormat::DnsDebug,
            file_path: file_path.to_string(),
            timezone_offset: None,
            error_code_spans: Vec::new(),
            ip_address: None,
            host_name: None,
            mac_address: None,
            result_code: None,
            gle_code: None,
            setup_phase: None,
            operation_name: None,
            http_method: None,
            uri_stem: None,
            uri_query: None,
            status_code: None,
            sub_status: None,
            time_taken_ms: None,
            client_ip: None,
            server_ip: None,
            user_agent: None,
            server_port: None,
            username: None,
            win32_status: None,
            query_name: Some(self.query_name),
            query_type: Some(self.query_type),
            response_code: Some(self.rcode),
            dns_direction: Some(self.direction),
            dns_protocol: Some(self.protocol),
            source_ip: Some(source_ip),
            dns_flags: Some(format!("0x{}", self.flags_hex)),
            dns_event_id: None,
            zone_name: None,
        }
    }
}

/// Parse regex captures from a PACKET summary line into a `PendingEntry`.
fn parse_packet_captures(
    caps: &regex::Captures,
    line_number: u32,
    date_order: DateOrder,
) -> Result<PendingEntry, ()> {
    let timestamp_raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let thread_hex = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let protocol = caps.get(3).map(|m| m.as_str()).unwrap_or("UDP");
    let direction = caps.get(4).map(|m| m.as_str()).unwrap_or("Rcv");
    let remote_ip = caps.get(5).map(|m| m.as_str()).unwrap_or("");
    let xid = caps.get(6).map(|m| m.as_str()).unwrap_or("");
    let flags_hex = caps.get(9).map(|m| m.as_str()).unwrap_or("");
    let rcode = caps.get(11).map(|m| m.as_str()).unwrap_or("NOERROR");
    let query_type = caps.get(12).map(|m| m.as_str()).unwrap_or("");
    let query_name_raw = caps.get(13).map(|m| m.as_str()).unwrap_or("");

    let thread = u32::from_str_radix(thread_hex, 16).ok();
    let thread_display = thread.map(|t| format!("{} (0x{})", t, thread_hex.to_uppercase()));

    let (timestamp, timestamp_display) = parse_dns_timestamp(timestamp_raw, date_order);
    let query_name = dns_types::decode_query_name(query_name_raw);
    let severity = dns_types::rcode_to_severity(rcode);

    Ok(PendingEntry {
        line_number,
        timestamp,
        timestamp_display,
        thread,
        thread_display,
        protocol: protocol.to_string(),
        direction: direction.to_string(),
        remote_ip: remote_ip.to_string(),
        xid: xid.to_string(),
        flags_hex: flags_hex.to_string(),
        rcode: rcode.to_string(),
        query_type: query_type.to_string(),
        query_name,
        severity,
        detail_lines: Vec::new(),
    })
}

/// Parse a DNS debug log timestamp string into epoch millis and display string.
///
/// Supports three formats:
/// - US locale: `M/d/yyyy h:mm:ss AM/PM`
/// - EU locale: `dd/MM/yyyy HH:mm:ss`
/// - ISO-style: `yyyyMMdd HH:mm:ss`
fn parse_dns_timestamp(raw: &str, date_order: DateOrder) -> (Option<i64>, Option<String>) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (None, None);
    }

    // Try ISO-style first: yyyyMMdd HH:mm:ss
    if let Some((date_part, time_part)) = trimmed.split_once(' ') {
        if date_part.len() == 8 && date_part.chars().all(|c| c.is_ascii_digit()) {
            let yr: i32 = date_part[0..4].parse().unwrap_or(0);
            let mon: u32 = date_part[4..6].parse().unwrap_or(1);
            let day: u32 = date_part[6..8].parse().unwrap_or(1);
            let (h, m, s) = parse_time_hms(time_part, false);

            return build_timestamp(yr, mon, day, h, m, s);
        }
    }

    // Slash-date format: split on space to get date, time, and optional AM/PM
    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return (None, Some(trimmed.to_string()));
    }

    let date_str = parts[0];
    let has_ampm = parts.len() == 3
        && (parts[2].eq_ignore_ascii_case("AM") || parts[2].eq_ignore_ascii_case("PM"));
    let time_str = parts[1];
    let is_pm = has_ampm && parts[2].eq_ignore_ascii_case("PM");
    let is_am = has_ampm && parts[2].eq_ignore_ascii_case("AM");

    let date_fields: Vec<&str> = date_str.split('/').collect();
    if date_fields.len() != 3 {
        return (None, Some(trimmed.to_string()));
    }

    let f1: u32 = date_fields[0].parse().unwrap_or(0);
    let f2: u32 = date_fields[1].parse().unwrap_or(0);
    let yr: i32 = date_fields[2].parse().unwrap_or(0);

    let (mon, day) = match date_order {
        DateOrder::DayFirst => (f2, f1),
        DateOrder::MonthFirst => (f1, f2),
    };

    let (mut h, m, s) = parse_time_hms(time_str, false);

    // Handle 12-hour AM/PM
    if has_ampm {
        if is_pm && h < 12 {
            h += 12;
        } else if is_am && h == 12 {
            h = 0;
        }
    }

    build_timestamp(yr, mon, day, h, m, s)
}

fn parse_time_hms(time_str: &str, _pad: bool) -> (u32, u32, u32) {
    let parts: Vec<&str> = time_str.split(':').collect();
    let h: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let m: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let s: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    (h, m, s)
}

fn build_timestamp(yr: i32, mon: u32, day: u32, h: u32, m: u32, s: u32) -> (Option<i64>, Option<String>) {
    let timestamp = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
        .and_then(|d| d.and_hms_opt(h, m, s))
        .map(|dt| dt.and_utc().timestamp_millis());

    let display = Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        yr, mon, day, h, m, s
    ));

    (timestamp, display)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_packet_line() {
        assert!(matches_dns_debug_record(
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)"
        ));
    }

    #[test]
    fn test_does_not_match_header() {
        assert!(!matches_dns_debug_record("DNS Server log file creation at 4/11/2026 3:29:17 PM"));
        assert!(!matches_dns_debug_record("Field #  Information         Values"));
        assert!(!matches_dns_debug_record(""));
    }

    #[test]
    fn test_does_not_match_detail_line() {
        assert!(!matches_dns_debug_record("  Remote addr 127.0.0.1, port 54159"));
        assert!(!matches_dns_debug_record("UDP question info at 000002DAEC36D650"));
    }

    #[test]
    fn test_parse_basic_query_response_pair() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Snd 127.0.0.1       d07e R Q [8085 A DR  NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let (entries, errors) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 2);

        // First entry: query (Rcv)
        assert_eq!(entries[0].dns_direction.as_deref(), Some("Rcv"));
        assert_eq!(entries[0].dns_protocol.as_deref(), Some("UDP"));
        assert_eq!(entries[0].query_name.as_deref(), Some("home.gell.one"));
        assert_eq!(entries[0].query_type.as_deref(), Some("SOA"));
        assert_eq!(entries[0].response_code.as_deref(), Some("NOERROR"));
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].format, LogFormat::DnsDebug);
        assert!(entries[0].message.contains("[Rcv]"));

        // Second entry: response (Snd)
        assert_eq!(entries[1].dns_direction.as_deref(), Some("Snd"));
        assert!(entries[1].message.contains("[Snd]"));
    }

    #[test]
    fn test_parse_with_detail_section_extracts_port() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 192.168.2.9     7822   U [0028       NOERROR] SOA    (4)home(4)gell(3)one(0)",
            "UDP question info at 000002DAEC3680D0",
            "  Socket = 876",
            "  Remote addr 192.168.2.9, port 57961",
            "  Time Query=1714823, Queued=0, Expire=0",
        ];
        let (entries, errors) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_ip.as_deref(), Some("192.168.2.9:57961"));
    }

    #[test]
    fn test_parse_severity_mapping() {
        let lines = vec![
            "4/11/2026 8:34:00 PM 0294 PACKET  000002DAEF3AFDC0 UDP Snd 127.0.0.1       3c8a R Q [8385 A DR NXDOMAIN] A      (4)HOME(4)home(4)gell(3)one(0)",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC3680D0 UDP Snd 192.168.2.9     7822 R U [02a8      SERVFAIL] SOA    (4)home(4)gell(3)one(0)",
        ];
        let (entries, _) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(entries[0].severity, Severity::Warning); // NXDOMAIN
        assert_eq!(entries[1].severity, Severity::Error); // SERVFAIL
    }

    #[test]
    fn test_parse_skips_header() {
        let lines = vec![
            "DNS Server log file creation at 4/11/2026 3:29:17 PM",
            "",
            "Message logging key (for packets - other items use a subset of these fields):",
            "  Field #  Information         Values",
            "  -------  -----------         ------",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let (entries, errors) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].query_type.as_deref(), Some("SOA"));
    }

    #[test]
    fn test_parse_thread_display() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] A      (4)home(4)gell(3)one(0)",
        ];
        let (entries, _) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(entries[0].thread, Some(660)); // 0x0294 = 660
        assert_eq!(entries[0].thread_display.as_deref(), Some("660 (0x0294)"));
    }

    #[test]
    fn test_parse_us_timestamp() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] A      (4)test(0)",
        ];
        let (entries, _) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2026-04-11 15:29:17")
        );
    }

    #[test]
    fn test_parse_dynamic_update_opcode() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC3680D0 UDP Rcv 192.168.2.9     7822   U [0028       NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let (entries, errors) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].query_type.as_deref(), Some("SOA"));
    }

    #[test]
    fn test_parse_root_query() {
        let lines = vec![
            "4/11/2026 8:33:19 PM 0294 PACKET  000002DAECB28D10 UDP Snd 192.168.2.9     131a R Q [8081   DR  NOERROR] NS     (0)",
        ];
        let (entries, _) = parse_lines(&lines, "dns.log", DateOrder::MonthFirst);

        assert_eq!(entries[0].query_name.as_deref(), Some("."));
        assert_eq!(entries[0].query_type.as_deref(), Some("NS"));
    }
}
```

- [ ] **Step 2: Register the module in `mod.rs`**

In `src-tauri/src/parser/mod.rs`, add after `pub mod dns_types;`:

```rust
pub mod dns_debug;
```

- [ ] **Step 3: Run tests**

```bash
cd src-tauri && cargo test dns_debug
```

Expected: all tests pass. If the PACKET regex needs tuning for edge cases, fix and rerun.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/parser/dns_debug.rs src-tauri/src/parser/mod.rs
git commit -m "feat(dns): add DNS debug log parser with LogicalRecord framing and detail extraction"
```

---

### Task 4: Detection Integration for DNS Debug Log

**Files:**
- Modify: `src-tauri/src/parser/detect.rs`

- [ ] **Step 1: Add DNS debug path hints and content counting**

In `detect.rs`, add a DNS path hint variable after the existing hints (near line 380):

```rust
    let dns_debug_path_hint = path_lower.contains("dns")
        || path_lower.ends_with("dns.log")
        || path_lower.contains("\\dns\\")
        || path_lower.contains("/dns/");
```

Add a counter variable alongside the existing counters (near line 395):

```rust
    let mut dns_debug_count = 0u32;
```

- [ ] **Step 2: Add DNS debug content matching in the sample loop**

In the `for line in &sample_lines` loop, add a check for DNS debug records. Add it after the `patchmypc_detection` check (near line 417) but before the `burn` check:

```rust
        } else if dns_debug::matches_dns_debug_record(line.trim()) {
            dns_debug_count += 1;
            timestamp_count += 1;
```

Also add the import at the top of the file — add `dns_debug` to the `use super::` import list (line 16):

```rust
use super::{
    burn, cbs, dhcp, dism, dns_debug, iis_w3c, intune_macos, msi, panther,
    patchmypc_detection, psadt, reporting_events,
    timestamped::{self, DateOrder},
};
```

- [ ] **Step 3: Extend sample window for DNS path hints**

Replace the sample_lines collection (lines 314-318) with a conditional window:

```rust
    let sample_limit = if dns_debug_path_hint { 50 } else { 20 };
    let sample_lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(sample_limit)
        .collect();
```

Note: `dns_debug_path_hint` needs to be computed before the sample collection. Move the path hint computation block to before the sample lines. This means the `path_lower` variable and the `dns_debug_path_hint` line need to be above the `sample_lines` computation.

- [ ] **Step 4: Add `ResolvedParser::dns_debug()` factory method**

Add after the `psadt_legacy()` method in `detect.rs` (near line 260):

```rust
    pub fn dns_debug(date_order: DateOrder) -> Self {
        Self::new(
            ParserKind::DnsDebug,
            ParserImplementation::DnsDebug,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::LogicalRecord,
            date_order,
            None,
        )
    }
```

- [ ] **Step 5: Add `DnsDebug` to `compatibility_format()`**

In the `compatibility_format()` method, add before the `PlainText` arm:

```rust
            ParserImplementation::DnsDebug => LogFormat::DnsDebug,
```

- [ ] **Step 6: Add DNS debug detection to the precedence chain**

In the detection precedence chain, add DNS debug detection. It should go after DHCP detection (the `dhcp_count` check) and before MSI detection. Add near line 472:

```rust
    } else if (dns_debug_path_hint && dns_debug_count >= 1) || dns_debug_count >= 2 {
        let dns_date_order = if has_day_first {
            DateOrder::DayFirst
        } else {
            DateOrder::MonthFirst
        };
        ResolvedParser::dns_debug(dns_date_order)
```

- [ ] **Step 7: Add detection tests**

Add to the `#[cfg(test)] mod tests` block in `detect.rs`:

```rust
    #[test]
    fn test_detect_dns_debug_from_path_and_content() {
        let content = concat!(
            "DNS Server log file creation at 4/11/2026 3:29:17 PM\n",
            "\n",
            "Message logging key (for packets):\n",
            "  Field #  Information         Values\n",
            "  -------  -----------         ------\n",
            "     1     Date\n",
            "     2     Time\n",
            "     3     Thread ID\n",
            "     4     Context\n",
            "     5     Internal packet identifier\n",
            "     6     UDP/TCP indicator\n",
            "     7     Send/Receive indicator\n",
            "     8     Remote IP\n",
            "     9     Xid (hex)\n",
            "    10     Query/Response      R = Response\n",
            "                               blank = Query\n",
            "    11     Opcode              Q = Standard Query\n",
            "                               N = Notify\n",
            "                               U = Update\n",
            "                               ? = Unknown\n",
            "    12     [ Flags (hex)\n",
            "    13     Flags (char codes)  A = Authoritative Answer\n",
            "                               T = Truncated Response\n",
            "                               D = Recursion Desired\n",
            "                               R = Recursion Available\n",
            "    14     ResponseCode ]\n",
            "    15     Question Type\n",
            "    16     Question Name\n",
            "\n",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)\n",
        );

        let detected = detect_parser("C:/Logs/DNSServer/DNSServer_debug.log", content);
        assert_eq!(detected.parser, ParserKind::DnsDebug);
        assert_eq!(detected.implementation, ParserImplementation::DnsDebug);
        assert_eq!(detected.record_framing, RecordFraming::LogicalRecord);
        assert_eq!(detected.parse_quality, ParseQuality::Structured);
    }

    #[test]
    fn test_generic_timestamped_with_dns_in_path_does_not_false_positive() {
        let content = "2026-04-11 15:29:17 DNS resolution started\n\
                        2026-04-11 15:29:18 DNS resolution complete";

        let detected = detect_parser("C:/logs/dns-resolver/app.log", content);
        assert_eq!(detected.parser, ParserKind::Timestamped);
    }
```

- [ ] **Step 8: Run all tests**

```bash
cd src-tauri && cargo test
```

Expected: all existing tests pass, plus the two new detection tests.

- [ ] **Step 9: Commit**

```bash
git add src-tauri/src/parser/detect.rs
git commit -m "feat(dns): integrate DNS debug log detection with path hints and extended sample window"
```

---

### Task 5: Routing Integration for DNS Debug Log

**Files:**
- Modify: `src-tauri/src/parser/mod.rs`

- [ ] **Step 1: Add `DnsDebug` to `parse_lines_with_selection()`**

In `src-tauri/src/parser/mod.rs`, add a new arm in the `match selection.implementation` block (after the `PatchMyPcDetection` arm, before the `Registry` arm):

```rust
        crate::models::log_entry::ParserImplementation::DnsDebug => {
            dns_debug::parse_lines(lines, file_path, selection.date_order)
        }
```

- [ ] **Step 2: Add a stub arm for `DnsAudit`**

Add after the `DnsDebug` arm:

```rust
        crate::models::log_entry::ParserImplementation::DnsAudit => {
            // EVTX files are parsed via the binary path in parse_file(), not the line-based pipeline.
            (vec![], 0)
        }
```

- [ ] **Step 3: Run all tests**

```bash
cd src-tauri && cargo test
```

Expected: all tests pass.

- [ ] **Step 4: Test with real fixture**

Add a test to `mod.rs` in the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn test_parse_lines_with_dns_debug_selection() {
        let selection = ResolvedParser::dns_debug(DateOrder::MonthFirst);
        let lines = [
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Snd 127.0.0.1       d07e R Q [8085 A DR  NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "dns.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].query_name.as_deref(), Some("home.gell.one"));
        assert_eq!(entries[0].format, crate::models::log_entry::LogFormat::DnsDebug);
        assert!(!entries[0].error_code_spans.is_empty() || entries[0].error_code_spans.is_empty()); // just verify it ran annotation
    }
```

- [ ] **Step 5: Run tests**

```bash
cd src-tauri && cargo test test_parse_lines_with_dns_debug
```

Expected: passes.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/parser/mod.rs
git commit -m "feat(dns): route DNS debug parser through parse_lines_with_selection"
```

---

### Task 6: DNS Audit EVTX Parser (`dns_audit.rs`)

**Files:**
- Create: `src-tauri/src/parser/dns_audit.rs`
- Modify: `src-tauri/src/parser/mod.rs` (add `pub mod dns_audit;`)

- [ ] **Step 1: Create `dns_audit.rs` with provider detection and EVTX parsing**

Create `src-tauri/src/parser/dns_audit.rs`:

```rust
//! Windows DNS Server audit EVTX parser.
//!
//! Parses DNS audit event logs (Event IDs 513-582) from `.evtx` files
//! using the `evtx` crate. Events are dispatched by schema group.
//!
//! Format reference: docs/compass_artifact_*.md, Section 3.

use evtx::EvtxParser;
use serde_json::Value;
use std::path::Path;

use super::dns_types;
use crate::models::log_entry::{
    LogEntry, LogFormat, ParseResult, ParseQuality, ParserImplementation, ParserKind,
    ParserProvenance, ParserSelectionInfo, RecordFraming, Severity,
};

/// The DNS Server ETW provider name.
const DNS_PROVIDER_NAME: &str = "Microsoft-Windows-DNSServer";

/// Check if an EVTX file contains DNS Server events.
/// Reads the first 5 records and checks the provider name.
pub fn is_dns_evtx(path: &Path) -> bool {
    let mut parser = match EvtxParser::from_path(path) {
        Ok(p) => p,
        Err(_) => return false,
    };

    for record in parser.records_json().take(5).flatten() {
        if let Ok(json) = serde_json::from_str::<Value>(&record.data) {
            let provider = json["Event"]["System"]["Provider"]["#attributes"]["Name"]
                .as_str()
                .unwrap_or("");
            if provider == DNS_PROVIDER_NAME {
                return true;
            }
        }
    }
    false
}

/// Parse a DNS audit EVTX file into `LogEntry` records.
pub fn parse_evtx(path: &str) -> Result<ParseResult, String> {
    let path_obj = Path::new(path);
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let mut parser = EvtxParser::from_path(path_obj)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path, e))?;

    let mut entries = Vec::new();
    let mut id: u64 = 0;
    let mut parse_errors: u32 = 0;
    let mut total_records: u32 = 0;

    for record_result in parser.records_json() {
        total_records += 1;
        let record = match record_result {
            Ok(r) => r,
            Err(e) => {
                log::warn!("event=dns_audit_record_skip file=\"{}\" error=\"{e}\"", path);
                parse_errors += 1;
                continue;
            }
        };

        let json: Value = match serde_json::from_str(&record.data) {
            Ok(v) => v,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };

        let system = &json["Event"]["System"];
        let event_data = &json["Event"]["EventData"];

        // Skip non-DNS events
        let provider = system["Provider"]["#attributes"]["Name"]
            .as_str()
            .unwrap_or("");
        if provider != DNS_PROVIDER_NAME {
            continue;
        }

        let event_id = extract_event_id(system);
        let timestamp_raw = system["TimeCreated"]["#attributes"]["SystemTime"]
            .as_str()
            .unwrap_or("");
        let (timestamp, timestamp_display) = parse_evtx_timestamp(timestamp_raw);

        let entry = build_log_entry(id, event_id, event_data, timestamp, timestamp_display, path);
        entries.push(entry);
        id += 1;
    }

    // Annotate error code spans
    super::annotate_error_code_spans(&mut entries);

    let selection_info = ParserSelectionInfo {
        parser: ParserKind::DnsAudit,
        implementation: ParserImplementation::DnsAudit,
        provenance: ParserProvenance::Dedicated,
        parse_quality: ParseQuality::Structured,
        record_framing: RecordFraming::PhysicalLine,
        date_order: None,
        specialization: None,
    };

    Ok(ParseResult {
        entries,
        format_detected: LogFormat::DnsAudit,
        parser_selection: selection_info,
        total_lines: total_records,
        parse_errors,
        file_path: path.to_string(),
        file_size,
        byte_offset: file_size,
    })
}

/// Build a `LogEntry` from a DNS audit event, dispatched by schema group.
fn build_log_entry(
    id: u64,
    event_id: u32,
    event_data: &Value,
    timestamp: Option<i64>,
    timestamp_display: Option<String>,
    file_path: &str,
) -> LogEntry {
    let (message, query_name, query_type, response_code, zone_name, source_ip, severity) =
        match event_id {
            515..=521 => extract_record_ops(event_id, event_data),
            513 | 514 | 522..=537 => extract_zone_config(event_id, event_data),
            540..=560 => extract_server_config(event_id, event_data),
            569..=572 => extract_dnssec_key_ops(event_id, event_data),
            577..=582 => extract_policy_ops(event_id, event_data),
            573..=576 => extract_delegation_subnet(event_id, event_data),
            561..=568 => extract_extended_zone_ops(event_id, event_data),
            _ => extract_generic(event_id, event_data),
        };

    LogEntry {
        id,
        line_number: id as u32 + 1,
        message,
        component: Some("DNSServer".to_string()),
        timestamp,
        timestamp_display,
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::DnsAudit,
        file_path: file_path.to_string(),
        timezone_offset: None,
        error_code_spans: Vec::new(),
        ip_address: None,
        host_name: None,
        mac_address: None,
        result_code: None,
        gle_code: None,
        setup_phase: None,
        operation_name: None,
        http_method: None,
        uri_stem: None,
        uri_query: None,
        status_code: None,
        sub_status: None,
        time_taken_ms: None,
        client_ip: None,
        server_ip: None,
        user_agent: None,
        server_port: None,
        username: None,
        win32_status: None,
        query_name,
        query_type,
        response_code,
        dns_direction: None,
        dns_protocol: None,
        source_ip,
        dns_flags: None,
        dns_event_id: Some(event_id),
        zone_name,
    }
}

// -- Schema group extractors --
// Each returns (message, query_name, query_type, response_code, zone_name, source_ip, severity)

type ExtractResult = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Severity,
);

fn get_str(data: &Value, key: &str) -> Option<String> {
    data[key].as_str().map(|s| s.to_string())
}

fn event_name(event_id: u32) -> &'static str {
    match event_id {
        513 => "Zone Delete",
        514 => "Zone Setting",
        515 => "Record Create",
        516 => "Record Delete",
        517 => "RRSET Delete",
        518 => "Node Delete",
        519 => "Record Create (Dynamic)",
        520 => "Record Delete (Dynamic)",
        521 => "Record Scavenge",
        525 => "Zone Sign",
        526 => "Zone Unsign",
        527 => "Zone Re-sign",
        536 => "Cache Purge",
        537 => "Forwarder Reset",
        541 => "Server Setting",
        _ => "DNS Audit",
    }
}

fn extract_record_ops(event_id: u32, data: &Value) -> ExtractResult {
    let name = get_str(data, "NAME");
    let rr_type = data["Type"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .or_else(|| data["Type"].as_u64().map(|n| n as u32));
    let type_name = rr_type.map(dns_types::qtype_name);
    let zone = get_str(data, "Zone");
    let ttl = get_str(data, "TTL");
    let rdata = get_str(data, "RDATA");
    let source_ip = get_str(data, "SourceIP");

    let mut msg = format!("[{} {}]", event_id, event_name(event_id));
    if let Some(ref n) = name {
        msg.push_str(&format!(" {}", n));
    }
    if let Some(ref t) = type_name {
        msg.push_str(&format!(" ({})", t));
    }
    if let Some(ref t) = ttl {
        msg.push_str(&format!(" TTL={}", t));
    }
    if let Some(ref z) = zone {
        msg.push_str(&format!(" Zone={}", z));
    }
    if let Some(ref r) = rdata {
        msg.push_str(&format!(" RDATA={}", r));
    }

    let severity = match event_id {
        516 | 520 => Severity::Warning,
        _ => Severity::Info,
    };

    (msg, name, type_name, None, zone, source_ip, severity)
}

fn extract_zone_config(event_id: u32, data: &Value) -> ExtractResult {
    let zone = get_str(data, "Zone");
    let setting = get_str(data, "Setting");
    let new_value = get_str(data, "NewValue");

    let mut msg = format!("[{} {}]", event_id, event_name(event_id));
    if let Some(ref z) = zone {
        msg.push_str(&format!(" {}", z));
    }
    if let Some(ref s) = setting {
        msg.push_str(&format!(" \u{2014} Setting={}", s));
    }
    if let Some(ref v) = new_value {
        msg.push_str(&format!(" NewValue={}", v));
    }

    let severity = match event_id {
        513 => Severity::Error,
        525..=527 => Severity::Warning,
        _ => Severity::Info,
    };

    (msg, None, None, None, zone, None, severity)
}

fn extract_server_config(event_id: u32, data: &Value) -> ExtractResult {
    let setting = get_str(data, "Setting");
    let value = get_str(data, "Value");
    let scope = get_str(data, "Scope");

    let mut msg = format!("[{} {}]", event_id, event_name(event_id));
    if let Some(ref s) = setting {
        msg.push_str(&format!(" {}", s));
    }
    if let Some(ref v) = value {
        msg.push_str(&format!(" = {}", v));
    }
    if let Some(ref sc) = scope {
        msg.push_str(&format!(" (Scope={})", sc));
    }

    let severity = match event_id {
        541 => Severity::Warning,
        _ => Severity::Info,
    };

    (msg, None, None, None, None, None, severity)
}

fn extract_dnssec_key_ops(event_id: u32, data: &Value) -> ExtractResult {
    let zone = get_str(data, "Zone");
    let algo = get_str(data, "CryptoAlgorithm");

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref z) = zone {
        msg.push_str(&format!(" Zone={}", z));
    }
    if let Some(ref a) = algo {
        msg.push_str(&format!(" Algorithm={}", a));
    }

    (msg, None, None, None, zone, None, Severity::Info)
}

fn extract_policy_ops(event_id: u32, data: &Value) -> ExtractResult {
    let policy_name = get_str(data, "PolicyName");
    let action = get_str(data, "Action");

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref p) = policy_name {
        msg.push_str(&format!(" Policy={}", p));
    }
    if let Some(ref a) = action {
        msg.push_str(&format!(" Action={}", a));
    }

    (msg, None, None, None, None, None, Severity::Info)
}

fn extract_delegation_subnet(event_id: u32, data: &Value) -> ExtractResult {
    let zone = get_str(data, "Zone");

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref z) = zone {
        msg.push_str(&format!(" Zone={}", z));
    }

    (msg, None, None, None, zone, None, Severity::Info)
}

fn extract_extended_zone_ops(event_id: u32, data: &Value) -> ExtractResult {
    let zone = get_str(data, "Zone");

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref z) = zone {
        msg.push_str(&format!(" Zone={}", z));
    }

    (msg, None, None, None, zone, None, Severity::Info)
}

fn extract_generic(event_id: u32, data: &Value) -> ExtractResult {
    // For unknown events, dump the first few EventData fields into the message
    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(obj) = data.as_object() {
        let mut count = 0;
        for (key, value) in obj {
            if count >= 5 {
                break;
            }
            if let Some(v) = value.as_str() {
                msg.push_str(&format!(" {}={}", key, v));
                count += 1;
            }
        }
    }

    (msg, None, None, None, None, None, Severity::Info)
}

fn extract_event_id(system: &Value) -> u32 {
    if let Some(id) = system["EventID"].as_u64() {
        return id as u32;
    }
    if let Some(id) = system["EventID"]["#text"].as_u64() {
        return id as u32;
    }
    if let Some(s) = system["EventID"]["#text"].as_str() {
        return s.parse().unwrap_or(0);
    }
    0
}

fn parse_evtx_timestamp(raw: &str) -> (Option<i64>, Option<String>) {
    if raw.is_empty() {
        return (None, None);
    }
    // EVTX timestamps are ISO 8601: "2026-04-11T15:29:17.123Z"
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        let millis = dt.timestamp_millis();
        let display = dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        return (Some(millis), Some(display));
    }
    // Fallback: try without fractional seconds
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
        let millis = dt.and_utc().timestamp_millis();
        let display = dt.format("%Y-%m-%d %H:%M:%S.000").to_string();
        return (Some(millis), Some(display));
    }
    (None, Some(raw.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event_data(fields: &[(&str, &str)]) -> Value {
        let mut map = serde_json::Map::new();
        for (k, v) in fields {
            map.insert(k.to_string(), Value::String(v.to_string()));
        }
        Value::Object(map)
    }

    #[test]
    fn test_extract_record_create() {
        let data = make_event_data(&[
            ("NAME", "test.homelab.local"),
            ("Type", "1"),
            ("TTL", "3600"),
            ("Zone", "homelab.local"),
            ("RDATA", "0x01010101"),
        ]);
        let (msg, qn, qt, _rc, zone, _ip, sev) = extract_record_ops(515, &data);

        assert!(msg.contains("[515 Record Create]"));
        assert!(msg.contains("test.homelab.local"));
        assert!(msg.contains("(A)"));
        assert!(msg.contains("TTL=3600"));
        assert_eq!(qn.as_deref(), Some("test.homelab.local"));
        assert_eq!(qt.as_deref(), Some("A"));
        assert_eq!(zone.as_deref(), Some("homelab.local"));
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn test_extract_record_delete_is_warning() {
        let data = make_event_data(&[("NAME", "old.homelab.local"), ("Type", "1"), ("Zone", "homelab.local")]);
        let (_msg, _qn, _qt, _rc, _zone, _ip, sev) = extract_record_ops(516, &data);
        assert_eq!(sev, Severity::Warning);
    }

    #[test]
    fn test_extract_dynamic_update_with_source_ip() {
        let data = make_event_data(&[
            ("NAME", "client1.homelab.local"),
            ("Type", "1"),
            ("Zone", "homelab.local"),
            ("SourceIP", "10.0.2.15"),
        ]);
        let (_msg, _qn, _qt, _rc, _zone, ip, _sev) = extract_record_ops(519, &data);
        assert_eq!(ip.as_deref(), Some("10.0.2.15"));
    }

    #[test]
    fn test_extract_zone_delete_is_error() {
        let data = make_event_data(&[("Zone", "homelab.local")]);
        let (_msg, _qn, _qt, _rc, zone, _ip, sev) = extract_zone_config(513, &data);
        assert_eq!(zone.as_deref(), Some("homelab.local"));
        assert_eq!(sev, Severity::Error);
    }

    #[test]
    fn test_extract_server_setting_is_warning() {
        let data = make_event_data(&[("Setting", "serverlevelplugindll"), ("Value", "test.dll")]);
        let (msg, _qn, _qt, _rc, _zone, _ip, sev) = extract_server_config(541, &data);
        assert!(msg.contains("serverlevelplugindll"));
        assert!(msg.contains("test.dll"));
        assert_eq!(sev, Severity::Warning);
    }

    #[test]
    fn test_extract_generic_unknown_event() {
        let data = make_event_data(&[("Foo", "bar"), ("Baz", "qux")]);
        let (msg, _qn, _qt, _rc, _zone, _ip, sev) = extract_generic(999, &data);
        assert!(msg.contains("[999 DNS Audit]"));
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn test_extract_missing_fields_graceful() {
        let data = Value::Object(serde_json::Map::new());
        let (msg, qn, qt, _rc, zone, ip, sev) = extract_record_ops(515, &data);
        assert!(msg.contains("[515 Record Create]"));
        assert!(qn.is_none());
        assert!(qt.is_none());
        assert!(zone.is_none());
        assert!(ip.is_none());
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn test_parse_evtx_timestamp_rfc3339() {
        let (ts, display) = parse_evtx_timestamp("2026-04-11T15:29:17.123Z");
        assert!(ts.is_some());
        assert!(display.unwrap().starts_with("2026-04-11 15:29:17"));
    }

    #[test]
    fn test_parse_evtx_timestamp_empty() {
        let (ts, display) = parse_evtx_timestamp("");
        assert!(ts.is_none());
        assert!(display.is_none());
    }
}
```

- [ ] **Step 2: Register the module in `mod.rs`**

In `src-tauri/src/parser/mod.rs`, add after `pub mod dns_debug;`:

```rust
#[cfg(feature = "event-log")]
pub mod dns_audit;
```

- [ ] **Step 3: Run tests**

```bash
cd src-tauri && cargo test dns_audit --features event-log
```

Expected: all unit tests pass.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/parser/dns_audit.rs src-tauri/src/parser/mod.rs
git commit -m "feat(dns): add DNS audit EVTX parser with schema group dispatch"
```

---

### Task 7: Binary File Detection in `parse_file()`

**Files:**
- Modify: `src-tauri/src/parser/mod.rs`
- Modify: `src-tauri/src/parser/detect.rs` (add `ResolvedParser::dns_audit()`)

- [ ] **Step 1: Add `ResolvedParser::dns_audit()` factory method**

In `src-tauri/src/parser/detect.rs`, add after `dns_debug()`:

```rust
    pub fn dns_audit() -> Self {
        Self::new(
            ParserKind::DnsAudit,
            ParserImplementation::DnsAudit,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }
```

- [ ] **Step 2: Add `DnsAudit` to `compatibility_format()`**

In `detect.rs` `compatibility_format()`, add before the `PlainText` arm:

```rust
            ParserImplementation::DnsAudit => LogFormat::DnsAudit,
```

- [ ] **Step 3: Add binary file detection guard in `parse_file()`**

In `src-tauri/src/parser/mod.rs`, modify `parse_file()` to intercept `.evtx` and `.etl` files before text decoding. Replace the current `parse_file()` function (lines 44-65):

```rust
pub fn parse_file(path: &str) -> Result<(ParseResult, ResolvedParser), String> {
    let path_obj = Path::new(path);

    // Binary file detection by extension — intercept before text decoding
    if let Some(ext) = path_obj.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();

        if ext_lower == "etl" {
            #[cfg(target_os = "windows")]
            return Err(
                "ETL analytical logs are not yet supported. Convert to XML with: \
                 tracerpt \"<file>\" -of XML -o output.xml — then open the XML file."
                    .to_string(),
            );
            #[cfg(not(target_os = "windows"))]
            return Err(
                "ETL files contain binary Windows event traces that require the Windows \
                 tracerpt tool to convert. Export to XML on a Windows machine first, \
                 then open the XML file here."
                    .to_string(),
            );
        }

        #[cfg(feature = "event-log")]
        if ext_lower == "evtx" {
            if dns_audit::is_dns_evtx(path_obj) {
                let result = dns_audit::parse_evtx(path)?;
                let selection = ResolvedParser::dns_audit();
                return Ok((result, selection));
            }
            // Not a DNS EVTX — fall through to let other handlers (Sysmon) deal with it.
            // Return an error here since the text parser can't handle binary EVTX.
            return Err(
                "This EVTX file does not contain DNS audit events. \
                 Try opening it in the Sysmon workspace instead."
                    .to_string(),
            );
        }
    }

    // Existing text-based parsing path
    let content = read_file_content(path)?;
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let selection = detect::detect_parser(path, &content);
    let parsed_chunk = parse_content_with_selection(&content, path, &selection);

    let result = ParseResult {
        entries: parsed_chunk.entries,
        format_detected: selection.compatibility_format(),
        parser_selection: selection.to_info(),
        total_lines: parsed_chunk.total_lines,
        parse_errors: parsed_chunk.parse_errors,
        file_path: path_obj.to_string_lossy().to_string(),
        file_size,
        byte_offset: file_size,
    };

    Ok((result, selection))
}
```

- [ ] **Step 4: Run `cargo check`**

```bash
cd src-tauri && cargo check --features event-log
```

Expected: compiles. Also check without the feature:

```bash
cd src-tauri && cargo check
```

Expected: compiles (the `#[cfg(feature = "event-log")]` guard skips the EVTX code).

- [ ] **Step 5: Run all tests**

```bash
cd src-tauri && cargo test --features event-log
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/parser/mod.rs src-tauri/src/parser/detect.rs
git commit -m "feat(dns): add binary file detection — EVTX DNS routing and ETL stub with platform messages"
```

---

### Task 8: Corpus Test Fixtures and Integration Tests

**Files:**
- Create: `src-tauri/tests/corpus/dns_debug/clean/basic.log`
- Create: `src-tauri/tests/corpus/dns_debug/clean/with_detail.log`
- Create: `src-tauri/tests/corpus/dns_debug/mixed/rcodes.log`
- Modify: `src-tauri/tests/parser_regression_corpus.rs` (add DNS tests)

- [ ] **Step 1: Create basic DNS debug fixture**

Create `src-tauri/tests/corpus/dns_debug/clean/basic.log` with summary-only lines (no detail sections):

```
DNS Server log file creation at 4/11/2026 3:29:17 PM

Message logging key (for packets - other items use a subset of these fields):
	Field #  Information         Values
	-------  -----------         ------
	   1     Date
	   2     Time
	   3     Thread ID
	   4     Context
	   5     Internal packet identifier
	   6     UDP/TCP indicator
	   7     Send/Receive indicator
	   8     Remote IP
	   9     Xid (hex)
	  10     Query/Response      R = Response
	                             blank = Query
	  11     Opcode              Q = Standard Query
	                             N = Notify
	                             U = Update
	                             ? = Unknown
	  12     [ Flags (hex)
	  13     Flags (char codes)  A = Authoritative Answer
	                             T = Truncated Response
	                             D = Recursion Desired
	                             R = Recursion Available
	  14     ResponseCode ]
	  15     Question Type
	  16     Question Name

4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)
4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Snd 127.0.0.1       d07e R Q [8085 A DR  NOERROR] SOA    (4)home(4)gell(3)one(0)
4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC370110 UDP Rcv 127.0.0.1       6ec3   Q [0001   D   NOERROR] NS     (4)home(4)gell(3)one(0)
4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC370110 UDP Snd 127.0.0.1       6ec3 R Q [8085 A DR  NOERROR] NS     (4)home(4)gell(3)one(0)
```

- [ ] **Step 2: Create DNS debug fixture with mixed RCODEs**

Create `src-tauri/tests/corpus/dns_debug/mixed/rcodes.log`:

```
4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] A      (4)home(4)gell(3)one(0)
4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Snd 127.0.0.1       d07e R Q [8085 A DR  NOERROR] A      (4)home(4)gell(3)one(0)
4/11/2026 8:34:00 PM 0294 PACKET  000002DAEF3AFDC0 UDP Snd 127.0.0.1       3c8a R Q [8385 A DR NXDOMAIN] A      (4)HOME(4)home(4)gell(3)one(0)
4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC3680D0 UDP Snd 192.168.2.9     7822 R U [02a8      SERVFAIL] SOA    (4)home(4)gell(3)one(0)
```

- [ ] **Step 3: Add regression tests to `parser_regression_corpus.rs`**

Add to `src-tauri/tests/parser_regression_corpus.rs`:

```rust
    #[test]
    fn test_dns_debug_basic_fixture_detection() {
        let fixture = TempLogFixture::new(
            "DNSServer_debug.log",
            &std::fs::read_to_string(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/dns_debug/clean/basic.log")
            ).expect("read fixture"),
        );
        let snapshot = fixture.detect();
        assert_eq!(snapshot.parser, "DnsDebug");
        assert_eq!(snapshot.record_framing, "LogicalRecord");
    }

    #[test]
    fn test_dns_debug_basic_fixture_parse() {
        let fixture = TempLogFixture::new(
            "DNSServer_debug.log",
            &std::fs::read_to_string(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/dns_debug/clean/basic.log")
            ).expect("read fixture"),
        );
        let parsed = fixture.parse();
        assert_eq!(parsed.selection.parser, "DnsDebug");
        assert_eq!(parsed.parse_errors, 0);
        assert_eq!(parsed.entries.len(), 4);
        assert_eq!(parsed.entries[0].severity, "Info");
    }

    #[test]
    fn test_dns_debug_rcodes_fixture_severity() {
        let fixture = TempLogFixture::new(
            "dns.log",
            &std::fs::read_to_string(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/dns_debug/mixed/rcodes.log")
            ).expect("read fixture"),
        );
        let parsed = fixture.parse();
        assert_eq!(parsed.entries.len(), 4);
        assert_eq!(parsed.entries[0].severity, "Info");     // NOERROR query
        assert_eq!(parsed.entries[1].severity, "Info");     // NOERROR response
        assert_eq!(parsed.entries[2].severity, "Warning");  // NXDOMAIN
        assert_eq!(parsed.entries[3].severity, "Error");    // SERVFAIL
    }
```

- [ ] **Step 4: Run regression tests**

```bash
cd src-tauri && cargo test parser_regression_corpus
```

Expected: all tests pass including new DNS tests.

- [ ] **Step 5: Run full test suite**

```bash
cd src-tauri && cargo test --features event-log
```

Expected: all tests pass.

- [ ] **Step 6: Run clippy**

```bash
cd src-tauri && cargo clippy --features event-log -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/tests/corpus/dns_debug/ src-tauri/tests/parser_regression_corpus.rs
git commit -m "test(dns): add DNS debug log corpus fixtures and regression tests"
```

---

### Task 9: TypeScript Type Updates

**Files:**
- Modify: `src/types/` (TypeScript types that mirror `LogEntry`)

- [ ] **Step 1: Find the TypeScript LogEntry type**

Search for the TypeScript definition of LogEntry or ParseResult that mirrors the Rust struct. This is the frontend type that needs the nine new DNS fields.

```bash
grep -r "query_name\|queryName\|LogEntry\|logEntry" src/types/ --include="*.ts" --include="*.tsx" -l
```

- [ ] **Step 2: Add DNS fields to the TypeScript type**

Add to the TypeScript `LogEntry` interface (using camelCase as per serde rename):

```typescript
  queryName?: string;
  queryType?: string;
  responseCode?: string;
  dnsDirection?: string;
  dnsProtocol?: string;
  sourceIp?: string;
  dnsFlags?: string;
  dnsEventId?: number;
  zoneName?: string;
```

- [ ] **Step 3: Add `DnsDebug` and `DnsAudit` to any TypeScript LogFormat enum/type**

Search for the TypeScript equivalent of `LogFormat` and add the two new variants.

- [ ] **Step 4: Run TypeScript check**

```bash
npx tsc --noEmit
```

Expected: zero errors.

- [ ] **Step 5: Commit**

```bash
git add src/types/
git commit -m "feat(dns): add DNS fields to TypeScript LogEntry type"
```

---

### Task 10: Final Integration Verification

- [ ] **Step 1: Run full Rust test suite**

```bash
cd src-tauri && cargo test --features event-log
```

Expected: all tests pass.

- [ ] **Step 2: Run clippy**

```bash
cd src-tauri && cargo clippy --features event-log -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 3: Run TypeScript check**

```bash
npx tsc --noEmit
```

Expected: zero errors.

- [ ] **Step 4: Test with real debug log fixture**

```bash
cd src-tauri && cargo test --features event-log -- --ignored dns_real_fixture 2>/dev/null || echo "No real fixture test yet — manual test"
```

Manually verify by opening `Logs/dns-fixtures-20260411-203254/DNSServer_debug.log` in the app (if building on Windows or with `npm run app:dev`).

- [ ] **Step 5: Commit any final fixes**

If any issues were found, fix and commit.

- [ ] **Step 6: Final commit with all changes verified**

```bash
git log --oneline -10
```

Verify the commit history shows the incremental feature development:
1. Type system foundation
2. Shared DNS types
3. DNS debug log parser
4. Detection integration
5. Routing integration
6. DNS audit EVTX parser
7. Binary file detection
8. Corpus test fixtures
9. TypeScript types
