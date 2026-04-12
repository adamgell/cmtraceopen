use evtx::EvtxParser;
use serde_json::Value;
use std::path::Path;

use super::dns_types;
use crate::models::log_entry::{
    LogEntry, LogFormat, ParseQuality, ParseResult, ParserImplementation, ParserKind,
    ParserProvenance, ParserSelectionInfo, RecordFraming, Severity,
};

/// The DNS Server ETW provider name used in Windows DNS audit EVTX logs.
const DNS_PROVIDER: &str = "Microsoft-Windows-DNSServer";

/// Extracted event fields: (message, query_name, query_type, response_code, zone_name, source_ip, severity).
type EventFields = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Severity,
);

/// Checks if an EVTX file contains DNS Server audit events.
///
/// Opens the file, reads up to 5 records, and checks whether the
/// provider name matches `Microsoft-Windows-DNSServer`.
/// Returns false on any error.
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
            if provider == DNS_PROVIDER {
                return true;
            }
        }
    }
    false
}

/// Parse a DNS Server audit EVTX file into `LogEntry` records.
///
/// Iterates all records in the file, filters for the DNS provider, and
/// dispatches each event by EventID to schema-group extractors that
/// produce structured `LogEntry` values.
pub fn parse_evtx(path: &str) -> Result<ParseResult, String> {
    let path_obj = Path::new(path);
    let file_size = std::fs::metadata(path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut parser = EvtxParser::from_path(path_obj)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path, e))?;

    let mut entries: Vec<LogEntry> = Vec::new();
    let mut id: u64 = 0;

    for record_result in parser.records_json() {
        let record = match record_result {
            Ok(r) => r,
            Err(e) => {
                log::warn!("event=dns_audit_record_skip file=\"{}\" error=\"{}\"", path, e);
                continue;
            }
        };

        let json: Value = match serde_json::from_str(&record.data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let system = &json["Event"]["System"];

        // Only process DNS Server events
        let provider = system["Provider"]["#attributes"]["Name"]
            .as_str()
            .unwrap_or("");
        if provider != DNS_PROVIDER {
            continue;
        }

        let event_id = extract_event_id(system);
        let event_data = &json["Event"]["EventData"];

        let (timestamp_ms, timestamp_display) = parse_evtx_timestamp(
            system["TimeCreated"]["#attributes"]["SystemTime"]
                .as_str()
                .unwrap_or(""),
        );

        let (message, query_name, query_type, response_code, zone_name, source_ip, severity) =
            extract_event_fields(event_id, event_data);

        entries.push(LogEntry {
            id,
            line_number: id as u32 + 1,
            message,
            component: Some("DNSServer".to_string()),
            timestamp: timestamp_ms,
            timestamp_display,
            severity,
            thread: None,
            thread_display: None,
            source_file: None,
            format: LogFormat::DnsAudit,
            file_path: path.to_string(),
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
        });

        id += 1;
    }

    super::annotate_error_code_spans(&mut entries);

    let total_lines = entries.len() as u32;
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
        total_lines,
        parse_errors: 0,
        file_path: path.to_string(),
        file_size,
        byte_offset: file_size,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract the EventID from the EVTX System block.
///
/// Handles both direct numeric values and the `{"#text": ...}` wrapper
/// that the evtx crate sometimes produces.
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

/// Get a string field from EventData, returning None if absent or null.
fn get_str(data: &Value, key: &str) -> Option<String> {
    data[key].as_str().map(|s| s.to_string())
}

/// Parse an RFC 3339 / ISO 8601 timestamp string into (millis, display).
fn parse_evtx_timestamp(raw: &str) -> (Option<i64>, Option<String>) {
    if raw.is_empty() {
        return (None, None);
    }
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(dt) => {
            let millis = dt.timestamp_millis();
            let display = dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            (Some(millis), Some(display))
        }
        Err(_) => (None, None),
    }
}

/// Human-readable event name for known DNS audit EventIDs.
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

/// Determine severity from the event ID.
fn event_severity(event_id: u32) -> Severity {
    match event_id {
        // Record delete events
        516 | 520 => Severity::Warning,
        // Zone delete
        513 => Severity::Error,
        // DNSSEC sign/unsign
        525..=527 => Severity::Warning,
        // Server setting change
        541 => Severity::Warning,
        // Everything else
        _ => Severity::Info,
    }
}

/// Dispatch to schema-group extractors based on EventID.
///
/// Returns `(message, query_name, query_type, response_code, zone_name, source_ip, severity)`.
fn extract_event_fields(event_id: u32, data: &Value) -> EventFields {
    match event_id {
        // Record operations
        515..=521 => extract_record_ops(event_id, data),
        // Zone configuration
        513 | 514 | 522..=537 => extract_zone_config(event_id, data),
        // Server configuration
        540..=560 => extract_server_config(event_id, data),
        // DNSSEC key operations
        569..=572 => extract_dnssec_key_ops(event_id, data),
        // Policy operations
        577..=582 => extract_policy_ops(event_id, data),
        // Delegation/subnet
        573..=576 => extract_delegation_subnet(event_id, data),
        // Extended zone operations
        561..=568 => extract_extended_zone_ops(event_id, data),
        // Generic fallback
        _ => extract_generic(event_id, data),
    }
}

/// Extract fields for record operation events (515-521).
fn extract_record_ops(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let name = get_str(data, "NAME");
    let zone = get_str(data, "Zone");
    let ttl = get_str(data, "TTL");
    let rdata = get_str(data, "RDATA");

    // Type field can be a string number or a JSON number
    let rr_type = data["Type"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .or_else(|| data["Type"].as_u64().map(|n| n as u32));
    let type_name = rr_type.map(dns_types::qtype_name);

    // Source IP only for dynamic update events (519-520)
    let source_ip = if matches!(event_id, 519 | 520) {
        get_str(data, "SourceIP")
    } else {
        None
    };

    let severity = event_severity(event_id);
    let ename = event_name(event_id);

    let mut msg = format!("[{} {}]", event_id, ename);
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

    (msg, name, type_name, None, zone, source_ip, severity)
}

/// Extract fields for zone configuration events (513-514, 522-537).
fn extract_zone_config(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let zone = get_str(data, "Zone");
    let setting = get_str(data, "Setting");
    let new_value = get_str(data, "NewValue");

    let severity = event_severity(event_id);
    let ename = event_name(event_id);

    let mut msg = format!("[{} {}]", event_id, ename);
    if let Some(ref z) = zone {
        msg.push_str(&format!(" {}", z));
    }
    if setting.is_some() || new_value.is_some() {
        msg.push_str(" \u{2014}");
    }
    if let Some(ref s) = setting {
        msg.push_str(&format!(" Setting={}", s));
    }
    if let Some(ref v) = new_value {
        msg.push_str(&format!(" NewValue={}", v));
    }

    (msg, None, None, None, zone, None, severity)
}

/// Extract fields for server configuration events (540-560).
fn extract_server_config(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let setting = get_str(data, "Setting");
    let value = get_str(data, "Value");
    let scope = get_str(data, "Scope");

    let severity = event_severity(event_id);
    let ename = event_name(event_id);

    let mut msg = format!("[{} {}]", event_id, ename);
    if let Some(ref s) = setting {
        msg.push_str(&format!(" {}", s));
    }
    if let Some(ref v) = value {
        msg.push_str(&format!(" = {}", v));
    }
    if let Some(ref sc) = scope {
        msg.push_str(&format!(" (scope={})", sc));
    }

    (msg, None, None, None, None, None, severity)
}

/// Extract fields for DNSSEC key operation events (569-572).
fn extract_dnssec_key_ops(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let zone = get_str(data, "Zone");
    let algo = get_str(data, "CryptoAlgorithm");

    let severity = event_severity(event_id);

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref z) = zone {
        msg.push_str(&format!(" Zone={}", z));
    }
    if let Some(ref a) = algo {
        msg.push_str(&format!(" Algorithm={}", a));
    }

    (msg, None, None, None, zone, None, severity)
}

/// Extract fields for policy operation events (577-582).
fn extract_policy_ops(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let policy = get_str(data, "PolicyName");
    let action = get_str(data, "Action");

    let severity = event_severity(event_id);

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref p) = policy {
        msg.push_str(&format!(" Policy={}", p));
    }
    if let Some(ref a) = action {
        msg.push_str(&format!(" Action={}", a));
    }

    (msg, None, None, None, None, None, severity)
}

/// Extract fields for delegation/subnet events (573-576).
fn extract_delegation_subnet(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let zone = get_str(data, "Zone");
    let severity = event_severity(event_id);

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref z) = zone {
        msg.push_str(&format!(" Zone={}", z));
    }

    (msg, None, None, None, zone, None, severity)
}

/// Extract fields for extended zone operation events (561-568).
fn extract_extended_zone_ops(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let zone = get_str(data, "Zone");
    let severity = event_severity(event_id);

    let mut msg = format!("[{} DNS Audit]", event_id);
    if let Some(ref z) = zone {
        msg.push_str(&format!(" Zone={}", z));
    }

    (msg, None, None, None, zone, None, severity)
}

/// Generic fallback extractor for unknown event IDs.
/// Grabs the first 5 string fields from EventData.
fn extract_generic(
    event_id: u32,
    data: &Value,
) -> EventFields {
    let severity = event_severity(event_id);

    let mut msg = format!("[{} DNS Audit]", event_id);

    if let Some(obj) = data.as_object() {
        let mut count = 0;
        for (key, val) in obj {
            if count >= 5 {
                break;
            }
            if let Some(s) = val.as_str() {
                msg.push_str(&format!(" {}={}", key, s));
                count += 1;
            }
        }
    }

    (msg, None, None, None, None, None, severity)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
            ("RDATA", "192.168.1.10"),
        ]);
        let (msg, qn, qt, _rc, zone, _ip, severity) = extract_event_fields(515, &data);

        assert!(msg.contains("[515 Record Create]"), "msg = {}", msg);
        assert_eq!(qn, Some("test.homelab.local".to_string()));
        assert_eq!(qt, Some("A".to_string()));
        assert_eq!(zone, Some("homelab.local".to_string()));
        assert_eq!(severity, Severity::Info);
    }

    #[test]
    fn test_extract_record_delete_is_warning() {
        let data = make_event_data(&[("NAME", "old.example.com"), ("Type", "1")]);
        let (_msg, _qn, _qt, _rc, _zone, _ip, severity) = extract_event_fields(516, &data);

        assert_eq!(severity, Severity::Warning);
    }

    #[test]
    fn test_extract_dynamic_update_with_source_ip() {
        let data = make_event_data(&[
            ("NAME", "client.lab.local"),
            ("Type", "1"),
            ("SourceIP", "10.0.2.15"),
            ("Zone", "lab.local"),
        ]);
        let (_msg, _qn, _qt, _rc, _zone, ip, _severity) = extract_event_fields(519, &data);

        assert_eq!(ip, Some("10.0.2.15".to_string()));
    }

    #[test]
    fn test_extract_zone_delete_is_error() {
        let data = make_event_data(&[("Zone", "old-zone.local")]);
        let (_msg, _qn, _qt, _rc, _zone, _ip, severity) = extract_event_fields(513, &data);

        assert_eq!(severity, Severity::Error);
    }

    #[test]
    fn test_extract_server_setting_is_warning() {
        let data = make_event_data(&[("Setting", "serverlevelplugindll"), ("Value", "test.dll")]);
        let (msg, _qn, _qt, _rc, _zone, _ip, severity) = extract_event_fields(541, &data);

        assert_eq!(severity, Severity::Warning);
        assert!(msg.contains("serverlevelplugindll"), "msg = {}", msg);
    }

    #[test]
    fn test_extract_generic_unknown_event() {
        let data = make_event_data(&[("Foo", "bar"), ("Baz", "qux")]);
        let (msg, _qn, _qt, _rc, _zone, _ip, severity) = extract_event_fields(999, &data);

        assert!(msg.contains("[999 DNS Audit]"), "msg = {}", msg);
        assert_eq!(severity, Severity::Info);
    }

    #[test]
    fn test_extract_missing_fields_graceful() {
        let data = Value::Object(serde_json::Map::new());
        let (msg, qn, qt, rc, zone, ip, severity) = extract_event_fields(515, &data);

        // Should not panic, and all optional fields should be None
        assert!(msg.contains("[515 Record Create]"), "msg = {}", msg);
        assert_eq!(qn, None);
        assert_eq!(qt, None);
        assert_eq!(rc, None);
        assert_eq!(zone, None);
        assert_eq!(ip, None);
        assert_eq!(severity, Severity::Info);
    }

    #[test]
    fn test_parse_evtx_timestamp_rfc3339() {
        let (millis, display) = parse_evtx_timestamp("2026-04-11T15:29:17.123Z");

        assert!(millis.is_some());
        let d = display.unwrap();
        assert!(d.starts_with("2026-04-11 15:29:17"), "display = {}", d);
    }

    #[test]
    fn test_parse_evtx_timestamp_empty() {
        let (millis, display) = parse_evtx_timestamp("");

        assert_eq!(millis, None);
        assert_eq!(display, None);
    }
}
