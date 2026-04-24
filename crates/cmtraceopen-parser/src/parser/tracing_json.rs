//! Parser for `tracing_subscriber::fmt::layer().json()` output.
//!
//! CMTraceOpen Agent ships structured logs inside every evidence bundle under
//! `agent/agent-<DATE>.log` since v0.1.4. Each line is a JSON object emitted
//! by tracing-subscriber's default JSON layer, e.g.:
//!
//! ```text
//! {"timestamp":"2026-04-23T19:47:55.076231Z","level":"INFO","fields":{"message":"service_main starting"},"target":"cmtraceopen_agent::service"}
//! ```
//!
//! Without a dedicated parser these lines fell through to `Plain`, which left
//! `ts_ms`, `component`, and the structured fields all empty and dumped the
//! raw JSON blob into the `message` column. This parser maps the common keys
//! into `LogEntry` so the viewer renders timestamp / severity / component /
//! message columns as operators expect.
//!
//! Extraction rules:
//! - `timestamp` (RFC3339 UTC) → `LogEntry::timestamp` (epoch ms, truncated
//!   from sub-second precision) and `LogEntry::timestamp_display`.
//! - `level` → `Severity` via case-insensitive mapping; "WARN" → Warning,
//!   "ERROR" → Error, everything else (including "TRACE"/"DEBUG"/"INFO") →
//!   Info. Unknown severities fall back to Info.
//! - `target` → `component` — the tracing target, typically a Rust module
//!   path (`cmtraceopen_agent::service`).
//! - `fields.message` → primary message text. Any remaining `fields.*` keys
//!   are rendered as trailing ` key=value` pairs so operators see the full
//!   structured payload inline. When `fields.message` is absent we
//!   JSON-encode the whole fields object.
//! - `thread` (rare; only emitted by some tracing-subscriber configs) →
//!   `thread_display`. Numeric threads also populate `thread`.
//!
//! TODO: surface `spans` (the tracing span stack) — deferred for v1 because
//! most entries don't have spans and the message tail already gives operators
//! enough context.
//!
//! Lines that fail JSON parsing bump `parse_errors` and are stashed as
//! fallback entries with the raw line as the message (mirrors the tolerant
//! pattern in `parser::timestamped`).

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// High-confidence structural sniff used by the classifier.
///
/// Cheap substring checks only — full JSON parsing happens in the line
/// parser. The three markers together (`{` prefix, `"timestamp":"`,
/// `"level":"`) are the tracing-subscriber default-JSON fingerprint and
/// don't collide with any other log format we currently classify.
pub fn matches_tracing_json_record(line: &str) -> bool {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('{') {
        return false;
    }
    trimmed.contains("\"timestamp\":\"") && trimmed.contains("\"level\":\"")
}

/// Map a tracing `level` string to our internal severity bucket.
fn severity_from_level(level: &str) -> Severity {
    match level.to_ascii_uppercase().as_str() {
        "WARN" | "WARNING" => Severity::Warning,
        "ERROR" | "CRITICAL" | "FATAL" => Severity::Error,
        // "TRACE" | "DEBUG" | "INFO" and anything else fall back to Info.
        _ => Severity::Info,
    }
}

/// Parse an RFC3339 timestamp (e.g. `2026-04-23T19:47:55.076231Z`) into
/// (epoch_ms, display string, tz_offset_minutes).
fn parse_rfc3339(ts: &str) -> (Option<i64>, Option<String>, Option<i32>) {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => {
            let epoch_ms = dt.timestamp_millis();
            let utc = dt.naive_utc();
            let display = Some(format!("{}", utc.format("%Y-%m-%d %H:%M:%S%.3f")));
            let tz = Some(dt.offset().local_minus_utc() / 60);
            (Some(epoch_ms), display, tz)
        }
        Err(_) => (None, Some(ts.to_string()), None),
    }
}

/// Render a remaining `fields.*` value as the RHS of a `key=value` tail.
fn render_field_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        // Arrays/objects → compact JSON, so operators still see the payload
        // without line-breaking the renderer.
        other => serde_json::to_string(other).unwrap_or_else(|_| "<unprintable>".to_string()),
    }
}

/// Build the full message string: `fields.message` followed by any
/// remaining `fields.*` key/value pairs. If `fields.message` is absent
/// we fall back to JSON-encoding the whole fields object so operators
/// still see the structured payload.
fn build_message(fields: &serde_json::Map<String, serde_json::Value>) -> String {
    let primary = fields
        .get("message")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // Stable order: render remaining keys alphabetically so the tail is
    // deterministic across runs and diffs.
    let mut extras: Vec<(&String, &serde_json::Value)> = fields
        .iter()
        .filter(|(k, _)| k.as_str() != "message")
        .collect();
    extras.sort_by(|a, b| a.0.cmp(b.0));

    match primary {
        Some(msg) if !extras.is_empty() => {
            let tail: Vec<String> = extras
                .iter()
                .map(|(k, v)| format!("{}={}", k, render_field_value(v)))
                .collect();
            format!("{} {}", msg, tail.join(" "))
        }
        Some(msg) => msg,
        None if !extras.is_empty() => {
            let tail: Vec<String> = extras
                .iter()
                .map(|(k, v)| format!("{}={}", k, render_field_value(v)))
                .collect();
            tail.join(" ")
        }
        None => serde_json::to_string(fields).unwrap_or_default(),
    }
}

/// Construct a placeholder entry for a line that failed JSON parsing.
fn fallback_entry(id: u64, line_number: u32, line: &str, file_path: &str) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message: line.to_string(),
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity: detect_severity_from_text(line),
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
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
        query_name: None,
        query_type: None,
        response_code: None,
        dns_direction: None,
        dns_protocol: None,
        source_ip: None,
        dns_flags: None,
        dns_event_id: None,
        zone_name: None,
        entry_kind: None,
        whatif: None,
        section_name: None,
        section_color: None,
        iteration: None,
        tags: None,
    }
}

/// Parse a single tracing-JSON line into a `LogEntry`.
/// Returns `None` if the line is not valid JSON or not an object.
fn parse_line(id: u64, line_number: u32, line: &str, file_path: &str) -> Option<LogEntry> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = value.as_object()?;

    // Timestamp — permissive-extract. Tracing's default uses `timestamp`;
    // some configurations emit `timestamp_rfc3339`. Prefer `timestamp` but
    // fall back if missing.
    let ts_str = obj
        .get("timestamp")
        .or_else(|| obj.get("timestamp_rfc3339"))
        .and_then(|v| v.as_str());
    let (timestamp, timestamp_display, timezone_offset) = match ts_str {
        Some(s) => parse_rfc3339(s),
        None => (None, None, None),
    };

    // Level → severity.
    let severity = obj
        .get("level")
        .and_then(|v| v.as_str())
        .map(severity_from_level)
        .unwrap_or(Severity::Info);

    // Target → component.
    let component = obj
        .get("target")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // Fields → message (+ trailing key=value pairs).
    let message = match obj.get("fields").and_then(|v| v.as_object()) {
        Some(fields) => build_message(fields),
        // If `fields` is missing, render the top-level object minus the
        // structural keys we've already consumed. Rare in practice.
        None => {
            let mut rest = obj.clone();
            rest.remove("timestamp");
            rest.remove("timestamp_rfc3339");
            rest.remove("level");
            rest.remove("target");
            rest.remove("spans");
            rest.remove("thread");
            rest.remove("thread_id");
            rest.remove("thread_name");
            serde_json::to_string(&rest).unwrap_or_default()
        }
    };

    // Optional thread info — tracing-subscriber only emits this when
    // `.with_thread_ids()` / `.with_thread_names()` is configured.
    let (thread, thread_display) = extract_thread(obj);

    // TODO: surface `spans` — captured tracing span stack. Skipped for v1
    // because most entries don't have spans and the message tail gives
    // operators enough context.

    Some(LogEntry {
        id,
        line_number,
        message,
        component,
        timestamp,
        timestamp_display,
        severity,
        thread,
        thread_display,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: file_path.to_string(),
        timezone_offset,
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
        query_name: None,
        query_type: None,
        response_code: None,
        dns_direction: None,
        dns_protocol: None,
        source_ip: None,
        dns_flags: None,
        dns_event_id: None,
        zone_name: None,
        entry_kind: None,
        whatif: None,
        section_name: None,
        section_color: None,
        iteration: None,
        tags: None,
    })
}

/// Best-effort thread extraction — tracing-subscriber variants exist.
fn extract_thread(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> (Option<u32>, Option<String>) {
    // Direct numeric thread id.
    if let Some(id) = obj.get("thread_id").and_then(|v| v.as_u64()) {
        let name = obj
            .get("thread_name")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let display = match name {
            Some(n) => Some(format!("{} ({})", id, n)),
            None => Some(id.to_string()),
        };
        return (Some(id as u32), display);
    }
    // String `thread` field.
    if let Some(s) = obj.get("thread").and_then(|v| v.as_str()) {
        // Try to pull a numeric id out of the front for the `thread` slot.
        let parsed = s
            .split(|c: char| !c.is_ascii_digit())
            .find(|tok| !tok.is_empty())
            .and_then(|tok| tok.parse::<u32>().ok());
        return (parsed, Some(s.to_string()));
    }
    (None, None)
}

/// Parse all lines of an agent tracing-JSON log.
///
/// Mirrors the shape of `parser::iis_w3c::parse_lines`: returns the parsed
/// entries along with a count of lines that failed JSON parsing.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors = 0u32;
    let mut id = 0u64;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let line_number = (i + 1) as u32;
        match parse_line(id, line_number, trimmed, file_path) {
            Some(entry) => entries.push(entry),
            None => {
                entries.push(fallback_entry(id, line_number, trimmed, file_path));
                parse_errors += 1;
            }
        }
        id += 1;
    }

    (entries, parse_errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample lines from the task description (real canary bundle shape).
    const SAMPLE_INFO: &str = r#"{"timestamp":"2026-04-23T19:47:55.076231Z","level":"INFO","fields":{"message":"service_main starting"},"target":"cmtraceopen_agent::service"}"#;
    const SAMPLE_WARN: &str = r#"{"timestamp":"2026-04-23T19:47:55.178414Z","level":"WARN","fields":{"message":"unexpected config shape; using defaults","detail":"missing field `api_endpoint`"},"target":"cmtraceopen_agent::config"}"#;
    const SAMPLE_INFO_WITH_SPANS: &str = r#"{"timestamp":"2026-04-23T19:47:55.948850Z","level":"INFO","fields":{"message":"bundle finalized","size_bytes":5300954,"upload_id":"019dbcbe..."},"target":"cmtraceopen_agent::routes::ingest","spans":[{"bundle_id":"abc","name":"init"}]}"#;

    // ----- matches_tracing_json_record -----------------------------------

    #[test]
    fn test_matches_positive_cases() {
        assert!(matches_tracing_json_record(SAMPLE_INFO));
        assert!(matches_tracing_json_record(SAMPLE_WARN));
        assert!(matches_tracing_json_record(SAMPLE_INFO_WITH_SPANS));
    }

    #[test]
    fn test_matches_negative_plain_text() {
        assert!(!matches_tracing_json_record("plain text line"));
    }

    #[test]
    fn test_matches_negative_ordinary_timestamped() {
        assert!(!matches_tracing_json_record(
            "2026-04-23 10:15:30 INFO something"
        ));
    }

    #[test]
    fn test_matches_negative_unrelated_json() {
        assert!(!matches_tracing_json_record(r#"{"not":"ours"}"#));
    }

    #[test]
    fn test_matches_negative_partial_fingerprint() {
        // Has `timestamp` but missing `level`.
        assert!(!matches_tracing_json_record(
            r#"{"timestamp":"2026-04-23T19:47:55Z","msg":"x"}"#
        ));
        // Has `level` but missing `timestamp`.
        assert!(!matches_tracing_json_record(
            r#"{"level":"INFO","msg":"x"}"#
        ));
    }

    // ----- parse_lines --------------------------------------------------

    #[test]
    fn test_parse_three_line_sample_emits_three_entries_with_correct_fields() {
        let lines = [SAMPLE_INFO, SAMPLE_WARN, SAMPLE_INFO_WITH_SPANS];
        let (entries, parse_errors) = parse_lines(&lines, "agent/agent-2026-04-23.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 3);

        // Line 1: INFO
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(
            entries[0].component.as_deref(),
            Some("cmtraceopen_agent::service")
        );
        assert!(entries[0].message.starts_with("service_main starting"));
        assert!(entries[0].timestamp.is_some());
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2026-04-23 19:47:55.076")
        );

        // Line 2: WARN with a detail field → rendered in tail
        assert_eq!(entries[1].severity, Severity::Warning);
        assert_eq!(
            entries[1].component.as_deref(),
            Some("cmtraceopen_agent::config")
        );
        assert!(entries[1]
            .message
            .starts_with("unexpected config shape; using defaults"));

        // Line 3: INFO — second INFO must stay Info
        assert_eq!(entries[2].severity, Severity::Info);
        assert_eq!(
            entries[2].component.as_deref(),
            Some("cmtraceopen_agent::routes::ingest")
        );
        assert!(entries[2].message.starts_with("bundle finalized"));

        // Sanity: timestamps are monotonic and epoch-ms.
        assert!(entries[0].timestamp.unwrap() < entries[2].timestamp.unwrap());
    }

    #[test]
    fn test_malformed_json_produces_fallback_entry() {
        let lines = ["not json at all, definitely broken"];
        let (entries, parse_errors) = parse_lines(&lines, "agent/agent-2026-04-23.log");

        assert_eq!(parse_errors, 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "not json at all, definitely broken");
        assert!(entries[0].timestamp.is_none());
        assert!(entries[0].component.is_none());
        assert!(entries[0].timestamp_display.is_none());
    }

    #[test]
    fn test_fields_detail_appears_as_key_value_tail() {
        let lines = [SAMPLE_WARN];
        let (entries, parse_errors) = parse_lines(&lines, "agent/agent-2026-04-23.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        let msg = &entries[0].message;

        // `message` first, `detail=...` in the tail.
        assert!(
            msg.starts_with("unexpected config shape; using defaults"),
            "message should lead with fields.message, got: {msg}"
        );
        assert!(
            msg.contains("detail="),
            "tail should render detail as key=value, got: {msg}"
        );
        assert!(
            msg.contains("missing field `api_endpoint`"),
            "tail value content must be preserved, got: {msg}"
        );
    }

    #[test]
    fn test_numeric_and_string_fields_render_in_tail() {
        let lines = [SAMPLE_INFO_WITH_SPANS];
        let (entries, _) = parse_lines(&lines, "agent/agent-2026-04-23.log");
        let msg = &entries[0].message;

        assert!(msg.contains("size_bytes=5300954"), "got: {msg}");
        assert!(msg.contains("upload_id=019dbcbe..."), "got: {msg}");
    }

    #[test]
    fn test_line_without_fields_message_falls_back_to_field_tail() {
        let line = r#"{"timestamp":"2026-04-23T19:47:55.000Z","level":"INFO","fields":{"op":"tick","value":42},"target":"cmtraceopen_agent::heartbeat"}"#;
        let (entries, parse_errors) = parse_lines(&[line], "agent/agent-2026-04-23.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        let msg = &entries[0].message;
        assert!(msg.contains("op=tick"), "got: {msg}");
        assert!(msg.contains("value=42"), "got: {msg}");
    }

    #[test]
    fn test_unknown_level_defaults_to_info() {
        let line = r#"{"timestamp":"2026-04-23T19:47:55.000Z","level":"VERBOSE","fields":{"message":"hi"},"target":"x"}"#;
        let (entries, _) = parse_lines(&[line], "agent/agent-2026-04-23.log");
        assert_eq!(entries[0].severity, Severity::Info);
    }

    #[test]
    fn test_trace_and_debug_map_to_info() {
        assert_eq!(severity_from_level("TRACE"), Severity::Info);
        assert_eq!(severity_from_level("DEBUG"), Severity::Info);
        assert_eq!(severity_from_level("INFO"), Severity::Info);
        assert_eq!(severity_from_level("WARN"), Severity::Warning);
        assert_eq!(severity_from_level("ERROR"), Severity::Error);
    }
}
