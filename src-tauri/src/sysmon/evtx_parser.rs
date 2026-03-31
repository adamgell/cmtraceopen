use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use evtx::EvtxParser;
use serde_json::Value;

use super::models::{
    SysmonConfig, SysmonEvent, SysmonEventType, SysmonEventTypeCount, SysmonSeverity,
    SysmonSummary,
};

/// Maximum entries to parse from a single EVTX file.
const MAX_ENTRIES_PER_FILE: usize = 100_000;

/// The Sysmon ETW provider name.
const SYSMON_PROVIDER: &str = "Microsoft-Windows-Sysmon";

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Discovers Sysmon .evtx files in a directory (recursive one level).
pub fn discover_sysmon_evtx_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    // Direct .evtx files in root
    collect_evtx_files(root, &mut files);

    // Check common subdirectories
    for subdir in &["evidence", "event-logs", "evidence/event-logs"] {
        let dir = root.join(subdir);
        if dir.is_dir() {
            collect_evtx_files(&dir, &mut files);
        }
    }

    // Deduplicate by canonical path
    files.sort();
    files.dedup();
    files
}

fn collect_evtx_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext.eq_ignore_ascii_case("evtx") {
                    out.push(path);
                }
            }
        }
    }
}

/// Returns true if the EVTX file contains Sysmon events (checks first few records).
pub fn is_sysmon_evtx(path: &Path) -> bool {
    let mut parser = match EvtxParser::from_path(path) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Sample first 5 records to check provider
    for record_result in parser.records_json().take(5) {
        if let Ok(record) = record_result {
            if let Ok(json) = serde_json::from_str::<Value>(&record.data) {
                let provider = json["Event"]["System"]["Provider"]["#attributes"]["Name"]
                    .as_str()
                    .unwrap_or("");
                if provider == SYSMON_PROVIDER {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Single-file parser
// ---------------------------------------------------------------------------

/// Parses a single Sysmon EVTX file into `SysmonEvent` records.
pub fn parse_sysmon_evtx(path: &Path, id_offset: u64) -> Result<Vec<SysmonEvent>, String> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path.display(), e))?;

    let source_file = path.to_string_lossy().to_string();
    let mut events = Vec::new();
    let mut current_id = id_offset;

    for record_result in parser.records_json() {
        if events.len() >= MAX_ENTRIES_PER_FILE {
            log::warn!(
                "event=sysmon_entry_cap file=\"{}\" cap={}",
                source_file,
                MAX_ENTRIES_PER_FILE
            );
            break;
        }

        let record = match record_result {
            Ok(r) => r,
            Err(e) => {
                log::warn!(
                    "event=sysmon_record_skip file=\"{}\" error=\"{}\"",
                    source_file,
                    e
                );
                continue;
            }
        };

        let json: Value = match serde_json::from_str(&record.data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let system = &json["Event"]["System"];

        // Only process Sysmon events
        let provider = system["Provider"]["#attributes"]["Name"]
            .as_str()
            .unwrap_or("");
        if provider != SYSMON_PROVIDER {
            continue;
        }

        let event_id = extract_event_id(system);
        let event_type = SysmonEventType::from_event_id(event_id);

        let timestamp = system["TimeCreated"]["#attributes"]["SystemTime"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let timestamp_ms = parse_timestamp_ms(&timestamp);

        let computer = system["Computer"].as_str().map(|s| s.to_string());

        let record_id = record.event_record_id;

        let event_data = &json["Event"]["EventData"];

        let severity = derive_severity(event_id);

        // Extract common and event-specific fields from EventData
        let rule_name = get_data_str(event_data, "RuleName");
        let utc_time = get_data_str(event_data, "UtcTime");
        let process_guid = get_data_str(event_data, "ProcessGuid");
        let process_id = get_data_u32(event_data, "ProcessId");
        let image = get_data_str(event_data, "Image");
        let command_line = get_data_str(event_data, "CommandLine");
        let user = get_data_str(event_data, "User");
        let hashes = get_data_str(event_data, "Hashes");
        let parent_image = get_data_str(event_data, "ParentImage");
        let parent_command_line = get_data_str(event_data, "ParentCommandLine");
        let parent_process_id = get_data_u32(event_data, "ParentProcessId");
        let target_filename = get_data_str(event_data, "TargetFilename");
        let protocol = get_data_str(event_data, "Protocol");
        let source_ip = get_data_str(event_data, "SourceIp");
        let source_port = get_data_u16(event_data, "SourcePort");
        let destination_ip = get_data_str(event_data, "DestinationIp");
        let destination_port = get_data_u16(event_data, "DestinationPort");
        let destination_hostname = get_data_str(event_data, "DestinationHostname");
        let target_object = get_data_str(event_data, "TargetObject");
        let details = get_data_str(event_data, "Details");
        let query_name = get_data_str(event_data, "QueryName");
        let query_results = get_data_str(event_data, "QueryResults");
        let source_image = get_data_str(event_data, "SourceImage");
        let target_image = get_data_str(event_data, "TargetImage");
        let granted_access = get_data_str(event_data, "GrantedAccess");

        let message = build_message(event_id, &event_type, event_data);

        events.push(SysmonEvent {
            id: current_id,
            event_id,
            event_type,
            event_type_display: event_type.display_name().to_string(),
            severity,
            timestamp,
            timestamp_ms,
            computer,
            record_id,
            rule_name,
            utc_time,
            process_guid,
            process_id,
            image,
            command_line,
            user,
            hashes,
            parent_image,
            parent_command_line,
            parent_process_id,
            target_filename,
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            destination_hostname,
            target_object,
            details,
            query_name,
            query_results,
            source_image,
            target_image,
            granted_access,
            message,
            source_file: source_file.clone(),
        });

        current_id += 1;
    }

    Ok(events)
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

/// Builds a summary from a slice of parsed Sysmon events.
pub fn build_summary(
    events: &[SysmonEvent],
    source_files: Vec<String>,
    parse_errors: u64,
) -> SysmonSummary {
    let mut type_counts: HashMap<u32, u64> = HashMap::new();
    let mut unique_processes: HashSet<String> = HashSet::new();
    let mut unique_computers: HashSet<String> = HashSet::new();
    let mut earliest: Option<&str> = None;
    let mut latest: Option<&str> = None;

    for event in events {
        *type_counts.entry(event.event_id).or_insert(0) += 1;

        if let Some(ref guid) = event.process_guid {
            if guid != "-" {
                unique_processes.insert(guid.clone());
            }
        }

        if let Some(ref computer) = event.computer {
            unique_computers.insert(computer.clone());
        }

        if !event.timestamp.is_empty() {
            let ts = event.timestamp.as_str();
            if earliest.is_none() || ts < earliest.unwrap() {
                earliest = Some(ts);
            }
            if latest.is_none() || ts > latest.unwrap() {
                latest = Some(ts);
            }
        }
    }

    let mut event_type_counts: Vec<SysmonEventTypeCount> = type_counts
        .into_iter()
        .map(|(eid, count)| {
            let et = SysmonEventType::from_event_id(eid);
            SysmonEventTypeCount {
                event_id: eid,
                event_type: et,
                display_name: et.display_name().to_string(),
                count,
            }
        })
        .collect();
    event_type_counts.sort_by(|a, b| b.count.cmp(&a.count));

    SysmonSummary {
        total_events: events.len() as u64,
        event_type_counts,
        unique_processes: unique_processes.len() as u64,
        unique_computers: unique_computers.len() as u64,
        earliest_timestamp: earliest.map(|s| s.to_string()),
        latest_timestamp: latest.map(|s| s.to_string()),
        source_files,
        parse_errors,
    }
}

// ---------------------------------------------------------------------------
// Configuration extraction
// ---------------------------------------------------------------------------

/// Extracts Sysmon configuration metadata from parsed events.
pub fn extract_config(events: &[SysmonEvent], summary: &SysmonSummary) -> SysmonConfig {
    let mut schema_version: Option<String> = None;
    let mut hash_algorithms: Option<String> = None;
    let mut last_config_change: Option<String> = None;
    let mut configuration_xml: Option<String> = None;
    let mut sysmon_version: Option<String> = None;

    // Look for ConfigChange events (ID 16) — they contain the config hash and sometimes XML
    // Look for ServiceStateChange events (ID 4) — they contain version info
    for event in events {
        match event.event_id {
            16 => {
                // ConfigChange: contains Configuration, ConfigurationFileHash
                if last_config_change.is_none()
                    || event.timestamp.as_str() > last_config_change.as_deref().unwrap_or("")
                {
                    last_config_change = Some(event.timestamp.clone());
                }
                // The message may contain config details
                if configuration_xml.is_none() && !event.message.is_empty() {
                    configuration_xml = Some(event.message.clone());
                }
            }
            4 => {
                // ServiceStateChange: may contain version
                if sysmon_version.is_none() {
                    if let Some(ref msg) = event.details {
                        if msg.contains("version") || msg.contains("Version") {
                            sysmon_version = Some(msg.clone());
                        }
                    }
                    // Also check the message field
                    if sysmon_version.is_none() && event.message.contains("version") {
                        sysmon_version = Some(event.message.clone());
                    }
                }
            }
            _ => {}
        }
    }

    // Infer hash algorithms from the first event with Hashes field
    for event in events {
        if let Some(ref h) = event.hashes {
            // Hashes format: "SHA256=abc,MD5=def" or "SHA1=abc"
            let algos: Vec<&str> = h
                .split(',')
                .filter_map(|part| part.split('=').next())
                .collect();
            if !algos.is_empty() {
                hash_algorithms = Some(algos.join(","));
                break;
            }
        }
    }

    // Infer schema version from RuleName if it contains schema info (rare)
    // This is typically only available from the config itself
    for event in events.iter().take(100) {
        if let Some(ref rule) = event.rule_name {
            if rule.contains("schema") {
                schema_version = Some(rule.clone());
                break;
            }
        }
    }

    SysmonConfig {
        schema_version,
        hash_algorithms,
        found: !events.is_empty(),
        last_config_change,
        configuration_xml,
        sysmon_version,
        active_event_types: summary.event_type_counts.clone(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract EventID which can appear as `{"#text": N}` or just `N`.
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

/// Parse ISO 8601 timestamp to unix millis.
fn parse_timestamp_ms(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .or_else(|| {
            // Handle timestamps like "2024-04-28T22:08:22.025812200Z" that may have
            // extra precision beyond what RFC 3339 strictly allows
            chrono::NaiveDateTime::parse_from_str(
                ts.trim_end_matches('Z'),
                "%Y-%m-%dT%H:%M:%S%.f",
            )
            .ok()
            .map(|ndt| {
                ndt.and_utc().fixed_offset()
            })
        })
        .map(|dt| dt.timestamp_millis())
}

fn get_data_str(event_data: &Value, key: &str) -> Option<String> {
    match &event_data[key] {
        Value::String(s) if !s.is_empty() && s != "-" => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn get_data_u32(event_data: &Value, key: &str) -> Option<u32> {
    event_data[key]
        .as_u64()
        .map(|n| n as u32)
        .or_else(|| {
            event_data[key]
                .as_str()
                .and_then(|s| s.parse().ok())
        })
}

fn get_data_u16(event_data: &Value, key: &str) -> Option<u16> {
    event_data[key]
        .as_u64()
        .map(|n| n as u16)
        .or_else(|| {
            event_data[key]
                .as_str()
                .and_then(|s| s.parse().ok())
        })
}

/// Derive severity from event ID.
fn derive_severity(event_id: u32) -> SysmonSeverity {
    match event_id {
        255 => SysmonSeverity::Error,
        8 | 10 | 23 | 25 | 26 | 27 | 28 => SysmonSeverity::Warning,
        _ => SysmonSeverity::Info,
    }
}

/// Build a human-readable message from the event's key fields.
fn build_message(event_id: u32, event_type: &SysmonEventType, event_data: &Value) -> String {
    let type_label = event_type.display_name();

    match event_id {
        1 => {
            // ProcessCreate
            let image = event_data["Image"].as_str().unwrap_or("?");
            let cmd = event_data["CommandLine"].as_str().unwrap_or("");
            let user = event_data["User"].as_str().unwrap_or("");
            if cmd.is_empty() {
                format!("{image} (User: {user})")
            } else {
                format!("{image} | {cmd} (User: {user})")
            }
        }
        3 => {
            // NetworkConnect
            let image = event_data["Image"].as_str().unwrap_or("?");
            let dst_ip = event_data["DestinationIp"].as_str().unwrap_or("?");
            let dst_port = event_data["DestinationPort"]
                .as_u64()
                .map(|p| p.to_string())
                .or_else(|| event_data["DestinationPort"].as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "?".to_string());
            let proto = event_data["Protocol"].as_str().unwrap_or("?");
            format!("{image} → {dst_ip}:{dst_port} ({proto})")
        }
        5 => {
            // ProcessTerminate
            let image = event_data["Image"].as_str().unwrap_or("?");
            format!("{image} terminated")
        }
        10 => {
            // ProcessAccess
            let src = event_data["SourceImage"].as_str().unwrap_or("?");
            let tgt = event_data["TargetImage"].as_str().unwrap_or("?");
            let access = event_data["GrantedAccess"].as_str().unwrap_or("?");
            format!("{src} → {tgt} (Access: {access})")
        }
        11 => {
            // FileCreate
            let image = event_data["Image"].as_str().unwrap_or("?");
            let target = event_data["TargetFilename"].as_str().unwrap_or("?");
            format!("{image} created {target}")
        }
        12 | 13 | 14 => {
            // Registry events
            let image = event_data["Image"].as_str().unwrap_or("?");
            let target = event_data["TargetObject"].as_str().unwrap_or("?");
            format!("{image} | {target}")
        }
        22 => {
            // DNSQuery
            let image = event_data["Image"].as_str().unwrap_or("?");
            let query = event_data["QueryName"].as_str().unwrap_or("?");
            let results = event_data["QueryResults"].as_str().unwrap_or("");
            if results.is_empty() {
                format!("{image} queried {query}")
            } else {
                format!("{image} queried {query} → {results}")
            }
        }
        23 | 26 => {
            // FileDelete / FileDeleteDetected
            let image = event_data["Image"].as_str().unwrap_or("?");
            let target = event_data["TargetFilename"].as_str().unwrap_or("?");
            format!("{image} deleted {target}")
        }
        _ => {
            // Generic: show Image if available, else first few data fields
            if let Some(image) = event_data["Image"].as_str() {
                format!("[{type_label}] {image}")
            } else {
                build_generic_message(type_label, event_data)
            }
        }
    }
}

/// Build a generic message from up to 3 key EventData fields.
fn build_generic_message(type_label: &str, event_data: &Value) -> String {
    if let Some(obj) = event_data.as_object() {
        let parts: Vec<String> = obj
            .iter()
            .filter(|(k, _)| *k != "#attributes")
            .take(3)
            .filter_map(|(k, v)| {
                let val = match v {
                    Value::String(s) if !s.is_empty() => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => return None,
                };
                Some(format!("{k}={val}"))
            })
            .collect();

        if parts.is_empty() {
            format!("[{type_label}]")
        } else {
            format!("[{type_label}] {}", parts.join(", "))
        }
    } else {
        format!("[{type_label}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_mapping() {
        assert_eq!(SysmonEventType::from_event_id(1), SysmonEventType::ProcessCreate);
        assert_eq!(SysmonEventType::from_event_id(3), SysmonEventType::NetworkConnect);
        assert_eq!(SysmonEventType::from_event_id(22), SysmonEventType::DnsQuery);
        assert_eq!(SysmonEventType::from_event_id(255), SysmonEventType::Error);
        assert_eq!(SysmonEventType::from_event_id(999), SysmonEventType::Unknown);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(derive_severity(1), SysmonSeverity::Info);
        assert_eq!(derive_severity(8), SysmonSeverity::Warning);
        assert_eq!(derive_severity(255), SysmonSeverity::Error);
    }

    #[test]
    fn test_parse_timestamp_ms() {
        // Standard RFC 3339
        let ts = "2024-04-28T22:08:22.025Z";
        assert!(parse_timestamp_ms(ts).is_some());

        // Extended precision (7+ fractional digits)
        let ts2 = "2024-04-28T22:08:22.025812200Z";
        assert!(parse_timestamp_ms(ts2).is_some());
    }

    #[test]
    fn test_get_data_str_skips_dash() {
        let data: Value = serde_json::json!({"RuleName": "-", "Image": "cmd.exe"});
        assert_eq!(get_data_str(&data, "RuleName"), None);
        assert_eq!(get_data_str(&data, "Image"), Some("cmd.exe".to_string()));
    }

    #[test]
    fn test_build_summary_empty() {
        let summary = build_summary(&[], vec![], 0);
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.unique_processes, 0);
        assert!(summary.earliest_timestamp.is_none());
    }

    #[test]
    fn test_extract_event_id_variants() {
        let direct: Value = serde_json::json!({"EventID": 1});
        assert_eq!(extract_event_id(&direct), 1);

        let nested: Value = serde_json::json!({"EventID": {"#text": 22}});
        assert_eq!(extract_event_id(&nested), 22);

        let string_nested: Value = serde_json::json!({"EventID": {"#text": "10"}});
        assert_eq!(extract_event_id(&string_nested), 10);
    }
}
