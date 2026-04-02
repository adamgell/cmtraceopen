use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use evtx::EvtxParser;
#[cfg(target_os = "windows")]
use regex::Regex;
use serde_json::Value;
#[cfg(target_os = "windows")]
use std::sync::OnceLock;

#[cfg(target_os = "windows")]
use crate::intune::eventlog_win32;
use super::models::{
    RankedItem, SecuritySummary, SysmonConfig, SysmonDashboardData, SysmonEvent, SysmonEventType,
    SysmonEventTypeCount, SysmonSeverity, SysmonSummary, TimeBucket,
};

/// Maximum entries to pull from the live Windows Event Log.
#[cfg(target_os = "windows")]
const MAX_LIVE_ENTRIES: usize = 10_000;

/// The Sysmon ETW provider name.
const SYSMON_PROVIDER: &str = "Microsoft-Windows-Sysmon";

/// The Sysmon Operational event log channel.
#[cfg(target_os = "windows")]
const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Discovers Sysmon .evtx files in a directory.
/// Checks the root and the following common subdirectories:
/// "evidence", "event-logs", "evidence/event-logs".
/// Deduplicates results by sorting and deduplicating raw PathBufs.
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
    for record in parser.records_json().take(5).flatten() {
        if let Ok(json) = serde_json::from_str::<Value>(&record.data) {
            let provider = json["Event"]["System"]["Provider"]["#attributes"]["Name"]
                .as_str()
                .unwrap_or("");
            if provider == SYSMON_PROVIDER {
                return true;
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
    let mut earliest_ms: Option<i64> = None;
    let mut latest_ms: Option<i64> = None;
    let mut earliest_ts: Option<String> = None;
    let mut latest_ts: Option<String> = None;

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
            if let Some(ms) = event.timestamp_ms {
                if earliest_ms.map_or(true, |existing| ms < existing) {
                    earliest_ms = Some(ms);
                    earliest_ts = Some(event.timestamp.clone());
                }
                if latest_ms.map_or(true, |existing| ms > existing) {
                    latest_ms = Some(ms);
                    latest_ts = Some(event.timestamp.clone());
                }
            } else {
                // Fallback: use string comparison when no numeric ms is available
                // for this event. String-only events can still update earliest/latest
                // even when other events had numeric timestamps.
                let ts = event.timestamp.as_str();
                if earliest_ts.as_deref().map_or(true, |existing| ts < existing) {
                    earliest_ts = Some(event.timestamp.clone());
                }
                if latest_ts.as_deref().map_or(true, |existing| ts > existing) {
                    latest_ts = Some(event.timestamp.clone());
                }
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
        earliest_timestamp: earliest_ts,
        latest_timestamp: latest_ts,
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
    let configuration_xml: Option<String> = None;
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
                // NOTE: Do not populate configuration_xml from event.message.
                // The Message field is a human-readable summary and does not reliably
                // contain the raw configuration XML. If configuration XML display is
                // needed, it should be extracted from the EventData "Configuration"
                // field during parsing and exposed via SysmonEvent.
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

    let found = last_config_change.is_some() || hash_algorithms.is_some() || sysmon_version.is_some();

    SysmonConfig {
        schema_version,
        hash_algorithms,
        found,
        last_config_change,
        configuration_xml,
        sysmon_version,
        active_event_types: summary.event_type_counts.clone(),
    }
}

// ---------------------------------------------------------------------------
// Dashboard aggregations
// ---------------------------------------------------------------------------

/// Builds pre-computed dashboard aggregations from parsed events.
pub fn build_dashboard_data(events: &[SysmonEvent]) -> SysmonDashboardData {
    use chrono::{DateTime, Utc};

    const TOP_N: usize = 20;

    let estimated_unique = (events.len() / 10).max(64);

    let mut minute_buckets: HashMap<i64, u64> = HashMap::with_capacity(estimated_unique);
    let mut hourly_buckets: HashMap<i64, u64> = HashMap::with_capacity(estimated_unique);
    let mut daily_buckets: HashMap<i64, u64> = HashMap::with_capacity(estimated_unique);

    let mut process_counts: HashMap<String, u64> = HashMap::with_capacity(estimated_unique);
    let mut dest_counts: HashMap<String, u64> = HashMap::with_capacity(estimated_unique);
    let mut port_counts: HashMap<String, u64> = HashMap::with_capacity(estimated_unique);
    let mut dns_counts: HashMap<String, u64> = HashMap::with_capacity(estimated_unique);
    let mut file_counts: HashMap<String, u64> = HashMap::with_capacity(estimated_unique);
    let mut registry_counts: HashMap<String, u64> = HashMap::with_capacity(estimated_unique);

    let mut total_warnings: u64 = 0;
    let mut total_errors: u64 = 0;
    let mut security_type_counts: HashMap<String, u64> = HashMap::with_capacity(estimated_unique);

    for event in events {
        if let Some(ms) = event.timestamp_ms {
            let minute_key = (ms / 60_000) * 60_000;
            let hourly_key = (ms / 3_600_000) * 3_600_000;
            let daily_key = (ms / 86_400_000) * 86_400_000;
            *minute_buckets.entry(minute_key).or_insert(0) += 1;
            *hourly_buckets.entry(hourly_key).or_insert(0) += 1;
            *daily_buckets.entry(daily_key).or_insert(0) += 1;
        }

        if let Some(ref image) = event.image {
            if !image.is_empty() {
                *process_counts.entry(image.clone()).or_insert(0) += 1;
            }
        }

        if event.event_id == 3 {
            let dest = event
                .destination_hostname
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(event.destination_ip.as_deref().filter(|s| !s.is_empty()));
            if let Some(d) = dest {
                *dest_counts.entry(d.to_string()).or_insert(0) += 1;
            }
            if let Some(port) = event.destination_port {
                *port_counts.entry(port.to_string()).or_insert(0) += 1;
            }
        }

        if event.event_id == 22 {
            if let Some(ref qname) = event.query_name {
                if !qname.is_empty() {
                    *dns_counts.entry(qname.clone()).or_insert(0) += 1;
                }
            }
        }

        if matches!(event.event_id, 2 | 11 | 15 | 23 | 24 | 26 | 27 | 28 | 29) {
            if let Some(ref tf) = event.target_filename {
                if !tf.is_empty() {
                    *file_counts.entry(tf.clone()).or_insert(0) += 1;
                }
            }
        }

        if let 12..=14 = event.event_id {
            if let Some(ref to) = event.target_object {
                if !to.is_empty() {
                    *registry_counts.entry(to.clone()).or_insert(0) += 1;
                }
            }
        }

        match event.severity {
            SysmonSeverity::Warning => {
                total_warnings += 1;
                *security_type_counts
                    .entry(event.event_type.display_name().to_string())
                    .or_insert(0) += 1;
            }
            SysmonSeverity::Error => {
                total_errors += 1;
                *security_type_counts
                    .entry(event.event_type.display_name().to_string())
                    .or_insert(0) += 1;
            }
            SysmonSeverity::Info => {}
        }
    }

    let buckets_to_vec = |map: HashMap<i64, u64>| -> Vec<TimeBucket> {
        let mut vec: Vec<TimeBucket> = map
            .into_iter()
            .map(|(ms, count)| {
                let ts = DateTime::<Utc>::from_timestamp_millis(ms)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default();
                TimeBucket {
                    timestamp: ts,
                    timestamp_ms: ms,
                    count,
                }
            })
            .collect();
        vec.sort_by_key(|b| b.timestamp_ms);
        vec
    };

    // Auto-aggregate timeline_minute based on time span to cap at ~1500 buckets.
    // Under 2h -> minute, 2-24h -> 5-min, 1-7d -> hourly, >7d -> daily.
    let auto_timeline = {
        let min_ms = minute_buckets.keys().copied().min();
        let max_ms = minute_buckets.keys().copied().max();
        match (min_ms, max_ms) {
            (Some(lo), Some(hi)) => {
                let span_ms = hi - lo;
                let two_hours = 2 * 3_600_000_i64;
                let twenty_four_hours = 24 * 3_600_000_i64;
                let seven_days = 7 * 86_400_000_i64;

                if span_ms < two_hours {
                    buckets_to_vec(minute_buckets)
                } else if span_ms < twenty_four_hours {
                    // Re-bucket into 5-minute intervals
                    let five_min_ms = 5 * 60_000_i64;
                    let mut rebucketed: HashMap<i64, u64> =
                        HashMap::with_capacity(minute_buckets.len() / 5 + 1);
                    for (ms, count) in minute_buckets {
                        let key = (ms / five_min_ms) * five_min_ms;
                        *rebucketed.entry(key).or_insert(0) += count;
                    }
                    buckets_to_vec(rebucketed)
                } else if span_ms < seven_days {
                    buckets_to_vec(hourly_buckets.clone())
                } else {
                    buckets_to_vec(daily_buckets.clone())
                }
            }
            _ => Vec::new(),
        }
    };

    let timeline_hourly_vec = buckets_to_vec(hourly_buckets);
    let timeline_daily_vec = buckets_to_vec(daily_buckets);

    let top_n = |map: HashMap<String, u64>| -> Vec<RankedItem> {
        let mut vec: Vec<RankedItem> = map
            .into_iter()
            .map(|(name, count)| RankedItem { name, count })
            .collect();
        vec.sort_by(|a, b| b.count.cmp(&a.count));
        vec.truncate(TOP_N);
        vec
    };

    let mut security_by_type: Vec<RankedItem> = security_type_counts
        .into_iter()
        .map(|(name, count)| RankedItem { name, count })
        .collect();
    security_by_type.sort_by(|a, b| b.count.cmp(&a.count));

    SysmonDashboardData {
        timeline_minute: auto_timeline,
        timeline_hourly: timeline_hourly_vec,
        timeline_daily: timeline_daily_vec,
        top_processes: top_n(process_counts),
        top_destinations: top_n(dest_counts),
        top_ports: top_n(port_counts),
        top_dns_queries: top_n(dns_counts),
        security_events: SecuritySummary {
            total_warnings,
            total_errors,
            events_by_type: security_by_type,
        },
        top_target_files: top_n(file_counts),
        top_registry_keys: top_n(registry_counts),
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
        12..=14 => {
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

// ---------------------------------------------------------------------------
// Live Windows Event Log support
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn live_provider_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"<Provider[^>]*Name=['\"]([^'\"]+)['\"]"#)
            .expect("provider regex must compile")
    })
}
#[cfg(target_os = "windows")]
fn live_event_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"<EventID(?:\s[^>]*)?>(\d+)</EventID>")
            .expect("event id regex must compile")
    })
}
#[cfg(target_os = "windows")]
fn live_time_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)['\"]"#)
            .expect("time regex must compile")
    })
}
#[cfg(target_os = "windows")]
fn live_computer_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"<Computer>(.*?)</Computer>").expect("computer regex must compile")
    })
}
#[cfg(target_os = "windows")]
fn live_record_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"<EventRecordID>(\d+)</EventRecordID>")
            .expect("record id regex must compile")
    })
}

#[cfg(target_os = "windows")]
fn extract_xml_value(text: &str, regex: &Regex) -> Option<String> {
    regex
        .captures(text)
        .and_then(|captures| captures.get(1).map(|value| value.as_str().to_string()))
}

/// Extract a named Data element value from Sysmon XML EventData.
/// Pattern: `<Data Name="FieldName">value</Data>`
#[cfg(target_os = "windows")]
fn extract_event_data_field(xml: &str, field_name: &str) -> Option<String> {
    // Build pattern: <Data Name="FieldName">...</Data>
    let pattern = format!(
        r#"<Data Name=['\"]{}['\"]>(.*?)</Data>"#,
        regex::escape(field_name)
    );
    let re = Regex::new(&pattern).ok()?;
    re.captures(xml)
        .and_then(|captures| captures.get(1))
        .map(|value| decode_xml_text(value.as_str()))
        .filter(|value| !value.is_empty() && value != "-")
}

#[cfg(target_os = "windows")]
fn decode_xml_text(value: &str) -> String {
    value
        .replace("&#13;", "\r")
        .replace("&#10;", "\n")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Query the live Windows Event Log for Sysmon events.
///
/// Returns parsed `SysmonEvent` records from the
/// `Microsoft-Windows-Sysmon/Operational` channel.
#[cfg(target_os = "windows")]
pub fn parse_sysmon_live_events() -> Result<Vec<SysmonEvent>, String> {
    let result = eventlog_win32::query_live_channel(SYSMON_CHANNEL, MAX_LIVE_ENTRIES)
        .map_err(|e| format!("Failed to query live Sysmon event log: {}", e))?;

    let source_file = result.source_file;
    let mut events = Vec::new();

    for record in result.records {
        let xml = &record.xml;

        // Verify this is a Sysmon event
        let provider = match extract_xml_value(xml, live_provider_re()) {
            Some(p) if p == SYSMON_PROVIDER => p,
            _ => continue,
        };
        let _ = provider;

        let event_id = extract_xml_value(xml, live_event_id_re())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let timestamp = match extract_xml_value(xml, live_time_re()) {
            Some(ts) => ts,
            None => continue,
        };
        let timestamp_ms = parse_timestamp_ms(&timestamp);

        let computer = extract_xml_value(xml, live_computer_re())
            .map(|v| decode_xml_text(&v));

        let record_id = extract_xml_value(xml, live_record_id_re())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let event_type = SysmonEventType::from_event_id(event_id);
        let severity = derive_severity(event_id);

        // Extract EventData fields from XML
        let rule_name = extract_event_data_field(xml, "RuleName");
        let utc_time = extract_event_data_field(xml, "UtcTime");
        let process_guid = extract_event_data_field(xml, "ProcessGuid");
        let process_id = extract_event_data_field(xml, "ProcessId")
            .and_then(|v| v.parse().ok());
        let image = extract_event_data_field(xml, "Image");
        let command_line = extract_event_data_field(xml, "CommandLine");
        let user = extract_event_data_field(xml, "User");
        let hashes = extract_event_data_field(xml, "Hashes");
        let parent_image = extract_event_data_field(xml, "ParentImage");
        let parent_command_line = extract_event_data_field(xml, "ParentCommandLine");
        let parent_process_id = extract_event_data_field(xml, "ParentProcessId")
            .and_then(|v| v.parse().ok());
        let target_filename = extract_event_data_field(xml, "TargetFilename");
        let protocol = extract_event_data_field(xml, "Protocol");
        let source_ip = extract_event_data_field(xml, "SourceIp");
        let source_port = extract_event_data_field(xml, "SourcePort")
            .and_then(|v| v.parse().ok());
        let destination_ip = extract_event_data_field(xml, "DestinationIp");
        let destination_port = extract_event_data_field(xml, "DestinationPort")
            .and_then(|v| v.parse().ok());
        let destination_hostname = extract_event_data_field(xml, "DestinationHostname");
        let target_object = extract_event_data_field(xml, "TargetObject");
        let details = extract_event_data_field(xml, "Details");
        let query_name = extract_event_data_field(xml, "QueryName");
        let query_results = extract_event_data_field(xml, "QueryResults");
        let source_image = extract_event_data_field(xml, "SourceImage");
        let target_image = extract_event_data_field(xml, "TargetImage");
        let granted_access = extract_event_data_field(xml, "GrantedAccess");

        // Build message from rendered message or from fields
        let message = record
            .rendered_message
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| {
                build_message_from_fields(&MessageFields {
                    event_id,
                    event_type: &event_type,
                    image: image.as_deref(),
                    command_line: command_line.as_deref(),
                    user: user.as_deref(),
                    destination_ip: destination_ip.as_deref(),
                    destination_port,
                    protocol: protocol.as_deref(),
                    target_filename: target_filename.as_deref(),
                    source_image: source_image.as_deref(),
                    target_image: target_image.as_deref(),
                    granted_access: granted_access.as_deref(),
                    query_name: query_name.as_deref(),
                    query_results: query_results.as_deref(),
                    target_object: target_object.as_deref(),
                })
            });

        events.push(SysmonEvent {
            id: events.len() as u64,
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
    }

    Ok(events)
}

/// Non-Windows stub for live event log queries.
#[cfg(not(target_os = "windows"))]
pub fn parse_sysmon_live_events() -> Result<Vec<SysmonEvent>, String> {
    Err("Live Sysmon event log queries are only supported on Windows".to_string())
}

/// Holds the fields needed to build a human-readable message for live events.
#[cfg(target_os = "windows")]
struct MessageFields<'a> {
    event_id: u32,
    event_type: &'a SysmonEventType,
    image: Option<&'a str>,
    command_line: Option<&'a str>,
    user: Option<&'a str>,
    destination_ip: Option<&'a str>,
    destination_port: Option<u16>,
    protocol: Option<&'a str>,
    target_filename: Option<&'a str>,
    source_image: Option<&'a str>,
    target_image: Option<&'a str>,
    granted_access: Option<&'a str>,
    query_name: Option<&'a str>,
    query_results: Option<&'a str>,
    target_object: Option<&'a str>,
}

/// Build a human-readable message from extracted field values (for live events).
#[cfg(target_os = "windows")]
fn build_message_from_fields(fields: &MessageFields<'_>) -> String {
    let type_label = fields.event_type.display_name();
    let event_id = fields.event_id;

    match event_id {
        1 => {
            let img = fields.image.unwrap_or("?");
            let usr = fields.user.unwrap_or("");
            match fields.command_line {
                Some(cmd) if !cmd.is_empty() => format!("{img} | {cmd} (User: {usr})"),
                _ => format!("{img} (User: {usr})"),
            }
        }
        3 => {
            let img = fields.image.unwrap_or("?");
            let dst_ip = fields.destination_ip.unwrap_or("?");
            let dst_port = fields
                .destination_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            let proto = fields.protocol.unwrap_or("?");
            format!("{img} → {dst_ip}:{dst_port} ({proto})")
        }
        5 => {
            let img = fields.image.unwrap_or("?");
            format!("{img} terminated")
        }
        10 => {
            let src = fields.source_image.unwrap_or("?");
            let tgt = fields.target_image.unwrap_or("?");
            let access = fields.granted_access.unwrap_or("?");
            format!("{src} → {tgt} (Access: {access})")
        }
        11 => {
            let img = fields.image.unwrap_or("?");
            let target = fields.target_filename.unwrap_or("?");
            format!("{img} created {target}")
        }
        12..=14 => {
            let img = fields.image.unwrap_or("?");
            let target = fields.target_object.unwrap_or("?");
            format!("{img} | {target}")
        }
        22 => {
            let img = fields.image.unwrap_or("?");
            let query = fields.query_name.unwrap_or("?");
            match fields.query_results {
                Some(results) if !results.is_empty() => {
                    format!("{img} queried {query} → {results}")
                }
                _ => format!("{img} queried {query}"),
            }
        }
        23 | 26 => {
            let img = fields.image.unwrap_or("?");
            let target = fields.target_filename.unwrap_or("?");
            format!("{img} deleted {target}")
        }
        _ => {
            if let Some(img) = fields.image {
                format!("[{type_label}] {img}")
            } else {
                format!("[{type_label}]")
            }
        }
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
