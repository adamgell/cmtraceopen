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
use crate::intune::models::{
    EvidenceBundleMetadata, EventLogAnalysis, EventLogAnalysisSource, EventLogChannel,
    EventLogChannelSummary, EventLogCorrelationKind, EventLogCorrelationLink, EventLogEntry,
    EventLogLiveQueryMetadata, EventLogSeverity, IntuneDiagnosticInsight, IntuneEvent,
    IntuneEventType, IntuneStatus, IntuneTimestampBounds,
};
#[cfg(target_os = "windows")]
use crate::intune::models::{EventLogLiveQueryChannelResult, EventLogLiveQueryStatus};

/// Maximum entries to parse from a single .evtx file to prevent memory issues.
const MAX_ENTRIES_PER_FILE: usize = 50_000;
#[cfg(target_os = "windows")]
const MAX_LIVE_ENTRIES_PER_CHANNEL: usize = 200;

#[cfg(target_os = "windows")]
const LIVE_EVENT_CHANNELS: &[&str] = &[
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational",
    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot",
    "Microsoft-Windows-AAD/Operational",
    "Microsoft-Windows-DeliveryOptimization/Operational",
    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService",
    "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin",
    "Microsoft-Windows-Shell-Core/Operational",
    "Microsoft-Windows-Time-Service/Operational",
    "Microsoft-Windows-User Device Registration/Admin",
];

#[cfg(target_os = "windows")]
fn provider_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"<Provider[^>]*Name=['\"]([^'\"]+)['\"]"#)
            .expect("provider regex must compile")
    })
}
#[cfg(target_os = "windows")]
fn channel_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"<Channel>(.*?)</Channel>").expect("channel regex must compile"))
}
#[cfg(target_os = "windows")]
fn event_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"<EventID(?:\s[^>]*)?>(\d+)</EventID>").expect("event id regex must compile"))
}
#[cfg(target_os = "windows")]
fn level_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"<Level>(\d+)</Level>").expect("level regex must compile"))
}
#[cfg(target_os = "windows")]
fn time_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)['\"]"#)
            .expect("time regex must compile")
    })
}
#[cfg(target_os = "windows")]
fn computer_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"<Computer>(.*?)</Computer>").expect("computer regex must compile"))
}
#[cfg(target_os = "windows")]
fn activity_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"<Correlation[^>]*ActivityID=['\"]([^'\"]+)['\"]"#)
            .expect("activity regex must compile")
    })
}
#[cfg(target_os = "windows")]
fn message_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"(?s)<Message>(.*?)</Message>").expect("message regex must compile"))
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Finds .evtx files in an evidence bundle's event-logs directory.
pub fn discover_evtx_files(
    bundle_root: &Path,
    evidence_bundle: &Option<EvidenceBundleMetadata>,
) -> Vec<PathBuf> {
    // Strategy 1: conventional evidence/event-logs/ path
    let event_logs_dir = bundle_root.join("evidence").join("event-logs");
    if event_logs_dir.is_dir() {
        return enumerate_evtx_in_dir(&event_logs_dir);
    }

    // Strategy 2: try evidence_root from bundle metadata
    if let Some(ref bundle) = evidence_bundle {
        if let Some(ref root) = bundle.evidence_root {
            let alt_dir = Path::new(root).join("event-logs");
            if alt_dir.is_dir() {
                return enumerate_evtx_in_dir(&alt_dir);
            }
        }
    }

    Vec::new()
}

fn enumerate_evtx_in_dir(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .map(|ext| ext.eq_ignore_ascii_case("evtx"))
                .unwrap_or(false)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Single-file EVTX parser
// ---------------------------------------------------------------------------

/// Parses a single .evtx file into `EventLogEntry` records.
/// Skips corrupt/malformed records rather than failing the whole file.
pub fn parse_evtx_file(path: &Path, id_offset: u64) -> Result<Vec<EventLogEntry>, String> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path.display(), e))?;

    let source_file = path.to_string_lossy().to_string();
    let mut entries = Vec::new();
    let mut current_id = id_offset;

    for record_result in parser.records_json() {
        if entries.len() >= MAX_ENTRIES_PER_FILE {
            log::warn!(
                "event=evtx_entry_cap_reached file=\"{}\" cap={}",
                source_file, MAX_ENTRIES_PER_FILE
            );
            break;
        }

        let record = match record_result {
            Ok(r) => r,
            Err(e) => {
                log::warn!(
                    "event=evtx_record_skip file=\"{}\" error=\"{}\"",
                    source_file, e
                );
                continue;
            }
        };

        let json: Value = match serde_json::from_str(&record.data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let system = &json["Event"]["System"];
        let event_data = &json["Event"]["EventData"];
        let user_data = &json["Event"]["UserData"];

        let channel_raw = system["Channel"].as_str().unwrap_or("").to_string();
        let channel = EventLogChannel::from_channel_string(&channel_raw);
        let channel_display = channel.display_name().to_string();

        let provider = system["Provider"]["#attributes"]["Name"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let event_id = extract_event_id(system);

        let level = system["Level"].as_u64().unwrap_or(0) as u8;
        let severity = EventLogSeverity::from_level(level);

        let timestamp = system["TimeCreated"]["#attributes"]["SystemTime"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let computer = system["Computer"].as_str().map(|s| s.to_string());

        let correlation_activity_id = system["Correlation"]["#attributes"]["ActivityID"]
            .as_str()
            .map(|s| s.to_string());

        let message = extract_message(event_data, user_data);

        entries.push(EventLogEntry {
            id: current_id,
            channel,
            channel_display,
            provider,
            event_id,
            severity,
            timestamp,
            computer,
            message,
            correlation_activity_id,
            source_file: source_file.clone(),
        });

        current_id += 1;
    }

    Ok(entries)
}

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

/// Build a human-readable message by concatenating EventData or UserData fields.
fn extract_message(event_data: &Value, user_data: &Value) -> String {
    // Try EventData first (most common)
    if let Some(obj) = event_data.as_object() {
        let parts: Vec<String> = obj
            .iter()
            .filter(|(k, _)| *k != "#attributes")
            .filter_map(|(k, v)| {
                let val = match v {
                    Value::String(s) => s.clone(),
                    Value::Null => return None,
                    other => other.to_string(),
                };
                if val.is_empty() {
                    None
                } else {
                    Some(format!("{}: {}", k, val))
                }
            })
            .collect();
        if !parts.is_empty() {
            return parts.join("; ");
        }
    }

    // Fall back to UserData
    if let Some(obj) = user_data.as_object() {
        let parts: Vec<String> = obj
            .values()
            .filter_map(|v| {
                if let Some(inner) = v.as_object() {
                    let sub_parts: Vec<String> = inner
                        .iter()
                        .filter(|(k, _)| *k != "#attributes" && *k != "xmlns")
                        .filter_map(|(k, v)| {
                            let val = match v {
                                Value::String(s) if !s.is_empty() => s.clone(),
                                Value::Null => return None,
                                Value::String(_) => return None,
                                other => other.to_string(),
                            };
                            Some(format!("{}: {}", k, val))
                        })
                        .collect();
                    if sub_parts.is_empty() {
                        None
                    } else {
                        Some(sub_parts.join("; "))
                    }
                } else {
                    None
                }
            })
            .collect();
        if !parts.is_empty() {
            return parts.join(" | ");
        }
    }

    String::new()
}

// ---------------------------------------------------------------------------
// Bundle orchestrator
// ---------------------------------------------------------------------------

/// Parses all .evtx files in an evidence bundle and builds the analysis container.
/// Returns `None` if no .evtx files are found or all are empty.
/// `correlation_links` is left empty — call `build_event_log_correlations` afterwards.
pub fn parse_bundle_event_logs(
    bundle_root: &Path,
    evidence_bundle: &Option<EvidenceBundleMetadata>,
) -> Option<EventLogAnalysis> {
    let evtx_files = discover_evtx_files(bundle_root, evidence_bundle);
    if evtx_files.is_empty() {
        return None;
    }

    let mut all_entries: Vec<EventLogEntry> = Vec::new();
    let mut id_offset: u64 = 0;
    let mut parsed_file_count: u32 = 0;

    for evtx_path in &evtx_files {
        match parse_evtx_file(evtx_path, id_offset) {
            Ok(entries) => {
                id_offset += entries.len() as u64;
                parsed_file_count += 1;
                all_entries.extend(entries);
            }
            Err(e) => {
                log::error!(
                    "event=evtx_file_error file=\"{}\" error=\"{}\"",
                    evtx_path.display(),
                    e
                );
            }
        }
    }

    build_event_log_analysis(
        all_entries,
        parsed_file_count,
        EventLogAnalysisSource::Bundle,
        None,
    )
}

pub fn parse_live_event_logs() -> Option<EventLogAnalysis> {
    #[cfg(target_os = "windows")]
    {
        let mut all_entries = Vec::new();
        let mut id_offset = 0u64;
        let mut parsed_file_count = 0u32;
        let mut live_channels = Vec::with_capacity(LIVE_EVENT_CHANNELS.len());

        for channel in LIVE_EVENT_CHANNELS {
            match eventlog_win32::query_live_channel(channel, MAX_LIVE_ENTRIES_PER_CHANNEL) {
                Ok(result) => {
                    let channel_enum = EventLogChannel::from_channel_string(&result.channel_path);
                    let entry_count = result.records.len() as u32;
                    let status = if entry_count == 0 {
                        EventLogLiveQueryStatus::Empty
                    } else {
                        EventLogLiveQueryStatus::Success
                    };

                    live_channels.push(EventLogLiveQueryChannelResult {
                        channel: channel_enum.clone(),
                        channel_display: channel_enum.display_name().to_string(),
                        channel_path: result.channel_path.clone(),
                        source_file: result.source_file.clone(),
                        status,
                        entry_count,
                        error_message: None,
                    });

                    for record in result.records {
                        if let Some(entry) = parse_live_event_record(
                            &record.xml,
                            &record.source_file,
                            record.rendered_message,
                            id_offset,
                            &result.channel_path,
                        ) {
                            all_entries.push(entry);
                            id_offset += 1;
                        }
                    }

                    if entry_count > 0 {
                        parsed_file_count += 1;
                    }
                }
                Err(error) => {
                    log::error!(
                        "event=live_event_log_query_failed channel=\"{}\" error=\"{}\"",
                        channel, error
                    );

                    let channel_enum = EventLogChannel::from_channel_string(channel);
                    live_channels.push(EventLogLiveQueryChannelResult {
                        channel: channel_enum.clone(),
                        channel_display: channel_enum.display_name().to_string(),
                        channel_path: channel.to_string(),
                        source_file: format!(
                            "live-event-log/{}.evtx",
                            sanitize_channel_name(channel)
                        ),
                        status: EventLogLiveQueryStatus::Failed,
                        entry_count: 0,
                        error_message: Some(error.to_string()),
                    });
                }
            }
        }

        build_event_log_analysis(
            all_entries,
            parsed_file_count,
            EventLogAnalysisSource::Live,
            Some(build_live_query_metadata(live_channels)),
        )
    }

    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

pub(crate) fn build_event_log_analysis(
    mut all_entries: Vec<EventLogEntry>,
    parsed_file_count: u32,
    source_kind: EventLogAnalysisSource,
    live_query: Option<EventLogLiveQueryMetadata>,
) -> Option<EventLogAnalysis> {
    if all_entries.is_empty() && !matches!(source_kind, EventLogAnalysisSource::Live) {
        return None;
    }

    all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    for (i, entry) in all_entries.iter_mut().enumerate() {
        entry.id = i as u64;
    }

    let channel_summaries = build_channel_summaries(&all_entries);

    let total_entry_count = all_entries.len() as u32;
    let error_entry_count = all_entries
        .iter()
        .filter(|e| matches!(e.severity, EventLogSeverity::Error | EventLogSeverity::Critical))
        .count() as u32;
    let warning_entry_count = all_entries
        .iter()
        .filter(|e| matches!(e.severity, EventLogSeverity::Warning))
        .count() as u32;

    let timestamp_bounds = if all_entries.is_empty() {
        None
    } else {
        Some(IntuneTimestampBounds {
            first_timestamp: all_entries.first().map(|e| e.timestamp.clone()),
            last_timestamp: all_entries.last().map(|e| e.timestamp.clone()),
        })
    };

    Some(EventLogAnalysis {
        source_kind,
        entries: all_entries,
        channel_summaries,
        correlation_links: Vec::new(),
        parsed_file_count,
        total_entry_count,
        error_entry_count,
        warning_entry_count,
        timestamp_bounds,
        live_query,
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn parse_live_event_record(
    xml: &str,
    source_file: &str,
    rendered_message: Option<String>,
    id: u64,
    fallback_channel: &str,
) -> Option<EventLogEntry> {
    let channel_raw = extract_regex_value(xml, channel_re())
        .unwrap_or_else(|| fallback_channel.to_string());
    let channel = EventLogChannel::from_channel_string(&channel_raw);
    let timestamp = extract_regex_value(xml, time_re())?;

    let provider = extract_regex_value(xml, provider_re()).unwrap_or_default();
    let event_id = extract_regex_value(xml, event_id_re())
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let level = extract_regex_value(xml, level_re())
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let computer = extract_regex_value(xml, computer_re());
    let correlation_activity_id = extract_regex_value(xml, activity_re());
    let message = rendered_message
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            extract_regex_value(xml, message_re())
                .map(|value| decode_xml_text(&value))
                .unwrap_or_default()
        });

    Some(EventLogEntry {
        id,
        channel: channel.clone(),
        channel_display: channel.display_name().to_string(),
        provider,
        event_id,
        severity: EventLogSeverity::from_level(level),
        timestamp,
        computer: computer.map(|value| decode_xml_text(&value)),
        message,
        correlation_activity_id,
        source_file: source_file.to_string(),
    })
}

#[cfg(target_os = "windows")]
fn extract_regex_value(text: &str, regex: &Regex) -> Option<String> {
    regex
        .captures(text)
        .and_then(|captures| captures.get(1).map(|value| value.as_str().to_string()))
}

#[cfg(target_os = "windows")]
fn sanitize_channel_name(channel: &str) -> String {
    channel
        .chars()
        .map(|value| match value {
            '/' | '\\' | ':' | ' ' => '-',
            other => other,
        })
        .collect()
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

#[cfg(target_os = "windows")]
fn build_live_query_metadata(
    channels: Vec<EventLogLiveQueryChannelResult>,
) -> EventLogLiveQueryMetadata {
    let attempted_channel_count = channels.len() as u32;
    let successful_channel_count = channels
        .iter()
        .filter(|channel| {
            matches!(
                channel.status,
                EventLogLiveQueryStatus::Success | EventLogLiveQueryStatus::Empty
            )
        })
        .count() as u32;
    let channels_with_results_count = channels
        .iter()
        .filter(|channel| channel.entry_count > 0)
        .count() as u32;
    let failed_channel_count = channels
        .iter()
        .filter(|channel| matches!(channel.status, EventLogLiveQueryStatus::Failed))
        .count() as u32;

    EventLogLiveQueryMetadata {
        attempted_channel_count,
        successful_channel_count,
        channels_with_results_count,
        failed_channel_count,
        per_channel_entry_limit: MAX_LIVE_ENTRIES_PER_CHANNEL as u32,
        channels,
    }
}

fn build_channel_summaries(entries: &[EventLogEntry]) -> Vec<EventLogChannelSummary> {
    struct Acc {
        channel: EventLogChannel,
        channel_display: String,
        entry_count: u32,
        error_count: u32,
        warning_count: u32,
        first_ts: Option<String>,
        last_ts: Option<String>,
        source_file: String,
    }

    let mut map: HashMap<String, Acc> = HashMap::new();

    for entry in entries {
        let key = entry.channel_display.clone();
        let acc = map.entry(key).or_insert_with(|| Acc {
            channel: entry.channel.clone(),
            channel_display: entry.channel_display.clone(),
            entry_count: 0,
            error_count: 0,
            warning_count: 0,
            first_ts: None,
            last_ts: None,
            source_file: entry.source_file.clone(),
        });

        acc.entry_count += 1;
        if matches!(
            entry.severity,
            EventLogSeverity::Error | EventLogSeverity::Critical
        ) {
            acc.error_count += 1;
        }
        if matches!(entry.severity, EventLogSeverity::Warning) {
            acc.warning_count += 1;
        }

        if acc.first_ts.is_none() || entry.timestamp < *acc.first_ts.as_ref().unwrap() {
            acc.first_ts = Some(entry.timestamp.clone());
        }
        if acc.last_ts.is_none() || entry.timestamp > *acc.last_ts.as_ref().unwrap() {
            acc.last_ts = Some(entry.timestamp.clone());
        }
    }

    let mut summaries: Vec<EventLogChannelSummary> = map
        .into_values()
        .map(|a| EventLogChannelSummary {
            channel: a.channel,
            channel_display: a.channel_display,
            entry_count: a.entry_count,
            error_count: a.error_count,
            warning_count: a.warning_count,
            timestamp_bounds: Some(IntuneTimestampBounds {
                first_timestamp: a.first_ts,
                last_timestamp: a.last_ts,
            }),
            source_file: a.source_file,
        })
        .collect();

    // Sort by error count desc, then entry count desc for stable UI ordering
    summaries.sort_by(|a, b| {
        b.error_count
            .cmp(&a.error_count)
            .then(b.entry_count.cmp(&a.entry_count))
    });

    summaries
}

// ---------------------------------------------------------------------------
// Correlation engine
// ---------------------------------------------------------------------------

/// Time window in seconds for channel-based correlation (Strategy 1).
const TIME_WINDOW_CHANNEL_SECS: f64 = 120.0;

/// Time window in seconds for enrollment context correlation (Strategy 3).
const TIME_WINDOW_ENROLLMENT_SECS: f64 = 300.0;

/// Builds deterministic correlation links between event log entries and
/// IME-derived Intune events + diagnostics.
pub fn build_event_log_correlations(
    ime_events: &[IntuneEvent],
    event_log_entries: &[EventLogEntry],
    diagnostics: &[IntuneDiagnosticInsight],
) -> Vec<EventLogCorrelationLink> {
    if event_log_entries.is_empty() {
        return Vec::new();
    }

    let mut links: Vec<EventLogCorrelationLink> = Vec::new();
    let mut seen: HashSet<(u64, Option<u64>)> = HashSet::new();

    // Strategy 1: TimeWindowChannelMatch
    correlate_by_time_window_channel(ime_events, event_log_entries, &mut links, &mut seen);

    // Strategy 2: ErrorCodeMatch
    correlate_by_error_code(ime_events, event_log_entries, &mut links, &mut seen);

    // Strategy 3: EnrollmentContextMatch
    correlate_by_enrollment_context(ime_events, event_log_entries, &mut links, &mut seen);

    // Diagnostic-level linking
    correlate_diagnostics(event_log_entries, diagnostics, &mut links, &mut seen);

    links
}

/// Strategy 1: For each failed/timed-out IME event, find event log entries
/// within a time window from contextually relevant channels.
fn correlate_by_time_window_channel(
    ime_events: &[IntuneEvent],
    entries: &[EventLogEntry],
    links: &mut Vec<EventLogCorrelationLink>,
    seen: &mut HashSet<(u64, Option<u64>)>,
) {
    for ime in ime_events {
        if !matches!(ime.status, IntuneStatus::Failed | IntuneStatus::Timeout) {
            continue;
        }

        let relevant_channels = channels_for_event_type(&ime.event_type);
        if relevant_channels.is_empty() {
            continue;
        }

        let ime_ts = best_timestamp_for_ime(ime);
        let ime_ndt = match parse_timestamp_loose(&ime_ts) {
            Some(t) => t,
            None => continue,
        };

        for entry in entries {
            if !entry.severity.is_error_or_warning() {
                continue;
            }
            if !relevant_channels.contains(&entry.channel) {
                continue;
            }

            let entry_ndt = match parse_timestamp_loose(&entry.timestamp) {
                Some(t) => t,
                None => continue,
            };

            let delta = (ime_ndt - entry_ndt).num_seconds().unsigned_abs() as f64;
            if delta > TIME_WINDOW_CHANNEL_SECS {
                continue;
            }

            let pair = (entry.id, Some(ime.id));
            if seen.contains(&pair) {
                continue;
            }
            seen.insert(pair);

            links.push(EventLogCorrelationLink {
                event_log_entry_id: entry.id,
                linked_intune_event_id: Some(ime.id),
                linked_diagnostic_id: None,
                correlation_kind: EventLogCorrelationKind::TimeWindowChannelMatch,
                time_delta_secs: Some(delta),
            });
        }
    }
}

/// Strategy 2: For each IME event with an error code, find event log entries
/// whose message contains that error code.
fn correlate_by_error_code(
    ime_events: &[IntuneEvent],
    entries: &[EventLogEntry],
    links: &mut Vec<EventLogCorrelationLink>,
    seen: &mut HashSet<(u64, Option<u64>)>,
) {
    for ime in ime_events {
        let error_code = match &ime.error_code {
            Some(code) if !code.is_empty() => code.to_ascii_lowercase(),
            _ => continue,
        };

        let ime_ts = best_timestamp_for_ime(ime);
        let ime_ndt = parse_timestamp_loose(&ime_ts);

        for entry in entries {
            if !entry.message.to_ascii_lowercase().contains(&error_code) {
                continue;
            }

            let pair = (entry.id, Some(ime.id));
            if seen.contains(&pair) {
                continue;
            }
            seen.insert(pair);

            let delta = ime_ndt.and_then(|i| {
                parse_timestamp_loose(&entry.timestamp)
                    .map(|e| (i - e).num_seconds().unsigned_abs() as f64)
            });

            links.push(EventLogCorrelationLink {
                event_log_entry_id: entry.id,
                linked_intune_event_id: Some(ime.id),
                linked_diagnostic_id: None,
                correlation_kind: EventLogCorrelationKind::ErrorCodeMatch,
                time_delta_secs: delta,
            });
        }
    }
}

/// Strategy 3: For ESP/SyncSession IME events, match against
/// AAD/Operational and User Device Registration channels.
fn correlate_by_enrollment_context(
    ime_events: &[IntuneEvent],
    entries: &[EventLogEntry],
    links: &mut Vec<EventLogCorrelationLink>,
    seen: &mut HashSet<(u64, Option<u64>)>,
) {
    let enrollment_channels = [
        EventLogChannel::AadOperational,
        EventLogChannel::UserDeviceRegistrationAdmin,
    ];

    for ime in ime_events {
        if !matches!(
            ime.event_type,
            IntuneEventType::Esp | IntuneEventType::SyncSession
        ) {
            continue;
        }

        let ime_ts = best_timestamp_for_ime(ime);
        let ime_ndt = match parse_timestamp_loose(&ime_ts) {
            Some(t) => t,
            None => continue,
        };

        for entry in entries {
            if !entry.severity.is_error_or_warning() {
                continue;
            }
            if !enrollment_channels.contains(&entry.channel) {
                continue;
            }

            let entry_ndt = match parse_timestamp_loose(&entry.timestamp) {
                Some(t) => t,
                None => continue,
            };

            let delta = (ime_ndt - entry_ndt).num_seconds().unsigned_abs() as f64;
            if delta > TIME_WINDOW_ENROLLMENT_SECS {
                continue;
            }

            let pair = (entry.id, Some(ime.id));
            if seen.contains(&pair) {
                continue;
            }
            seen.insert(pair);

            links.push(EventLogCorrelationLink {
                event_log_entry_id: entry.id,
                linked_intune_event_id: Some(ime.id),
                linked_diagnostic_id: None,
                correlation_kind: EventLogCorrelationKind::EnrollmentContextMatch,
                time_delta_secs: Some(delta),
            });
        }
    }
}

/// Diagnostic-level linking: for each diagnostic, check if its error codes
/// appear in event log entries that were already linked.
fn correlate_diagnostics(
    entries: &[EventLogEntry],
    diagnostics: &[IntuneDiagnosticInsight],
    links: &mut Vec<EventLogCorrelationLink>,
    seen: &mut HashSet<(u64, Option<u64>)>,
) {
    // Build a set of entry IDs already linked by event-level strategies
    let linked_entry_ids: HashSet<u64> = links.iter().map(|l| l.event_log_entry_id).collect();

    for diag in diagnostics {
        if diag.related_error_codes.is_empty() {
            continue;
        }

        let lower_codes: Vec<String> = diag
            .related_error_codes
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect();

        for entry in entries {
            // Only link entries that were already connected via event-level strategies
            // or that have error/warning severity
            if !linked_entry_ids.contains(&entry.id) && !entry.severity.is_error_or_warning() {
                continue;
            }

            let lower_msg = entry.message.to_ascii_lowercase();
            let has_match = lower_codes.iter().any(|code| lower_msg.contains(code));
            if !has_match {
                continue;
            }

            let pair = (entry.id, None);
            if seen.contains(&pair) {
                continue;
            }
            seen.insert(pair);

            links.push(EventLogCorrelationLink {
                event_log_entry_id: entry.id,
                linked_intune_event_id: None,
                linked_diagnostic_id: Some(diag.id.clone()),
                correlation_kind: EventLogCorrelationKind::ErrorCodeMatch,
                time_delta_secs: None,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the set of event log channels contextually relevant for a given IME event type.
fn channels_for_event_type(event_type: &IntuneEventType) -> Vec<EventLogChannel> {
    match event_type {
        IntuneEventType::Win32App
        | IntuneEventType::WinGetApp
        | IntuneEventType::ContentDownload => vec![
            EventLogChannel::DeviceManagementAdmin,
            EventLogChannel::DeviceManagementOperational,
            EventLogChannel::DeliveryOptimizationOperational,
        ],
        IntuneEventType::PolicyEvaluation => vec![
            EventLogChannel::DeviceManagementAdmin,
            EventLogChannel::DeviceManagementOperational,
        ],
        IntuneEventType::Esp => vec![
            EventLogChannel::Autopilot,
            EventLogChannel::DeviceManagementAdmin,
            EventLogChannel::ManagementService,
        ],
        IntuneEventType::SyncSession => vec![
            EventLogChannel::DeviceManagementAdmin,
            EventLogChannel::DeviceManagementOperational,
        ],
        IntuneEventType::PowerShellScript | IntuneEventType::Remediation => vec![
            EventLogChannel::DeviceManagementAdmin,
            EventLogChannel::DeviceManagementOperational,
        ],
        IntuneEventType::Other => Vec::new(),
    }
}

/// Pick the best timestamp to use from an IME event for time-based correlation.
fn best_timestamp_for_ime(ime: &IntuneEvent) -> String {
    // Prefer end_time (closer to the failure moment), fall back to start_time
    ime.end_time
        .as_deref()
        .or(ime.start_time.as_deref())
        .unwrap_or("")
        .to_string()
}

/// Parse a timestamp string loosely, supporting both ISO 8601 (EVTX) and
/// common IME log timestamp formats.
fn parse_timestamp_loose(ts: &str) -> Option<chrono::NaiveDateTime> {
    if ts.is_empty() {
        return None;
    }

    // ISO 8601 with Z suffix (EVTX format)
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        return Some(dt.naive_utc());
    }

    // ISO 8601 without timezone
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt);
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt);
    }

    // IME format: MM/DD/YYYY HH:MM:SS (12h with AM/PM)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%m/%d/%Y %I:%M:%S %p") {
        return Some(dt);
    }

    // IME format: MM-DD-YYYY HH:MM:SS.fff
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%m-%d-%Y %H:%M:%S%.f") {
        return Some(dt);
    }

    // IME format: MM/DD/YYYY HH:MM:SS.fff
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%m/%d/%Y %H:%M:%S%.f") {
        return Some(dt);
    }

    None
}

/// Build corroboration evidence strings from correlation links for appending
/// to diagnostic insights.
pub fn build_corroboration_evidence(
    entries: &[EventLogEntry],
    correlation_links: &[EventLogCorrelationLink],
    diagnostic_id: &str,
) -> Vec<String> {
    let mut evidence = Vec::new();

    // Find entry-level links connected to this diagnostic's IME events
    // plus direct diagnostic-level links
    let relevant_entry_ids: Vec<u64> = correlation_links
        .iter()
        .filter(|l| l.linked_diagnostic_id.as_deref() == Some(diagnostic_id))
        .map(|l| l.event_log_entry_id)
        .collect();

    let entry_map: HashMap<u64, &EventLogEntry> =
        entries.iter().map(|e| (e.id, e)).collect();

    for entry_id in relevant_entry_ids.iter().take(3) {
        if let Some(entry) = entry_map.get(entry_id) {
            let truncated_msg = if entry.message.len() > 80 {
                format!("{}...", &entry.message[..80])
            } else {
                entry.message.clone()
            };
            evidence.push(format!(
                "Windows Event Log: {} Event ID {} ({:?}) at {} \u{2014} {}",
                entry.channel_display, entry.event_id, entry.severity, entry.timestamp, truncated_msg
            ));
        }
    }

    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_from_string_maps_known_channels() {
        assert_eq!(
            EventLogChannel::from_channel_string(
                "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
            ),
            EventLogChannel::DeviceManagementAdmin
        );
        assert_eq!(
            EventLogChannel::from_channel_string(
                "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational"
            ),
            EventLogChannel::DeviceManagementOperational
        );
        assert_eq!(
            EventLogChannel::from_channel_string(
                "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot"
            ),
            EventLogChannel::Autopilot
        );
        assert_eq!(
            EventLogChannel::from_channel_string("Microsoft-Windows-AAD/Operational"),
            EventLogChannel::AadOperational
        );
        assert_eq!(
            EventLogChannel::from_channel_string(
                "Microsoft-Windows-DeliveryOptimization/Operational"
            ),
            EventLogChannel::DeliveryOptimizationOperational
        );
        assert_eq!(
            EventLogChannel::from_channel_string(
                "Microsoft-Windows-User Device Registration/Admin"
            ),
            EventLogChannel::UserDeviceRegistrationAdmin
        );
    }

    #[test]
    fn channel_from_string_falls_back_to_other() {
        let ch = EventLogChannel::from_channel_string("SomeCustom/Channel");
        assert!(matches!(ch, EventLogChannel::Other(ref s) if s == "SomeCustom/Channel"));
    }

    #[test]
    fn severity_from_level_maps_correctly() {
        assert_eq!(EventLogSeverity::from_level(1), EventLogSeverity::Critical);
        assert_eq!(EventLogSeverity::from_level(2), EventLogSeverity::Error);
        assert_eq!(EventLogSeverity::from_level(3), EventLogSeverity::Warning);
        assert_eq!(
            EventLogSeverity::from_level(4),
            EventLogSeverity::Information
        );
        assert_eq!(EventLogSeverity::from_level(5), EventLogSeverity::Verbose);
        assert_eq!(EventLogSeverity::from_level(99), EventLogSeverity::Unknown);
    }

    #[test]
    fn parse_timestamp_loose_handles_formats() {
        // ISO 8601 with Z
        assert!(parse_timestamp_loose("2026-03-12T16:01:23.456Z").is_some());
        // ISO 8601 without TZ
        assert!(parse_timestamp_loose("2026-03-12T16:01:23.456").is_some());
        // IME 12h format
        assert!(parse_timestamp_loose("03/12/2026 04:01:23 PM").is_some());
        // IME dash format
        assert!(parse_timestamp_loose("03-12-2026 16:01:23.456").is_some());
        // Empty
        assert!(parse_timestamp_loose("").is_none());
        // Garbage
        assert!(parse_timestamp_loose("not-a-timestamp").is_none());
    }

    #[test]
    fn channels_for_event_type_returns_relevant_channels() {
        let channels = channels_for_event_type(&IntuneEventType::Win32App);
        assert!(channels.contains(&EventLogChannel::DeviceManagementAdmin));
        assert!(channels.contains(&EventLogChannel::DeliveryOptimizationOperational));
        assert!(!channels.contains(&EventLogChannel::Autopilot));

        let esp_channels = channels_for_event_type(&IntuneEventType::Esp);
        assert!(esp_channels.contains(&EventLogChannel::Autopilot));
    }

    #[test]
    fn build_event_log_correlations_returns_empty_for_no_entries() {
        let links = build_event_log_correlations(&[], &[], &[]);
        assert!(links.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_live_event_record_extracts_rendered_xml_fields() {
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider'/><EventID>813</EventID><Level>2</Level><TimeCreated SystemTime='2026-03-12T16:01:23.456Z'/><Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel><Computer>CONTOSO-01</Computer><Correlation ActivityID='{123}'/></System><RenderingInfo Culture='en-US'><Message>Enrollment failed &amp; needs attention</Message></RenderingInfo></Event>"#;

        let entry = parse_live_event_record(
            xml,
            "live-event-log/test.evtx",
            None,
            7,
            "fallback",
        )
        .expect("live entry");

        assert_eq!(entry.id, 7);
        assert_eq!(entry.event_id, 813);
        assert_eq!(entry.severity, EventLogSeverity::Error);
        assert_eq!(entry.provider, "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider");
        assert_eq!(entry.timestamp, "2026-03-12T16:01:23.456Z");
        assert_eq!(entry.message, "Enrollment failed & needs attention");
    }
}
