//! Layer 4: Cross-Source Correlation Detection
//!
//! Detects anomalies where a failure in one IME log source correlates
//! temporally with events in a different log source. This reveals
//! cross-component failure cascades that are invisible when analyzing
//! each log file in isolation.

use std::collections::HashMap;

use chrono::NaiveDateTime;

use super::models::{Anomaly, AnomalyKind, AnomalySeverity, AnomalyTimeRange, DetectionLayer};
use crate::intune::event_tracker::{classify_source_kind, ImeSourceKind};
use crate::intune::models::{
    EventLogAnalysis, EventLogSeverity, IntuneEvent, IntuneEventType, IntuneStatus,
};
use crate::intune::timeline;
use crate::parser::etl::EtlEvent;

/// Maximum time delta (in seconds) for two events to be considered correlated.
const CORRELATION_WINDOW_SECS: i64 = 60;

/// Detect cross-source correlation anomalies.
///
/// For each **failed** event in one source family, we search all other source
/// families for events within a ±60-second window. If correlated events exist
/// in at least one other source, an anomaly is emitted. If `event_log_analysis`
/// is provided, matching EVTX entries within the same window can boost severity
/// to Critical.
pub fn detect_cross_source_anomalies(
    events: &[IntuneEvent],
    event_log_analysis: Option<&EventLogAnalysis>,
    etl_events: Option<&[EtlEvent]>,
) -> Vec<Anomaly> {
    // Step 1 & 2: Classify each event by source and build a map of
    // ImeSourceKind -> Vec<(parsed_timestamp, &IntuneEvent)>.
    let mut source_map: HashMap<ImeSourceKind, Vec<(NaiveDateTime, &IntuneEvent)>> =
        HashMap::new();

    for event in events {
        let kind = classify_source_kind(&event.source_file);
        if let Some(ts) = event
            .start_time
            .as_deref()
            .and_then(timeline::parse_timestamp)
        {
            source_map.entry(kind).or_default().push((ts, event));
        }
    }

    // Pre-parse event log timestamps if available.
    let parsed_log_entries: Vec<(NaiveDateTime, u64, &EventLogSeverity)> = event_log_analysis
        .map(|ela| {
            ela.entries
                .iter()
                .filter_map(|entry| {
                    timeline::parse_timestamp(&entry.timestamp)
                        .map(|ts| (ts, entry.id, &entry.severity))
                })
                .collect()
        })
        .unwrap_or_default();

    // Step 3-7: For each failed event, search other sources.
    // Use a map keyed by (source_kind, event_id) to deduplicate / merge.
    let mut anomaly_map: HashMap<u64, PendingAnomaly> = HashMap::new();

    for (source_kind, source_events) in &source_map {
        for &(failed_ts, failed_event) in source_events {
            if failed_event.status != IntuneStatus::Failed {
                continue;
            }

            let mut correlated_ids: Vec<u64> = Vec::new();
            let mut correlated_sources: Vec<ImeSourceKind> = Vec::new();
            let mut correlated_event_types: Vec<(ImeSourceKind, IntuneEventType)> = Vec::new();
            let mut earliest_ts = failed_ts;
            let mut latest_ts = failed_ts;

            // Search all other source families.
            for (other_kind, other_events) in &source_map {
                if other_kind == source_kind {
                    continue;
                }

                for &(other_ts, other_event) in other_events {
                    let delta = (other_ts - failed_ts).num_seconds().abs();
                    if delta <= CORRELATION_WINDOW_SECS {
                        correlated_ids.push(other_event.id);
                        if !correlated_sources.contains(other_kind) {
                            correlated_sources.push(*other_kind);
                        }
                        correlated_event_types.push((*other_kind, other_event.event_type));
                        if other_ts < earliest_ts {
                            earliest_ts = other_ts;
                        }
                        if other_ts > latest_ts {
                            latest_ts = other_ts;
                        }
                    }
                }
            }

            if correlated_ids.is_empty() {
                continue;
            }

            // Step 4: Determine severity from the pattern.
            let severity = determine_severity(
                *source_kind,
                failed_event.event_type,
                &correlated_event_types,
            );

            // Step 5: Check event log entries for ±60s correlation.
            let mut correlated_log_ids: Vec<u64> = Vec::new();
            let mut boosted = false;
            for &(log_ts, log_id, log_severity) in &parsed_log_entries {
                let delta = (log_ts - failed_ts).num_seconds().abs();
                if delta <= CORRELATION_WINDOW_SECS {
                    correlated_log_ids.push(log_id);
                    if matches!(
                        log_severity,
                        EventLogSeverity::Error | EventLogSeverity::Critical
                    ) {
                        boosted = true;
                    }
                    if log_ts < earliest_ts {
                        earliest_ts = log_ts;
                    }
                    if log_ts > latest_ts {
                        latest_ts = log_ts;
                    }
                }
            }

            // Step 5b: Check ETL telemetry events for correlation by error_code or timestamp.
            if let Some(etl) = etl_events {
                for etl_event in etl {
                    if let Some(ref telem) = etl_event.telemetry_data {
                        // Correlate by error_code match
                        if let (Some(ref etl_err), Some(ref ime_err)) =
                            (&telem.error_code, &failed_event.error_code)
                        {
                            if !etl_err.is_empty() && etl_err == ime_err {
                                boosted = true;
                            }
                        }
                        // Correlate by correlation_id in timestamp window
                        if telem.correlation_id.is_some() {
                            if let Some(etl_ts) =
                                timeline::parse_timestamp(&etl_event.timestamp)
                            {
                                let delta = (etl_ts - failed_ts).num_seconds().abs();
                                if delta <= CORRELATION_WINDOW_SECS {
                                    boosted = true;
                                }
                            }
                        }
                    }
                }
            }

            let final_severity = if boosted {
                AnomalySeverity::Critical
            } else {
                severity
            };

            // Step 6 & 7: Merge into existing anomaly or create new one.
            let mut all_affected = vec![failed_event.id];
            all_affected.extend(&correlated_ids);

            let source_names: Vec<&str> = {
                let mut names = vec![source_kind_label(source_kind)];
                for s in &correlated_sources {
                    names.push(source_kind_label(s));
                }
                names
            };

            let title = format!("Cross-source failure: {}", source_names.join(" + "));

            let description = format!(
                "Failed {} event '{}' in {} correlates with {} event(s) in {} within ±{}s",
                event_type_label(failed_event.event_type),
                failed_event.name,
                source_kind_label(source_kind),
                correlated_ids.len(),
                source_names[1..].join(", "),
                CORRELATION_WINDOW_SECS,
            );

            let pending = anomaly_map
                .entry(failed_event.id)
                .or_insert_with(|| PendingAnomaly {
                    severity: final_severity,
                    affected_event_ids: vec![failed_event.id],
                    affected_event_log_ids: Vec::new(),
                    earliest_ts,
                    latest_ts,
                    title: title.clone(),
                    description: description.clone(),
                });

            // Merge: extend IDs, upgrade severity if needed.
            for id in &correlated_ids {
                if !pending.affected_event_ids.contains(id) {
                    pending.affected_event_ids.push(*id);
                }
            }
            for id in &correlated_log_ids {
                if !pending.affected_event_log_ids.contains(id) {
                    pending.affected_event_log_ids.push(*id);
                }
            }
            if final_severity > pending.severity {
                pending.severity = final_severity;
            }
            if earliest_ts < pending.earliest_ts {
                pending.earliest_ts = earliest_ts;
            }
            if latest_ts > pending.latest_ts {
                pending.latest_ts = latest_ts;
            }
            // Keep the more descriptive title/description if we're upgrading.
            if final_severity >= pending.severity {
                pending.title = title;
                pending.description = description;
            }
        }
    }

    // Convert pending anomalies into final results.
    let mut counter = 0u64;
    anomaly_map
        .into_values()
        .map(|p| {
            let id = format!("xsrc-{}", counter);
            counter += 1;
            Anomaly {
                id,
                kind: AnomalyKind::CrossSourceCorrelation,
                severity: p.severity,
                score: 0.0,
                title: p.title,
                description: p.description,
                affected_event_ids: p.affected_event_ids,
                affected_event_log_ids: p.affected_event_log_ids,
                detection_layer: DetectionLayer::CrossSource,
                score_factors: vec![],
                time_range: Some(AnomalyTimeRange {
                    start: p.earliest_ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                    end: p.latest_ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                }),
                flow_context: None,
                statistical_context: None,
                enriched_error_codes: vec![],
            }
        })
        .collect()
}

/// Intermediate accumulator for deduplication/merging.
struct PendingAnomaly {
    severity: AnomalySeverity,
    affected_event_ids: Vec<u64>,
    affected_event_log_ids: Vec<u64>,
    earliest_ts: NaiveDateTime,
    latest_ts: NaiveDateTime,
    title: String,
    description: String,
}

/// Determine anomaly severity based on the source/event-type pattern.
fn determine_severity(
    failed_source: ImeSourceKind,
    failed_event_type: IntuneEventType,
    correlated: &[(ImeSourceKind, IntuneEventType)],
) -> AnomalySeverity {
    // ContentDownload failure in AppWorkload + related events in any other source → Critical
    if failed_source == ImeSourceKind::AppWorkload
        && failed_event_type == IntuneEventType::ContentDownload
        && !correlated.is_empty()
    {
        return AnomalySeverity::Critical;
    }

    // Win32App install failure in PrimaryIme + no corresponding install event in AppWorkload → Critical
    if failed_source == ImeSourceKind::PrimaryIme
        && failed_event_type == IntuneEventType::Win32App
    {
        let has_appworkload_install = correlated.iter().any(|(kind, etype)| {
            *kind == ImeSourceKind::AppWorkload && *etype == IntuneEventType::Win32App
        });
        if !has_appworkload_install {
            return AnomalySeverity::Critical;
        }
    }

    // PolicyEvaluation events in AppActionProcessor + install attempt in AppWorkload → Warning
    if correlated.iter().any(|(kind, etype)| {
        (*kind == ImeSourceKind::AppActionProcessor
            && *etype == IntuneEventType::PolicyEvaluation)
            || (*kind == ImeSourceKind::AppWorkload && *etype == IntuneEventType::Win32App)
    }) {
        return AnomalySeverity::Warning;
    }

    // Default cross-source correlation
    AnomalySeverity::Warning
}

/// Human-readable label for an `ImeSourceKind`.
fn source_kind_label(kind: &ImeSourceKind) -> &'static str {
    match kind {
        ImeSourceKind::PrimaryIme => "PrimaryIme",
        ImeSourceKind::AppWorkload => "AppWorkload",
        ImeSourceKind::AppActionProcessor => "AppActionProcessor",
        ImeSourceKind::AgentExecutor => "AgentExecutor",
        ImeSourceKind::HealthScripts => "HealthScripts",
        ImeSourceKind::ClientHealth => "ClientHealth",
        ImeSourceKind::ClientCertCheck => "ClientCertCheck",
        ImeSourceKind::DeviceHealthMonitoring => "DeviceHealthMonitoring",
        ImeSourceKind::Sensor => "Sensor",
        ImeSourceKind::Win32AppInventory => "Win32AppInventory",
        ImeSourceKind::Other => "Other",
    }
}

/// Human-readable label for an `IntuneEventType`.
fn event_type_label(etype: IntuneEventType) -> &'static str {
    match etype {
        IntuneEventType::Win32App => "Win32App",
        IntuneEventType::WinGetApp => "WinGetApp",
        IntuneEventType::PowerShellScript => "PowerShellScript",
        IntuneEventType::Remediation => "Remediation",
        IntuneEventType::Esp => "ESP",
        IntuneEventType::SyncSession => "SyncSession",
        IntuneEventType::PolicyEvaluation => "PolicyEvaluation",
        IntuneEventType::ContentDownload => "ContentDownload",
        IntuneEventType::Other => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::models::{IntuneEventType, IntuneStatus};

    fn make_event(
        id: u64,
        status: IntuneStatus,
        start_time: &str,
        source: &str,
        event_type: IntuneEventType,
    ) -> IntuneEvent {
        IntuneEvent {
            id,
            event_type,
            name: format!("Test Event {}", id),
            guid: Some("test-guid-1".to_string()),
            status,
            start_time: Some(start_time.to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: String::new(),
            source_file: source.to_string(),
            line_number: id as u32,
        }
    }

    #[test]
    fn test_cross_source_failure_correlation() {
        let events = vec![
            make_event(
                1,
                IntuneStatus::Failed,
                "01-15-2024 10:00:05.000",
                "AppWorkload.log",
                IntuneEventType::Win32App,
            ),
            make_event(
                2,
                IntuneStatus::Success,
                "01-15-2024 10:00:10.000",
                "IntuneManagementExtension.log",
                IntuneEventType::Win32App,
            ),
        ];

        let anomalies = detect_cross_source_anomalies(&events, None, None);
        assert_eq!(
            anomalies.len(),
            1,
            "Expected 1 cross-source anomaly, got {}",
            anomalies.len()
        );
        assert_eq!(anomalies[0].kind, AnomalyKind::CrossSourceCorrelation);
        assert_eq!(anomalies[0].detection_layer, DetectionLayer::CrossSource);
        assert!(anomalies[0].affected_event_ids.contains(&1));
        assert!(anomalies[0].affected_event_ids.contains(&2));
    }

    #[test]
    fn test_no_correlation_across_time_gap() {
        let events = vec![
            make_event(
                1,
                IntuneStatus::Failed,
                "01-15-2024 10:00:05.000",
                "AppWorkload.log",
                IntuneEventType::Win32App,
            ),
            make_event(
                2,
                IntuneStatus::Success,
                "01-15-2024 10:10:05.000", // 10 minutes later
                "IntuneManagementExtension.log",
                IntuneEventType::Win32App,
            ),
        ];

        let anomalies = detect_cross_source_anomalies(&events, None, None);
        assert!(
            anomalies.is_empty(),
            "Expected no anomalies when events are >60s apart, got {}",
            anomalies.len()
        );
    }

    #[test]
    fn test_single_source_no_correlation() {
        let events = vec![
            make_event(
                1,
                IntuneStatus::Failed,
                "01-15-2024 10:00:05.000",
                "AppWorkload.log",
                IntuneEventType::Win32App,
            ),
            make_event(
                2,
                IntuneStatus::Success,
                "01-15-2024 10:00:10.000",
                "AppWorkload.log", // Same source
                IntuneEventType::Win32App,
            ),
        ];

        let anomalies = detect_cross_source_anomalies(&events, None, None);
        assert!(
            anomalies.is_empty(),
            "Expected no anomalies when all events from same source, got {}",
            anomalies.len()
        );
    }
}
