//! Layer 3: Severity Escalation Detection
//!
//! Detects patterns where event severity monotonically increases within a
//! sliding window, indicating a cascading failure. A window of 5 events is
//! checked for non-decreasing severity that transitions from level 0
//! (success/in-progress) to level 2 (failed). Overlapping windows that share
//! 4 of 5 events are deduplicated, keeping the higher-severity result.

use chrono::NaiveDateTime;

use super::models::{Anomaly, AnomalyKind, AnomalySeverity, AnomalyTimeRange, DetectionLayer};
use crate::intune::models::{IntuneEvent, IntuneStatus};
use crate::intune::timeline;

/// Window size for escalation detection.
const WINDOW_SIZE: usize = 5;

/// Map an `IntuneStatus` to a numeric severity proxy.
///   0 = Success / InProgress / Pending / Unknown
///   1 = Timeout
///   2 = Failed
fn severity_proxy(status: IntuneStatus) -> u8 {
    match status {
        IntuneStatus::Success | IntuneStatus::InProgress => 0,
        IntuneStatus::Pending | IntuneStatus::Unknown => 0,
        IntuneStatus::Timeout => 1,
        IntuneStatus::Failed => 2,
    }
}

/// Detect severity escalation chains across a sliding window of events.
pub fn detect_escalation_anomalies(events: &[IntuneEvent]) -> Vec<Anomaly> {
    if events.len() < WINDOW_SIZE {
        return Vec::new();
    }

    let mut raw_anomalies: Vec<Anomaly> = Vec::new();

    for start_idx in 0..=(events.len() - WINDOW_SIZE) {
        let window = &events[start_idx..start_idx + WINDOW_SIZE];
        let severities: Vec<u8> = window.iter().map(|e| severity_proxy(e.status)).collect();

        // Check monotonically non-decreasing
        let is_non_decreasing = severities.windows(2).all(|pair| pair[0] <= pair[1]);
        if !is_non_decreasing {
            continue;
        }

        // Must start at 0 and end at 2 (transition from success-level to failed)
        if severities[0] != 0 || severities[WINDOW_SIZE - 1] != 2 {
            continue;
        }

        // Compute escalation velocity: severity-increasing transitions / time span in minutes
        let increasing_transitions = severities
            .windows(2)
            .filter(|pair| pair[1] > pair[0])
            .count();

        let first_ts = window
            .first()
            .and_then(|e| e.start_time.as_deref())
            .and_then(timeline::parse_timestamp);
        let last_ts = window
            .last()
            .and_then(|e| e.start_time.as_deref())
            .and_then(timeline::parse_timestamp);

        let (velocity, time_span_secs) =
            compute_velocity(first_ts, last_ts, increasing_transitions);

        let severity = if velocity > 1.0 {
            AnomalySeverity::Critical
        } else {
            AnomalySeverity::Warning
        };

        let affected_ids: Vec<u64> = window.iter().map(|e| e.id).collect();

        let time_range = make_time_range(first_ts, last_ts);

        let description = format!(
            "Events escalated from Success to Failed over {} events in {:.0} seconds",
            WINDOW_SIZE, time_span_secs
        );

        let anomaly_id = format!("esc-{}-{}", start_idx, affected_ids[0]);
        raw_anomalies.push(Anomaly {
            id: anomaly_id,
            kind: AnomalyKind::SeverityEscalation,
            severity,
            score: 0.0,
            title: "Severity escalation detected".to_string(),
            description,
            affected_event_ids: affected_ids,
            affected_event_log_ids: vec![],
            detection_layer: DetectionLayer::Escalation,
            score_factors: vec![],
            time_range,
            flow_context: None,
            statistical_context: None,
            enriched_error_codes: vec![],
        });
    }

    deduplicate_overlapping(raw_anomalies)
}

/// Compute velocity (increasing transitions per minute) and the raw time span.
fn compute_velocity(
    first_ts: Option<NaiveDateTime>,
    last_ts: Option<NaiveDateTime>,
    increasing_transitions: usize,
) -> (f64, f64) {
    match (first_ts, last_ts) {
        (Some(first), Some(last)) => {
            let span_secs = (last - first).num_seconds().unsigned_abs() as f64;
            let span_minutes = span_secs / 60.0;
            if span_minutes > 0.0 {
                (increasing_transitions as f64 / span_minutes, span_secs)
            } else {
                // All events at the same timestamp – treat as instantaneous (high velocity)
                (f64::INFINITY, 0.0)
            }
        }
        _ => {
            // Cannot compute velocity without timestamps; default to warning-level
            (0.0, 0.0)
        }
    }
}

/// Build an `AnomalyTimeRange` from parsed timestamps.
fn make_time_range(
    first_ts: Option<NaiveDateTime>,
    last_ts: Option<NaiveDateTime>,
) -> Option<AnomalyTimeRange> {
    match (first_ts, last_ts) {
        (Some(first), Some(last)) => Some(AnomalyTimeRange {
            start: first.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            end: last.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        }),
        _ => None,
    }
}

/// Deduplicate overlapping windows: if two anomalies share 4 of 5 event IDs,
/// keep the one with higher severity (or more affected events as tiebreaker).
fn deduplicate_overlapping(mut anomalies: Vec<Anomaly>) -> Vec<Anomaly> {
    if anomalies.len() <= 1 {
        return anomalies;
    }

    // Sort by severity descending then by number of affected events descending
    // so that when we encounter overlaps, the first one wins.
    anomalies.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.affected_event_ids.len().cmp(&a.affected_event_ids.len()))
    });

    let mut kept: Vec<Anomaly> = Vec::new();

    for candidate in anomalies {
        let dominated = kept.iter().any(|existing| {
            let shared = candidate
                .affected_event_ids
                .iter()
                .filter(|id| existing.affected_event_ids.contains(id))
                .count();
            shared >= WINDOW_SIZE - 1 // 4 of 5 shared
        });
        if !dominated {
            kept.push(candidate);
        }
    }

    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::models::{IntuneEventType, IntuneStatus};

    fn make_event(id: u64, status: IntuneStatus, start_time: &str, source: &str) -> IntuneEvent {
        IntuneEvent {
            id,
            event_type: IntuneEventType::Win32App,
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
    fn test_escalation_chain() {
        let events = vec![
            make_event(1, IntuneStatus::Success, "01-01-2024 10:00:00.000", "log.log"),
            make_event(2, IntuneStatus::Success, "01-01-2024 10:01:00.000", "log.log"),
            make_event(3, IntuneStatus::Timeout, "01-01-2024 10:02:00.000", "log.log"),
            make_event(4, IntuneStatus::Failed, "01-01-2024 10:03:00.000", "log.log"),
            make_event(5, IntuneStatus::Failed, "01-01-2024 10:04:00.000", "log.log"),
        ];

        let anomalies = detect_escalation_anomalies(&events);
        assert_eq!(anomalies.len(), 1, "Expected exactly 1 escalation anomaly");
        assert_eq!(anomalies[0].kind, AnomalyKind::SeverityEscalation);
        assert_eq!(anomalies[0].detection_layer, DetectionLayer::Escalation);
        assert_eq!(anomalies[0].affected_event_ids, vec![1, 2, 3, 4, 5]);
        assert_eq!(anomalies[0].title, "Severity escalation detected");
    }

    #[test]
    fn test_no_escalation_flat() {
        let events = vec![
            make_event(1, IntuneStatus::Success, "01-01-2024 10:00:00.000", "log.log"),
            make_event(2, IntuneStatus::Success, "01-01-2024 10:01:00.000", "log.log"),
            make_event(3, IntuneStatus::Success, "01-01-2024 10:02:00.000", "log.log"),
            make_event(4, IntuneStatus::Success, "01-01-2024 10:03:00.000", "log.log"),
            make_event(5, IntuneStatus::Success, "01-01-2024 10:04:00.000", "log.log"),
        ];

        let anomalies = detect_escalation_anomalies(&events);
        assert!(anomalies.is_empty(), "Expected no anomalies for flat severity");
    }

    #[test]
    fn test_no_escalation_improving() {
        let events = vec![
            make_event(1, IntuneStatus::Failed, "01-01-2024 10:00:00.000", "log.log"),
            make_event(2, IntuneStatus::Failed, "01-01-2024 10:01:00.000", "log.log"),
            make_event(3, IntuneStatus::Timeout, "01-01-2024 10:02:00.000", "log.log"),
            make_event(4, IntuneStatus::Success, "01-01-2024 10:03:00.000", "log.log"),
            make_event(5, IntuneStatus::Success, "01-01-2024 10:04:00.000", "log.log"),
        ];

        let anomalies = detect_escalation_anomalies(&events);
        assert!(
            anomalies.is_empty(),
            "Expected no anomalies for de-escalation pattern"
        );
    }

    #[test]
    fn test_short_event_list() {
        let events = vec![
            make_event(1, IntuneStatus::Success, "01-01-2024 10:00:00.000", "log.log"),
            make_event(2, IntuneStatus::Timeout, "01-01-2024 10:01:00.000", "log.log"),
            make_event(3, IntuneStatus::Failed, "01-01-2024 10:02:00.000", "log.log"),
        ];

        let anomalies = detect_escalation_anomalies(&events);
        assert!(
            anomalies.is_empty(),
            "Expected no anomalies with fewer than 5 events"
        );
    }
}
