use std::collections::HashSet;
use std::path::Path;

use chrono::NaiveDateTime;

use super::models::{IntuneEvent, IntuneEventType, IntuneStatus, IntuneTimestampBounds};

struct TimelineEvent {
    event: IntuneEvent,
    parsed_time: Option<NaiveDateTime>,
    source_identity: String,
}

#[derive(Hash, PartialEq, Eq)]
struct PairedEventKey {
    guid: Option<String>,
    event_type: IntuneEventType,
    source_identity: String,
}

#[derive(Hash, PartialEq, Eq)]
struct ExactEventKey {
    source_identity: String,
    event_type: IntuneEventType,
    status: IntuneStatus,
    start_time: Option<String>,
    end_time: Option<String>,
    guid: Option<String>,
    name: String,
    detail: String,
}

/// Sort events chronologically and deduplicate paired events.
/// After `event_tracker::extract_events` has already paired start/end events,
/// this function cleans up the timeline by:
/// 1. Removing "end" events that were consumed by pairing
/// 2. Sorting by start_time
/// 3. Re-assigning sequential IDs
pub fn build_timeline(events: Vec<IntuneEvent>) -> Vec<IntuneEvent> {
    let mut timeline = deduplicate_events(events);

    // Sort by the cached parsed timestamp first, then source+line for deterministic ordering.
    timeline.sort_by(|a, b| {
        a.parsed_time
            .cmp(&b.parsed_time)
            .then_with(|| a.event.source_file.cmp(&b.event.source_file))
            .then_with(|| a.event.line_number.cmp(&b.event.line_number))
            .then_with(|| a.event.name.cmp(&b.event.name))
    });

    // Re-assign sequential IDs and populate epoch timestamps
    for (i, entry) in timeline.iter_mut().enumerate() {
        entry.event.id = i as u64;
        entry.event.start_time_epoch = entry
            .event
            .start_time
            .as_deref()
            .and_then(parse_timestamp)
            .map(|dt| dt.and_utc().timestamp_millis());
        entry.event.end_time_epoch = entry
            .event
            .end_time
            .as_deref()
            .and_then(parse_timestamp)
            .map(|dt| dt.and_utc().timestamp_millis());
    }

    timeline.into_iter().map(|entry| entry.event).collect()
}

/// Remove duplicate or already-consumed events before timeline ordering.
/// This keeps paired start events, drops consumed completion rows when they
/// still leak through, and removes exact duplicate entries from the same file.
fn deduplicate_events(events: Vec<IntuneEvent>) -> Vec<TimelineEvent> {
    let prepared_events: Vec<TimelineEvent> = events
        .into_iter()
        .map(|event| TimelineEvent {
            parsed_time: parsed_event_time(&event),
            source_identity: normalized_source_identity(&event.source_file),
            event,
        })
        .collect();

    let mut paired_keys: HashSet<PairedEventKey> = HashSet::with_capacity(prepared_events.len());
    for prepared_event in &prepared_events {
        if prepared_event.event.end_time.is_some() {
            paired_keys.insert(PairedEventKey {
                guid: prepared_event.event.guid.clone(),
                event_type: prepared_event.event.event_type,
                source_identity: prepared_event.source_identity.clone(),
            });
        }
    }

    let mut seen_exact: HashSet<ExactEventKey> = HashSet::with_capacity(prepared_events.len());
    let mut result = Vec::with_capacity(prepared_events.len());
    for prepared_event in prepared_events {
        let exact_key = ExactEventKey {
            source_identity: prepared_event.source_identity.clone(),
            event_type: prepared_event.event.event_type,
            status: prepared_event.event.status,
            start_time: prepared_event.event.start_time.clone(),
            end_time: prepared_event.event.end_time.clone(),
            guid: prepared_event.event.guid.clone(),
            name: prepared_event.event.name.clone(),
            detail: prepared_event.event.detail.clone(),
        };

        if !seen_exact.insert(exact_key) {
            continue;
        }

        if prepared_event.event.end_time.is_some() {
            result.push(prepared_event);
            continue;
        }

        if prepared_event.event.guid.is_none() {
            result.push(prepared_event);
            continue;
        }

        let key = PairedEventKey {
            guid: prepared_event.event.guid.clone(),
            event_type: prepared_event.event.event_type,
            source_identity: prepared_event.source_identity.clone(),
        };
        let is_consumed_end = matches!(
            prepared_event.event.status,
            IntuneStatus::Success | IntuneStatus::Failed | IntuneStatus::Timeout
        )
            && paired_keys.contains(&key);

        if !is_consumed_end {
            result.push(prepared_event);
        }
    }

    result
}

pub fn normalized_source_identity(source_file: &str) -> String {
    let stem = Path::new(source_file)
        .file_stem()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| source_file.to_string());

    for separator in [".", "-", "_"] {
        if let Some((base, suffix)) = stem.rsplit_once(separator) {
            if is_rotation_suffix(suffix) {
                return base.to_ascii_lowercase();
            }
        }
    }

    stem.to_ascii_lowercase()
}

fn is_rotation_suffix(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    if normalized.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }

    if normalized.starts_with("lo_") || normalized == "bak" || normalized == "old" {
        return true;
    }

    normalized.len() == 8 && normalized.chars().all(|ch| ch.is_ascii_digit())
}

fn parsed_event_time(event: &IntuneEvent) -> Option<NaiveDateTime> {
    event
        .start_time
        .as_deref()
        .and_then(parse_timestamp)
        .or_else(|| event.end_time.as_deref().and_then(parse_timestamp))
}

pub fn parse_timestamp(value: &str) -> Option<NaiveDateTime> {
    const FORMATS: &[&str] = &[
        "%m-%d-%Y %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S%.f",
    ];

    for format in FORMATS {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(value, format) {
            return Some(parsed);
        }
    }

    // RFC 3339 / ISO 8601 with timezone (e.g. "2024-01-15T10:30:00.000Z")
    // IME parser produces timestamp_utc in this format via to_rfc3339_opts().
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.naive_utc())
        .ok()
}

pub fn calculate_timestamp_bounds(events: &[IntuneEvent]) -> Option<IntuneTimestampBounds> {
    let mut earliest: Option<(NaiveDateTime, String)> = None;
    let mut latest: Option<(NaiveDateTime, String)> = None;

    for event in events {
        if let Some(timestamp) = event.start_time.as_deref() {
            update_timestamp_bounds(&mut earliest, &mut latest, timestamp);
        }

        if let Some(timestamp) = event.end_time.as_deref() {
            update_timestamp_bounds(&mut earliest, &mut latest, timestamp);
        }
    }

    match (earliest, latest) {
        (Some((_, first_timestamp)), Some((_, last_timestamp))) => Some(IntuneTimestampBounds {
            first_timestamp: Some(first_timestamp),
            last_timestamp: Some(last_timestamp),
        }),
        _ => None,
    }
}

fn update_timestamp_bounds(
    earliest: &mut Option<(NaiveDateTime, String)>,
    latest: &mut Option<(NaiveDateTime, String)>,
    value: &str,
) {
    let Some(parsed) = parse_timestamp(value) else {
        return;
    };

    match earliest {
        Some((current, current_raw))
            if parsed > *current || (parsed == *current && value >= current_raw.as_str()) => {}
        _ => *earliest = Some((parsed, value.to_string())),
    }

    match latest {
        Some((current, current_raw))
            if parsed < *current || (parsed == *current && value <= current_raw.as_str()) => {}
        _ => *latest = Some((parsed, value.to_string())),
    }
}

/// Calculate the time span covered by a set of events.
/// Returns a human-readable string like "2h 15m 30s".
pub fn calculate_time_span(events: &[IntuneEvent]) -> Option<String> {
    let bounds = calculate_timestamp_bounds(events)?;
    let start = parse_timestamp(bounds.first_timestamp.as_deref()?)?;
    let end = parse_timestamp(bounds.last_timestamp.as_deref()?)?;
    let duration = end.signed_duration_since(start).num_milliseconds() as f64 / 1000.0;

    if duration < 0.0 {
        None
    } else {
        Some(format_duration(duration))
    }
}

/// Estimate duration between two timestamp strings in seconds.
#[cfg(test)]
fn estimate_duration_secs(start: &str, end: &str) -> Option<f64> {
    let parse_seconds = |ts: &str| -> Option<f64> {
        let time_part = ts.split_whitespace().last()?;
        let parts: Vec<&str> = time_part.split(':').collect();
        if parts.len() >= 3 {
            let h: f64 = parts[0].parse().ok()?;
            let m: f64 = parts[1].parse().ok()?;
            let s: f64 = parts[2].parse().ok()?;
            Some(h * 3600.0 + m * 60.0 + s)
        } else {
            None
        }
    };

    let start_secs = parse_seconds(start)?;
    let end_secs = parse_seconds(end)?;

    let diff = end_secs - start_secs;
    if diff >= 0.0 {
        Some(diff)
    } else {
        Some(diff + 86400.0) // crossed midnight
    }
}

/// Format seconds into a human-readable duration string.
fn format_duration(total_secs: f64) -> String {
    let total = total_secs as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0.0), "0s");
        assert_eq!(format_duration(45.0), "45s");
        assert_eq!(format_duration(125.0), "2m 5s");
        assert_eq!(format_duration(3661.0), "1h 1m 1s");
    }

    #[test]
    fn test_estimate_duration() {
        let d = estimate_duration_secs("01-01-2024 10:00:00.000", "01-01-2024 10:05:30.000");
        assert_eq!(d, Some(330.0));
    }

    #[test]
    fn test_estimate_duration_midnight() {
        let d = estimate_duration_secs("01-01-2024 23:59:00.000", "01-02-2024 00:01:00.000");
        assert_eq!(d, Some(120.0));
    }

    #[test]
    fn calculate_timestamp_bounds_prefers_parsed_order() {
        let bounds = calculate_timestamp_bounds(&[
            IntuneEvent {
                id: 0,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Later".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("12-31-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "later".to_string(),
                source_file: "b.log".to_string(),
                line_number: 2,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
            IntuneEvent {
                id: 1,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Earlier".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("01-01-2024 10:00:00.000".to_string()),
                end_time: Some("01-01-2024 10:05:00.000".to_string()),
                duration_secs: None,
                error_code: None,
                detail: "earlier".to_string(),
                source_file: "a.log".to_string(),
                line_number: 1,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
        ])
        .expect("timestamp bounds");

        assert_eq!(bounds.first_timestamp.as_deref(), Some("01-01-2024 10:00:00.000"));
        assert_eq!(bounds.last_timestamp.as_deref(), Some("12-31-2024 10:00:00.000"));
    }

    #[test]
    fn calculate_time_span_uses_parsed_dates() {
        let events = vec![
            IntuneEvent {
                id: 0,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Later".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("12-31-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "later".to_string(),
                source_file: "b.log".to_string(),
                line_number: 2,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
            IntuneEvent {
                id: 1,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Earlier".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("01-01-2024 10:00:00.000".to_string()),
                end_time: Some("01-01-2024 10:05:00.000".to_string()),
                duration_secs: None,
                error_code: None,
                detail: "earlier".to_string(),
                source_file: "a.log".to_string(),
                line_number: 1,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
        ];

        assert_eq!(calculate_time_span(&events), Some("8760h 0m 0s".to_string()));
    }

    #[test]
    fn build_timeline_sorts_by_parsed_timestamp() {
        let timeline = build_timeline(vec![
            IntuneEvent {
                id: 0,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Later".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("12-31-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "later".to_string(),
                source_file: "b.log".to_string(),
                line_number: 2,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
            IntuneEvent {
                id: 1,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Earlier".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("01-01-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "earlier".to_string(),
                source_file: "a.log".to_string(),
                line_number: 1,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
        ]);

        assert_eq!(timeline[0].name, "Earlier");
        assert_eq!(timeline[1].name, "Later");
    }

    #[test]
    fn build_timeline_deduplicates_exact_duplicate_events() {
        let event = IntuneEvent {
            id: 0,
            event_type: super::super::models::IntuneEventType::Win32App,
            name: "Duplicate".to_string(),
            guid: Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string()),
            status: IntuneStatus::Success,
            start_time: Some("01-01-2024 10:00:00.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "same".to_string(),
            source_file: "a.log".to_string(),
            line_number: 1,
            start_time_epoch: None,
            end_time_epoch: None,
            script_body: None,
            parent_app_guid: None,
        };

        let timeline = build_timeline(vec![event.clone(), event]);
        assert_eq!(timeline.len(), 1);
    }

    #[test]
    fn build_timeline_deduplicates_rotated_duplicate_events() {
        let event = IntuneEvent {
            id: 0,
            event_type: super::super::models::IntuneEventType::ContentDownload,
            name: "AppWorkload Hash Validation (abcd1234...)".to_string(),
            guid: Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string()),
            status: IntuneStatus::Failed,
            start_time: Some("01-15-2024 10:00:00.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "Hash validation failed after staging cached content".to_string(),
            source_file: "C:/Logs/AppWorkload.log".to_string(),
            line_number: 12,
            start_time_epoch: None,
            end_time_epoch: None,
            script_body: None,
            parent_app_guid: None,
        };

        let mut rotated = event.clone();
        rotated.id = 1;
        rotated.source_file = "C:/Logs/AppWorkload-1.log".to_string();
        rotated.line_number = 44;

        let timeline = build_timeline(vec![event, rotated]);
        assert_eq!(timeline.len(), 1);
    }

    #[test]
    fn build_timeline_populates_epoch_fields() {
        let timeline = build_timeline(vec![
            IntuneEvent {
                id: 0,
                event_type: IntuneEventType::Win32App,
                name: "Test".to_string(),
                guid: None,
                status: IntuneStatus::Success,
                start_time: Some("01-15-2024 10:30:00.000".to_string()),
                end_time: Some("01-15-2024 10:35:00.000".to_string()),
                duration_secs: Some(300.0),
                error_code: None,
                detail: "test".to_string(),
                source_file: "a.log".to_string(),
                line_number: 1,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
            IntuneEvent {
                id: 1,
                event_type: IntuneEventType::Win32App,
                name: "NoTime".to_string(),
                guid: None,
                status: IntuneStatus::Pending,
                start_time: None,
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "no time".to_string(),
                source_file: "b.log".to_string(),
                line_number: 1,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
        ]);

        let timed = &timeline[1]; // sorted after NoTime (which has None timestamp)
        assert!(timed.start_time_epoch.is_some(), "start_time_epoch should be populated");
        assert!(timed.end_time_epoch.is_some(), "end_time_epoch should be populated");

        let untimed = &timeline[0]; // None timestamps sort first
        assert!(untimed.start_time_epoch.is_none());
        assert!(untimed.end_time_epoch.is_none());
    }

    #[test]
    fn parse_timestamp_handles_rfc3339() {
        let result = parse_timestamp("2024-01-15T10:30:00.000Z");
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.hour(), 10);
        assert_eq!(dt.minute(), 30);
    }

    #[test]
    fn parse_timestamp_handles_rfc3339_with_offset() {
        let result = parse_timestamp("2024-01-15T10:30:00.000+05:00");
        assert!(result.is_some());
        let dt = result.unwrap();
        // naive_utc converts to UTC: 10:30 +05:00 = 05:30 UTC
        assert_eq!(dt.hour(), 5);
        assert_eq!(dt.minute(), 30);
    }

    #[test]
    fn build_timeline_sorts_rfc3339_timestamps_across_files() {
        let timeline = build_timeline(vec![
            IntuneEvent {
                id: 0,
                event_type: IntuneEventType::Win32App,
                name: "Later".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("2024-12-31T10:00:00.000Z".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "later".to_string(),
                source_file: "b.log".to_string(),
                line_number: 2,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
            IntuneEvent {
                id: 1,
                event_type: IntuneEventType::Win32App,
                name: "Earlier".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("2024-01-01T10:00:00.000Z".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "earlier".to_string(),
                source_file: "a.log".to_string(),
                line_number: 1,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
        ]);

        // Events should be interleaved by time, not grouped by file
        assert_eq!(timeline[0].name, "Earlier");
        assert_eq!(timeline[0].source_file, "a.log");
        assert_eq!(timeline[1].name, "Later");
        assert_eq!(timeline[1].source_file, "b.log");
        assert!(timeline[0].start_time_epoch.is_some());
        assert!(timeline[1].start_time_epoch.is_some());
    }

    #[test]
    fn build_timeline_reassigns_ids_after_sorting() {
        let timeline = build_timeline(vec![
            IntuneEvent {
                id: 41,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Later".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("12-31-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "later".to_string(),
                source_file: "b.log".to_string(),
                line_number: 2,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
            IntuneEvent {
                id: 99,
                event_type: super::super::models::IntuneEventType::Win32App,
                name: "Earlier".to_string(),
                guid: None,
                status: IntuneStatus::InProgress,
                start_time: Some("01-01-2024 10:00:00.000".to_string()),
                end_time: None,
                duration_secs: None,
                error_code: None,
                detail: "earlier".to_string(),
                source_file: "a.log".to_string(),
                line_number: 1,
                start_time_epoch: None,
                end_time_epoch: None,
                script_body: None,
                parent_app_guid: None,
            },
        ]);

        assert_eq!(timeline[0].id, 0);
        assert_eq!(timeline[1].id, 1);
        assert_eq!(timeline[0].name, "Earlier");
        assert_eq!(timeline[1].name, "Later");
    }
}
