use chrono::{DateTime, Utc};

use super::models::{EspObservationContext, EspTimelineEntry};

pub fn stable_timeline_entry_id(context: &EspObservationContext, ordinal: usize) -> String {
    stable_record_id("timeline", context, ordinal)
}

pub(crate) fn stable_record_id(
    prefix: &str,
    context: &EspObservationContext,
    ordinal: usize,
) -> String {
    format!(
        "{}|{}|{}|{}",
        prefix,
        escape_component(&context.provenance.source_artifact_id),
        escape_component(&context.evidence_ref.evidence_id),
        ordinal
    )
}

pub(crate) fn sort_timeline_entries(
    mut entries: Vec<(usize, EspTimelineEntry)>,
) -> Vec<EspTimelineEntry> {
    entries.sort_by_cached_key(|(ordinal, entry)| {
        (
            timeline_instant(entry),
            timeline_identity_base(entry).to_string(),
            *ordinal,
            entry.entry_id.clone(),
        )
    });
    entries.into_iter().map(|(_, entry)| entry).collect()
}

/// Primary chronological ordering key for a timeline entry.
///
/// `normalized_utc` producers standardize on `SecondsFormat::AutoSi`, but raw
/// evidence can still carry mixed fractional-second widths (e.g. `...05Z` vs
/// `...05.250Z`). Comparing the parsed instant instead of the RFC 3339 string
/// keeps sub-second events in true chronological order — a lexicographic
/// compare would sort `...05.250Z` before `...05Z` because `'.'` < `'Z'`.
/// Entries whose timestamp cannot be parsed fall back to a stable string key so
/// the overall ordering stays total and deterministic.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TimelineInstant {
    At(DateTime<Utc>),
    Unresolved(String),
}

fn timeline_instant(entry: &EspTimelineEntry) -> TimelineInstant {
    match entry
        .timestamp
        .normalized_utc
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
    {
        Some(parsed) => TimelineInstant::At(parsed.with_timezone(&Utc)),
        None => TimelineInstant::Unresolved(
            entry
                .timestamp
                .normalized_utc
                .clone()
                .unwrap_or_else(|| entry.timestamp.raw_text.clone()),
        ),
    }
}

fn timeline_identity_base(entry: &EspTimelineEntry) -> &str {
    entry
        .entry_id
        .rsplit_once('|')
        .map(|(base, _)| base)
        .unwrap_or(&entry.entry_id)
}

fn escape_component(value: &str) -> String {
    value.replace('%', "%25").replace('|', "%7C")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esp::models::{EspTimelineKind, EspTimestamp, EspTimestampKind};

    fn timeline_entry(entry_id: &str, normalized_utc: &str) -> EspTimelineEntry {
        EspTimelineEntry {
            entry_id: entry_id.to_string(),
            timestamp: EspTimestamp {
                raw_text: normalized_utc.to_string(),
                original_offset: Some("Z".to_string()),
                normalized_utc: Some(normalized_utc.to_string()),
                kind: EspTimestampKind::Utc,
            },
            kind: EspTimelineKind::Other,
            title: "event".to_string(),
            detail: None,
            status: None,
            evidence: Vec::new(),
        }
    }

    fn sorted_timestamps(entries: Vec<(usize, EspTimelineEntry)>) -> Vec<String> {
        sort_timeline_entries(entries)
            .into_iter()
            .map(|entry| entry.timestamp.normalized_utc.unwrap())
            .collect()
    }

    #[test]
    fn whole_second_sorts_before_same_second_subsecond_event() {
        // Ingest order deliberately places the whole-second entry first and the
        // sub-second entry second. The old lexicographic key ordered
        // "...05.250Z" before "...05Z" because '.' (0x2E) < 'Z' (0x5A), which
        // inverts chronology; the parsed-instant key must keep 05 before 05.250.
        let entries = vec![
            (0usize, timeline_entry("timeline|a|b|0", "2026-07-15T12:00:05Z")),
            (
                1usize,
                timeline_entry("timeline|a|b|1", "2026-07-15T12:00:05.250Z"),
            ),
        ];
        assert_eq!(
            sorted_timestamps(entries),
            vec![
                "2026-07-15T12:00:05Z".to_string(),
                "2026-07-15T12:00:05.250Z".to_string(),
            ],
        );
    }

    #[test]
    fn differing_fractional_widths_sort_chronologically() {
        // .100 (100ms) must sort before .100000001 (100ms + 1ns). A string
        // compare of "...100000001Z" vs "...100Z" places the longer value first
        // because '0' (0x30) < 'Z' (0x5A) at the diverging position.
        let entries = vec![
            (
                0usize,
                timeline_entry("timeline|a|b|0", "2026-07-15T12:00:05.100000001Z"),
            ),
            (
                1usize,
                timeline_entry("timeline|a|b|1", "2026-07-15T12:00:05.100Z"),
            ),
        ];
        assert_eq!(
            sorted_timestamps(entries),
            vec![
                "2026-07-15T12:00:05.100Z".to_string(),
                "2026-07-15T12:00:05.100000001Z".to_string(),
            ],
        );
    }
}
