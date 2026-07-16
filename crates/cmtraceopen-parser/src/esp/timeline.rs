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
    entries.sort_by(|(left_ordinal, left), (right_ordinal, right)| {
        timeline_sort_key(left)
            .cmp(timeline_sort_key(right))
            .then_with(|| left_ordinal.cmp(right_ordinal))
    });
    entries.into_iter().map(|(_, entry)| entry).collect()
}

fn timeline_sort_key(entry: &EspTimelineEntry) -> &str {
    entry
        .timestamp
        .normalized_utc
        .as_deref()
        .unwrap_or(&entry.timestamp.raw_text)
}

fn escape_component(value: &str) -> String {
    value.replace('%', "%25").replace('|', "%7C")
}
