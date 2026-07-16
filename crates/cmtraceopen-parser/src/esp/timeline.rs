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
            .then_with(|| timeline_identity_base(left).cmp(timeline_identity_base(right)))
            .then_with(|| left_ordinal.cmp(right_ordinal))
            .then_with(|| left.entry_id.cmp(&right.entry_id))
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
