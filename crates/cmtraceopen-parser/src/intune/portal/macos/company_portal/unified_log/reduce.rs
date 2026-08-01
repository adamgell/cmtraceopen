//! Reduction of a validated capture into Company Portal evidence.
//!
//! Reduction preserves exact source sequence: evidence is emitted in stream
//! order and never re-sorted by timestamp. That matters because unified-log
//! records can share a timestamp to microsecond precision, and because a
//! capture may contain records whose wall clock is unknown entirely.

use std::collections::BTreeMap;

use super::models::*;
use super::schema::PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION;
use super::selection::{classify_category, classify_records, rejection_detail};

/// Fallback artifact id when a capture carried no `captureId`.
const FALLBACK_ARTIFACT_ID: &str = "macos-company-portal-unified-log";

/// Parses and reduces a supplied capture in one step.
pub fn reduce_capture_text(input: &str) -> PortalUnifiedLogReduction {
    reduce_capture_set(super::ingest::parse_capture(input))
}

/// Reduces an already-validated capture into evidence, activities, and coverage.
pub fn reduce_capture_set(capture_set: PortalUnifiedLogCaptureSet) -> PortalUnifiedLogReduction {
    let PortalUnifiedLogCaptureSet {
        schema_id,
        schema_version,
        supported,
        capture,
        records,
        mut coverage,
        mut stats,
        raw_unsupported: _,
    } = capture_set;

    if !supported {
        return PortalUnifiedLogReduction {
            schema_id,
            schema_version,
            supported,
            capture,
            evidence: Vec::new(),
            activities: Vec::new(),
            coverage,
            stats,
        };
    }

    let artifact_id = capture
        .as_ref()
        .map(|c| c.capture_id.clone())
        .unwrap_or_else(|| FALLBACK_ARTIFACT_ID.to_string());

    let verdicts = classify_records(&records);
    let mut evidence = Vec::new();

    for (record, selection) in records.iter().zip(verdicts) {
        if !selection.selected {
            // The id is the entry's own position in the array it is being
            // appended to, so reduction continues ingest's numbering without
            // knowing anything about ingest's counter.
            coverage.push(PortalCoverageEntry {
                coverage_id: coverage_id(coverage.len()),
                status: PortalCoverageStatus::NotSelected,
                scope: PortalCoverageScope::Record,
                detail: rejection_detail(record, &selection),
                stream_index: Some(record.stream_index),
                raw_excerpt: None,
                evidence: Vec::new(),
            });
            continue;
        }

        let kind = classify_category(record.category.as_deref());
        let confidence = confidence_for(&selection, kind.is_some());
        let evidence_id = format!("cp-ul-{:06}", record.stream_index);

        evidence.push(PortalUnifiedLogEvidence {
            evidence: vec![PortalEvidenceRef {
                evidence_id: evidence_id.clone(),
                source_artifact_id: artifact_id.clone(),
            }],
            evidence_id,
            record_id: record.record_id.clone(),
            stream_index: record.stream_index,
            kind: kind.unwrap_or(PortalUnifiedLogEvidenceKind::Unclassified),
            confidence,
            level: record.message_type.level.clone(),
            timestamp: record.timestamp.clone(),
            summary: record.event_message.clone(),
            activity: record.activity.clone(),
            selection,
        });
    }

    stats.records_selected = evidence.len() as u64;
    let activities = build_activity_groups(&records, &evidence);

    PortalUnifiedLogReduction {
        schema_id,
        schema_version,
        supported,
        capture,
        evidence,
        activities,
        coverage,
        stats,
    }
}

fn confidence_for(selection: &PortalSelection, known_category: bool) -> PortalEvidenceConfidence {
    match (&selection.reason, known_category) {
        (PortalSelectionReason::VerifiedProcessAndSubsystem, true) => {
            PortalEvidenceConfidence::Exact
        }
        (PortalSelectionReason::VerifiedProcessAndSubsystem, false) => {
            PortalEvidenceConfidence::Strong
        }
        (PortalSelectionReason::ActivityLinkedToSelected, true) => PortalEvidenceConfidence::Strong,
        _ => PortalEvidenceConfidence::Low,
    }
}

/// Groups selected records by activity identifier, preserving source order.
fn build_activity_groups(
    records: &[PortalUnifiedLogRecord],
    evidence: &[PortalUnifiedLogEvidence],
) -> Vec<PortalActivityGroup> {
    let selected: BTreeMap<u64, &PortalUnifiedLogEvidence> = evidence
        .iter()
        .map(|item| (item.stream_index, item))
        .collect();

    let mut groups: BTreeMap<String, PortalActivityGroup> = BTreeMap::new();

    for record in records {
        if !selected.contains_key(&record.stream_index) {
            continue;
        }
        let Some(activity_id) = record.activity.activity_id.as_deref() else {
            continue;
        };

        let group = groups
            .entry(activity_id.to_string())
            .or_insert_with(|| PortalActivityGroup {
                activity_id: activity_id.to_string(),
                parent_activity_id: None,
                record_ids: Vec::new(),
                signpost_ids: Vec::new(),
                first_stream_index: record.stream_index,
                last_stream_index: record.stream_index,
            });

        if group.parent_activity_id.is_none() {
            group.parent_activity_id = record.activity.parent_activity_id.clone();
        }
        group.record_ids.push(record.record_id.clone());
        if let Some(signpost) = record.activity.signpost_id.as_deref() {
            if !group.signpost_ids.iter().any(|s| s == signpost) {
                group.signpost_ids.push(signpost.to_string());
            }
        }
        group.last_stream_index = record.stream_index;
    }

    let mut groups: Vec<PortalActivityGroup> = groups.into_values().collect();
    groups.sort_by(|a, b| {
        a.first_stream_index
            .cmp(&b.first_stream_index)
            .then_with(|| a.activity_id.cmp(&b.activity_id))
    });
    groups
}

/// Convenience: the selection-predicate version stamped on every verdict.
pub fn selection_predicate_version() -> u32 {
    PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION
}
