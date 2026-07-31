//! Correlation between unified-log evidence and direct Company Portal logs.
//!
//! Unified-log evidence corroborates the direct app log; it does not replace it.
//! A merge is permitted **only** on an explicit shared identifier or a reviewed,
//! documented relationship.
//!
//! # Why time never merges
//!
//! Company Portal, `IntuneMdmAgent`, and `IntuneMdmDaemon` all log
//! concurrently, and unified-log timestamps are microsecond-resolution wall
//! clock. Two records sharing an instant is ordinary concurrency, not evidence
//! of a shared operation — and on a busy device it is common. A time-only
//! coincidence is therefore reported as a *rejection*: it stays visible as a
//! near-miss with [`PortalEvidenceConfidence::Low`], but
//! [`PortalCorrelationRejection::merged`] is always `false`.

use super::models::*;

/// Whether a basis is strong enough to justify merging two observations.
///
/// This is the single point of truth for the merge rule. Time coincidence is
/// the only basis that never qualifies.
pub fn merge_is_permitted(basis: &PortalMergeBasis) -> bool {
    !matches!(basis, PortalMergeBasis::TimeOnly)
}

/// Confidence attached to a given merge basis.
fn confidence_for(basis: &PortalMergeBasis) -> PortalEvidenceConfidence {
    match basis {
        PortalMergeBasis::ActivityId
        | PortalMergeBasis::SignpostId
        | PortalMergeBasis::RequestId
        | PortalMergeBasis::CorrelationId => PortalEvidenceConfidence::Exact,
        PortalMergeBasis::DocumentedRelationship => PortalEvidenceConfidence::Strong,
        PortalMergeBasis::TimeOnly => PortalEvidenceConfidence::Low,
    }
}

/// Finds the strongest explicit key shared by an anchor and an evidence item.
///
/// Keys are checked in a fixed order so the result is deterministic when more
/// than one matches.
fn explicit_match(
    anchor: &PortalDirectLogAnchor,
    evidence: &PortalUnifiedLogEvidence,
) -> Option<(PortalMergeBasis, String)> {
    let ids = &evidence.activity;
    let candidates: [(PortalMergeBasis, Option<&str>, Option<&str>); 5] = [
        (
            PortalMergeBasis::ActivityId,
            anchor.activity_id.as_deref(),
            ids.activity_id.as_deref(),
        ),
        (
            PortalMergeBasis::SignpostId,
            anchor.signpost_id.as_deref(),
            ids.signpost_id.as_deref(),
        ),
        (
            PortalMergeBasis::RequestId,
            anchor.request_id.as_deref(),
            ids.request_id.as_deref(),
        ),
        (
            PortalMergeBasis::CorrelationId,
            anchor.correlation_id.as_deref(),
            ids.correlation_id.as_deref(),
        ),
        (
            PortalMergeBasis::DocumentedRelationship,
            anchor.documented_relationship_id.as_deref(),
            ids.trace_id.as_deref(),
        ),
    ];

    candidates
        .into_iter()
        .find_map(|(basis, left, right)| match (left, right) {
            (Some(a), Some(b)) if !a.is_empty() && a == b => Some((basis, a.to_string())),
            _ => None,
        })
}

/// True when two timestamps denote the same instant, or the same literal text
/// when neither can be resolved to an absolute instant.
fn same_instant(left: &PortalTimestamp, right: &PortalTimestamp) -> bool {
    match (&left.normalized_utc, &right.normalized_utc) {
        (Some(a), Some(b)) => a == b,
        _ => !left.raw_text.is_empty() && left.raw_text == right.raw_text,
    }
}

/// Correlates reduced unified-log evidence against direct Company Portal anchors.
///
/// Output ordering is deterministic: anchors in supplied order, evidence in
/// exact source sequence.
pub fn correlate_with_direct_logs(
    reduction: &PortalUnifiedLogReduction,
    anchors: &[PortalDirectLogAnchor],
) -> PortalCorrelationResult {
    let mut result = PortalCorrelationResult::default();

    for anchor in anchors {
        for evidence in &reduction.evidence {
            if let Some((basis, matched_value)) = explicit_match(anchor, evidence) {
                let confidence = confidence_for(&basis);
                let merged = merge_is_permitted(&basis);
                result.links.push(PortalCorrelationLink {
                    anchor_id: anchor.anchor_id.clone(),
                    record_id: evidence.record_id.clone(),
                    basis,
                    // Operation handles, not identity: preserved through the
                    // redacted export so an exported reduction can still be
                    // joined. See `redaction` for the reasoning.
                    matched_value: PortalClassifiedString::public(matched_value),
                    confidence,
                    merged,
                });
                continue;
            }

            if same_instant(&anchor.timestamp, &evidence.timestamp) {
                result.rejections.push(PortalCorrelationRejection {
                    anchor_id: anchor.anchor_id.clone(),
                    record_id: evidence.record_id.clone(),
                    basis: PortalMergeBasis::TimeOnly,
                    confidence: PortalEvidenceConfidence::Low,
                    merged: false,
                    detail: format!(
                        "anchor `{}` and record `{}` share an instant but no explicit activity, \
                         signpost, request, or correlation identifier; a time-only join is low \
                         confidence and never merges",
                        anchor.anchor_id, evidence.record_id
                    ),
                });
            }
        }
    }

    result
}
