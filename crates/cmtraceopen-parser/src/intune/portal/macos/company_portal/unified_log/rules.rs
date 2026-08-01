//! Conservative findings derived from a reduced capture.
//!
//! Every rule is a private `push_*` over the immutable snapshot, in a fixed
//! order, so the output is deterministic. A rule emits only when its triggering
//! evidence is present, and every finding it produces cites either the
//! observations it was built from or the coverage gap that blocked it — the
//! invariant [`IntuneFinding::is_evidence_backed`] exists to check.
//!
//! What no rule here will do:
//!
//! * promote an `error`-level unified-log record to a root cause. Unified-log
//!   evidence corroborates a direct Company Portal log; on its own it is a
//!   symptom, so these findings cap out at medium confidence;
//! * treat the absence of a signal in a capped, skipped, or predicate-mismatched
//!   capture as proof that the signal never occurred;
//! * merge or conclude across records that share only an instant in time.

use std::collections::BTreeSet;

use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity,
};

use super::models::*;
use super::schema::{UnifiedLogCaptureCompleteness, UnifiedLogRejectReason};

/// Derive read-only findings from an immutable reduced capture.
pub fn derive_findings(analysis: &UnifiedLogAnalysis) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_artifact_not_collected(analysis, &mut findings);
    push_unsupported_schema(analysis, &mut findings);
    push_malformed_records(analysis, &mut findings);
    push_capture_truncated(analysis, &mut findings);
    push_predicate_mismatch(analysis, &mut findings);
    push_failure_records(analysis, &mut findings);
    push_privacy_limited_evidence(analysis, &mut findings);
    push_unanchored_timestamps(analysis, &mut findings);
    push_sequence_anomalies(analysis, &mut findings);
    push_no_relevant_records(analysis, &mut findings);

    findings
}

// ── Rules ───────────────────────────────────────────────────────────────────

/// An expected capture that never produced bytes.
fn push_artifact_not_collected(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let gaps = analysis
        .coverage
        .iter()
        .filter(|entry| {
            matches!(
                entry.status,
                IntuneArtifactStatus::Missing
                    | IntuneArtifactStatus::PermissionDenied
                    | IntuneArtifactStatus::Skipped
            )
        })
        .map(|entry| entry.artifact_id.clone())
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-capture-not-collected".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "A unified-log capture was not collected".to_owned(),
        summary: format!(
            "{} expected unified-log capture(s) were absent, skipped, or refused by the \
             operating system, so the absence of a Company Portal signal in this bundle \
             proves nothing.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Re-run the collector with Full Disk Access granted and confirm the capture window \
             covers the reported problem."
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

/// A payload this build cannot interpret at all.
fn push_unsupported_schema(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let gaps = analysis
        .captures
        .iter()
        .filter(|capture| {
            capture.rejected.iter().any(|rejection| {
                matches!(
                    rejection.reason,
                    UnifiedLogRejectReason::UnknownSchema
                        | UnifiedLogRejectReason::UnsupportedVersion
                )
            })
        })
        .map(|capture| capture.artifact_id.clone())
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-unsupported-schema".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "A capture declared a schema this build cannot read".to_owned(),
        summary: format!(
            "{} capture(s) declared a normalized schema identifier or version this build does \
             not implement. Field semantics are unknown, so no record was parsed rather than \
             parsed on a guess.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Re-collect with a collector matching this build, or upgrade the analyzer to a \
             version that declares the capture's schema."
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

/// Lines that were lost, while the rest of the capture survived.
fn push_malformed_records(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let mut gaps = Vec::new();
    let mut lost = 0usize;
    for capture in &analysis.captures {
        let malformed = capture
            .rejected
            .iter()
            .filter(|rejection| {
                matches!(
                    rejection.reason,
                    UnifiedLogRejectReason::MalformedJson
                        | UnifiedLogRejectReason::MissingHeader
                        | UnifiedLogRejectReason::UnknownRecordType
                        | UnifiedLogRejectReason::EmptyPayload
                )
            })
            .count();
        if malformed > 0 {
            gaps.push(capture.artifact_id.clone());
            lost += malformed;
        }
    }
    if gaps.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-malformed-records".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Some capture lines could not be read".to_owned(),
        summary: format!(
            "{lost} line(s) across {} capture(s) were not valid normalized records and were \
             skipped. The surrounding records were kept, but this capture is incomplete and a \
             missing signal may simply have been on a lost line.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Check the collector for a truncated write or an interleaved writer, then re-collect."
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

/// A capture that hit a limit, from either the manifest state or its own header.
fn push_capture_truncated(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let gaps = analysis
        .captures
        .iter()
        .filter(|capture| is_truncated(capture))
        .map(|capture| capture.artifact_id.clone())
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-capture-truncated".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "A unified-log capture was truncated".to_owned(),
        summary: format!(
            "{} capture(s) stopped short of everything the predicate matched. Any conclusion \
             drawn from a signal that is *not* present in these captures is unsupported.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Re-collect with a narrower time window or a higher record cap so the capture is \
             complete."
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

fn is_truncated(capture: &UnifiedLogCaptureSummary) -> bool {
    if capture.capture_state == UnifiedLogCaptureState::Capped {
        return true;
    }
    let Some(coverage) = capture.coverage.as_ref() else {
        return false;
    };
    if matches!(
        coverage.completeness,
        UnifiedLogCaptureCompleteness::Capped | UnifiedLogCaptureCompleteness::Partial
    ) {
        return true;
    }
    matches!(
        (coverage.records_matched, coverage.records_emitted),
        (Some(matched), Some(emitted)) if matched > emitted
    )
}

/// A capture produced by a selection rule this build does not implement.
fn push_predicate_mismatch(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let gaps = analysis
        .captures
        .iter()
        .filter(|capture| capture.predicate_mismatch)
        .map(|capture| capture.artifact_id.clone())
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-predicate-mismatch".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "A capture ran a different source-selection rule".to_owned(),
        summary: format!(
            "{} capture(s) declared a predicate identifier or version other than the one this \
             build implements. The records present are still evidence; the records *absent* \
             cannot be assumed to have been in scope.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Re-collect using the predicate this build reports, then compare the two captures."
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

/// Error- and fault-level Company Portal records.
fn push_failure_records(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let failures = analysis
        .relevant_observations()
        .filter(|observation| observation.level.is_failure())
        .collect::<Vec<_>>();
    if failures.is_empty() {
        return;
    }

    let has_fault = failures
        .iter()
        .any(|observation| observation.level == UnifiedLogLevel::Fault);

    findings.push(IntuneFinding {
        finding_id: "unified-log-failures-observed".to_owned(),
        severity: if has_fault {
            IntuneFindingSeverity::Error
        } else {
            IntuneFindingSeverity::Warning
        },
        // Capped at medium on purpose: a unified-log error is a symptom the
        // Company Portal process reported, not proof of the operation's outcome.
        // Raising it would let corroborating evidence outrank the direct log.
        confidence: IntuneFindingConfidence::Medium,
        title: "Company Portal logged failures to the unified log".to_owned(),
        summary: format!(
            "{} Company Portal record(s) were logged at error or fault level, covering: {}.",
            failures.len(),
            activity_labels(failures.iter().map(|observation| observation.activity_kind)),
        ),
        recommended_checks: vec![
            "Correlate the cited records with the direct Company Portal log on a shared activity \
             or request identifier before treating them as a cause."
                .to_owned(),
        ],
        evidence: evidence_refs(failures.iter().copied()),
        coverage_gap_ids: Vec::new(),
    });
}

/// Evidence Apple's own privacy filter had already stripped.
fn push_privacy_limited_evidence(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let masked = analysis
        .relevant_observations()
        .filter(|observation| observation.apple_redacted_values > 0)
        .collect::<Vec<_>>();
    if masked.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-privacy-masked-values".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Records arrived with values already masked by the operating system".to_owned(),
        summary: format!(
            "{} Company Portal record(s) contain values Apple's privacy filter replaced with \
             <private> before the record was written. Those values are unrecoverable from this \
             capture and their absence is not a defect in the collector.",
            masked.len()
        ),
        recommended_checks: vec![
            "Install the Company Portal logging profile that enables private data, reproduce, and \
             re-collect if the masked values are needed."
                .to_owned(),
        ],
        evidence: evidence_refs(masked.iter().copied()),
        coverage_gap_ids: Vec::new(),
    });
}

/// Records that cannot be aligned with evidence from another source.
fn push_unanchored_timestamps(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let unanchored = analysis
        .relevant_observations()
        .filter(|observation| observation.boot_relative_only)
        .collect::<Vec<_>>();
    if unanchored.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-unanchored-timestamps".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Some records carry no wall-clock time".to_owned(),
        summary: format!(
            "{} Company Portal record(s) stated no usable timezone, so only their boot-relative \
             or offset-free time is known. They remain ordered by the collector's sequence, but \
             they cannot be aligned against evidence from another source.",
            unanchored.len()
        ),
        recommended_checks: vec![
            "Re-collect with a collector that records the device timezone offset, or correlate \
             these records on an activity or request identifier instead of on time."
                .to_owned(),
        ],
        evidence: evidence_refs(unanchored.iter().copied()),
        coverage_gap_ids: Vec::new(),
    });
}

/// The collector's own ordering disagreeing with itself.
fn push_sequence_anomalies(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    if analysis.sequence_anomalies.is_empty() {
        return;
    }

    let ids = analysis
        .sequence_anomalies
        .iter()
        .flat_map(|anomaly| anomaly.observation_ids.iter())
        .collect::<BTreeSet<_>>();
    let involved = analysis
        .observations
        .iter()
        .filter(|observation| ids.contains(&observation.observation_id))
        .collect::<Vec<_>>();

    let duplicates = analysis
        .sequence_anomalies
        .iter()
        .filter(|anomaly| anomaly.kind == UnifiedLogSequenceAnomalyKind::Duplicate)
        .count();
    let out_of_order = analysis.sequence_anomalies.len() - duplicates;

    findings.push(IntuneFinding {
        finding_id: "unified-log-sequence-anomalies".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "The capture's record sequence is inconsistent".to_owned(),
        summary: format!(
            "{duplicates} duplicate and {out_of_order} out-of-order sequence value(s) were \
             found. Every record was kept in the order it was written; the declared sequence \
             numbers are not a reliable ordering for this capture."
        ),
        recommended_checks: vec![
            "Check whether two collector runs were concatenated into one artifact, then \
             re-collect into separate files."
                .to_owned(),
        ],
        evidence: evidence_refs(involved.iter().copied()),
        coverage_gap_ids: Vec::new(),
    });
}

/// A readable capture in which nothing passed the selection rule.
fn push_no_relevant_records(analysis: &UnifiedLogAnalysis, findings: &mut Vec<IntuneFinding>) {
    let gaps = analysis
        .captures
        .iter()
        .filter(|capture| capture.records_read > 0 && capture.records_relevant == 0)
        .map(|capture| capture.artifact_id.clone())
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "unified-log-no-company-portal-records".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "A capture contained no Company Portal records".to_owned(),
        summary: format!(
            "{} capture(s) were read successfully but contained no record from a known Company \
             Portal subsystem or bundle. A process name or a mention of Company Portal in a \
             message is deliberately not accepted as evidence.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Confirm Company Portal ran inside the capture window, and that the collector used \
             the predicate this build reports."
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// De-duplicated, deterministically ordered evidence references.
fn evidence_refs<'a>(
    observations: impl Iterator<Item = &'a UnifiedLogObservation>,
) -> Vec<IntuneEvidenceRef> {
    observations
        .map(|observation| observation.context.evidence_ref.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Comma-joined, de-duplicated workflow labels for a finding summary.
///
/// Labels only. Message text never reaches a summary: a summary is exported by
/// default, and unified-log messages carry identity.
fn activity_labels(kinds: impl Iterator<Item = UnifiedLogActivityKind>) -> String {
    let labels = kinds
        .map(|kind| match kind {
            UnifiedLogActivityKind::ProcessStartup => "process startup",
            UnifiedLogActivityKind::Authentication => "authentication",
            UnifiedLogActivityKind::EnrollmentProfile => "enrollment or profile",
            UnifiedLogActivityKind::SyncCompliance => "sync or compliance",
            UnifiedLogActivityKind::AppAction => "app actions",
            UnifiedLogActivityKind::DeviceAction => "device actions",
            UnifiedLogActivityKind::NetworkRequest => "network requests",
            UnifiedLogActivityKind::Diagnostics => "diagnostics",
            UnifiedLogActivityKind::Unclassified => "uncategorized activity",
        })
        .collect::<BTreeSet<_>>();
    labels.into_iter().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_analysis_produces_no_findings() {
        let findings = derive_findings(&UnifiedLogAnalysis::default());
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn every_finding_a_rule_can_emit_is_evidence_backed() {
        // Enforced here as well as in the corpus so a new rule cannot ship an
        // uncited finding even before a fixture exercises it.
        let analysis = UnifiedLogAnalysis {
            coverage: vec![crate::intune::evidence::IntuneArtifactCoverage {
                artifact_id: "missing".to_owned(),
                family: "companyPortalMacosUnifiedLog".to_owned(),
                status: IntuneArtifactStatus::Missing,
                detail: None,
                observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
                evidence: Vec::new(),
            }],
            ..UnifiedLogAnalysis::default()
        };
        let findings = derive_findings(&analysis);
        assert!(!findings.is_empty());
        for finding in &findings {
            assert!(
                finding.is_evidence_backed(),
                "{} cites nothing",
                finding.finding_id
            );
        }
    }

    #[test]
    fn activity_labels_are_deduplicated_and_ordered() {
        let labels = activity_labels(
            [
                UnifiedLogActivityKind::Authentication,
                UnifiedLogActivityKind::AppAction,
                UnifiedLogActivityKind::Authentication,
            ]
            .into_iter(),
        );
        assert_eq!(labels, "app actions, authentication");
    }
}
