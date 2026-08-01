//! Conservative findings derived from a [`CompanyPortalLogSnapshot`].
//!
//! One private `push_*` per rule, each of which either cites the records it rests
//! on or names the coverage gap that prevented a stronger claim. A finding that
//! cites neither is an assertion rather than a diagnosis, and
//! [`IntuneFinding::is_evidence_backed`] exists so that invariant is testable
//! rather than review-enforced.
//!
//! Nothing here interprets *what* Company Portal was doing. Classifying a record
//! as an enrollment or sign-in event needs a validated vocabulary from real
//! sanitized corpora, and inventing one would produce confident, wrong workflow
//! claims. These rules stay on ground the evidence actually covers: what was
//! collected, what was readable, and what the app itself called an error.

use crate::intune::evidence::{
    IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence, IntuneFindingSeverity,
};

use super::models::{
    CompanyPortalCaptureState, CompanyPortalLogRecord, CompanyPortalLogRejection,
    CompanyPortalLogSnapshot, CompanyPortalRecordProfile,
};

/// Evidence references a single finding carries.
///
/// A busy device writes tens of thousands of records; a finding listing every
/// one of them is unreadable and bloats an export without adding information.
/// The count that mattered is stated in the summary, and the snapshot still
/// holds every record.
const MAX_FINDING_EVIDENCE: usize = 10;

/// Derive every finding this leaf supports, in a stable order.
pub fn derive_findings(snapshot: &CompanyPortalLogSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_no_confirmed_app_log(snapshot, &mut findings);
    push_foreign_artifacts(snapshot, &mut findings);
    push_incomplete_captures(snapshot, &mut findings);
    push_unknown_app_version(snapshot, &mut findings);
    push_malformed_records(snapshot, &mut findings);
    push_advanced_logging_privacy(snapshot, &mut findings);
    push_failure_records(snapshot, &mut findings);

    findings
}

/// No artifact was confirmed as a direct app log, so nothing below can be said.
fn push_no_confirmed_app_log(snapshot: &CompanyPortalLogSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.artifacts.is_empty()
        || snapshot
            .artifacts
            .iter()
            .any(|artifact| artifact.detection.confirmed)
    {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "company-portal-macos-logs/no-confirmed-app-log".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "No direct Company Portal application log was confirmed".to_owned(),
        summary: format!(
            "{} artifact(s) were supplied and none matched the Company Portal application-log \
             grammar, so no conclusion about Company Portal activity can be drawn from this \
             collection.",
            snapshot.artifacts.len()
        ),
        recommended_checks: vec![
            "Collect ~/Library/Logs/CompanyPortal/ while the signed-in user is logged on".to_owned(),
            "Confirm the collection captured the application log rather than a saved diagnostic report".to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: snapshot
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect(),
    });
}

/// An artifact was collected but belongs to a different source kind.
fn push_foreign_artifacts(snapshot: &CompanyPortalLogSnapshot, findings: &mut Vec<IntuneFinding>) {
    let foreign: Vec<&str> = snapshot
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.detection.rejection,
                Some(CompanyPortalLogRejection::DiagnosticReport)
                    | Some(CompanyPortalLogRejection::UnifiedLogExport)
                    | Some(CompanyPortalLogRejection::ForeignProcess)
            )
        })
        .map(|artifact| artifact.artifact_id.as_str())
        .collect();

    if foreign.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "company-portal-macos-logs/artifact-is-another-source-kind".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Collected artifact is not a direct Company Portal application log".to_owned(),
        summary: format!(
            "{} artifact(s) were recognized as a saved diagnostic report, a unified-log export, or \
             another process's log. They are retained in coverage but contribute no direct \
             application-log records.",
            foreign.len()
        ),
        recommended_checks: vec![
            "Route saved diagnostic reports and unified-log exports to their own analyzers".to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: foreign.into_iter().map(str::to_owned).collect(),
    });
}

/// An expected artifact was missing, denied, capped, skipped, or unreadable.
fn push_incomplete_captures(
    snapshot: &CompanyPortalLogSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let incomplete: Vec<&str> = snapshot
        .artifacts
        .iter()
        .filter(|artifact| artifact.capture_state != CompanyPortalCaptureState::Captured)
        .map(|artifact| artifact.artifact_id.as_str())
        .collect();

    if incomplete.is_empty() {
        return;
    }

    findings.push(IntuneFinding {
        finding_id: "company-portal-macos-logs/incomplete-capture".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Some Company Portal log evidence was not fully collected".to_owned(),
        summary: format!(
            "{} artifact(s) were missing, truncated, denied, skipped, unsupported, or unreadable. \
             The absence of a signal in this collection therefore proves nothing about the device.",
            incomplete.len()
        ),
        recommended_checks: vec![
            "Re-collect with permission to read the signed-in user's Library/Logs directory".to_owned(),
            "Include every rotation member, not only the live file".to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: incomplete.into_iter().map(str::to_owned).collect(),
    });
}

/// Records declared an app version outside the supported set.
fn push_unknown_app_version(
    snapshot: &CompanyPortalLogSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.unknown_app_versions.is_empty() {
        return;
    }

    let evidence = evidence_for(snapshot, |record| {
        record
            .app_version
            .as_ref()
            .is_some_and(|version| snapshot.unknown_app_versions.contains(version))
    });

    findings.push(IntuneFinding {
        finding_id: "company-portal-macos-logs/unknown-app-version".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::Low,
        title: "Company Portal reported an app version this build has not validated".to_owned(),
        summary: format!(
            "Version(s) {} are outside the validated set. Records were parsed and preserved in \
             full, but field meanings are not guaranteed for this version.",
            snapshot.unknown_app_versions.join(", ")
        ),
        recommended_checks: vec![
            "Re-validate the record grammar against this Company Portal version".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

/// Records were present that this build could not decompose.
fn push_malformed_records(snapshot: &CompanyPortalLogSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.stats.malformed_records == 0 {
        return;
    }

    let evidence = evidence_for(snapshot, |record| {
        record.profile == CompanyPortalRecordProfile::Unrecognized
    });

    findings.push(IntuneFinding {
        finding_id: "company-portal-macos-logs/unreadable-records".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Some Company Portal records could not be decomposed".to_owned(),
        summary: format!(
            "{} of {} records were truncated or did not match the known field shape. Their text is \
             preserved verbatim, but their fields are unavailable for filtering.",
            snapshot.stats.malformed_records, snapshot.stats.total_records
        ),
        recommended_checks: vec![
            "Check whether the log was copied while the app was mid-write".to_owned(),
            "Collect the adjacent rotation member to recover the truncated record".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

/// Advanced logging was on, which widens what the log contains.
fn push_advanced_logging_privacy(
    snapshot: &CompanyPortalLogSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if !snapshot.advanced_logging_observed {
        return;
    }

    let evidence = evidence_for(snapshot, CompanyPortalLogRecord::is_advanced);

    findings.push(IntuneFinding {
        finding_id: "company-portal-macos-logs/advanced-logging-enabled".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Company Portal advanced logging is enabled".to_owned(),
        summary: format!(
            "{} record(s) carry advanced-logging detail, which can include certificate and \
             network-response material. Share this log only through the redacted export.",
            snapshot.stats.advanced_records
        ),
        recommended_checks: vec![
            "Use the redacted export before attaching these logs to a support case".to_owned(),
            "Turn advanced logging off once the reproduction is captured".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

/// The app itself classified records as errors.
fn push_failure_records(snapshot: &CompanyPortalLogSnapshot, findings: &mut Vec<IntuneFinding>) {
    let failures = snapshot.stats.severity_counts.error + snapshot.stats.severity_counts.fatal;
    if failures == 0 {
        return;
    }

    let evidence = evidence_for(snapshot, |record| {
        record
            .severity
            .as_ref()
            .is_some_and(super::models::CompanyPortalSeverity::is_failure)
    });

    findings.push(IntuneFinding {
        finding_id: "company-portal-macos-logs/error-records-present".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Company Portal logged error-severity records".to_owned(),
        summary: format!(
            "{failures} record(s) carry an error or fatal severity assigned by Company Portal \
             itself. The severity is the app's own classification; the cause is not inferred here."
        ),
        recommended_checks: vec![
            "Read the cited records and their continuation payloads in full".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

/// Evidence references for the first [`MAX_FINDING_EVIDENCE`] matching records.
fn evidence_for(
    snapshot: &CompanyPortalLogSnapshot,
    predicate: impl Fn(&CompanyPortalLogRecord) -> bool,
) -> Vec<IntuneEvidenceRef> {
    snapshot
        .records
        .iter()
        .filter(|record| predicate(record))
        .take(MAX_FINDING_EVIDENCE)
        .map(|record| record.context.evidence_ref.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::portal::macos::company_portal::logs::{
        analyze_company_portal_logs, CompanyPortalLogSource,
    };

    fn source(file_name: &str, content: &str) -> CompanyPortalLogSource {
        CompanyPortalLogSource::captured("cp", file_name, content, "2026-07-31T00:00:00Z")
    }

    fn ids(findings: &[IntuneFinding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect()
    }

    #[test]
    fn every_finding_cites_evidence_or_a_coverage_gap() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Logging | version=9.0.1 | starting\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | E | 1 | Network | category=Http | activity=0x1 | failed\n",
            "2026-03-12 09:14:24:000 | CompanyPortal | I\n",
        );
        let snapshot = analyze_company_portal_logs(&[source("CompanyPortal.log", content)]);
        let findings = derive_findings(&snapshot);
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
    fn a_clean_capture_produces_no_findings() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Catalog | listing apps\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | I | 1 | Catalog | listed 3 apps\n",
        );
        let snapshot = analyze_company_portal_logs(&[source("CompanyPortal.log", content)]);
        assert!(derive_findings(&snapshot).is_empty());
    }

    #[test]
    fn a_refused_artifact_raises_both_the_foreign_and_no_confirmed_rules() {
        let snapshot = analyze_company_portal_logs(&[source(
            "CompanyPortal.log",
            "Timestamp                       Thread     Type        Activity             PID\n",
        )]);
        let findings = derive_findings(&snapshot);
        assert!(ids(&findings).contains(&"company-portal-macos-logs/no-confirmed-app-log"));
        assert!(
            ids(&findings).contains(&"company-portal-macos-logs/artifact-is-another-source-kind")
        );
    }

    #[test]
    fn an_incomplete_capture_is_reported_as_a_coverage_gap() {
        let mut absent = source("CompanyPortal-1.log", "");
        absent.capture_state = CompanyPortalCaptureState::Absent;
        absent.content = None;
        absent.artifact_id = "cp-1".to_owned();

        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Catalog | listing apps\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | I | 1 | Catalog | listed 3 apps\n",
        );
        let snapshot =
            analyze_company_portal_logs(&[source("CompanyPortal.log", content), absent]);
        let findings = derive_findings(&snapshot);
        let gap = findings
            .iter()
            .find(|finding| finding.finding_id.ends_with("incomplete-capture"))
            .expect("an absent rotation must be reported");
        assert_eq!(gap.coverage_gap_ids, vec!["cp-1".to_owned()]);
        assert!(gap.evidence.is_empty());
    }

    #[test]
    fn finding_evidence_is_bounded() {
        let mut content = String::new();
        for index in 0..(MAX_FINDING_EVIDENCE + 5) {
            content.push_str(&format!(
                "2026-03-12 09:14:{:02}:000 | CompanyPortal | E | 1 | Catalog | failure {index}\n",
                index
            ));
        }
        let snapshot = analyze_company_portal_logs(&[source("CompanyPortal.log", &content)]);
        let findings = derive_findings(&snapshot);
        let errors = findings
            .iter()
            .find(|finding| finding.finding_id.ends_with("error-records-present"))
            .expect("error records must be reported");
        assert_eq!(errors.evidence.len(), MAX_FINDING_EVIDENCE);
        assert!(errors.summary.contains("15 record(s)"));
    }
}
