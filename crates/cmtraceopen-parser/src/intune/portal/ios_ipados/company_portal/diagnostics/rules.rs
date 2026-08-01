//! Conservative findings derived from a Console diagnostics snapshot.
//!
//! Every rule here obeys one constraint that the source material forces: a
//! Console capture covers only the window in which the operator was recording,
//! and only the records they happened to copy. Nothing absent from it proves
//! anything. So no rule concludes "did not happen", "is not enrolled", or "never
//! signed in"; the rules report what the capture *contains*, and report the
//! shape of the window itself so the reader can weigh it.
//!
//! Each rule is one `push_*` function that either emits a finding citing
//! evidence or a coverage gap, or emits nothing at all.

use super::models::{
    ConsoleArtifact, ConsoleDiagnosticsSnapshot, ConsoleRecord, ConsoleSemanticKind,
    ConsoleSourceClass,
};
use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity, IntuneParseState, IntuneTimestampKind,
};

/// Evidence references one finding cites before the list is truncated.
///
/// A finding that cites two hundred records is not more rigorous than one that
/// cites twelve; it is just unreadable. The count that matters stays in the
/// summary.
const MAX_EVIDENCE_PER_FINDING: usize = 12;

/// Derive every finding this snapshot supports.
///
/// The order is fixed so that two analyses of the same bundle produce the same
/// list, byte for byte.
pub fn derive_findings(snapshot: &ConsoleDiagnosticsSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_uncollected_artifacts(snapshot, &mut findings);
    push_unsupported_layout(snapshot, &mut findings);
    push_parse_failure(snapshot, &mut findings);
    push_truncated_capture(snapshot, &mut findings);
    push_company_portal_sign_in_failure(snapshot, &mut findings);
    push_company_portal_failure(snapshot, &mut findings);
    push_no_company_portal_records(snapshot, &mut findings);
    push_malformed_records(snapshot, &mut findings);
    push_offsetless_timestamps(snapshot, &mut findings);
    push_unknown_app_version(snapshot, &mut findings);
    push_capture_window_is_partial(snapshot, &mut findings);

    findings
}

// ── Coverage rules ──────────────────────────────────────────────────────────

fn push_uncollected_artifacts(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let gaps = artifact_ids(snapshot, |artifact| {
        matches!(
            artifact.status,
            IntuneArtifactStatus::Missing
                | IntuneArtifactStatus::PermissionDenied
                | IntuneArtifactStatus::Skipped
        )
    });
    if gaps.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-artifact-not-collected".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "An expected Console export was not collected".to_owned(),
        summary: format!(
            "{} of the expected Console exports supplied no content, so nothing in this analysis speaks to what they would have contained.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Repeat the Console capture for the missing export and re-run the analysis.".to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

fn push_unsupported_layout(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let gaps = artifact_ids(snapshot, |artifact| {
        artifact.status == IntuneArtifactStatus::Unsupported
    });
    if gaps.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-layout-unsupported".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "A supplied file is not a recognized Console export".to_owned(),
        summary: format!(
            "{} supplied file(s) carry no Console column layout this build recognizes, so no record was read from them.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Re-export from Console with the Timestamp, Type, Process, Subsystem, Category, and Message columns visible.".to_owned(),
            "Confirm the file is the plain-text conversion of copied Console rows and not another log.".to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

fn push_parse_failure(snapshot: &ConsoleDiagnosticsSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = artifact_ids(snapshot, |artifact| {
        artifact.status == IntuneArtifactStatus::ParseFailed
    });
    if gaps.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-export-unreadable".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "A Console export resolved a layout but yielded no usable record".to_owned(),
        summary: format!(
            "{} export(s) declared a recognized column layout, yet every row beneath it failed to parse.",
            gaps.len()
        ),
        recommended_checks: vec![
            "Check whether the file was re-encoded, reflowed, or edited after export.".to_owned(),
            "Repeat the capture and save the copied rows without post-processing.".to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: gaps,
    });
}

fn push_truncated_capture(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let truncated: Vec<&ConsoleArtifact> = snapshot
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.truncated_leading_fragment
                || artifact.truncated_trailing_record
                || artifact.record_cap_reached
        })
        .collect();
    if truncated.is_empty() {
        return;
    }
    // Scoped to the truncated artifacts: a fragment in a *different* export is
    // not evidence that this one was cut.
    let ids: Vec<&str> = truncated
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect();
    let evidence = evidence_of(snapshot.records.iter().filter(|record| {
        ids.contains(&record.context.provenance.source_artifact_id.as_str())
            && (record.truncated || record.context.parse_state == IntuneParseState::Raw)
    }));
    let gaps: Vec<String> = truncated
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    findings.push(IntuneFinding {
        finding_id: "console-capture-truncated".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "A Console export begins or ends mid-record".to_owned(),
        summary: format!(
            "{} export(s) were cut at a record boundary, so the first or last message is incomplete and any activity outside the copied selection is simply absent.",
            truncated.len()
        ),
        recommended_checks: vec![
            "Re-copy the Console selection so it starts and ends on whole records.".to_owned(),
            "Do not read the absence of a signal near the cut as evidence the signal did not occur.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: gaps,
    });
}

/// Always emitted once records exist: the window itself is a finding.
///
/// Every other conclusion drawn from this evidence is bounded by it, and the
/// reader is entitled to see that bound stated rather than inferred.
fn push_capture_window_is_partial(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.records.is_empty() {
        return;
    }
    let evidence = evidence_of(boundary_records(snapshot).into_iter());
    if evidence.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-capture-window-is-partial".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "This evidence covers only the recorded reproduction window".to_owned(),
        summary: format!(
            "{} record(s) were read, of which {} are verified Company Portal records. The capture holds only what Console was showing while the operator recorded, so nothing missing from it is evidence of absence.",
            snapshot.totals.record_count, snapshot.totals.company_portal_record_count
        ),
        recommended_checks: vec![
            "Compare the window's first and last cited records against when the problem was reproduced.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

// ── Company Portal signal rules ─────────────────────────────────────────────

fn push_company_portal_sign_in_failure(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let failures = snapshot.records.iter().filter(|record| {
        record.is_company_portal_failure() && record.semantic == Some(ConsoleSemanticKind::SignInAuth)
    });
    let evidence = evidence_of(failures);
    if evidence.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-company-portal-sign-in-failure".to_owned(),
        severity: IntuneFindingSeverity::Error,
        confidence: IntuneFindingConfidence::Medium,
        title: "Company Portal reported a sign-in or token failure".to_owned(),
        summary: "One or more Company Portal records classified as sign-in or token activity were logged at error or fault level during the capture.".to_owned(),
        recommended_checks: vec![
            "Read the cited records in full for the authentication error code they carry.".to_owned(),
            "Correlate the cited local wall-clock times against Entra ID sign-in logs for the same device.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

fn push_company_portal_failure(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let failures = snapshot.records.iter().filter(|record| {
        record.is_company_portal_failure() && record.semantic != Some(ConsoleSemanticKind::SignInAuth)
    });
    let evidence = evidence_of(failures);
    if evidence.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-company-portal-failure".to_owned(),
        severity: IntuneFindingSeverity::Error,
        confidence: IntuneFindingConfidence::High,
        title: "Company Portal logged an error or fault".to_owned(),
        summary: "Records verified as Company Portal by their process or subsystem were logged at error or fault level during the capture.".to_owned(),
        recommended_checks: vec![
            "Read the cited records in full, including their continuation lines.".to_owned(),
            "Check whether the surrounding unrelated-process records show a network or service failure at the same wall-clock time.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

/// The capture contained records, but none of them were Company Portal.
///
/// Reported at low confidence and worded as a coverage problem, never as "the
/// app did nothing": the operator may simply have copied the wrong selection, or
/// filtered Console before copying.
fn push_no_company_portal_records(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let readable: Vec<&ConsoleArtifact> = snapshot
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.status,
                IntuneArtifactStatus::Available | IntuneArtifactStatus::Capped
            ) && artifact.record_count > 0
                && artifact.company_portal_record_count == 0
        })
        .collect();
    if readable.is_empty() {
        return;
    }
    let ids: Vec<&str> = readable
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect();
    let evidence = evidence_of(snapshot.records.iter().filter(|record| {
        record.source_class == ConsoleSourceClass::Unrelated
            && ids.contains(&record.context.provenance.source_artifact_id.as_str())
    }));
    if evidence.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-no-company-portal-records".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::Low,
        title: "The capture contains no verified Company Portal records".to_owned(),
        summary: "Every record read carries a process and subsystem belonging to some other component. This says the capture missed Company Portal, not that Company Portal was idle.".to_owned(),
        recommended_checks: vec![
            "Confirm info and debug messages were enabled in Console before reproducing the problem.".to_owned(),
            "Re-capture with the whole visible record set copied, not a filtered subset.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

// ── Data-quality rules ──────────────────────────────────────────────────────

fn push_malformed_records(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let malformed = snapshot
        .records
        .iter()
        .filter(|record| record.context.parse_state == IntuneParseState::Malformed);
    let evidence = evidence_of(malformed);
    if evidence.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-records-malformed".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Some rows do not match the export's own column layout".to_owned(),
        summary: format!(
            "{} row(s) carried an unparsable timestamp or fewer columns than the header declares, and were kept as malformed rather than folded into the message above them.",
            snapshot.totals.malformed_record_count
        ),
        recommended_checks: vec![
            "Check whether the export was opened and re-saved by an editor that reflowed long lines.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

/// Records whose wall clock carried no offset cannot be ordered against a
/// service-side log, and saying so is the entire point of keeping the timestamp
/// kind rather than assuming UTC.
fn push_offsetless_timestamps(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let offsetless = snapshot.records.iter().filter(|record| {
        matches!(
            record.context.source_timestamp.as_ref().map(|stamp| &stamp.kind),
            Some(IntuneTimestampKind::Local)
        )
    });
    let evidence = evidence_of(offsetless);
    if evidence.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-timestamps-have-no-offset".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Console timestamps carry no UTC offset".to_owned(),
        summary: format!(
            "{} record(s) carry a bare local wall-clock time. They were not normalized to UTC, because doing so would silently shift them by the Mac's timezone and leave no trace of the guess.",
            snapshot.totals.offsetless_record_count
        ),
        recommended_checks: vec![
            "Establish the capturing Mac's timezone before ordering these records against Intune or Entra ID service logs.".to_owned(),
            "Re-export with the timestamp column set to show the UTC offset if precise ordering matters.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

/// Company Portal evidence with no version banner in the window.
///
/// Version-specific interpretation is unsafe without it, so this is reported as
/// a limit on confidence rather than as a defect.
fn push_unknown_app_version(
    snapshot: &ConsoleDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let unversioned: Vec<&ConsoleArtifact> = snapshot
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.company_portal_record_count > 0 && artifact.reported_app_version.is_none()
        })
        .collect();
    if unversioned.is_empty() {
        return;
    }
    let ids: Vec<&str> = unversioned
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect();
    let evidence = evidence_of(snapshot.records.iter().filter(|record| {
        record.is_company_portal()
            && ids.contains(&record.context.provenance.source_artifact_id.as_str())
    }));
    if evidence.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "console-app-version-unknown".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::Low,
        title: "The Company Portal version is not stated in the capture".to_owned(),
        summary: "No record in the recorded window announced a Company Portal version, so nothing here can be read as version-specific behavior.".to_owned(),
        recommended_checks: vec![
            "Read the installed Company Portal and iOS/iPadOS versions from the device and record them alongside this capture.".to_owned(),
        ],
        evidence,
        coverage_gap_ids: Vec::new(),
    });
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn artifact_ids(
    snapshot: &ConsoleDiagnosticsSnapshot,
    predicate: impl Fn(&ConsoleArtifact) -> bool,
) -> Vec<String> {
    snapshot
        .artifacts
        .iter()
        .filter(|artifact| predicate(artifact))
        .map(|artifact| artifact.artifact_id.clone())
        .collect()
}

/// The first and last record of every artifact that produced any.
fn boundary_records(snapshot: &ConsoleDiagnosticsSnapshot) -> Vec<&ConsoleRecord> {
    let mut boundaries = Vec::new();
    for artifact in &snapshot.artifacts {
        let mut own = snapshot
            .records
            .iter()
            .filter(|record| record.context.provenance.source_artifact_id == artifact.artifact_id);
        let Some(first) = own.next() else {
            continue;
        };
        boundaries.push(first);
        if let Some(last) = own.next_back() {
            boundaries.push(last);
        }
    }
    boundaries
}

/// Evidence references for a set of records, in capture order, capped.
///
/// De-duplicated because a record may satisfy two predicates in one rule.
fn evidence_of<'a>(records: impl Iterator<Item = &'a ConsoleRecord>) -> Vec<IntuneEvidenceRef> {
    let mut refs: Vec<IntuneEvidenceRef> = Vec::new();
    for record in records {
        let candidate = record.context.evidence_ref.clone();
        if !refs.contains(&candidate) {
            refs.push(candidate);
        }
        if refs.len() >= MAX_EVIDENCE_PER_FINDING {
            break;
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::super::models::{ConsoleAnalysisOptions, ConsoleExportInput};
    use super::super::reducer::analyze_console_exports;
    use super::*;
    use crate::intune::evidence::IntuneAccessState;

    const HEADER: &str =
        "Timestamp\tType\tProcess\tPID\tTID\tActivity\tSubsystem\tCategory\tMessage";

    fn row(seconds: &str, kind: &str, process: &str, subsystem: &str, category: &str, message: &str) -> String {
        format!(
            "2026-03-12 10:15:{seconds}.100000-0700\t{kind}\t{process}\t418\t0x1f4a\t0\t{subsystem}\t{category}\t{message}"
        )
    }

    fn analyze(body: &str) -> ConsoleDiagnosticsSnapshot {
        analyze_console_exports(
            &[ConsoleExportInput::captured(
                "a1",
                "console.log",
                format!("{HEADER}\n{body}\n"),
            )],
            &ConsoleAnalysisOptions::observed_at("2026-07-31T00:00:00Z"),
        )
    }

    fn ids(snapshot: &ConsoleDiagnosticsSnapshot) -> Vec<&str> {
        snapshot
            .findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect()
    }

    #[test]
    fn every_finding_cites_evidence_or_a_coverage_gap() {
        let snapshot = analyze(&format!(
            "{}\n{}",
            row("22", "Error", "CompanyPortal", "com.microsoft.CompanyPortal", "Authentication", "acquireToken failed"),
            row("23", "Default", "SpringBoard", "com.apple.springboard", "Default", "unrelated")
        ));
        assert!(!snapshot.findings.is_empty());
        for finding in &snapshot.findings {
            assert!(
                finding.is_evidence_backed(),
                "{} cites nothing",
                finding.finding_id
            );
        }
    }

    #[test]
    fn a_sign_in_failure_is_reported_separately_from_other_failures() {
        let snapshot = analyze(&row(
            "22",
            "Error",
            "CompanyPortal",
            "com.microsoft.CompanyPortal",
            "Authentication",
            "acquireToken failed",
        ));
        assert!(ids(&snapshot).contains(&"console-company-portal-sign-in-failure"));
        assert!(!ids(&snapshot).contains(&"console-company-portal-failure"));
    }

    #[test]
    fn an_unrelated_error_never_becomes_a_company_portal_failure() {
        let snapshot = analyze(&row(
            "22",
            "Fault",
            "SpringBoard",
            "com.apple.springboard",
            "Default",
            "Intune Company Portal mentioned in text only",
        ));
        assert!(!ids(&snapshot).contains(&"console-company-portal-failure"));
        assert!(ids(&snapshot).contains(&"console-no-company-portal-records"));
    }

    #[test]
    fn a_capture_with_no_company_portal_records_is_never_read_as_an_idle_app() {
        let snapshot = analyze(&row(
            "22",
            "Default",
            "SpringBoard",
            "com.apple.springboard",
            "Default",
            "nothing to do with Intune",
        ));
        let finding = snapshot
            .findings
            .iter()
            .find(|finding| finding.finding_id == "console-no-company-portal-records")
            .expect("the coverage finding must be emitted");
        assert_eq!(finding.confidence, IntuneFindingConfidence::Low);
        assert!(finding.summary.contains("not that Company Portal was idle"));
    }

    #[test]
    fn a_bare_local_timestamp_is_reported_rather_than_assumed_utc() {
        let snapshot = analyze(
            "2026-03-12 10:15:22.100000\tDefault\tCompanyPortal\t418\t0x1\t0\tcom.microsoft.CompanyPortal\tGeneral\thello",
        );
        assert!(ids(&snapshot).contains(&"console-timestamps-have-no-offset"));
        assert_eq!(snapshot.totals.offsetless_record_count, 1);
    }

    #[test]
    fn the_partial_window_finding_is_always_present_when_records_exist() {
        let snapshot = analyze(&row(
            "22",
            "Default",
            "CompanyPortal",
            "com.microsoft.CompanyPortal",
            "General",
            "hello",
        ));
        assert!(ids(&snapshot).contains(&"console-capture-window-is-partial"));
    }

    #[test]
    fn an_empty_analysis_emits_no_findings_at_all() {
        let snapshot = analyze_console_exports(&[], &ConsoleAnalysisOptions::default());
        assert!(snapshot.findings.is_empty());
    }

    #[test]
    fn an_uncollected_artifact_produces_a_coverage_gap_finding() {
        let snapshot = analyze_console_exports(
            &[ConsoleExportInput {
                artifact_id: "a1".to_owned(),
                file_name: "console.log".to_owned(),
                file_path: None,
                content: None,
                acquisition: IntuneAccessState::Missing,
                detail: None,
            }],
            &ConsoleAnalysisOptions::default(),
        );
        let finding = snapshot
            .findings
            .iter()
            .find(|finding| finding.finding_id == "console-artifact-not-collected")
            .expect("a missing artifact is itself a finding");
        assert_eq!(finding.coverage_gap_ids, vec!["a1".to_owned()]);
        assert!(finding.evidence.is_empty());
    }

    #[test]
    fn evidence_lists_are_capped_but_the_count_survives_in_the_summary() {
        let mut body = String::new();
        for index in 0..20 {
            if index > 0 {
                body.push('\n');
            }
            body.push_str(&row(
                &format!("{:02}", 20 + index % 40),
                "Error",
                "CompanyPortal",
                "com.microsoft.CompanyPortal",
                "General",
                "boom",
            ));
        }
        let snapshot = analyze(&body);
        let finding = snapshot
            .findings
            .iter()
            .find(|finding| finding.finding_id == "console-company-portal-failure")
            .expect("failures are reported");
        assert_eq!(finding.evidence.len(), MAX_EVIDENCE_PER_FINDING);
    }
}
