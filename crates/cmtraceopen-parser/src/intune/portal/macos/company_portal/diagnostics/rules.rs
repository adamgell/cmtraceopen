//! Findings derived from an immutable snapshot.
//!
//! Same shape as `crate::esp::rules`: one `push_*` per rule, each emitting only
//! when its triggering evidence is in the snapshot, and each citing either
//! evidence references or coverage-gap identifiers. A finding that cites
//! neither is an assertion rather than a diagnosis, so the invariant is
//! asserted here as well as in the fixture harness.
//!
//! No rule reads the original import. If a rule needs something, it belongs in
//! the snapshot.

use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity,
};

use super::models::*;

/// Derive every finding this build supports from `snapshot`.
///
/// Order is fixed by the call sequence, not by input order, so two runs over
/// the same report produce the same list.
pub fn derive_findings(snapshot: &DiagnosticReportSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_unsupported_envelope_schema(snapshot, &mut findings);
    push_report_not_declared(snapshot, &mut findings);
    push_detection_contradicted(snapshot, &mut findings);
    push_rejected_member_paths(snapshot, &mut findings);
    push_extraction_incomplete(snapshot, &mut findings);
    push_malformed_members(snapshot, &mut findings);
    push_unsupported_members(snapshot, &mut findings);
    push_capped_members(snapshot, &mut findings);
    push_absent_members(snapshot, &mut findings);
    push_role_contradiction(snapshot, &mut findings);
    push_direct_log_delegation(snapshot, &mut findings);
    push_report_schema_not_fixture_backed(snapshot, &mut findings);

    debug_assert!(
        findings.iter().all(IntuneFinding::is_evidence_backed),
        "every finding must cite evidence or a coverage gap"
    );
    findings
}

// ── Envelope and detection ──────────────────────────────────────────────────

fn push_unsupported_envelope_schema(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.envelope_state != EnvelopeState::UnsupportedSchemaVersion {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-unsupported-envelope-schema".to_owned(),
        severity: IntuneFindingSeverity::Error,
        confidence: IntuneFindingConfidence::High,
        title: "Report import envelope is newer than this build reads".to_owned(),
        summary: format!(
            "The import envelope declared schema version {}, and this build reads at most {}. \
             No member facts were claimed from it.",
            snapshot.schema_version, COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION
        ),
        recommended_checks: vec![
            "Re-import with a build whose diagnostics envelope version matches the collector"
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: vec![snapshot.report_coverage.artifact_id.clone()],
    });
}

fn push_report_not_declared(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.detection != ReportDetection::Refused {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-not-a-company-portal-report".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Container was not declared a Company Portal diagnostic report".to_owned(),
        summary: format!(
            "The import boundary did not declare this container as a macOS Company Portal saved \
             report, so its {} member(s) were not interpreted as Company Portal evidence.",
            snapshot.members.len()
        ),
        recommended_checks: vec![
            "Confirm the file came from Company Portal's Help > Save Diagnostic Report flow"
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: vec![snapshot.report_coverage.artifact_id.clone()],
    });
}

fn push_detection_contradicted(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.detection != ReportDetection::DeclaredContradicted {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-declaration-contradicted".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::Medium,
        title: "Declared report contains no readable evidence".to_owned(),
        summary: "The container was declared a Company Portal diagnostic report, but every member \
                  that decoded was binary, empty, or refused, so nothing in it supports the \
                  declaration."
            .to_owned(),
        recommended_checks: vec![
            "Re-collect the report and confirm the archive is not truncated or re-compressed"
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: vec![snapshot.report_coverage.artifact_id.clone()],
    });
}

// ── Import security ─────────────────────────────────────────────────────────

fn push_rejected_member_paths(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let rejected: Vec<&ClassifiedMember> = snapshot
        .members
        .iter()
        .filter(|member| member.rejection.is_some())
        .collect();
    if rejected.is_empty() {
        return;
    }

    let duplicates = rejected
        .iter()
        .filter(|member| member.rejection == Some(MemberPathRejection::DuplicatePath))
        .count();
    let unsafe_paths = rejected.len() - duplicates;

    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-member-path-refused".to_owned(),
        severity: IntuneFindingSeverity::Error,
        confidence: IntuneFindingConfidence::High,
        title: "Report members were refused by the import guard".to_owned(),
        summary: format!(
            "{unsafe_paths} member(s) carried an unsafe container path and {duplicates} collided \
             with another member after case-insensitive normalization. Refused members contribute \
             no evidence, and a report containing them should be treated as untrusted."
        ),
        recommended_checks: vec![
            "Inspect the container with an archiver that shows raw member paths".to_owned(),
            "Do not extract this container to a writable location".to_owned(),
        ],
        evidence: evidence_of(&rejected),
        coverage_gap_ids: ids_of(&rejected),
    });
}

// ── Coverage ────────────────────────────────────────────────────────────────

fn push_extraction_incomplete(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let (severity, outcome) = match snapshot.report.extraction {
        ExtractionOutcome::Complete => return,
        ExtractionOutcome::Failed => (IntuneFindingSeverity::Error, "failed"),
        ExtractionOutcome::Truncated => (IntuneFindingSeverity::Warning, "truncated"),
        ExtractionOutcome::Capped => (IntuneFindingSeverity::Warning, "capped"),
        ExtractionOutcome::Unknown(_) => (IntuneFindingSeverity::Warning, "unrecognized"),
    };

    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-extraction-incomplete".to_owned(),
        severity,
        confidence: IntuneFindingConfidence::High,
        title: "Report collection did not complete".to_owned(),
        summary: format!(
            "Container extraction was reported as {outcome}. A member missing from a {outcome} \
             collection is not evidence that Company Portal did not write it."
        ),
        recommended_checks: vec![
            "Re-run Help > Save Diagnostic Report and confirm the archive is written completely"
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: vec![snapshot.report_coverage.artifact_id.clone()],
    });
}

fn push_malformed_members(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let malformed = members_with_status(snapshot, IntuneArtifactStatus::ParseFailed);
    if malformed.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-malformed-member".to_owned(),
        severity: IntuneFindingSeverity::Error,
        confidence: IntuneFindingConfidence::High,
        title: "Report members could not be interpreted".to_owned(),
        summary: format!(
            "{} member(s) were collected but did not parse: {}. The bytes are present, so this is \
             a corruption or format change rather than a collection gap.",
            malformed.len(),
            labels(&malformed)
        ),
        recommended_checks: vec![
            "Compare the member against a report from a known-good Company Portal version"
                .to_owned(),
        ],
        evidence: evidence_of(&malformed),
        coverage_gap_ids: ids_of(&malformed),
    });
}

fn push_unsupported_members(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    // Path-refused members already have their own, more specific finding.
    let unsupported: Vec<&ClassifiedMember> = snapshot
        .members
        .iter()
        .filter(|member| member.rejection.is_none())
        .filter(|member| {
            matches!(
                member.import_state,
                MemberImportState::Encrypted
                    | MemberImportState::UnknownCompression
                    | MemberImportState::Rejected
                    | MemberImportState::NotClaimed
            )
        })
        .collect();
    if unsupported.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-unsupported-member".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Report members were not readable by this build".to_owned(),
        summary: format!(
            "{} member(s) were encrypted, used an unsupported compression method, or belong to a \
             container this build does not claim: {}. They remain visible as coverage rather than \
             being dropped.",
            unsupported.len(),
            labels(&unsupported)
        ),
        recommended_checks: vec![
            "Confirm the archive was not re-compressed or password protected after collection"
                .to_owned(),
        ],
        evidence: evidence_of(&unsupported),
        coverage_gap_ids: ids_of(&unsupported),
    });
}

fn push_capped_members(snapshot: &DiagnosticReportSnapshot, findings: &mut Vec<IntuneFinding>) {
    let capped = members_with_status(snapshot, IntuneArtifactStatus::Capped);
    if capped.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-capped-member".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::High,
        title: "Report members were truncated at an import limit".to_owned(),
        summary: format!(
            "{} member(s) hit a size or decompression limit: {}. Absence of a signal in a capped \
             member proves nothing about the device.",
            capped.len(),
            labels(&capped)
        ),
        recommended_checks: vec![
            "Re-import with a higher member size limit if the truncated member is the one in question"
                .to_owned(),
        ],
        evidence: evidence_of(&capped),
        coverage_gap_ids: ids_of(&capped),
    });
}

fn push_absent_members(snapshot: &DiagnosticReportSnapshot, findings: &mut Vec<IntuneFinding>) {
    let absent = members_with_status(snapshot, IntuneArtifactStatus::Missing);
    if absent.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-absent-member".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Report members declared by the importer were not present".to_owned(),
        summary: format!(
            "{} member(s) the importer expected were not in the container: {}. Whether Company \
             Portal writes them at all is unknown while the report schema is undocumented.",
            absent.len(),
            labels(&absent)
        ),
        recommended_checks: vec![
            "Collect a second report from the same app version and compare the member list"
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: ids_of(&absent),
    });
}

// ── Classification ──────────────────────────────────────────────────────────

fn push_role_contradiction(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let contradicted: Vec<&ClassifiedMember> = snapshot
        .members
        .iter()
        .filter(|member| member.role_confirmation == RoleConfirmation::Contradicted)
        .collect();
    if contradicted.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-role-contradicted".to_owned(),
        severity: IntuneFindingSeverity::Warning,
        confidence: IntuneFindingConfidence::Medium,
        title: "Declared member roles are contradicted by the content".to_owned(),
        summary: format!(
            "{} member(s) were declared with a role their content does not support: {}. The \
             declaration was not promoted, because a path hint only selects a candidate.",
            contradicted.len(),
            labels(&contradicted)
        ),
        recommended_checks: vec![
            "Check whether the collector's member-role mapping is stale for this app version"
                .to_owned(),
        ],
        evidence: evidence_of(&contradicted),
        coverage_gap_ids: Vec::new(),
    });
}

fn push_direct_log_delegation(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let delegated: Vec<&ClassifiedMember> = snapshot.delegated_direct_logs().collect();
    if delegated.is_empty() {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-direct-log-delegated".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Direct log members are handed to the app-log parser".to_owned(),
        summary: format!(
            "{} member(s) are log-framed and are parsed as records by {DIRECT_LOG_DELEGATION_TARGET}: {}. \
             This module classifies them and does not duplicate the record grammar.",
            delegated.len(),
            labels(&delegated)
        ),
        recommended_checks: vec![
            "Run the direct app-log analysis over the delegated members for record-level detail"
                .to_owned(),
        ],
        evidence: evidence_of(&delegated),
        coverage_gap_ids: Vec::new(),
    });
}

fn push_report_schema_not_fixture_backed(
    snapshot: &DiagnosticReportSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.support_state != DiagnosticsSupportState::SourceContract {
        return;
    }
    findings.push(IntuneFinding {
        finding_id: "cp-macos-diagnostics-report-schema-not-fixture-backed".to_owned(),
        severity: IntuneFindingSeverity::Info,
        confidence: IntuneFindingConfidence::High,
        title: "Saved report schema is not yet fixture-backed".to_owned(),
        summary: "No sanitized real macOS Company Portal saved report is committed to this \
                  repository, so no member name, layout, or field vocabulary is asserted. Member \
                  roles other than a structurally confirmed direct log are reported as declared \
                  and unconfirmed."
            .to_owned(),
        recommended_checks: vec![
            "Capture sanitized reports from two app versions and add them to the corpus before \
             relying on member-level semantics"
                .to_owned(),
        ],
        evidence: Vec::new(),
        coverage_gap_ids: vec![snapshot.report_coverage.artifact_id.clone()],
    });
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn members_with_status(
    snapshot: &DiagnosticReportSnapshot,
    status: IntuneArtifactStatus,
) -> Vec<&ClassifiedMember> {
    let ids: Vec<&str> = snapshot
        .coverage
        .iter()
        .filter(|entry| entry.status == status)
        .map(|entry| entry.artifact_id.as_str())
        .collect();
    snapshot
        .members
        .iter()
        .filter(|member| ids.contains(&member.member_id.as_str()))
        .collect()
}

fn evidence_of(members: &[&ClassifiedMember]) -> Vec<IntuneEvidenceRef> {
    let mut refs: Vec<IntuneEvidenceRef> = members
        .iter()
        .map(|member| member.context.evidence_ref.clone())
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

fn ids_of(members: &[&ClassifiedMember]) -> Vec<String> {
    let mut ids: Vec<String> = members
        .iter()
        .map(|member| member.member_id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Human-readable member list for a summary, in a stable order.
fn labels(members: &[&ClassifiedMember]) -> String {
    let mut labels: Vec<String> = members
        .iter()
        .map(|member| member.member_path.clone())
        .collect();
    labels.sort();
    labels.dedup();
    labels.join(", ")
}
