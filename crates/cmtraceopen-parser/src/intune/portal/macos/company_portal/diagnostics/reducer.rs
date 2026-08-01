//! Reduction from a supplied report import to an immutable snapshot.
//!
//! The pipeline mirrors `crate::esp`: build observations that each carry an
//! [`IntuneObservationContext`], reduce them into a snapshot, then derive
//! findings from the snapshot in [`super::rules`]. Nothing here emits a
//! finding, and nothing in `rules` re-reads the input.
//!
//! Two rules govern the whole file:
//!
//! * The parser only ever *downgrades* what the importer claimed. An importer
//!   that says a traversal member decoded cleanly does not get to keep that.
//! * Anything not read becomes coverage. A member that was encrypted, capped,
//!   absent, or refused is visible in the output; it is never dropped, because
//!   a silently missing member is indistinguishable from a member that was
//!   read and had nothing in it.

use std::collections::BTreeMap;

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneEvidenceRef,
    IntuneNamedValue, IntuneObservationContext, IntuneParseState, IntuneProvenance,
    IntuneSensitivity, IntuneSourceKind,
};

use super::classify::{
    classify_content, confirm_role, failure_excerpt, is_plausible_evidence, line_count,
    looks_like_json_attempt,
};
use super::import::check_member_paths;
use super::models::*;

/// Reduce a supplied report into an immutable snapshot, without findings.
///
/// [`super::analyze_diagnostic_report`] is the entry point most callers want;
/// it runs this and then attaches derived findings.
pub fn reduce_diagnostic_report(import: &DiagnosticReportImport) -> DiagnosticReportSnapshot {
    let envelope_state = if import.schema_version > COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION {
        EnvelopeState::UnsupportedSchemaVersion
    } else {
        EnvelopeState::Supported
    };
    let envelope_supported = envelope_state == EnvelopeState::Supported;

    let declared_company_portal = matches!(
        import.report.declared_product,
        Some(DeclaredProduct::CompanyPortalMacos)
    );

    let path_checks = check_member_paths(import.members.iter().map(|m| m.member_path.as_str()));

    let mut members: Vec<ClassifiedMember> = import
        .members
        .iter()
        .zip(path_checks)
        .map(|(supplied, check)| {
            classify_member(
                supplied,
                check,
                &import.report,
                envelope_supported,
                declared_company_portal,
            )
        })
        .collect();

    let detection = detect(declared_company_portal, envelope_supported, &members);

    // A container that is not a declared Company Portal report yields no member
    // facts at all. Classification is retained because "we looked and this is
    // what was in there" is the evidence for refusing, but nothing is promoted.
    if detection == ReportDetection::Refused || !envelope_supported {
        let reason = unsupported_reason(&detection, &envelope_state);
        for member in &mut members {
            demote_to_unsupported(member, reason);
        }
    }

    // Deterministic order, independent of how the importer enumerated the
    // container. Path first so a reader sees the report's own layout; member id
    // breaks ties, including the case where two rejected members share a path.
    members.sort_by(|left, right| {
        (&left.member_path, &left.member_id).cmp(&(&right.member_path, &right.member_id))
    });

    let facts = if envelope_supported && detection != ReportDetection::Refused {
        envelope_facts(&import.report)
    } else {
        Vec::new()
    };

    let coverage = member_coverage(&members, &import.report.observed_at_utc);
    let report_coverage = report_coverage(import, &envelope_state, &detection, &members);

    DiagnosticReportSnapshot {
        schema_version: import.schema_version,
        envelope_state,
        support_state: report_schema_support_state(),
        detection,
        report: import.report.clone(),
        members,
        facts,
        report_coverage,
        coverage,
        findings: Vec::new(),
    }
}

fn detect(
    declared_company_portal: bool,
    envelope_supported: bool,
    members: &[ClassifiedMember],
) -> ReportDetection {
    if !declared_company_portal {
        return ReportDetection::Refused;
    }
    if !envelope_supported {
        // The envelope could not be read, so the absence of plausible members
        // proves nothing about the container. Refusing to contradict is the
        // conservative reading.
        return ReportDetection::DeclaredUnconfirmed;
    }

    let decoded = members
        .iter()
        .filter(|member| member.content_kind != MemberContentKind::Undecoded)
        .collect::<Vec<_>>();
    if decoded.is_empty() {
        // Nothing was decoded: a coverage problem, not a contradiction.
        return ReportDetection::DeclaredUnconfirmed;
    }
    if decoded
        .iter()
        .any(|member| !member.is_rejected() && is_plausible_evidence(&member.content_kind))
    {
        ReportDetection::DeclaredUnconfirmed
    } else {
        ReportDetection::DeclaredContradicted
    }
}

impl ClassifiedMember {
    fn is_rejected(&self) -> bool {
        self.rejection.is_some()
    }
}

fn classify_member(
    supplied: &SuppliedReportMember,
    check: super::import::MemberPathCheck,
    envelope: &DiagnosticReportEnvelope,
    envelope_supported: bool,
    declared_company_portal: bool,
) -> ClassifiedMember {
    let rejected = check.is_rejected();
    // A refused path means the bytes cannot be attributed to a location inside
    // the report, so they are not classified as evidence of anything.
    let content = if rejected {
        None
    } else {
        supplied.content.as_deref()
    };
    let content_kind = classify_content(content);

    let (mut confirmed_role, mut role_confirmation) = if rejected {
        (
            ReportMemberRole::Unclassified,
            RoleConfirmation::NotDeclared,
        )
    } else {
        confirm_role(supplied.declared_role.as_ref(), &content_kind)
    };

    // A member that claimed to be structured and is not is malformed evidence,
    // which is a different fact from "an artifact this build does not model".
    let malformed_structure = !rejected
        && content
            .map(|text| {
                looks_like_json_attempt(text) && content_kind != MemberContentKind::Json
            })
            .unwrap_or(false);

    let mut import_state = supplied.import_state.clone();
    let mut detail = supplied.import_detail.clone();
    let mut failure = None;

    if rejected {
        import_state = MemberImportState::Rejected;
        detail = with_importer_detail(
            &format!(
                "member path refused by the parser import guard ({})",
                rejection_label(check.rejection.as_ref())
            ),
            detail.as_deref(),
        );
    } else if content_kind == MemberContentKind::Binary {
        import_state = MemberImportState::Undecodable;
        detail = with_importer_detail(
            "decoded text contains NUL bytes and is not text",
            detail.as_deref(),
        );
    } else if malformed_structure {
        import_state = MemberImportState::Undecodable;
        detail = with_importer_detail(
            "member begins as JSON but does not parse",
            detail.as_deref(),
        );
    }

    if matches!(import_state, MemberImportState::Undecodable) {
        confirmed_role = ReportMemberRole::Unclassified;
        if role_confirmation == RoleConfirmation::ContentConfirmed {
            role_confirmation = RoleConfirmation::Contradicted;
        }
        failure = content.map(failure_excerpt).filter(|text| !text.is_empty());
    }

    let delegation = (confirmed_role == ReportMemberRole::DirectLog
        && envelope_supported
        && declared_company_portal)
        .then(|| MemberDelegation {
            target: DIRECT_LOG_DELEGATION_TARGET.to_owned(),
            reason: "member content is log-framed; record parsing belongs to the direct app-log parser".to_owned(),
        });

    let decoded_bytes = content.map(|text| text.len() as u64).unwrap_or(0);
    let line_count = content.map(line_count).unwrap_or(0);

    let context = observation_context(
        supplied,
        &check.path,
        envelope,
        &import_state,
        &content_kind,
        rejected,
    );

    ClassifiedMember {
        member_id: supplied.member_id.clone(),
        member_path: check.path,
        context,
        import_state,
        content_kind,
        declared_role: supplied.declared_role.clone(),
        confirmed_role,
        role_confirmation,
        delegation,
        declared_bytes: supplied.declared_bytes,
        decoded_bytes,
        line_count,
        declared_encoding: supplied.declared_encoding.clone(),
        transcoded_from: supplied.transcoded_from.clone(),
        rejection: check.rejection,
        detail,
        failure_excerpt: failure,
    }
}

fn observation_context(
    supplied: &SuppliedReportMember,
    normalized_path: &str,
    envelope: &DiagnosticReportEnvelope,
    import_state: &MemberImportState,
    content_kind: &MemberContentKind,
    rejected: bool,
) -> IntuneObservationContext {
    IntuneObservationContext {
        evidence_ref: IntuneEvidenceRef {
            evidence_id: format!("member:{}", supplied.member_id),
            source_artifact_id: supplied.member_id.clone(),
        },
        provenance: IntuneProvenance {
            source_kind: source_kind_for(content_kind),
            source_artifact_id: supplied.member_id.clone(),
            file_path: Some(normalized_path.to_owned()),
            line_number: None,
            record_number: None,
            registry: None,
            event: None,
        },
        source_timestamp: None,
        observed_at_utc: envelope.observed_at_utc.clone(),
        sensitivity: sensitivity_for(supplied.declared_role.as_ref()),
        parse_state: parse_state_for(import_state, content_kind, rejected),
        access_state: access_state_for(import_state),
    }
}

/// Map decoded structure onto the shared source vocabulary.
///
/// A member whose structure says nothing stays [`IntuneSourceKind::DiagnosticReport`]
/// rather than being guessed into a more specific kind.
fn source_kind_for(content_kind: &MemberContentKind) -> IntuneSourceKind {
    match content_kind {
        MemberContentKind::PlainTextLog => IntuneSourceKind::PlainTextLog,
        MemberContentKind::Json => IntuneSourceKind::Json,
        _ => IntuneSourceKind::DiagnosticReport,
    }
}

/// Members are sensitive by default.
///
/// Member paths and log bodies routinely carry identity, tenant, and device
/// data, and a member the importer declared as auth evidence is assumed to
/// carry tokens. Under-classifying here is the failure that leaks.
fn sensitivity_for(declared_role: Option<&ReportMemberRole>) -> IntuneSensitivity {
    match declared_role {
        Some(ReportMemberRole::AuthEvidence) => IntuneSensitivity::Restricted,
        _ => IntuneSensitivity::Sensitive,
    }
}

fn parse_state_for(
    import_state: &MemberImportState,
    content_kind: &MemberContentKind,
    rejected: bool,
) -> IntuneParseState {
    if rejected {
        return IntuneParseState::Unsupported;
    }
    match import_state {
        MemberImportState::Undecodable => IntuneParseState::Malformed,
        MemberImportState::Encrypted
        | MemberImportState::UnknownCompression
        | MemberImportState::Rejected
        | MemberImportState::NotClaimed => IntuneParseState::Unsupported,
        // No content was ever offered, so "unsupported" is the least wrong of
        // the four parse states: nothing was parsed, and nothing was malformed.
        MemberImportState::Absent | MemberImportState::Skipped => IntuneParseState::Unsupported,
        MemberImportState::Decoded | MemberImportState::Capped | MemberImportState::Oversized => {
            match content_kind {
                MemberContentKind::PlainTextLog
                | MemberContentKind::Json
                | MemberContentKind::PropertyList => IntuneParseState::Parsed,
                MemberContentKind::Binary => IntuneParseState::Malformed,
                _ => IntuneParseState::Raw,
            }
        }
        MemberImportState::Unknown(_) => IntuneParseState::Unsupported,
    }
}

fn access_state_for(import_state: &MemberImportState) -> IntuneAccessState {
    match import_state {
        MemberImportState::Decoded => IntuneAccessState::Available,
        MemberImportState::Capped | MemberImportState::Oversized => IntuneAccessState::Capped,
        MemberImportState::Absent => IntuneAccessState::Missing,
        MemberImportState::Skipped => IntuneAccessState::Skipped,
        MemberImportState::Undecodable => IntuneAccessState::Failed,
        MemberImportState::Encrypted
        | MemberImportState::UnknownCompression
        | MemberImportState::Rejected
        | MemberImportState::NotClaimed
        | MemberImportState::Unknown(_) => IntuneAccessState::Unsupported,
    }
}

fn artifact_status_for(import_state: &MemberImportState) -> IntuneArtifactStatus {
    match access_state_for(import_state) {
        IntuneAccessState::Available => IntuneArtifactStatus::Available,
        IntuneAccessState::Missing => IntuneArtifactStatus::Missing,
        IntuneAccessState::PermissionDenied => IntuneArtifactStatus::PermissionDenied,
        IntuneAccessState::Capped => IntuneArtifactStatus::Capped,
        IntuneAccessState::Skipped => IntuneArtifactStatus::Skipped,
        IntuneAccessState::Failed => IntuneArtifactStatus::ParseFailed,
        IntuneAccessState::Unsupported => IntuneArtifactStatus::Unsupported,
    }
}

/// Combine the parser's reason with whatever the importer said.
///
/// Overwriting the importer's note loses the only account of what happened
/// upstream, which is exactly the context a reviewer needs when the parser and
/// the importer disagree about a member.
fn with_importer_detail(reason: &str, importer_detail: Option<&str>) -> Option<String> {
    Some(match importer_detail {
        Some(importer) if !importer.is_empty() => {
            format!("{reason}; importer reported: {importer}")
        }
        _ => reason.to_owned(),
    })
}

/// Force a member to unsupported without discarding what was observed.
fn demote_to_unsupported(member: &mut ClassifiedMember, reason: &str) {
    member.import_state = MemberImportState::NotClaimed;
    member.confirmed_role = ReportMemberRole::Unclassified;
    member.role_confirmation = RoleConfirmation::NotDeclared;
    member.delegation = None;
    member.failure_excerpt = None;
    member.detail = with_importer_detail(reason, member.detail.as_deref());
    member.context.parse_state = IntuneParseState::Unsupported;
    member.context.access_state = IntuneAccessState::Unsupported;
}

fn unsupported_reason(detection: &ReportDetection, envelope_state: &EnvelopeState) -> &'static str {
    if *envelope_state == EnvelopeState::UnsupportedSchemaVersion {
        "import envelope schema version is newer than this build reads; no member facts are claimed"
    } else if *detection == ReportDetection::Refused {
        "container is not a declared Company Portal diagnostic report; no member facts are claimed"
    } else {
        "member is not claimed by this build"
    }
}

fn rejection_label(rejection: Option<&MemberPathRejection>) -> String {
    rejection
        .and_then(|value| serde_json::to_value(value).ok())
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Coverage for every supplied member, sorted by member id.
fn member_coverage(
    members: &[ClassifiedMember],
    observed_at_utc: &str,
) -> Vec<IntuneArtifactCoverage> {
    let mut coverage: Vec<IntuneArtifactCoverage> = members
        .iter()
        .map(|member| IntuneArtifactCoverage {
            artifact_id: member.member_id.clone(),
            family: COMPANY_PORTAL_MACOS_DIAGNOSTICS_FAMILY.to_owned(),
            status: artifact_status_for(&member.import_state),
            detail: member.detail.clone(),
            observed_at_utc: observed_at_utc.to_owned(),
            evidence: vec![member.context.evidence_ref.clone()],
        })
        .collect();
    coverage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    coverage
}

/// Container-level coverage.
///
/// Kept separate from the per-member entries because its `artifact_id` names
/// the report rather than an artifact inside it, and a consumer that iterates
/// members should not have to filter the container back out.
fn report_coverage(
    import: &DiagnosticReportImport,
    envelope_state: &EnvelopeState,
    detection: &ReportDetection,
    members: &[ClassifiedMember],
) -> IntuneArtifactCoverage {
    let usable = members
        .iter()
        .filter(|member| {
            matches!(
                artifact_status_for(&member.import_state),
                IntuneArtifactStatus::Available | IntuneArtifactStatus::Capped
            )
        })
        .count();

    let (status, detail) = match (envelope_state, detection, &import.report.extraction) {
        (EnvelopeState::UnsupportedSchemaVersion, _, _) => (
            IntuneArtifactStatus::Unsupported,
            format!(
                "import envelope schema version {} is newer than {} and was not read",
                import.schema_version, COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION
            ),
        ),
        (_, ReportDetection::Refused, _) => (
            IntuneArtifactStatus::Unsupported,
            "container was not declared as a macOS Company Portal diagnostic report".to_owned(),
        ),
        (_, _, ExtractionOutcome::Failed) => (
            IntuneArtifactStatus::ParseFailed,
            import
                .report
                .extraction_detail
                .clone()
                .unwrap_or_else(|| "container extraction failed".to_owned()),
        ),
        (_, _, ExtractionOutcome::Truncated | ExtractionOutcome::Capped) => (
            IntuneArtifactStatus::Capped,
            import.report.extraction_detail.clone().unwrap_or_else(|| {
                "container extraction did not complete; absent members prove nothing".to_owned()
            }),
        ),
        // Nothing usable came out of a container that opened fine. Which
        // status that is depends on why: bytes that failed to parse are a
        // different problem from members this build refuses to interpret, and
        // reporting both as parseFailed would send a reader looking for
        // corruption that is not there.
        _ if usable == 0 && !members.is_empty() => {
            let malformed = members
                .iter()
                .filter(|member| {
                    artifact_status_for(&member.import_state) == IntuneArtifactStatus::ParseFailed
                })
                .count();
            if malformed > 0 {
                (
                    IntuneArtifactStatus::ParseFailed,
                    format!("no member of the container could be read; {malformed} failed to parse"),
                )
            } else {
                (
                    IntuneArtifactStatus::Unsupported,
                    "no member of the container could be interpreted by this build".to_owned(),
                )
            }
        }
        _ => (
            IntuneArtifactStatus::Available,
            format!("{usable} of {} members readable", members.len()),
        ),
    };

    IntuneArtifactCoverage {
        artifact_id: import.report.report_id.clone(),
        family: COMPANY_PORTAL_MACOS_DIAGNOSTICS_FAMILY.to_owned(),
        status,
        detail: Some(detail),
        observed_at_utc: import.report.observed_at_utc.clone(),
        evidence: members
            .iter()
            .map(|member| member.context.evidence_ref.clone())
            .collect(),
    }
}

/// Normalized facts, drawn only from what the importer declared.
///
/// No fact is derived from a member field. That would mean naming a report
/// schema, and none is fixture-backed. Facts are sorted by name so the export
/// bytes do not depend on the order they were added in.
fn envelope_facts(envelope: &DiagnosticReportEnvelope) -> Vec<DiagnosticFact> {
    let mut declared: BTreeMap<&str, (String, IntuneSensitivity)> = BTreeMap::new();

    declared.insert(
        "containerKind",
        (
            wire_string(&envelope.container_kind),
            IntuneSensitivity::Public,
        ),
    );
    declared.insert(
        "extraction",
        (wire_string(&envelope.extraction), IntuneSensitivity::Public),
    );
    if let Some(schema) = &envelope.declared_report_schema {
        declared.insert(
            "declaredReportSchema",
            (schema.clone(), IntuneSensitivity::Public),
        );
    }
    if let Some(version) = &envelope.declared_app_version {
        declared.insert(
            "declaredAppVersion",
            (version.clone(), IntuneSensitivity::Public),
        );
    }
    if let Some(collected) = &envelope.collected_at {
        declared.insert("collectedAt", (collected.clone(), IntuneSensitivity::Public));
    }
    if let Some(path) = &envelope.sanitized_source_path {
        declared.insert(
            "sanitizedSourcePath",
            (path.clone(), IntuneSensitivity::Sensitive),
        );
    }

    declared
        .into_iter()
        .map(|(name, (value, sensitivity))| DiagnosticFact {
            fact: IntuneNamedValue {
                name: name.to_owned(),
                value,
            },
            context: IntuneObservationContext {
                evidence_ref: IntuneEvidenceRef {
                    evidence_id: format!("report:{}:{name}", envelope.report_id),
                    source_artifact_id: envelope.report_id.clone(),
                },
                provenance: IntuneProvenance {
                    source_kind: IntuneSourceKind::SuppliedFact,
                    source_artifact_id: envelope.report_id.clone(),
                    file_path: None,
                    line_number: None,
                    record_number: None,
                    registry: None,
                    event: None,
                },
                source_timestamp: None,
                observed_at_utc: envelope.observed_at_utc.clone(),
                sensitivity,
                parse_state: IntuneParseState::Parsed,
                access_state: IntuneAccessState::Available,
            },
        })
        .collect()
}

/// Render a raw-preserving enum through its own wire form.
///
/// Going via serde rather than a hand-written match means an `Unknown` value
/// keeps the token the importer sent instead of becoming the word "unknown".
fn wire_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}
