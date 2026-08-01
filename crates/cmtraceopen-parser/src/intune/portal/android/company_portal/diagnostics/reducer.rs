//! Reduce an imported bundle to an immutable snapshot.
//!
//! The reducer enumerates, classifies, and records. It does not interpret
//! member contents, because no verified contract says how to. Everything it
//! emits is either a fact the importer supplied (recorded with
//! `SuppliedFact` provenance) or a property of the member list itself.
//!
//! Timestamps are normalized only when the supplied text carries its own
//! offset. A bare wall-clock string plus a named time zone is left
//! un-normalized: this crate carries no time-zone database, and inventing an
//! offset from the host's own locale would silently attribute the parsing
//! machine's clock to the device.

use chrono::{DateTime, NaiveDateTime, Utc};

use super::contract::{
    match_verified_contract, AndroidUploadOutcome, AndroidVerboseLoggingState,
    ANDROID_DIAGNOSTICS_FAMILY, ANDROID_DIAGNOSTICS_SCHEMA_VERSION,
};
use super::models::{
    access_state_for, AndroidDiagnosticBundleInput, AndroidDiagnosticMember,
    AndroidDiagnosticMemberInput, AndroidDiagnosticReportMetadata, AndroidDiagnosticsSnapshot,
    AndroidMemberClassification,
};
use super::rules::derive_findings;
use super::sources::{classify_bundle, classify_member, duplicates_in, safety_flags_for};
use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneArtifactStatus, IntuneEvidenceRef, IntuneObservationContext,
    IntuneParseState, IntuneProvenance, IntuneSensitivity, IntuneSourceKind, IntuneTimestamp,
    IntuneTimestampKind,
};

/// Artifact identifier under which the importer's own claims are recorded.
///
/// Suffixed onto the bundle id so a finding about a supplied fact points
/// somewhere real without pretending an archive member said it.
pub const SUPPLIED_FACTS_SUFFIX: &str = "#suppliedFacts";

/// Analyze one already-extracted Android diagnostic bundle.
///
/// Deterministic: members are processed in `artifact_id` order and every output
/// list is stably ordered, so two runs over the same input serialize to the
/// same bytes.
pub fn analyze_android_diagnostic_bundle(
    input: &AndroidDiagnosticBundleInput,
) -> AndroidDiagnosticsSnapshot {
    let mut ordered: Vec<&AndroidDiagnosticMemberInput> = input.members.iter().collect();
    ordered.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let duplicates = duplicates_in(input);

    let mut members = Vec::with_capacity(ordered.len());
    let mut coverage = Vec::with_capacity(ordered.len());
    let mut classifications = Vec::with_capacity(ordered.len());

    for member in &ordered {
        let safety_flags = safety_flags_for(member, &duplicates, &input.limits);
        let classification = classify_member(member, &safety_flags);
        classifications.push(classification.clone());

        let context = member_context(input, member, &classification);
        coverage.push(IntuneArtifactCoverage {
            artifact_id: member.artifact_id.clone(),
            family: ANDROID_DIAGNOSTICS_FAMILY.to_owned(),
            status: member.status.clone(),
            detail: Some(coverage_detail(&classification)),
            observed_at_utc: input.observed_at_utc.clone(),
            evidence: vec![context.evidence_ref.clone()],
        });

        members.push(AndroidDiagnosticMember {
            artifact_id: member.artifact_id.clone(),
            entry_name: member.entry_name.clone(),
            sanitized_entry_path: member.sanitized_entry_path.clone(),
            classification,
            status: member.status.clone(),
            declared_bytes: member.declared_bytes,
            encoding: member.encoding.clone(),
            rotation: member.rotation.clone(),
            safety_flags,
            context,
        });
    }

    // `classify_bundle` expects classifications parallel to `input.members`.
    // They were built in sorted order, which is a permutation of the same set,
    // and every rule in `classify_bundle` is order-independent.
    let classification = classify_bundle(input, &classifications);

    let entry_names: Vec<String> = input
        .members
        .iter()
        .map(|member| member.entry_name.clone())
        .collect();
    let verified_contract_id = match_verified_contract(
        input.supplied.declared_schema_token.as_deref(),
        &entry_names,
    )
    .map(|contract| contract.contract_id.to_owned());

    let metadata = AndroidDiagnosticReportMetadata {
        bundle_id: input.bundle_id.clone(),
        schema_version: ANDROID_DIAGNOSTICS_SCHEMA_VERSION,
        generated_at_utc: input.observed_at_utc.clone(),
        classification,
        verified_contract_id,
        app: input.supplied.app.clone(),
        app_version: input.supplied.app_version.clone(),
        management_mode: input.supplied.management_mode.clone(),
        collection_flow: input.supplied.collection_flow.clone(),
        verbose_logging: input
            .supplied
            .verbose_logging
            .clone()
            .unwrap_or(AndroidVerboseLoggingState::Unreported),
        upload_outcome: input
            .supplied
            .upload_outcome
            .clone()
            .unwrap_or(AndroidUploadOutcome::Unreported),
        incident_id: input.supplied.incident_id.clone(),
        collected_at: input
            .supplied
            .collected_at_text
            .as_deref()
            .map(|text| normalize_supplied_timestamp(text, input.supplied.device_time_zone.as_deref())),
        declared_schema_token: input.supplied.declared_schema_token.clone(),
        container_kind: input.supplied.container_kind.clone(),
        supplied_extra: input.supplied.extra.clone(),
        supplied_context: supplied_context(input),
    };

    let mut snapshot = AndroidDiagnosticsSnapshot {
        metadata,
        members,
        // No verified contract means no record grammar, so there is nothing to
        // populate this with that would not be invented. See `contract.rs`.
        records: Vec::new(),
        coverage,
        findings: Vec::new(),
    };
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

/// The envelope recording that a fact came from the importer, not the artifact.
fn supplied_context(input: &AndroidDiagnosticBundleInput) -> IntuneObservationContext {
    let artifact_id = format!("{}{SUPPLIED_FACTS_SUFFIX}", input.bundle_id);
    IntuneObservationContext {
        evidence_ref: IntuneEvidenceRef {
            evidence_id: artifact_id.clone(),
            source_artifact_id: artifact_id.clone(),
        },
        provenance: IntuneProvenance {
            source_kind: IntuneSourceKind::SuppliedFact,
            source_artifact_id: artifact_id,
            file_path: None,
            line_number: None,
            record_number: None,
            registry: None,
            event: None,
        },
        source_timestamp: input
            .supplied
            .collected_at_text
            .as_deref()
            .map(|text| normalize_supplied_timestamp(text, input.supplied.device_time_zone.as_deref())),
        observed_at_utc: input.observed_at_utc.clone(),
        // An incident id is a correlation identifier for a support submission,
        // so the envelope carrying it is sensitive whenever one is present.
        sensitivity: if input.supplied.incident_id.is_some() {
            IntuneSensitivity::Sensitive
        } else {
            IntuneSensitivity::Public
        },
        // The importer's claims were read exactly as given. Nothing about them
        // was interpreted, which is what `Raw` means here.
        parse_state: IntuneParseState::Raw,
        access_state: crate::intune::evidence::IntuneAccessState::Available,
    }
}

fn member_context(
    input: &AndroidDiagnosticBundleInput,
    member: &AndroidDiagnosticMemberInput,
    classification: &AndroidMemberClassification,
) -> IntuneObservationContext {
    IntuneObservationContext {
        evidence_ref: IntuneEvidenceRef {
            evidence_id: format!("{}/{}", member.artifact_id, member.entry_name),
            source_artifact_id: member.artifact_id.clone(),
        },
        provenance: IntuneProvenance {
            source_kind: IntuneSourceKind::DiagnosticReport,
            source_artifact_id: member.artifact_id.clone(),
            file_path: member.sanitized_entry_path.clone(),
            line_number: None,
            record_number: None,
            registry: None,
            event: None,
        },
        source_timestamp: None,
        observed_at_utc: input.observed_at_utc.clone(),
        sensitivity: member_sensitivity(member),
        parse_state: member_parse_state(member, classification),
        access_state: access_state_for(&member.status),
    }
}

/// A member that carries collected content is sensitive; one that carries none
/// has nothing to protect and stays public so the distinction remains useful.
fn member_sensitivity(member: &AndroidDiagnosticMemberInput) -> IntuneSensitivity {
    if member.text.is_some() || member.sanitized_entry_path.is_some() {
        IntuneSensitivity::Sensitive
    } else {
        IntuneSensitivity::Public
    }
}

/// Every member is unsupported except one that failed to decode.
///
/// `Unsupported` is the accurate word while no contract is verified: the bytes
/// may be perfectly well formed, and this build simply will not claim to
/// understand them. `Malformed` is reserved for a member the importer already
/// determined it could not read, where the failure is a fact rather than a
/// limitation of this parser.
fn member_parse_state(
    member: &AndroidDiagnosticMemberInput,
    classification: &AndroidMemberClassification,
) -> IntuneParseState {
    if member.status == IntuneArtifactStatus::ParseFailed {
        return IntuneParseState::Malformed;
    }
    match classification {
        AndroidMemberClassification::RejectedUnsafe
        | AndroidMemberClassification::RecognizedForeignLogcat
        | AndroidMemberClassification::Enumerated
        | AndroidMemberClassification::NotCollected => IntuneParseState::Unsupported,
    }
}

fn coverage_detail(classification: &AndroidMemberClassification) -> String {
    match classification {
        AndroidMemberClassification::Enumerated => {
            "Enumerated only: no verified Android Company Portal artifact contract matched, so the member's contents were not interpreted."
        }
        AndroidMemberClassification::RecognizedForeignLogcat => {
            "Recognized as an Android logcat capture and excluded: a general logcat parser is out of scope."
        }
        AndroidMemberClassification::RejectedUnsafe => {
            "Excluded from evidence because the member carries an import safety flag."
        }
        AndroidMemberClassification::NotCollected => {
            "No content was collected for this member."
        }
    }
    .to_owned()
}

/// Normalize a supplied collection timestamp, preserving the original text.
///
/// Only a value that states its own offset is normalized. A bare wall-clock
/// string is [`IntuneTimestampKind::Local`] when a zone name accompanies it and
/// [`IntuneTimestampKind::Unspecified`] when nothing does; neither produces a
/// UTC value, because this crate cannot resolve a zone name and must not
/// substitute the host's.
pub fn normalize_supplied_timestamp(text: &str, device_time_zone: Option<&str>) -> IntuneTimestamp {
    let trimmed = text.trim();

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        let is_utc = parsed.offset().local_minus_utc() == 0
            && (trimmed.ends_with('Z') || trimmed.ends_with('z'));
        return IntuneTimestamp {
            raw_text: trimmed.to_owned(),
            original_offset: Some(parsed.offset().to_string()),
            normalized_utc: Some(parsed.with_timezone(&Utc).to_rfc3339()),
            kind: if is_utc {
                IntuneTimestampKind::Utc
            } else {
                IntuneTimestampKind::Offset
            },
        };
    }

    let naive_formats = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"];
    let parses_as_wall_clock = naive_formats
        .iter()
        .any(|format| NaiveDateTime::parse_from_str(trimmed, format).is_ok());

    if parses_as_wall_clock {
        return IntuneTimestamp {
            raw_text: trimmed.to_owned(),
            original_offset: None,
            normalized_utc: None,
            kind: if device_time_zone.is_some() {
                IntuneTimestampKind::Local
            } else {
                IntuneTimestampKind::Unspecified
            },
        };
    }

    IntuneTimestamp {
        raw_text: trimmed.to_owned(),
        original_offset: None,
        normalized_utc: None,
        kind: IntuneTimestampKind::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::contract::AndroidDiagnosticApp;
    use super::super::models::{
        AndroidImportLimits, AndroidSuppliedCollectionFacts,
    };

    fn bundle(members: Vec<AndroidDiagnosticMemberInput>) -> AndroidDiagnosticBundleInput {
        AndroidDiagnosticBundleInput {
            bundle_id: "bundle-1".to_owned(),
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            supplied: AndroidSuppliedCollectionFacts {
                app: Some(AndroidDiagnosticApp::CompanyPortal),
                ..Default::default()
            },
            members,
            limits: AndroidImportLimits::default(),
        }
    }

    fn member(artifact_id: &str, entry_name: &str) -> AndroidDiagnosticMemberInput {
        AndroidDiagnosticMemberInput {
            artifact_id: artifact_id.to_owned(),
            entry_name: entry_name.to_owned(),
            sanitized_entry_path: None,
            status: IntuneArtifactStatus::Available,
            declared_bytes: 12,
            encoding: Some("utf-8".to_owned()),
            rotation: None,
            text: Some("key = value\n".to_owned()),
            safety_flags: Vec::new(),
        }
    }

    #[test]
    fn no_bundle_produces_a_parsed_record() {
        let snapshot = analyze_android_diagnostic_bundle(&bundle(vec![
            member("b", "second.txt"),
            member("a", "first.txt"),
        ]));
        assert!(snapshot.records.is_empty());
        assert!(snapshot.metadata.verified_contract_id.is_none());
    }

    #[test]
    fn members_and_coverage_are_emitted_in_artifact_id_order() {
        let snapshot = analyze_android_diagnostic_bundle(&bundle(vec![
            member("z-last", "z.txt"),
            member("a-first", "a.txt"),
        ]));
        let ids: Vec<&str> = snapshot
            .members
            .iter()
            .map(|entry| entry.artifact_id.as_str())
            .collect();
        assert_eq!(ids, vec!["a-first", "z-last"]);
        let coverage_ids: Vec<&str> = snapshot
            .coverage
            .iter()
            .map(|entry| entry.artifact_id.as_str())
            .collect();
        assert_eq!(coverage_ids, vec!["a-first", "z-last"]);
    }

    #[test]
    fn analysis_is_deterministic() {
        let input = bundle(vec![member("a", "a.txt"), member("b", "b.txt")]);
        let first = serde_json::to_string(&analyze_android_diagnostic_bundle(&input)).unwrap();
        let second = serde_json::to_string(&analyze_android_diagnostic_bundle(&input)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn an_offset_timestamp_is_normalized_and_keeps_its_offset() {
        let stamp = normalize_supplied_timestamp("2026-07-31T09:14:02+10:00", None);
        assert_eq!(stamp.kind, IntuneTimestampKind::Offset);
        assert_eq!(stamp.original_offset.as_deref(), Some("+10:00"));
        assert!(stamp.normalized_utc.is_some());
    }

    #[test]
    fn a_utc_timestamp_is_reported_as_utc() {
        let stamp = normalize_supplied_timestamp("2026-07-31T09:14:02Z", None);
        assert_eq!(stamp.kind, IntuneTimestampKind::Utc);
    }

    #[test]
    fn a_wall_clock_with_a_zone_name_is_local_and_never_normalized() {
        let stamp = normalize_supplied_timestamp("2026-07-31T09:14:02", Some("Australia/Sydney"));
        assert_eq!(stamp.kind, IntuneTimestampKind::Local);
        assert_eq!(stamp.normalized_utc, None);
    }

    #[test]
    fn a_wall_clock_without_a_zone_is_unspecified() {
        let stamp = normalize_supplied_timestamp("2026-07-31 09:14:02", None);
        assert_eq!(stamp.kind, IntuneTimestampKind::Unspecified);
        assert_eq!(stamp.normalized_utc, None);
    }

    #[test]
    fn an_unreadable_timestamp_is_invalid_and_keeps_its_text() {
        let stamp = normalize_supplied_timestamp("yesterday afternoon", None);
        assert_eq!(stamp.kind, IntuneTimestampKind::Invalid);
        assert_eq!(stamp.raw_text, "yesterday afternoon");
    }

    #[test]
    fn a_parse_failed_member_is_malformed_rather_than_unsupported() {
        let mut broken = member("a", "a.txt");
        broken.status = IntuneArtifactStatus::ParseFailed;
        let snapshot = analyze_android_diagnostic_bundle(&bundle(vec![broken]));
        assert_eq!(
            snapshot.members[0].context.parse_state,
            IntuneParseState::Malformed
        );
    }

    #[test]
    fn a_member_with_no_collected_content_is_public_rather_than_sensitive() {
        let mut absent = member("a", "a.txt");
        absent.status = IntuneArtifactStatus::Missing;
        absent.text = None;
        absent.declared_bytes = 0;
        let snapshot = analyze_android_diagnostic_bundle(&bundle(vec![absent]));
        assert_eq!(
            snapshot.members[0].context.sensitivity,
            IntuneSensitivity::Public
        );
    }
}
