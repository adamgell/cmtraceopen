//! Reduction from supplied artifacts to a [`CompanyPortalLogSnapshot`].
//!
//! The reduction is total: every framed record becomes an observation, whether
//! or not this build understood it. A record it could not decompose keeps its
//! exact source text and is marked
//! [`IntuneParseState::Malformed`] or [`IntuneParseState::Raw`], which is what
//! makes "we saw nothing" and "we could not read what we saw" distinguishable
//! downstream.

use std::collections::BTreeSet;

use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneEvidenceRef, IntuneNamedValue, IntuneObservationContext,
    IntuneParseState, IntuneProvenance, IntuneSensitivity, IntuneSourceKind, IntuneTimestamp,
    IntuneTimestampKind,
};

use super::grammar::{frame_records, FramedRecord, HeaderTimestamp};
use super::models::{
    CompanyPortalClassifiedString, CompanyPortalLogArtifact, CompanyPortalLogRecord,
    CompanyPortalLogSnapshot, CompanyPortalLogStats, CompanyPortalRecordProfile,
    CompanyPortalSeverity, CompanyPortalSeverityCounts, COMPANY_PORTAL_LOG_SCHEMA_VERSION,
    SUPPORTED_APP_VERSION_MAJORS,
};
use super::sources::CompanyPortalLogSource;

/// Source-kind token for a direct Company Portal application log.
///
/// Carried as [`IntuneSourceKind::Unknown`] rather than a new shared variant.
/// The shared enum round-trips unrecognized kinds precisely so a leaf can name
/// its own source without editing a file every sibling issue also touches, and
/// this keeps direct app logs distinct from `diagnosticReport` and `unifiedLog`.
pub const COMPANY_PORTAL_APP_LOG_SOURCE_KIND: &str = "companyPortalAppLog";

/// Coverage family every artifact of this leaf reports under.
pub const COMPANY_PORTAL_LOG_FAMILY: &str = "portal/macos/company-portal/logs";

/// Reduce supplied artifacts into one snapshot.
///
/// Artifacts are visited oldest rotation first, so the record order in the
/// snapshot is the order the app wrote them across the whole directory rather
/// than the order the adapter happened to enumerate files.
pub fn analyze_company_portal_logs(sources: &[CompanyPortalLogSource]) -> CompanyPortalLogSnapshot {
    let mut ordered: Vec<&CompanyPortalLogSource> = sources.iter().collect();
    ordered.sort_by(|left, right| {
        left.rotation()
            .chronological_key()
            .cmp(&right.rotation().chronological_key())
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });

    let mut artifacts = Vec::with_capacity(ordered.len());
    let mut records = Vec::new();
    let mut coverage = Vec::with_capacity(ordered.len());
    let mut unknown_versions: BTreeSet<String> = BTreeSet::new();

    for source in ordered {
        let detection = super::detection::detect_company_portal_log(source);

        // Only a confirmed artifact contributes records. An artifact refused as
        // a diagnostic report or a unified-log export is still reported in
        // coverage, so the operator can see it was present and why it was not
        // used, instead of it vanishing.
        let framed: Vec<FramedRecord> = match (&source.content, detection.confirmed) {
            (Some(content), true) => frame_records(content),
            _ => Vec::new(),
        };

        let mut artifact_records = Vec::with_capacity(framed.len());
        for (index, record) in framed.iter().enumerate() {
            let record = build_record(source, record, index as u32);
            if let Some(version) = &record.app_version {
                if !is_supported_app_version(version) {
                    unknown_versions.insert(version.clone());
                }
            }
            artifact_records.push(record);
        }

        let malformed = artifact_records
            .iter()
            .filter(|record| record.profile == CompanyPortalRecordProfile::Unrecognized)
            .count() as u32;

        coverage.push(IntuneArtifactCoverage {
            artifact_id: source.artifact_id.clone(),
            family: COMPANY_PORTAL_LOG_FAMILY.to_owned(),
            status: source.capture_state.artifact_status(),
            detail: coverage_detail(&detection),
            observed_at_utc: source.captured_at_utc.clone(),
            // One anchor rather than the whole record list: coverage answers
            // whether the artifact was usable, not what it said. Findings cite
            // the records they actually rest on.
            evidence: artifact_records
                .first()
                .map(|record| record.context.evidence_ref.clone())
                .into_iter()
                .collect(),
        });

        artifacts.push(CompanyPortalLogArtifact {
            artifact_id: source.artifact_id.clone(),
            file_name: source.file_name.clone(),
            file_path: source
                .sanitized_file_path
                .clone()
                .map(CompanyPortalClassifiedString::sensitive),
            capture_state: source.capture_state,
            rotation: source.rotation(),
            detection,
            encoding: source.encoding.clone(),
            record_count: artifact_records.len() as u32,
            malformed_record_count: malformed,
            captured_at_utc: source.captured_at_utc.clone(),
        });

        records.extend(artifact_records);
    }

    let stats = build_stats(&records);
    let advanced_logging_observed = stats.advanced_records > 0;

    CompanyPortalLogSnapshot {
        schema_version: COMPANY_PORTAL_LOG_SCHEMA_VERSION,
        artifacts,
        records,
        coverage,
        stats,
        unknown_app_versions: unknown_versions.into_iter().collect(),
        advanced_logging_observed,
    }
}

fn coverage_detail(
    detection: &super::models::CompanyPortalLogDetection,
) -> Option<String> {
    use super::models::CompanyPortalLogRejection as Rejection;
    let rejection = detection.rejection.as_ref()?;
    Some(
        match rejection {
            Rejection::NoRecords => "no line matched the Company Portal app-log grammar",
            Rejection::ForeignProcess => {
                "records parsed but named a process other than Company Portal"
            }
            Rejection::DiagnosticReport => {
                "content is a saved diagnostic report, which is a separate source kind"
            }
            Rejection::UnifiedLogExport => {
                "content is an Apple unified-log export, which is a separate source kind"
            }
            Rejection::InsufficientEvidence => {
                "too few Company Portal records to confirm without a path hint"
            }
            Rejection::NoContent => "the capture produced no bytes to inspect",
        }
        .to_owned(),
    )
}

fn build_stats(records: &[CompanyPortalLogRecord]) -> CompanyPortalLogStats {
    let malformed = records
        .iter()
        .filter(|record| record.profile == CompanyPortalRecordProfile::Unrecognized)
        .count() as u32;

    CompanyPortalLogStats {
        total_records: records.len() as u32,
        parsed_records: records.len() as u32 - malformed,
        malformed_records: malformed,
        continuation_lines: records.iter().map(|record| record.continuation_lines).sum(),
        advanced_records: records.iter().filter(|record| record.is_advanced()).count() as u32,
        severity_counts: CompanyPortalSeverityCounts::from_records(records),
    }
}

/// Is this app version one this build claims to understand?
///
/// Only the major component is checked. Company Portal's minor component is a
/// build stamp that changes every release, so pinning it would report every
/// shipped version as unknown and the signal would be worthless.
pub fn is_supported_app_version(version: &str) -> bool {
    version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| SUPPORTED_APP_VERSION_MAJORS.contains(&major))
}

fn build_record(
    source: &CompanyPortalLogSource,
    framed: &FramedRecord,
    index: u32,
) -> CompanyPortalLogRecord {
    let evidence_ref = IntuneEvidenceRef {
        evidence_id: format!("{}#{index}", source.artifact_id),
        source_artifact_id: source.artifact_id.clone(),
    };

    let profile = match &framed.fields {
        Some(fields) if fields.attributes.is_empty() => CompanyPortalRecordProfile::Basic,
        Some(_) => CompanyPortalRecordProfile::Attributed,
        None => CompanyPortalRecordProfile::Unrecognized,
    };

    let parse_state = match (&framed.fields, framed.orphaned) {
        (Some(_), _) => IntuneParseState::Parsed,
        // A tail with no header above it is not corrupt: it is the far side of a
        // rotation boundary. Calling it malformed would report a fault that the
        // evidence does not support.
        (None, true) => IntuneParseState::Raw,
        (None, false) => IntuneParseState::Malformed,
    };

    let severity_token = framed
        .fields
        .as_ref()
        .map(|fields| fields.severity_token.clone());
    let severity = severity_token.as_deref().map(|token| {
        CompanyPortalSeverity::from_token(token)
            .unwrap_or_else(|| CompanyPortalSeverity::Unknown(token.to_owned()))
    });

    let attributes: Vec<IntuneNamedValue> = framed
        .fields
        .as_ref()
        .map(|fields| {
            fields
                .attributes
                .iter()
                .map(|(name, value)| IntuneNamedValue {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let attribute = |key: &str| {
        attributes
            .iter()
            .find(|entry| entry.name == key)
            .map(|entry| entry.value.clone())
    };
    let category = attribute("category");
    let activity_id = attribute("activity");

    // Advanced logging widens what the app writes to include certificate and
    // network-response material, so the classification tightens with it. Keyed on
    // the same signal as `CompanyPortalLogRecord::is_advanced`.
    let sensitivity = if category.is_some() || activity_id.is_some() {
        IntuneSensitivity::Restricted
    } else {
        IntuneSensitivity::Sensitive
    };

    CompanyPortalLogRecord {
        context: IntuneObservationContext {
            evidence_ref,
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::Unknown(
                    COMPANY_PORTAL_APP_LOG_SOURCE_KIND.to_owned(),
                ),
                source_artifact_id: source.artifact_id.clone(),
                file_path: source.sanitized_file_path.clone(),
                line_number: Some(framed.line_number),
                record_number: Some(u64::from(index)),
                registry: None,
                event: None,
            },
            source_timestamp: framed
                .fields
                .as_ref()
                .map(|fields| normalize_timestamp(&fields.timestamp)),
            observed_at_utc: source.captured_at_utc.clone(),
            sensitivity,
            parse_state,
            access_state: source.capture_state.access_state(),
        },
        record_index: index,
        profile,
        process: framed
            .fields
            .as_ref()
            .map(|fields| fields.process.clone()),
        severity,
        severity_token,
        thread: framed
            .fields
            .as_ref()
            .and_then(|fields| fields.thread_token.parse().ok()),
        subsystem: framed
            .fields
            .as_ref()
            .map(|fields| fields.subsystem.clone()),
        category,
        activity_id,
        app_version: attribute("version"),
        attributes,
        message: CompanyPortalClassifiedString::sensitive(framed.message()),
        raw: CompanyPortalClassifiedString::sensitive(framed.raw.clone()),
        continuation_lines: framed.continuation_lines,
    }
}

/// Normalize a header timestamp without inventing information.
///
/// A UTC value is produced only when the record stated its own offset. Deriving
/// one from a bare local wall-clock time would silently bake in the timezone of
/// whichever machine happened to run the parse, and the resulting value would
/// differ between the technician's laptop and the customer's.
fn normalize_timestamp(timestamp: &HeaderTimestamp) -> IntuneTimestamp {
    let naive = chrono::NaiveDate::from_ymd_opt(timestamp.year, timestamp.month, timestamp.day)
        .and_then(|date| {
            date.and_hms_milli_opt(
                timestamp.hour,
                timestamp.minute,
                timestamp.second,
                timestamp.millisecond,
            )
        });

    let Some(naive) = naive else {
        return IntuneTimestamp {
            raw_text: timestamp.raw_text.clone(),
            original_offset: timestamp.offset_text.clone(),
            normalized_utc: None,
            kind: IntuneTimestampKind::Invalid,
        };
    };

    match timestamp.offset_minutes {
        Some(minutes) => {
            let utc = naive - chrono::Duration::minutes(i64::from(minutes));
            IntuneTimestamp {
                raw_text: timestamp.raw_text.clone(),
                original_offset: timestamp.offset_text.clone(),
                normalized_utc: Some(
                    utc.and_utc()
                        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                        .to_string(),
                ),
                kind: if minutes == 0 {
                    IntuneTimestampKind::Utc
                } else {
                    IntuneTimestampKind::Offset
                },
            }
        }
        None => IntuneTimestamp {
            raw_text: timestamp.raw_text.clone(),
            original_offset: None,
            normalized_utc: None,
            kind: IntuneTimestampKind::Unspecified,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::IntuneArtifactStatus;
    use crate::intune::portal::macos::company_portal::logs::models::CompanyPortalCaptureState;

    fn source(artifact_id: &str, file_name: &str, content: &str) -> CompanyPortalLogSource {
        CompanyPortalLogSource {
            artifact_id: artifact_id.to_owned(),
            file_name: file_name.to_owned(),
            sanitized_file_path: Some(format!(
                "SYNTHETIC://Library/Logs/CompanyPortal/{file_name}"
            )),
            capture_state: CompanyPortalCaptureState::Captured,
            content: Some(content.to_owned()),
            encoding: Some("UTF-8".to_owned()),
            captured_at_utc: "2026-07-31T00:00:00Z".to_owned(),
        }
    }

    const BASIC: &str = concat!(
        "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | listing apps\n",
        "2026-03-12 09:14:23:100 | CompanyPortal | E | 8412 | Catalog | listing failed\n",
    );

    #[test]
    fn a_confirmed_artifact_contributes_records_and_available_coverage() {
        let snapshot = analyze_company_portal_logs(&[source("cp", "CompanyPortal.log", BASIC)]);
        assert_eq!(snapshot.records.len(), 2);
        assert_eq!(snapshot.stats.severity_counts.info, 1);
        assert_eq!(snapshot.stats.severity_counts.error, 1);
        assert_eq!(snapshot.coverage[0].status, IntuneArtifactStatus::Available);
        assert_eq!(
            snapshot.records[0].context.evidence_ref.evidence_id,
            "cp#0"
        );
    }

    #[test]
    fn records_are_ordered_oldest_rotation_first() {
        let older = concat!(
            "2026-03-11 08:00:00:000 | CompanyPortal | I | 1 | Catalog | older\n",
            "2026-03-11 08:00:01:000 | CompanyPortal | I | 1 | Catalog | older still\n",
        );
        let snapshot = analyze_company_portal_logs(&[
            source("cp-current", "CompanyPortal.log", BASIC),
            source("cp-1", "CompanyPortal-1.log", older),
        ]);
        assert_eq!(
            snapshot
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cp-1", "cp-current"]
        );
        assert_eq!(snapshot.records[0].message.value, "older");
    }

    #[test]
    fn an_offset_bearing_record_normalizes_to_utc_and_a_bare_one_does_not() {
        let content = concat!(
            "2026-03-12 09:14:22:301-0700 | CompanyPortal | I | 1 | Catalog | with offset\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | I | 1 | Catalog | without offset\n",
        );
        let snapshot = analyze_company_portal_logs(&[source("cp", "CompanyPortal.log", content)]);
        let first = snapshot.records[0].context.source_timestamp.as_ref().unwrap();
        assert_eq!(
            first.normalized_utc.as_deref(),
            Some("2026-03-12T16:14:22.301Z")
        );
        assert_eq!(first.kind, IntuneTimestampKind::Offset);

        let second = snapshot.records[1].context.source_timestamp.as_ref().unwrap();
        assert_eq!(second.normalized_utc, None);
        assert_eq!(second.kind, IntuneTimestampKind::Unspecified);
        assert_eq!(second.raw_text, "2026-03-12 09:14:23:000");
    }

    #[test]
    fn a_truncated_record_is_malformed_and_still_preserved() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Catalog | good\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | I\n",
            "2026-03-12 09:14:24:000 | CompanyPortal | I | 1 | Catalog | good again\n",
        );
        let snapshot = analyze_company_portal_logs(&[source("cp", "CompanyPortal.log", content)]);
        assert_eq!(snapshot.stats.malformed_records, 1);
        let malformed = &snapshot.records[1];
        assert_eq!(malformed.profile, CompanyPortalRecordProfile::Unrecognized);
        assert_eq!(malformed.context.parse_state, IntuneParseState::Malformed);
        assert_eq!(malformed.raw.value, "2026-03-12 09:14:23:000 | CompanyPortal | I");
    }

    #[test]
    fn a_rejected_artifact_still_appears_in_coverage_with_a_reason() {
        let mut refused = source("cp", "CompanyPortal.log", "=== Company Portal Diagnostic Report ===\nDiagnosticReportVersion: 3\n");
        refused.capture_state = CompanyPortalCaptureState::Captured;
        let snapshot = analyze_company_portal_logs(&[refused]);
        assert!(snapshot.records.is_empty());
        assert_eq!(snapshot.coverage[0].status, IntuneArtifactStatus::Available);
        assert!(snapshot.coverage[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("diagnostic report"));
    }

    #[test]
    fn an_unsupported_major_version_is_reported_without_dropping_the_record() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Logging | version=9.2601.0 | starting\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | I | 1 | Catalog | listing apps\n",
        );
        let snapshot = analyze_company_portal_logs(&[source("cp", "CompanyPortal.log", content)]);
        assert_eq!(snapshot.unknown_app_versions, vec!["9.2601.0".to_owned()]);
        assert_eq!(snapshot.records.len(), 2);
        assert!(is_supported_app_version("5.2404.0"));
        assert!(!is_supported_app_version("nightly"));
    }

    #[test]
    fn advanced_records_are_classified_restricted() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | E | 1 | Network | category=Http | activity=0x1 | failed\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | I | 1 | Catalog | fine\n",
        );
        let snapshot = analyze_company_portal_logs(&[source("cp", "CompanyPortal.log", content)]);
        assert!(snapshot.advanced_logging_observed);
        assert_eq!(
            snapshot.records[0].context.sensitivity,
            IntuneSensitivity::Restricted
        );
        assert_eq!(
            snapshot.records[1].context.sensitivity,
            IntuneSensitivity::Sensitive
        );
        assert_eq!(snapshot.records[0].activity_id.as_deref(), Some("0x1"));
        assert_eq!(snapshot.records[0].category.as_deref(), Some("Http"));
    }
}
