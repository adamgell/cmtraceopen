//! Reduction of supplied Console exports into one immutable snapshot.
//!
//! The reducer never decides that something did not happen. A Console capture
//! covers only the window in which the operator was recording, so the artifact
//! status, the truncation flags, and the record cap are all carried forward and
//! every rule downstream is written against them.

use super::classify::{reported_app_version, reported_os_version};
use super::layout::resolve_layout;
use super::models::{
    ConsoleAnalysisOptions, ConsoleArtifact, ConsoleDiagnosticsSnapshot, ConsoleExportInput,
    ConsoleLayout, ConsoleLayoutConfidence, ConsoleLayoutRefusal, ConsoleRecord, ConsoleSourceClass,
    ConsoleTotals, COMPANY_PORTAL_IOS_CONSOLE_FAMILY, COMPANY_PORTAL_IOS_CONSOLE_SCHEMA_VERSION,
};
use super::parse::{parse_export, ParseContext, ParseOutcome};
use super::rules::derive_findings;
use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneParseState,
    IntuneTimestampKind,
};

/// Analyze a bundle of imported Console exports.
///
/// Inputs are read in the order given, and records keep capture order within
/// each artifact, so two runs over the same bundle produce byte-identical
/// output.
pub fn analyze_console_exports(
    inputs: &[ConsoleExportInput],
    options: &ConsoleAnalysisOptions,
) -> ConsoleDiagnosticsSnapshot {
    let mut artifacts = Vec::with_capacity(inputs.len());
    let mut records: Vec<ConsoleRecord> = Vec::new();
    let mut coverage = Vec::with_capacity(inputs.len());

    for input in inputs {
        let (artifact, outcome) = analyze_one(input, options);
        coverage.push(IntuneArtifactCoverage {
            artifact_id: artifact.artifact_id.clone(),
            family: COMPANY_PORTAL_IOS_CONSOLE_FAMILY.to_owned(),
            status: artifact.status.clone(),
            detail: coverage_detail(input, &artifact),
            observed_at_utc: options.observed_at_utc.clone(),
            evidence: Vec::new(),
        });
        artifacts.push(artifact);
        records.extend(outcome.records);
    }

    let totals = totals_of(&artifacts, &records);

    let mut snapshot = ConsoleDiagnosticsSnapshot {
        schema_version: COMPANY_PORTAL_IOS_CONSOLE_SCHEMA_VERSION,
        observed_at_utc: options.observed_at_utc.clone(),
        artifacts,
        records,
        coverage,
        findings: Vec::new(),
        totals,
    };
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

fn analyze_one(
    input: &ConsoleExportInput,
    options: &ConsoleAnalysisOptions,
) -> (ConsoleArtifact, ParseOutcome) {
    let Some(content) = input.content.as_deref().filter(|_| carries_content(input)) else {
        return (uncollected_artifact(input), ParseOutcome::default());
    };

    let lines: Vec<&str> = content.lines().collect();
    let resolved = resolve_layout(&lines);
    let context = ParseContext {
        artifact_id: &input.artifact_id,
        file_path: input.file_path.as_deref(),
        observed_at_utc: &options.observed_at_utc,
        access_state: input.acquisition.clone(),
        max_records: options.max_records_per_artifact,
    };
    let outcome = parse_export(content, &resolved, &context);

    let parsed_records = outcome
        .records
        .iter()
        .filter(|record| record.context.parse_state == IntuneParseState::Parsed)
        .count();
    let status = derive_status(input, &resolved.layout, &outcome, parsed_records);

    let company_portal_record_count = count_class(&outcome.records, ConsoleSourceClass::CompanyPortal);
    let unrelated_record_count = count_class(&outcome.records, ConsoleSourceClass::Unrelated);
    let malformed_record_count = outcome
        .records
        .iter()
        .filter(|record| record.context.parse_state == IntuneParseState::Malformed)
        .count();

    let artifact = ConsoleArtifact {
        artifact_id: input.artifact_id.clone(),
        file_name: input.file_name.clone(),
        file_path: input.file_path.clone(),
        layout: resolved.layout,
        layout_confidence: resolved.confidence,
        layout_refusal: resolved.refusal,
        status,
        columns: resolved.columns.clone(),
        preamble_line_count: resolved.preamble_line_count,
        record_count: as_u32(outcome.records.len()),
        company_portal_record_count: as_u32(company_portal_record_count),
        unrelated_record_count: as_u32(unrelated_record_count),
        malformed_record_count: as_u32(malformed_record_count),
        truncated_leading_fragment: outcome.truncated_leading_fragment,
        truncated_trailing_record: outcome.truncated_trailing_record,
        record_cap_reached: outcome.record_cap_reached,
        reported_app_version: first_match(&outcome.records, reported_app_version),
        reported_os_version: first_match(&outcome.records, reported_os_version),
    };

    (artifact, outcome)
}

/// Whether this input actually supplied bytes to read.
fn carries_content(input: &ConsoleExportInput) -> bool {
    matches!(
        input.acquisition,
        IntuneAccessState::Available | IntuneAccessState::Capped
    )
}

fn uncollected_artifact(input: &ConsoleExportInput) -> ConsoleArtifact {
    ConsoleArtifact {
        artifact_id: input.artifact_id.clone(),
        file_name: input.file_name.clone(),
        file_path: input.file_path.clone(),
        layout: ConsoleLayout::Unresolved,
        layout_confidence: ConsoleLayoutConfidence::None,
        layout_refusal: None,
        status: status_of_acquisition(&input.acquisition),
        columns: Vec::new(),
        preamble_line_count: 0,
        record_count: 0,
        company_portal_record_count: 0,
        unrelated_record_count: 0,
        malformed_record_count: 0,
        truncated_leading_fragment: false,
        truncated_trailing_record: false,
        record_cap_reached: false,
        reported_app_version: None,
        reported_os_version: None,
    }
}

/// The coverage status implied by an acquisition state alone.
fn status_of_acquisition(acquisition: &IntuneAccessState) -> IntuneArtifactStatus {
    match acquisition {
        IntuneAccessState::Available => IntuneArtifactStatus::Available,
        IntuneAccessState::Capped => IntuneArtifactStatus::Capped,
        IntuneAccessState::Missing => IntuneArtifactStatus::Missing,
        IntuneAccessState::PermissionDenied => IntuneArtifactStatus::PermissionDenied,
        IntuneAccessState::Skipped => IntuneArtifactStatus::Skipped,
        IntuneAccessState::Unsupported => IntuneArtifactStatus::Unsupported,
        IntuneAccessState::Failed => IntuneArtifactStatus::ParseFailed,
    }
}

/// Decide what became of an artifact that did supply bytes.
///
/// Acquisition is what the collector knows; `Unsupported` and `ParseFailed` are
/// conclusions only the content can support, so they are derived here and never
/// accepted from a caller.
fn derive_status(
    input: &ConsoleExportInput,
    layout: &ConsoleLayout,
    outcome: &ParseOutcome,
    parsed_records: usize,
) -> IntuneArtifactStatus {
    if *layout == ConsoleLayout::Unresolved {
        // Not this format. Refusing beats emitting confident nonsense about a
        // file that was never a Console export.
        return IntuneArtifactStatus::Unsupported;
    }
    if parsed_records == 0 {
        // The layout resolved and nothing inside it survived: the bytes are
        // present and unusable, which is precisely `ParseFailed`.
        return IntuneArtifactStatus::ParseFailed;
    }
    if outcome.record_cap_reached || input.acquisition == IntuneAccessState::Capped {
        return IntuneArtifactStatus::Capped;
    }
    IntuneArtifactStatus::Available
}

fn coverage_detail(input: &ConsoleExportInput, artifact: &ConsoleArtifact) -> Option<String> {
    if let Some(detail) = input.detail.clone() {
        return Some(detail);
    }
    match artifact.layout_refusal {
        Some(ConsoleLayoutRefusal::NotAConsoleExport) => {
            Some("The file is not a macOS Console plain-text export.".to_owned())
        }
        Some(ConsoleLayoutRefusal::UnknownHeaderVocabulary) => Some(
            "The header row matches no Console column vocabulary this build recognizes.".to_owned(),
        ),
        Some(ConsoleLayoutRefusal::IncompleteHeader) => Some(
            "The header row omits a timestamp or message column, so records cannot be framed."
                .to_owned(),
        ),
        None if artifact.status == IntuneArtifactStatus::ParseFailed => Some(
            "The layout resolved but no record could be read from it.".to_owned(),
        ),
        None if artifact.record_cap_reached => {
            Some("The per-artifact record cap was reached; the remainder was not read.".to_owned())
        }
        None => None,
    }
}

fn count_class(records: &[ConsoleRecord], class: ConsoleSourceClass) -> usize {
    records
        .iter()
        .filter(|record| record.source_class == class)
        .count()
}

/// The first non-empty extraction across a set of Company Portal records.
fn first_match(
    records: &[ConsoleRecord],
    extract: fn(&str) -> Option<String>,
) -> Option<String> {
    records
        .iter()
        .filter(|record| record.is_company_portal())
        .find_map(|record| extract(&record.message))
}

fn totals_of(artifacts: &[ConsoleArtifact], records: &[ConsoleRecord]) -> ConsoleTotals {
    ConsoleTotals {
        artifact_count: as_u32(artifacts.len()),
        record_count: as_u32(records.len()),
        company_portal_record_count: as_u32(count_class(
            records,
            ConsoleSourceClass::CompanyPortal,
        )),
        malformed_record_count: as_u32(
            records
                .iter()
                .filter(|record| record.context.parse_state == IntuneParseState::Malformed)
                .count(),
        ),
        offsetless_record_count: as_u32(
            records
                .iter()
                .filter(|record| {
                    record
                        .context
                        .source_timestamp
                        .as_ref()
                        .is_some_and(|stamp| stamp.kind == IntuneTimestampKind::Local)
                })
                .count(),
        ),
    }
}

fn as_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::IntuneSourceKind;

    const HEADER: &str =
        "Timestamp\tType\tProcess\tPID\tTID\tActivity\tSubsystem\tCategory\tMessage";

    fn export(body: &str) -> String {
        format!("{HEADER}\n{body}\n")
    }

    fn row(seconds: &str, process: &str, subsystem: &str, message: &str) -> String {
        format!(
            "2026-03-12 10:15:{seconds}.100000-0700\tDefault\t{process}\t418\t0x1f4a\t0\t{subsystem}\tGeneral\t{message}"
        )
    }

    fn analyze(inputs: &[ConsoleExportInput]) -> ConsoleDiagnosticsSnapshot {
        analyze_console_exports(inputs, &ConsoleAnalysisOptions::observed_at("2026-07-31T00:00:00Z"))
    }

    #[test]
    fn a_supported_export_reports_available_coverage_and_cited_records() {
        let content = export(&row("22", "CompanyPortal", "com.microsoft.CompanyPortal", "hello"));
        let snapshot = analyze(&[ConsoleExportInput::captured("a1", "console.log", content)]);
        assert_eq!(snapshot.coverage[0].status, IntuneArtifactStatus::Available);
        assert_eq!(snapshot.totals.company_portal_record_count, 1);
        assert_eq!(
            snapshot.records[0].context.provenance.source_kind,
            IntuneSourceKind::PlainTextLog
        );
        assert_eq!(
            snapshot.records[0].context.evidence_ref.evidence_id,
            "a1:r1"
        );
    }

    #[test]
    fn an_arbitrary_text_file_is_unsupported_not_empty() {
        let snapshot = analyze(&[ConsoleExportInput::captured(
            "a1",
            "notes.log",
            "some notes\nmore notes\n",
        )]);
        assert_eq!(snapshot.coverage[0].status, IntuneArtifactStatus::Unsupported);
        assert!(snapshot.records.is_empty());
        assert_eq!(
            snapshot.artifacts[0].layout_refusal,
            Some(ConsoleLayoutRefusal::NotAConsoleExport)
        );
    }

    #[test]
    fn a_resolved_layout_with_no_usable_record_is_a_parse_failure() {
        let content = format!("{HEADER}\n2026-13-45 99:99:99\tx\ty\n");
        let snapshot = analyze(&[ConsoleExportInput::captured("a1", "console.log", content)]);
        assert_eq!(snapshot.coverage[0].status, IntuneArtifactStatus::ParseFailed);
    }

    #[test]
    fn a_caller_declared_cap_survives_a_clean_parse() {
        let content = export(&row("22", "CompanyPortal", "com.microsoft.CompanyPortal", "hi"));
        let input = ConsoleExportInput {
            acquisition: IntuneAccessState::Capped,
            ..ConsoleExportInput::captured("a1", "console.log", content)
        };
        let snapshot = analyze(&[input]);
        assert_eq!(snapshot.coverage[0].status, IntuneArtifactStatus::Capped);
    }

    #[test]
    fn an_uncollected_artifact_still_produces_coverage() {
        let input = ConsoleExportInput {
            artifact_id: "a2".to_owned(),
            file_name: "console-2.log".to_owned(),
            file_path: None,
            content: None,
            acquisition: IntuneAccessState::PermissionDenied,
            detail: Some("The export could not be read.".to_owned()),
        };
        let snapshot = analyze(&[input]);
        assert_eq!(
            snapshot.coverage[0].status,
            IntuneArtifactStatus::PermissionDenied
        );
        assert_eq!(
            snapshot.coverage[0].detail.as_deref(),
            Some("The export could not be read.")
        );
        assert!(snapshot.records.is_empty());
    }

    #[test]
    fn analysis_is_byte_for_byte_reproducible() {
        let content = export(&format!(
            "{}\n{}",
            row("22", "CompanyPortal", "com.microsoft.CompanyPortal", "one"),
            row("23", "SpringBoard", "com.apple.springboard", "two")
        ));
        let inputs = [ConsoleExportInput::captured("a1", "console.log", content)];
        let first = serde_json::to_string(&analyze(&inputs)).expect("snapshot serializes");
        let second = serde_json::to_string(&analyze(&inputs)).expect("snapshot serializes");
        assert_eq!(first, second);
    }

    #[test]
    fn a_version_banner_is_attributed_only_to_company_portal_records() {
        let content = export(&format!(
            "{}\n{}",
            row(
                "22",
                "SpringBoard",
                "com.apple.springboard",
                "Company Portal 9.9.9 mentioned by an unrelated process"
            ),
            row(
                "23",
                "CompanyPortal",
                "com.microsoft.CompanyPortal",
                "Company Portal 5.2026.1 on iOS 18.4 starting"
            )
        ));
        let snapshot = analyze(&[ConsoleExportInput::captured("a1", "console.log", content)]);
        assert_eq!(
            snapshot.artifacts[0].reported_app_version.as_deref(),
            Some("5.2026.1")
        );
        assert_eq!(
            snapshot.artifacts[0].reported_os_version.as_deref(),
            Some("18.4")
        );
    }
}
