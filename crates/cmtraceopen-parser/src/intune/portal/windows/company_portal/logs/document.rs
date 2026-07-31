//! Builds the canonical Company Portal Windows log evidence document.
//!
//! There is **no semantic phase classification here**. Company Portal spans
//! sign-in, enrollment, app catalog, compliance, sync, device actions, and
//! support, but not one of those concepts is proven by the single published
//! record, so records stay ordinary parsed log records. Codes and unknown
//! tokens are preserved as text; nothing is promoted to an outcome.

use super::detect::parse_file_identity;
use super::framing::{frame_records, FramedRecord, FramedRecordKind};
use super::models::*;
use super::redaction::redacted_export_projection;

/// Coverage artifact id for the file itself.
const FILE_COVERAGE_ARTIFACT_ID: &str = "companyPortal.windows.logs";
/// Coverage artifact id for the grammar-version gap.
const GRAMMAR_COVERAGE_ARTIFACT_ID: &str = "companyPortal.windows.logs.grammar";
const COVERAGE_FAMILY: &str = "company-portal-logs";

/// Parse Company Portal log text into a **redacted** evidence document.
///
/// This is the default entry point: the returned document has already had
/// UPN/email, user-profile paths, SIDs, tenant/serial/token-labelled values,
/// and network identifiers removed. Use
/// [`parse_log_document_preserving_local_values`] only for local rendering that
/// never leaves the machine.
///
/// `file_path` is used only to derive the file identity — no filesystem access
/// is performed, and only the file name is retained in the document.
pub fn parse_log_document(file_path: &str, content: &str) -> CompanyPortalLogDocument {
    redacted_export_projection(&parse_log_document_preserving_local_values(
        file_path, content,
    ))
}

/// Parse Company Portal log text without redacting sensitive values.
///
/// The result carries `redacted: false` and must not be exported, uploaded, or
/// attached to a support case.
pub fn parse_log_document_preserving_local_values(
    file_path: &str,
    content: &str,
) -> CompanyPortalLogDocument {
    let file = parse_file_identity(file_name_of(file_path));
    let lines: Vec<&str> = content.lines().collect();
    let framed = frame_records(&lines);

    let records: Vec<CompanyPortalLogRecord> = framed
        .iter()
        .map(|record| build_record(&file.file_name, record))
        .collect();

    let parsed_count = framed.len() - framed.iter().filter(|r| r.is_parse_error()).count();
    let experimental_count = framed
        .iter()
        .filter(|record| match &record.kind {
            FramedRecordKind::Record(fields) => {
                fields.app_version.support == CompanyPortalGrammarSupport::Experimental
            }
            _ => false,
        })
        .count();

    // A file is only a validated read when it actually produced records and
    // every one of them came from an app version the grammar was derived from.
    let grammar_support = if parsed_count > 0 && experimental_count == 0 {
        CompanyPortalGrammarSupport::Validated
    } else {
        CompanyPortalGrammarSupport::Experimental
    };

    CompanyPortalLogDocument {
        schema_version: COMPANY_PORTAL_WINDOWS_LOGS_SCHEMA_VERSION,
        grammar_version: CompanyPortalGrammarVersion::V1,
        grammar_support,
        // Never `High`: the grammar rests on a single published app version.
        confidence: match grammar_support {
            CompanyPortalGrammarSupport::Validated => CompanyPortalConfidence::Medium,
            CompanyPortalGrammarSupport::Experimental => CompanyPortalConfidence::Low,
        },
        redacted: false,
        coverage: build_coverage(
            &file,
            framed.len(),
            parsed_count,
            experimental_count,
            grammar_support,
        ),
        file,
        records,
    }
}

fn build_record(file_name: &str, framed: &FramedRecord<'_>) -> CompanyPortalLogRecord {
    let raw_text = framed.raw_text();
    let record_id = format!("companyPortalLog|{file_name}|{}", framed.line_number);

    match &framed.kind {
        FramedRecordKind::Record(fields) => CompanyPortalLogRecord {
            record_id,
            line_number: framed.line_number,
            parse_state: CompanyPortalParseState::Parsed,
            timestamp: Some(fields.timestamp.clone()),
            severity: Some(fields.severity.clone()),
            category: Some(fields.category.clone()),
            scenario: Some(fields.scenario.clone()),
            sequence: Some(fields.sequence),
            activity_id: Some(fields.activity_id.clone()),
            app_version: Some(fields.app_version.clone()),
            component: fields.component.clone(),
            message: super::framing::join_lines(&fields.message, &framed.continuations),
            raw_text,
        },
        FramedRecordKind::Malformed | FramedRecordKind::Orphaned => CompanyPortalLogRecord {
            record_id,
            line_number: framed.line_number,
            parse_state: match framed.kind {
                FramedRecordKind::Malformed => CompanyPortalParseState::Malformed,
                _ => CompanyPortalParseState::Orphaned,
            },
            timestamp: None,
            severity: None,
            category: None,
            scenario: None,
            sequence: None,
            activity_id: None,
            app_version: None,
            component: None,
            // Nothing was claimed, so the whole record is the message.
            message: raw_text.clone(),
            raw_text,
        },
    }
}

fn build_coverage(
    file: &CompanyPortalLogFileIdentity,
    total_records: usize,
    parsed_count: usize,
    experimental_count: usize,
    grammar_support: CompanyPortalGrammarSupport,
) -> Vec<CompanyPortalCoverage> {
    let mut coverage = Vec::new();
    let unreadable = total_records - parsed_count;

    coverage.push(CompanyPortalCoverage {
        artifact_id: FILE_COVERAGE_ARTIFACT_ID.to_string(),
        family: COVERAGE_FAMILY.to_string(),
        status: if unreadable == 0 {
            CompanyPortalCoverageStatus::Available
        } else {
            CompanyPortalCoverageStatus::ParseFailed
        },
        detail: Some(format!(
            "{} read {parsed_count} of {total_records} record(s) with grammar V1; \
             {unreadable} record(s) did not match and are preserved as source text.",
            file.file_name
        )),
    });

    if grammar_support == CompanyPortalGrammarSupport::Experimental {
        coverage.push(CompanyPortalCoverage {
            artifact_id: GRAMMAR_COVERAGE_ARTIFACT_ID.to_string(),
            family: COVERAGE_FAMILY.to_string(),
            status: CompanyPortalCoverageStatus::Unsupported,
            detail: Some(if experimental_count > 0 {
                format!(
                    "{experimental_count} record(s) report a Company Portal app version the V1 \
                     grammar was not derived from. Fields were read with V1 unchanged and this \
                     document is downgraded to low confidence."
                )
            } else {
                "No record matched the V1 grammar, so no app version could be confirmed."
                    .to_string()
            }),
        });
    }

    coverage
}

/// Last path component, handling both separators. Pure string work — the parser
/// crate performs no filesystem access.
fn file_name_of(file_path: &str) -> &str {
    file_path.rsplit(['/', '\\']).next().unwrap_or(file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_LOG_PATH: &str = "C:/Users/adele.vance/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log";

    #[test]
    fn document_records_the_schema_and_grammar_versions() {
        let content = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n";
        let document = parse_log_document(APP_LOG_PATH, content);

        assert_eq!(document.schema_version, 1);
        assert_eq!(document.grammar_version, CompanyPortalGrammarVersion::V1);
        assert_eq!(
            document.grammar_support,
            CompanyPortalGrammarSupport::Validated
        );
        assert_eq!(document.confidence, CompanyPortalConfidence::Medium);
        assert!(document.redacted);
    }

    #[test]
    fn document_keeps_only_the_file_name_not_the_user_profile_path() {
        let content = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  ok\n";
        let document = parse_log_document(APP_LOG_PATH, content);

        assert_eq!(document.file.file_name, "Log_1.log");
        assert_eq!(document.file.rotation_index, Some(1));
        let json = serde_json::to_string(&document).expect("document must serialize");
        assert!(!json.contains("adele.vance"));
    }

    #[test]
    fn unreadable_records_become_coverage_not_silence() {
        let content = "2024-13-45T99:99:99.0000000Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  impossible\n";
        let document = parse_log_document(APP_LOG_PATH, content);

        assert_eq!(document.records.len(), 1);
        assert_eq!(
            document.records[0].parse_state,
            CompanyPortalParseState::Malformed
        );
        assert_eq!(
            document.coverage[0].status,
            CompanyPortalCoverageStatus::ParseFailed
        );
        // No record parsed, so no app version could be confirmed either.
        assert_eq!(
            document.coverage[1].status,
            CompanyPortalCoverageStatus::Unsupported
        );
    }

    #[test]
    fn local_projection_is_marked_unredacted() {
        let content = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  ok\n";
        let document = parse_log_document_preserving_local_values(APP_LOG_PATH, content);

        assert!(!document.redacted);
    }
}
