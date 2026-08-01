//! Format detection for direct macOS Company Portal application logs.
//!
//! # The rule
//!
//! A path under `~/Library/Logs/CompanyPortal/` is a *candidate* hint. It is
//! never proof: anything can be copied into that directory, and the directory
//! also holds saved diagnostic reports and unified-log exports, which are
//! separate source kinds owned by separate leaves. Confirmation always comes
//! from content — records matching the grammar in [`super::grammar`] that name a
//! Company Portal process.
//!
//! # Registration
//!
//! [`detect_company_portal_log_content`] is the registration hook: it takes a
//! file name, a sanitized path, and text, and answers with a
//! [`CompanyPortalLogDetection`]. It is deliberately self-contained rather than
//! wired into `crate::parser::detect`, so that adding this leaf cannot change
//! how any existing file is classified. Company Portal logs continue to resolve
//! through the generic timestamped fallback until a follow-up change routes them
//! here, which is why [`detect_company_portal_log_content`] reports the sample
//! counts it used: a caller can apply its own threshold without re-scanning.

use super::grammar::{is_unified_log_line, parse_header};
use super::models::{CompanyPortalLogDetection, CompanyPortalLogRejection};
use super::sources::{CompanyPortalLogSource, COMPANY_PORTAL_PROCESSES, PATH_HINTS};

/// Lines examined before deciding. Enough to clear a preamble, bounded so that
/// detection stays cheap on a multi-megabyte rotation.
const SAMPLE_LINES: usize = 200;

/// Lines in which a foreign-format banner is believed.
///
/// Restricted to the preamble on purpose: a Company Portal record whose *message*
/// mentions a diagnostic report must not cause the whole artifact to be rejected.
const BANNER_LINES: usize = 20;

/// Markers that identify a saved Company Portal diagnostic report.
///
/// This is a guard, not a parser. The report format is owned by its own leaf;
/// all this leaf needs is to refuse to claim one.
const DIAGNOSTIC_REPORT_MARKERS: &[&str] = &[
    "company portal diagnostic report",
    "companyportaldiagnosticreport",
    "diagnosticreportversion",
    "=== diagnostic report ===",
    "mdmdiagnosticreport",
];

/// Records naming a Company Portal process required to confirm without a hint.
const RECORDS_REQUIRED_WITHOUT_HINT: u32 = 2;

/// Records naming a Company Portal process required to confirm with a hint.
const RECORDS_REQUIRED_WITH_HINT: u32 = 1;

/// Is this process token one a direct Company Portal app log writes?
pub fn is_company_portal_process(process: &str) -> bool {
    let lowered = process.trim().to_ascii_lowercase();
    COMPANY_PORTAL_PROCESSES
        .iter()
        .any(|candidate| *candidate == lowered)
}

/// Does this path or file name suggest the Company Portal log directory?
fn path_suggests_company_portal(file_name: &str, sanitized_path: Option<&str>) -> bool {
    let haystack = sanitized_path
        .unwrap_or(file_name)
        .to_ascii_lowercase()
        .replace('\\', "/");
    PATH_HINTS
        .iter()
        .any(|hint| haystack.contains(&hint.replace('\\', "/")))
        || super::sources::file_name_is_candidate(file_name)
}

/// Decide whether `content` is a direct Company Portal application log.
///
/// This is the registration hook described in the module docs. `sanitized_path`
/// is the adapter's path with the user's home directory already replaced; it
/// contributes a hint only.
pub fn detect_company_portal_log_content(
    file_name: &str,
    sanitized_path: Option<&str>,
    content: &str,
) -> CompanyPortalLogDetection {
    let path_hint = path_suggests_company_portal(file_name, sanitized_path);

    let sample: Vec<&str> = content
        .lines()
        .map(|line| line.trim_start_matches('\u{feff}'))
        .filter(|line| !line.trim().is_empty())
        .take(SAMPLE_LINES)
        .collect();

    if sample.is_empty() {
        return rejected(CompanyPortalLogRejection::NoRecords, 0, 0, path_hint);
    }

    let mut matched_records = 0u32;
    let mut company_portal_records = 0u32;

    for line in &sample {
        if let Some(fields) = parse_header(line) {
            matched_records += 1;
            if is_company_portal_process(&fields.process) {
                company_portal_records += 1;
            }
        }
    }

    // Foreign-format banners are only believed in the preamble, which ends at
    // the first line that parses as a Company Portal record. Scanning past that
    // point would let a *continuation* line — an exception payload, a quoted
    // support ticket — reject a genuine log because of its message text.
    for line in sample.iter().take(BANNER_LINES) {
        if parse_header(line).is_some() {
            break;
        }
        if is_unified_log_line(line) {
            return rejected(
                CompanyPortalLogRejection::UnifiedLogExport,
                matched_records,
                company_portal_records,
                path_hint,
            );
        }
        let lowered = line.to_ascii_lowercase();
        if DIAGNOSTIC_REPORT_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            return rejected(
                CompanyPortalLogRejection::DiagnosticReport,
                matched_records,
                company_portal_records,
                path_hint,
            );
        }
    }

    if matched_records == 0 {
        return rejected(
            CompanyPortalLogRejection::NoRecords,
            0,
            0,
            path_hint,
        );
    }
    if company_portal_records == 0 {
        return rejected(
            CompanyPortalLogRejection::ForeignProcess,
            matched_records,
            0,
            path_hint,
        );
    }

    let required = if path_hint {
        RECORDS_REQUIRED_WITH_HINT
    } else {
        RECORDS_REQUIRED_WITHOUT_HINT
    };

    if company_portal_records >= required {
        CompanyPortalLogDetection {
            confirmed: true,
            rejection: None,
            matched_records,
            company_portal_records,
            path_hint,
        }
    } else {
        rejected(
            CompanyPortalLogRejection::InsufficientEvidence,
            matched_records,
            company_portal_records,
            path_hint,
        )
    }
}

/// Detect from a supplied artifact, honoring its capture state.
///
/// An artifact that produced no bytes is rejected as [`CompanyPortalLogRejection::NoContent`]
/// rather than as "no records": the difference is whether the absence of records
/// says anything about the file.
pub fn detect_company_portal_log(source: &CompanyPortalLogSource) -> CompanyPortalLogDetection {
    let path_hint = source.has_path_hint();
    match source.content.as_deref() {
        Some(content) if source.capture_state.has_content() => detect_company_portal_log_content(
            &source.file_name,
            source.sanitized_file_path.as_deref(),
            content,
        ),
        _ => rejected(CompanyPortalLogRejection::NoContent, 0, 0, path_hint),
    }
}

/// Convenience predicate for callers that only need a yes or no.
pub fn is_company_portal_log(
    file_name: &str,
    sanitized_path: Option<&str>,
    content: &str,
) -> bool {
    detect_company_portal_log_content(file_name, sanitized_path, content).confirmed
}

fn rejected(
    rejection: CompanyPortalLogRejection,
    matched_records: u32,
    company_portal_records: u32,
    path_hint: bool,
) -> CompanyPortalLogDetection {
    CompanyPortalLogDetection {
        confirmed: false,
        rejection: Some(rejection),
        matched_records,
        company_portal_records,
        path_hint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_RECORDS: &str = concat!(
        "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | listing apps\n",
        "2026-03-12 09:14:23:100 | CompanyPortal | I | 8412 | Catalog | listed 3 apps\n",
    );

    #[test]
    fn two_company_portal_records_confirm_without_any_path_hint() {
        let detection = detect_company_portal_log_content("captured.txt", None, TWO_RECORDS);
        assert!(detection.confirmed);
        assert!(!detection.path_hint);
        assert_eq!(detection.company_portal_records, 2);
    }

    #[test]
    fn one_record_confirms_only_with_a_path_hint() {
        let single =
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | listing apps\n";
        let without = detect_company_portal_log_content("captured.txt", None, single);
        assert!(!without.confirmed);
        assert_eq!(
            without.rejection,
            Some(CompanyPortalLogRejection::InsufficientEvidence)
        );

        let with = detect_company_portal_log_content(
            "CompanyPortal.log",
            Some("SYNTHETIC://Library/Logs/CompanyPortal/CompanyPortal.log"),
            single,
        );
        assert!(with.confirmed);
        assert!(with.path_hint);
    }

    #[test]
    fn a_path_hint_alone_never_confirms() {
        let detection = detect_company_portal_log_content(
            "CompanyPortal.log",
            Some("SYNTHETIC://Library/Logs/CompanyPortal/CompanyPortal.log"),
            "nothing here resembles a record\nnor does this line\n",
        );
        assert!(!detection.confirmed);
        assert_eq!(detection.rejection, Some(CompanyPortalLogRejection::NoRecords));
        assert!(detection.path_hint);
    }

    #[test]
    fn records_from_another_process_in_the_same_directory_are_refused() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | IntuneMDM-Daemon | I | 8412 | SyncActivityTracer | sync\n",
            "2026-03-12 09:14:23:100 | IntuneMDM-Daemon | I | 8412 | SyncActivityTracer | done\n",
        );
        let detection = detect_company_portal_log_content(
            "IntuneMDMDaemon.log",
            Some("SYNTHETIC://Library/Logs/CompanyPortal/IntuneMDMDaemon.log"),
            content,
        );
        assert!(!detection.confirmed);
        assert_eq!(
            detection.rejection,
            Some(CompanyPortalLogRejection::ForeignProcess)
        );
        assert_eq!(detection.matched_records, 2);
    }

    #[test]
    fn a_saved_diagnostic_report_is_refused_even_under_the_right_path() {
        let content = concat!(
            "=== Company Portal Diagnostic Report ===\n",
            "DiagnosticReportVersion: 3\n",
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | excerpt\n",
            "2026-03-12 09:14:23:100 | CompanyPortal | I | 8412 | Catalog | excerpt\n",
        );
        let detection = detect_company_portal_log_content(
            "CompanyPortal.log",
            Some("SYNTHETIC://Library/Logs/CompanyPortal/CompanyPortal.log"),
            content,
        );
        assert!(!detection.confirmed);
        assert_eq!(
            detection.rejection,
            Some(CompanyPortalLogRejection::DiagnosticReport)
        );
    }

    #[test]
    fn a_unified_log_export_is_refused_even_under_the_right_path() {
        let content = concat!(
            "Timestamp                       Thread     Type        Activity             PID    TTL\n",
            "2026-03-12 09:14:22.301474-0700 0x1a2b3c   Default     0x0                  412    0    CompanyPortal: start\n",
        );
        let detection = detect_company_portal_log_content(
            "CompanyPortal.log",
            Some("SYNTHETIC://Library/Logs/CompanyPortal/CompanyPortal.log"),
            content,
        );
        assert!(!detection.confirmed);
        assert_eq!(
            detection.rejection,
            Some(CompanyPortalLogRejection::UnifiedLogExport)
        );
    }

    #[test]
    fn a_record_merely_mentioning_a_diagnostic_report_still_confirms() {
        // The banner scan must not fire on message text, or collecting a report
        // would make the live log unreadable.
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Support | user requested a Company Portal Diagnostic Report\n",
            "2026-03-12 09:14:23:100 | CompanyPortal | I | 8412 | Support | report uploaded\n",
        );
        let detection = detect_company_portal_log_content("CompanyPortal.log", None, content);
        assert!(detection.confirmed);
    }

    #[test]
    fn a_continuation_line_quoting_a_banner_does_not_reject_the_log() {
        // Continuations are not headers, so a naive "skip header lines" banner
        // scan would read this payload and refuse a perfectly good app log.
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | E | 8412 | Support | attaching support bundle\n",
            "  === Company Portal Diagnostic Report ===\n",
            "  DiagnosticReportVersion: 3\n",
            "2026-03-12 09:14:23:100 | CompanyPortal | I | 8412 | Support | bundle uploaded\n",
        );
        let detection = detect_company_portal_log_content("CompanyPortal.log", None, content);
        assert!(
            detection.confirmed,
            "a quoted banner below the first record must not reject the artifact"
        );
    }

    #[test]
    fn an_artifact_with_no_bytes_is_refused_as_no_content_not_no_records() {
        use super::super::models::CompanyPortalCaptureState;
        let source = CompanyPortalLogSource {
            artifact_id: "a1".to_owned(),
            file_name: "CompanyPortal.log".to_owned(),
            sanitized_file_path: None,
            capture_state: CompanyPortalCaptureState::Absent,
            content: None,
            encoding: None,
            captured_at_utc: "2026-07-31T00:00:00Z".to_owned(),
        };
        let detection = detect_company_portal_log(&source);
        assert_eq!(
            detection.rejection,
            Some(CompanyPortalLogRejection::NoContent)
        );
    }

    #[test]
    fn the_predicate_agrees_with_the_full_detection() {
        assert!(is_company_portal_log("CompanyPortal.log", None, TWO_RECORDS));
        assert!(!is_company_portal_log("CompanyPortal.log", None, "plain text\n"));
    }
}
