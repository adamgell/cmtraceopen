//! Source-kind detection for direct Company Portal macOS application logs.
//!
//! Detection is content-driven. A path hint may *select* this parser as a
//! candidate, but only record structure plus the structural process field can
//! confirm it, and competing macOS artifacts (unified-log exports, saved
//! diagnostic reports, other Intune processes using the same house grammar) are
//! recognized and rejected explicitly.

use super::grammar::{
    app_version_support, is_company_portal_process, looks_like_record_start, parse_record_head,
    split_physical_lines, version_banner,
};
use super::models::{
    PortalDetection, PortalDetectionConfidence, PortalSignature, PortalSourceKind,
    PortalVersionSupport, COMPANY_PORTAL_LOG_DIRECTORY_HINT,
};

/// Physical lines sampled from the head of the artifact during detection.
pub const DETECTION_SAMPLE_LINES: usize = 200;

/// A strict majority of record-start lines must satisfy the full grammar before
/// the artifact is treated as structurally sound.
const MIN_WELL_FORMED_RATIO: f32 = 0.5;

/// True when a caller-supplied path sits under the known Company Portal log
/// folder. A hint only — never sufficient on its own.
pub fn path_hint_matches(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.contains(COMPANY_PORTAL_LOG_DIRECTORY_HINT)
}

fn looks_like_unified_log_ndjson(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with('{')
        && trimmed.contains("\"eventMessage\"")
        && (trimmed.contains("\"processImagePath\"") || trimmed.contains("\"subsystem\""))
}

/// Allocation-free: this runs for every sampled line of every candidate
/// artifact, and `to_ascii_lowercase` allocated a fresh `String` per check.
fn starts_with_ignore_ascii_case(haystack: &str, prefix: &str) -> bool {
    haystack
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn looks_like_diagnostic_report_header(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.eq_ignore_ascii_case("Company Portal Diagnostic Report")
        || starts_with_ignore_ascii_case(trimmed, "report id:")
        || starts_with_ignore_ascii_case(trimmed, "included files:")
}

/// Detect what a candidate artifact actually is.
///
/// `path_hint` is optional and only ever contributes a [`PortalSignature`]; it
/// cannot change the resulting [`PortalSourceKind`].
pub fn detect_company_portal_macos_log(text: &str, path_hint: Option<&str>) -> PortalDetection {
    let lines = split_physical_lines(text);
    let mut sample: Vec<&str> = lines.iter().copied().take(DETECTION_SAMPLE_LINES).collect();

    // Rotation cuts a file at a byte boundary, not a record boundary, so a
    // rotated member can open with a long run of continuation lines from a
    // payload that began in the previous member. When the head window shows no
    // evidence of any kind, re-anchor the sample at the first line that looks
    // like a record start instead of declaring the whole file unrecognized and
    // dropping every record in it. This stays content-only: the re-anchor is
    // driven by the text, never by the path hint, and it only runs when the head
    // window was entirely inconclusive, so the NDJSON and diagnostic-report
    // negatives still decide from the head as before.
    let head_window_inconclusive = sample.iter().all(|line| {
        !looks_like_record_start(line)
            && !looks_like_unified_log_ndjson(line)
            && !looks_like_diagnostic_report_header(line)
    });
    if head_window_inconclusive {
        if let Some(first_start) = lines.iter().position(|line| looks_like_record_start(line)) {
            sample = lines
                .iter()
                .copied()
                .skip(first_start)
                .take(DETECTION_SAMPLE_LINES)
                .collect();
        }
    }

    let mut record_start_lines = 0u32;
    let mut record_head_lines = 0u32;
    let mut company_portal_record_lines = 0u32;
    let mut ndjson_lines = 0u32;
    let mut report_header_lines = 0u32;
    let mut banner: Option<String> = None;

    for line in &sample {
        if looks_like_record_start(line) {
            record_start_lines += 1;
        }
        match parse_record_head(line) {
            Some(head) => {
                record_head_lines += 1;
                if is_company_portal_process(&head.process) {
                    company_portal_record_lines += 1;
                    if banner.is_none() {
                        banner = version_banner(&head.message);
                    }
                }
            }
            None => {
                if looks_like_unified_log_ndjson(line) {
                    ndjson_lines += 1;
                } else if looks_like_diagnostic_report_header(line) {
                    report_header_lines += 1;
                }
            }
        }
    }

    let path_hint_matched = path_hint.is_some_and(path_hint_matches);
    let mut signatures = Vec::new();
    let mut rejections = Vec::new();
    if path_hint_matched {
        signatures.push(PortalSignature::PathHint);
    }
    if record_head_lines > 0 {
        signatures.push(PortalSignature::RecordGrammar);
    }
    if company_portal_record_lines > 0 {
        signatures.push(PortalSignature::CompanyPortalProcessToken);
    }
    if banner.is_some() {
        signatures.push(PortalSignature::VersionBanner);
    }
    if ndjson_lines > 0 {
        signatures.push(PortalSignature::UnifiedLogNdjsonShape);
    }
    if report_header_lines > 0 {
        signatures.push(PortalSignature::DiagnosticReportHeader);
    }
    signatures.sort_unstable();
    signatures.dedup();

    let (source_kind, confidence) = if company_portal_record_lines > 0 {
        let well_formed_ratio = if record_start_lines == 0 {
            1.0
        } else {
            record_head_lines as f32 / record_start_lines as f32
        };
        let confidence = if well_formed_ratio <= MIN_WELL_FORMED_RATIO {
            rejections.push(format!(
                "only {record_head_lines} of {record_start_lines} record starts satisfied the grammar"
            ));
            PortalDetectionConfidence::Low
        } else if banner
            .as_deref()
            .map(app_version_support)
            .is_some_and(|support| support != PortalVersionSupport::Validated)
        {
            PortalDetectionConfidence::Probable
        } else {
            PortalDetectionConfidence::Confirmed
        };
        (PortalSourceKind::CompanyPortalMacosAppLog, confidence)
    } else if ndjson_lines > 0 {
        rejections.push(
            "records are Apple unified-log ndjson objects, not Company Portal app-log records"
                .to_string(),
        );
        (
            PortalSourceKind::MacosUnifiedLogExport,
            PortalDetectionConfidence::Rejected,
        )
    } else if report_header_lines > 0 {
        rejections.push(
            "content is a saved Company Portal diagnostic-report summary, not a direct app log"
                .to_string(),
        );
        (
            PortalSourceKind::CompanyPortalDiagnosticReport,
            PortalDetectionConfidence::Rejected,
        )
    } else if record_head_lines > 0 {
        rejections.push(
            "records use the macOS Intune house grammar but no record declares a Company Portal process"
                .to_string(),
        );
        (
            PortalSourceKind::IntuneMacosOtherProcessLog,
            PortalDetectionConfidence::Rejected,
        )
    } else {
        rejections.push("no Company Portal record structure found".to_string());
        (
            PortalSourceKind::Unrecognized,
            PortalDetectionConfidence::Rejected,
        )
    };

    PortalDetection {
        source_kind,
        confidence,
        path_hint_matched,
        signatures,
        rejections,
        sampled_lines: sample.len() as u32,
        record_start_lines,
        record_head_lines,
        company_portal_record_lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_hint_alone_never_confirms() {
        let detection = detect_company_portal_macos_log(
            "not a log at all",
            Some("/Users/x/Library/Logs/CompanyPortal/CompanyPortal.log"),
        );
        assert!(detection.path_hint_matched);
        assert_eq!(detection.source_kind, PortalSourceKind::Unrecognized);
        assert_eq!(detection.confidence, PortalDetectionConfidence::Rejected);
    }

    #[test]
    fn process_token_in_message_text_never_confirms() {
        let text = "2026-05-12 08:14:20:104 | IntuneMdmAgent | I | 300140 | SyncActivityTracer | Sync requested by CompanyPortal";
        let detection = detect_company_portal_macos_log(text, None);
        assert_eq!(
            detection.source_kind,
            PortalSourceKind::IntuneMacosOtherProcessLog
        );
        assert_eq!(detection.company_portal_record_lines, 0);
    }

    #[test]
    fn structural_process_field_confirms_without_a_path_hint() {
        let text = "2026-05-12 08:14:20:104 | CompanyPortal | I | 261481 | AppDelegate | started";
        let detection = detect_company_portal_macos_log(text, None);
        assert_eq!(
            detection.source_kind,
            PortalSourceKind::CompanyPortalMacosAppLog
        );
        assert_eq!(detection.confidence, PortalDetectionConfidence::Confirmed);
        assert!(!detection.path_hint_matched);
    }
}
