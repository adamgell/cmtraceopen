//! Download statistics over the shared IME logs.
//!
//! Ownership note: `intune::apps::windows::win32` is the canonical
//! *transaction* view of Win32 app deployments and owns that behavior alone.
//! This module keeps its statistics surface and public API unchanged, and it
//! owns the *content-download vocabulary* — the phrases that say a download
//! started, completed, failed, or stalled. The Win32 transaction analyzer
//! consumes that vocabulary through the `pub(crate)` accessors below instead
//! of keeping a parallel copy, so one grammar owns the words.

use std::collections::HashMap;
use std::path::Path;

use regex::Regex;

#[cfg(test)]
use super::guid_registry::explicit_app_identity_context;
use super::guid_registry::{
    explicit_app_identity_context_with_named_guid_fallback, extract_app_name, is_fallback_name,
    ExplicitAppIdentity, GuidRegistry,
};
use super::ime_parser::ImeLine;
use super::models::DownloadStat;
use super::timeline::parse_timestamp;
use std::sync::OnceLock;

pub(crate) fn download_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r#"(?i)(?:(?-u:\b)download(?:ing|ed)?(?-u:\b)|content\s+download|delivery\s+optimization|bytes\s+downloaded|staging\s+(?:file|content)|hash\s+validation|content\s+cached|cache\s+location)"#,
    )
    .unwrap()
})
}
fn download_ignore_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r#"(?i)adding\s+new\s+state\s+transition\s*-\s*from:"#).unwrap())
}

/// The gate every consumer of the download vocabulary must check first.
///
/// IME's state-machine transition template (`Adding new state transition -
/// From: … To: … With Event: Download Failed.`) quotes the download phrases
/// without being a download statement, so matching the vocabulary against one
/// of these lines reads the state machine's bookkeeping as evidence. This
/// module checks the gate before its own vocabulary in `extract_downloads`;
/// exposing it here keeps the gating grammar owned in one place instead of
/// letting a consumer re-derive (or forget) it.
pub(crate) fn is_state_transition_template(message: &str) -> bool {
    download_ignore_re().is_match(message)
}
fn size_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"(?i)(?:content\s+)?size[:\s]+([\d.]+)\s*(bytes|kb|mb|gb)"#).unwrap()
    })
}
fn speed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"(?i)(?:speed|rate)[:\s]+([\d.]+)\s*(bytes?/s|kb/s|mb/s|bps|kbps|mbps)"#)
            .unwrap()
    })
}
fn do_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"(?i)(?:delivery\s+optimization|DO)[:\s]+([\d.]+)\s*%"#).unwrap()
    })
}
fn content_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r#"(?i)(?:content|app|application)\s*(?:id)?[:\s]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#).unwrap()
})
}
// The `is` / bare-adjective completion forms and the `has failed` /
// `state: Failed` / `result = Failed` failure forms are genuine IME wordings:
// they were carried by the Win32 transaction analyzer's local rules before the
// vocabulary was consolidated here, so the shared regexes carry them for every
// consumer rather than letting the consolidation lose recall.
pub(crate) fn download_complete_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r#"(?i)(?:download\s+(?:is\s+)?(?:complete|completed|finished|succeeded|done)|content\s+cached|staging\s+completed|hash\s+validation\s+succeeded)"#,
    )
    .unwrap()
})
}
pub(crate) fn download_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r#"(?i)(?:download\s+(?:has\s+)?(?:failed|error)|download\s+(?:state|result)\s*[:=]\s*failed|failed\s+to\s+download|(?:fail(?:ed|ure)|unable)\s+to\s+start\s+(?:the\s+)?(?:content\s+)?download|hash\s+validation\s+failed|hash\s+mismatch|staging\s+failed|content\s+not\s+found|unable\s+to\s+download|cancelled|aborted)"#,
    )
    .unwrap()
})
}
pub(crate) fn download_start_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
        r#"(?i)(?:(?:starting|beginning|queued|requesting|resuming).*(?:download|content\s+download)|\bstart(?:ed)?\s+(?:the\s+)?(?:content\s+)?download)"#,
    )
    .unwrap()
    })
}
/// A start verb preceded by a failure verb (`failed to start download`).
///
/// The regex crate has no lookbehind, so the start vocabulary cannot exclude
/// the negated forms itself; consumers of [`download_start_re`] check this
/// second pattern in code and treat a match as *not* a start. The negated
/// phrase is carried by [`download_failed_re`] instead, because a download the
/// agent could not start is honestly a download failure.
fn negated_start_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:fail(?:ed|ure)?\s+to|unable\s+to|couldn'?t|could\s+not|cannot|can'?t)\s+(?:start|begin|resume|queue|request)\b"#,
        )
        .unwrap()
    })
}

/// Whether a line asserts a download start: the start vocabulary matched and
/// no failure verb negates it.
///
/// `pub(crate)` for the same reason the vocabulary accessors are: the Win32
/// transaction analyzer composes this predicate instead of keeping a parallel
/// copy of the negation rule.
pub(crate) fn is_download_start(msg: &str) -> bool {
    download_start_re().is_match(msg) && !negated_start_re().is_match(msg)
}
fn download_progress_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:bytes\s+downloaded|downloading|download\s+progress|delivery\s+optimization)"#,
        )
        .unwrap()
    })
}
pub(crate) fn download_stall_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
        r#"(?i)(?:stalled|not\s+progressing|no\s+progress|timed?\s*out|timeout|retry\s+exhausted)"#,
    )
    .unwrap()
    })
}
fn appworkload_retry_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r#"(?i)(?:(?-u:\b)retrying(?-u:\b)|(?-u:\b)reattempt(?:ing)?(?-u:\b)|will\s+retry|retry\s+exhausted|failed[^\r\n]{0,80}retry)"#).unwrap()
})
}
fn duration_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
        r#"(?i)(?:duration|took|elapsed)[:\s]+([\d.]+)\s*(s(?:ec(?:ond)?s?)?|m(?:in(?:ute)?s?)?)"#,
    )
    .unwrap()
    })
}

/// Pre-consolidation IME phrasings the shared vocabulary must keep carrying.
///
/// These wordings were matched by the Win32 transaction analyzer's local rules
/// before the vocabulary moved here. One table feeds both this module's tests
/// and the win32 rules tests, so the two assertions can never drift apart.
#[cfg(test)]
pub(crate) mod test_vocabulary {
    pub(crate) const PRE_CONSOLIDATION_FAILED: [&str; 3] = [
        "Download has failed",
        "Download state: Failed",
        "Download result = Failed",
    ];
    pub(crate) const PRE_CONSOLIDATION_COMPLETE: [&str; 3] = [
        "Download is complete",
        "Download is completed",
        "Download complete",
    ];
    pub(crate) const PRE_CONSOLIDATION_START: [&str; 2] =
        ["Started the download", "Start content download"];
}

pub fn extract_downloads(
    lines: &[ImeLine],
    source_file: &str,
    registry: &GuidRegistry,
) -> Vec<DownloadStat> {
    let source_kind = classify_download_source(source_file);
    if source_kind == DownloadSourceKind::Unsupported {
        return Vec::new();
    }

    let mut downloads = Vec::new();
    let mut active: HashMap<String, PartialDownload> = HashMap::new();

    for line in lines {
        let msg = &line.message;
        let timestamp = line.timestamp_utc.as_deref().or(line.timestamp.as_deref());
        let timestamp_owned = timestamp.map(|value| value.to_string());
        let Some(analysis) = DownloadLineAnalysis::from_message(msg) else {
            continue;
        };

        let content_id = analysis
            .content_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let display_name = analysis.display_name.clone();

        if analysis.is_retry {
            let previous = active.remove(&content_id);
            let inherited_suppression = previous
                .as_ref()
                .is_some_and(|download| download.suppress_registry_enrichment);
            if let Some(stat) = finalize_download(
                previous,
                Some(content_id.clone()),
                display_name.clone(),
                &analysis,
                timestamp,
                false,
                registry,
            ) {
                downloads.push(stat);
            }

            active.insert(
                content_id.clone(),
                PartialDownload::new(
                    Some(content_id),
                    display_name,
                    timestamp_owned.clone(),
                    inherited_suppression || analysis.suppress_registry_enrichment,
                ),
            );
            continue;
        }

        if analysis.is_start || analysis.is_progress {
            let entry = active.entry(content_id.clone()).or_insert_with(|| {
                PartialDownload::new(
                    Some(content_id.clone()),
                    display_name.clone(),
                    timestamp_owned.clone(),
                    analysis.suppress_registry_enrichment,
                )
            });
            apply_download_analysis(entry, &analysis, timestamp);
        }

        if analysis.is_complete {
            if let Some(stat) = finalize_download(
                active.remove(&content_id),
                Some(content_id),
                display_name,
                &analysis,
                timestamp,
                true,
                registry,
            ) {
                downloads.push(stat);
            }
            continue;
        }

        if analysis.is_failed || analysis.is_stall {
            if let Some(stat) = finalize_download(
                active.remove(&content_id),
                Some(content_id),
                display_name,
                &analysis,
                timestamp,
                false,
                registry,
            ) {
                downloads.push(stat);
            }
        }
    }

    for partial in active.into_values() {
        if partial.saw_failure_signal || partial.saw_retry_signal {
            let cid = partial
                .content_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let raw_name = partial
                .display_name
                .clone()
                .unwrap_or_else(|| short_id(&cid));
            let name = if is_fallback_name(&raw_name) && !partial.suppress_registry_enrichment {
                registry
                    .resolve(&cid)
                    .map(|n| n.to_string())
                    .unwrap_or(raw_name)
            } else {
                raw_name
            };
            let ts = partial.last_timestamp.or(partial.start_time);
            downloads.push(DownloadStat {
                content_id: cid,
                name,
                size_bytes: partial.size_bytes.unwrap_or(0),
                speed_bps: partial.speed_bps.unwrap_or(0.0),
                do_percentage: partial.do_percentage.unwrap_or(0.0),
                duration_secs: partial.duration_secs.unwrap_or(0.0),
                success: false,
                timestamp_epoch: ts
                    .as_deref()
                    .and_then(parse_timestamp)
                    .map(|dt| dt.and_utc().timestamp_millis()),
                timestamp: ts,
            });
        }
    }

    downloads
}

#[derive(Debug, Clone, Default)]
struct DownloadLineAnalysis {
    content_id: Option<String>,
    display_name: Option<String>,
    size_bytes: Option<u64>,
    speed_bps: Option<f64>,
    do_percentage: Option<f64>,
    duration_secs: Option<f64>,
    suppress_registry_enrichment: bool,
    is_retry: bool,
    is_start: bool,
    is_progress: bool,
    is_complete: bool,
    is_failed: bool,
    is_stall: bool,
}

impl DownloadLineAnalysis {
    fn from_message(msg: &str) -> Option<Self> {
        if download_ignore_re().is_match(msg) || !download_re().is_match(msg) {
            return None;
        }

        let size_bytes = capture_number_and_unit(size_re(), msg)
            .map(|(value, unit)| convert_size_to_bytes(value, unit));
        let speed_bps = capture_number_and_unit(speed_re(), msg)
            .map(|(value, unit)| convert_speed_to_bps(value, unit));
        let do_percentage = do_re()
            .captures(msg)
            .and_then(|captures| captures.get(1))
            .and_then(|capture| capture.as_str().parse::<f64>().ok());
        let duration_secs = capture_number_and_unit(duration_re(), msg).map(|(value, unit)| {
            if unit.starts_with('m') {
                value * 60.0
            } else {
                value
            }
        });

        let identity = extract_download_identity(msg);

        Some(Self {
            content_id: identity.content_id,
            display_name: identity.display_name,
            size_bytes,
            speed_bps,
            do_percentage,
            duration_secs,
            suppress_registry_enrichment: identity.suppress_registry_enrichment,
            is_retry: appworkload_retry_re().is_match(msg),
            is_start: is_download_start(msg),
            is_progress: download_progress_re().is_match(msg),
            is_complete: download_complete_re().is_match(msg),
            is_failed: download_failed_re().is_match(msg),
            is_stall: download_stall_re().is_match(msg),
        })
    }
}

struct PartialDownload {
    content_id: Option<String>,
    display_name: Option<String>,
    start_time: Option<String>,
    last_timestamp: Option<String>,
    size_bytes: Option<u64>,
    speed_bps: Option<f64>,
    do_percentage: Option<f64>,
    duration_secs: Option<f64>,
    suppress_registry_enrichment: bool,
    saw_progress: bool,
    saw_failure_signal: bool,
    saw_retry_signal: bool,
}

impl PartialDownload {
    fn new(
        content_id: Option<String>,
        display_name: Option<String>,
        start_time: Option<String>,
        suppress_registry_enrichment: bool,
    ) -> Self {
        Self {
            content_id,
            display_name,
            start_time,
            last_timestamp: None,
            size_bytes: None,
            speed_bps: None,
            do_percentage: None,
            duration_secs: None,
            suppress_registry_enrichment,
            saw_progress: false,
            saw_failure_signal: false,
            saw_retry_signal: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadSourceKind {
    PrimaryIme,
    AppWorkload,
    Unsupported,
}

fn classify_download_source(source_file: &str) -> DownloadSourceKind {
    let file_name = Path::new(source_file)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| source_file.to_ascii_lowercase());

    if file_name.contains("appworkload") {
        DownloadSourceKind::AppWorkload
    } else if file_name.contains("intunemanagementextension") {
        DownloadSourceKind::PrimaryIme
    } else {
        DownloadSourceKind::Unsupported
    }
}

#[cfg(test)]
fn extract_content_id(msg: &str) -> Option<String> {
    extract_download_identity(msg).content_id
}

#[cfg(test)]
fn extract_display_name(msg: &str) -> Option<String> {
    extract_download_identity(msg).display_name
}

struct DownloadIdentityAnalysis {
    content_id: Option<String>,
    display_name: Option<String>,
    suppress_registry_enrichment: bool,
}

fn extract_download_identity(msg: &str) -> DownloadIdentityAnalysis {
    let context = explicit_app_identity_context_with_named_guid_fallback(msg);
    match context.identity {
        ExplicitAppIdentity::Valid(guid) => {
            let display_name = context.local_name;
            let suppress_registry_enrichment = display_name.is_none();
            DownloadIdentityAnalysis {
                content_id: Some(guid),
                display_name,
                suppress_registry_enrichment,
            }
        }
        ExplicitAppIdentity::Invalid => DownloadIdentityAnalysis {
            content_id: None,
            display_name: None,
            suppress_registry_enrichment: true,
        },
        ExplicitAppIdentity::Absent => {
            // Preserve named-context and download-specific heuristics only
            // when the line has no explicit JSON identity field.
            let content_id = context.fallback_app_id.or_else(|| {
                content_id_re()
                    .captures(msg)
                    .and_then(|captures| captures.get(1))
                    .map(|value| value.as_str().to_string())
            });
            DownloadIdentityAnalysis {
                content_id,
                display_name: extract_app_name(msg),
                suppress_registry_enrichment: false,
            }
        }
    }
}

fn apply_download_analysis(
    download: &mut PartialDownload,
    analysis: &DownloadLineAnalysis,
    timestamp: Option<&str>,
) {
    if download.start_time.is_none() {
        download.start_time = timestamp.map(|value| value.to_string());
    }
    download.last_timestamp = timestamp.map(|value| value.to_string());

    if let Some(content_id) = analysis.content_id.clone() {
        if download.content_id.is_none() || download.content_id.as_deref() == Some("unknown") {
            download.content_id = Some(content_id);
        }
    }
    if download.display_name.is_none() {
        download.display_name = analysis.display_name.clone();
    }
    download.suppress_registry_enrichment |= analysis.suppress_registry_enrichment;

    if analysis.is_progress {
        download.saw_progress = true;
    }
    if analysis.is_failed || analysis.is_stall {
        download.saw_failure_signal = true;
    }
    if analysis.is_retry {
        download.saw_retry_signal = true;
    }

    if let Some(size_bytes) = analysis.size_bytes {
        download.size_bytes = Some(size_bytes);
    }

    if let Some(speed_bps) = analysis.speed_bps {
        download.speed_bps = Some(speed_bps);
    }

    if let Some(do_percentage) = analysis.do_percentage {
        download.do_percentage = Some(do_percentage);
    }

    if let Some(duration_secs) = analysis.duration_secs {
        download.duration_secs = Some(duration_secs);
    }
}

fn capture_number_and_unit<'a>(re: &Regex, msg: &'a str) -> Option<(f64, &'a str)> {
    let captures = re.captures(msg)?;
    let value = captures.get(1)?.as_str().parse::<f64>().ok()?;
    let unit = captures.get(2)?.as_str();
    Some((value, unit))
}

fn convert_size_to_bytes(value: f64, unit: &str) -> u64 {
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "gb" => 1024.0 * 1024.0 * 1024.0,
        "mb" => 1024.0 * 1024.0,
        "kb" => 1024.0,
        _ => 1.0,
    };

    (value * multiplier).round() as u64
}

fn convert_speed_to_bps(value: f64, unit: &str) -> f64 {
    let normalized = unit.to_ascii_lowercase();
    if normalized.contains("mb") {
        value * 1024.0 * 1024.0
    } else if normalized.contains("kb") {
        value * 1024.0
    } else {
        value
    }
}

fn finalize_download(
    partial: Option<PartialDownload>,
    content_id: Option<String>,
    display_name: Option<String>,
    analysis: &DownloadLineAnalysis,
    timestamp: Option<&str>,
    success: bool,
    registry: &GuidRegistry,
) -> Option<DownloadStat> {
    let mut partial = partial.unwrap_or_else(|| {
        PartialDownload::new(
            content_id.clone(),
            display_name.clone(),
            timestamp.map(|value| value.to_string()),
            analysis.suppress_registry_enrichment,
        )
    });
    apply_download_analysis(&mut partial, analysis, timestamp);

    if partial.display_name.is_none() {
        partial.display_name = display_name;
    }

    let resolved_content_id = content_id
        .or(partial.content_id.clone())
        .unwrap_or_else(|| "unknown".to_string());

    if !success && !partial.saw_failure_signal && !partial.saw_retry_signal && !analysis.is_stall {
        return None;
    }

    // Resolve display name: use existing name if it's a real name,
    // otherwise try the GUID registry, otherwise fall back to short ID
    let raw_name = partial
        .display_name
        .clone()
        .unwrap_or_else(|| short_id(&resolved_content_id));
    let name = if is_fallback_name(&raw_name) && !partial.suppress_registry_enrichment {
        registry
            .resolve(&resolved_content_id)
            .map(|n| n.to_string())
            .unwrap_or(raw_name)
    } else {
        raw_name
    };

    let ts = timestamp
        .map(|value| value.to_string())
        .or(partial.last_timestamp)
        .or(partial.start_time);

    Some(DownloadStat {
        content_id: resolved_content_id,
        name,
        size_bytes: partial.size_bytes.unwrap_or(0),
        speed_bps: partial.speed_bps.unwrap_or(0.0),
        do_percentage: partial.do_percentage.unwrap_or(0.0),
        duration_secs: partial.duration_secs.unwrap_or(0.0),
        success,
        timestamp_epoch: ts
            .as_deref()
            .and_then(parse_timestamp)
            .map(|dt| dt.and_utc().timestamp_millis()),
        timestamp: ts,
    })
}

fn short_id(id: &str) -> String {
    format!("Download ({id})")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_registry() -> GuidRegistry {
        GuidRegistry::new()
    }

    fn completed_json_download(payload: &str) -> DownloadStat {
        let mut downloads = extract_downloads(
            &[ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: format!("Download completed successfully {payload}"),
                component: None,
                thread: None,
                timezone_offset: None,
            }],
            "C:/Logs/AppWorkload.log",
            &empty_registry(),
        );
        assert_eq!(downloads.len(), 1, "missing coverage record for {payload}");
        downloads.remove(0)
    }

    fn test_line(line_number: u32, message: impl Into<String>) -> ImeLine {
        ImeLine {
            line_number,
            timestamp: Some("01-15-2024 10:00:05.000".to_string()),
            timestamp_utc: None,
            message: message.into(),
            component: None,
            thread: None,
            timezone_offset: None,
        }
    }

    #[test]
    fn completed_download_is_recorded() {
        let lines = vec![
            ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                timestamp_utc: None,
                message: "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: "Download completed successfully. Content size: 5242880 bytes, speed: 1048576 Bps, Delivery Optimization: 75.5%".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert!(downloads[0].success);
        assert_eq!(downloads[0].size_bytes, 5242880);
    }

    #[test]
    fn stalled_download_is_recorded_as_failed() {
        let lines = vec![
            ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                timestamp_utc: None,
                message: "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:30.000".to_string()),
                timestamp_utc: None,
                message: "Content download stalled with no progress for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert!(!downloads[0].success);
    }

    #[test]
    fn plain_start_line_does_not_create_failed_download() {
        let lines = vec![ImeLine {
            line_number: 1,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
            timestamp_utc: None,
            message: "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                .to_string(),
            component: None,
            thread: None,
            timezone_offset: None,
        }];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert!(downloads.is_empty());
    }

    #[test]
    fn retry_creates_failed_attempt() {
        let lines = vec![
            ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                timestamp_utc: None,
                message: "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: "Download failed, retrying content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert!(!downloads[0].success);
    }

    #[test]
    fn a_failed_start_is_a_download_failure_never_a_start() {
        // "Failed to start download" contains the start vocabulary, but the
        // line states the opposite of a start: the analysis must not assert a
        // start observation for it, and the honest classification is a
        // download failure.
        for message in [
            "Failed to start download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "Failed to start the content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "Unable to start download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        ] {
            let analysis = DownloadLineAnalysis::from_message(message)
                .expect("a failed-start line is download-shaped");
            assert!(
                !analysis.is_start,
                "a negated start must not assert a start: {message:?}"
            );
            assert!(
                analysis.is_failed,
                "a failed start is a download failure: {message:?}"
            );
        }

        // End to end: a lone failed-start line yields one failed download
        // instead of a dangling phantom start that reports nothing.
        let downloads = extract_downloads(
            &[test_line(
                1,
                "Failed to start download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            )],
            "C:/Logs/AppWorkload.log",
            &empty_registry(),
        );
        assert_eq!(downloads.len(), 1);
        assert!(!downloads[0].success);
    }

    #[test]
    fn an_ordinary_start_line_still_asserts_a_start() {
        let analysis = DownloadLineAnalysis::from_message(
            "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        )
        .expect("a start line is download-shaped");
        assert!(analysis.is_start);
        assert!(!analysis.is_failed);
    }

    #[test]
    fn ime_transition_template_is_ignored() {
        let lines = vec![ImeLine {
            line_number: 1,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
            timestamp_utc: None,
            message: "Adding new state transition - From: Install In Progress To: Download In Progress With Event: Download Started.".to_string(),
            component: None,
            thread: None,
            timezone_offset: None,
        }];

        let downloads = extract_downloads(
            &lines,
            "C:/Logs/IntuneManagementExtension.log",
            &empty_registry(),
        );
        assert!(downloads.is_empty());
    }

    #[test]
    fn the_shared_vocabulary_carries_the_pre_consolidation_ime_phrasings() {
        // One phrase table (test_vocabulary) feeds this test and the win32
        // rules test, so the owner regexes and the consumer's recall
        // assertions can never drift apart.
        for phrase in test_vocabulary::PRE_CONSOLIDATION_FAILED {
            assert!(download_failed_re().is_match(phrase), "{phrase:?}");
        }
        for phrase in test_vocabulary::PRE_CONSOLIDATION_COMPLETE {
            assert!(download_complete_re().is_match(phrase), "{phrase:?}");
        }
        for phrase in test_vocabulary::PRE_CONSOLIDATION_START {
            assert!(download_start_re().is_match(phrase), "{phrase:?}");
        }
    }

    #[test]
    fn appworkload_metadata_does_not_create_retry_failure() {
        let lines = vec![ImeLine {
            line_number: 1,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
            timestamp_utc: None,
            message: r#"RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"MaxRetries\":3,\"RetryIntervalInMinutes\":5,\"DownloadStartTimeUTC\":\"\\/Date(-62135578800000)\\/\"}"#.to_string(),
            component: None,
            thread: None,
            timezone_offset: None,
        }];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert!(downloads.is_empty());
    }

    #[test]
    fn json_app_identity_is_used_for_real_download_lines() {
        let lines = vec![
            ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                timestamp_utc: None,
                message: r#"Starting content download RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Contoso App\"}"#.to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: r#"Download completed successfully RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Contoso App\"}"#.to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert_eq!(
            downloads[0].content_id,
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        );
        assert_eq!(downloads[0].name, "Contoso App");
    }

    #[test]
    fn completed_download_has_timestamp_epoch() {
        let lines = vec![
            ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                timestamp_utc: None,
                message: "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: "Download completed successfully. Content size: 5242880 bytes, speed: 1048576 Bps, Delivery Optimization: 75.5%".to_string(),
                component: None,
                thread: None,
                timezone_offset: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert!(
            downloads[0].timestamp_epoch.is_some(),
            "timestamp_epoch should be populated"
        );
    }

    #[test]
    fn escaped_json_fields_are_extracted_without_normalization() {
        let message = r#"Download completed successfully RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Contoso App\",\"SetUpFilePath\":\"C:\\Cache\\setup.exe\"}"#;

        // extract_content_id reuses the shared explicit-identity context before
        // the download-specific content-ID fallback.
        assert_eq!(
            extract_content_id(message).as_deref(),
            Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        );
        // extract_display_name delegates to guid_registry::extract_app_name
        assert_eq!(
            extract_display_name(message).as_deref(),
            Some("Contoso App")
        );
    }

    #[test]
    fn invalid_explicit_identity_suppresses_download_line_fallback() {
        let message = r#"Starting content download for app 11111111-2222-3333-4444-555555555555 {"AppId":"not-an-app-guid","ApplicationName":"Contoso"}"#;
        assert_eq!(extract_content_id(message), None);
    }

    #[test]
    fn download_app_id_syntaxes_precede_id() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let id_guid = "11111111-2222-3333-4444-555555555555";
        let payloads = [
            format!(r#"{{"AppId":"{app_guid}","Id":"{id_guid}","Name":"Contoso"}}"#),
            format!(r#"{{\"AppId\":\"{app_guid}\",\"Id\":\"{id_guid}\",\"Name\":\"Contoso\"}}"#),
            format!(r#"{{"AppId" : "{app_guid}","Id":"{id_guid}","Name":"Contoso"}}"#),
            format!(r#"{{\"AppId\" : \"{app_guid}\",\"Id\":\"{id_guid}\",\"Name\":\"Contoso\"}}"#),
            format!(r#"{{"AppId":"Win32App_{app_guid}_1","Id":"{id_guid}","Name":"Contoso"}}"#),
            format!(
                r#"{{\"AppId\":\"Win32App_{app_guid}_1\",\"Id\":\"{id_guid}\",\"Name\":\"Contoso\"}}"#
            ),
            format!(r#"{{"Id":"{id_guid}","AppId" : "{app_guid}","Name":"Contoso"}}"#),
            format!(
                r#"{{\"Id\":\"{id_guid}\",\"AppId\":\"Win32App_{app_guid}_1\",\"Name\":\"Contoso\"}}"#
            ),
        ];

        for payload in payloads {
            let lines = vec![
                ImeLine {
                    line_number: 1,
                    timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                    timestamp_utc: None,
                    message: format!("Starting content download {payload}"),
                    component: None,
                    thread: None,
                    timezone_offset: None,
                },
                ImeLine {
                    line_number: 2,
                    timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                    timestamp_utc: None,
                    message: format!("Download completed successfully {payload}"),
                    component: None,
                    thread: None,
                    timezone_offset: None,
                },
            ];

            let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
            assert_eq!(downloads.len(), 1, "missing download for {payload}");
            assert_eq!(
                downloads[0].content_id, app_guid,
                "wrong identity for {payload}"
            );
        }
    }

    #[test]
    fn download_invalid_app_id_still_allows_valid_id_fallback() {
        let id_guid = "11111111-2222-3333-4444-555555555555";
        let payload = format!(r#"{{"AppId":"invalid","Id":"{id_guid}","Name":"Contoso"}}"#);
        let lines = vec![
            ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                timestamp_utc: None,
                message: format!("Starting content download {payload}"),
                component: None,
                thread: None,
                timezone_offset: None,
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: format!("Download completed successfully {payload}"),
                component: None,
                thread: None,
                timezone_offset: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].content_id, id_guid);
    }

    #[test]
    fn download_duplicate_identity_conflicts_have_no_attribution() {
        let first = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let second = "11111111-2222-3333-4444-555555555555";
        let payloads = [
            format!(r#"{{"AppId":"{first}","AppId":"{second}","Name":"Contoso"}}"#),
            format!(r#"{{"Id":"{first}","Id":"{second}","Name":"Contoso"}}"#),
            format!(r#"{{"AppId":"{first}",\"AppId\":\"{second}\","Name":"Contoso"}}"#),
            format!(r#"{{"Id":"{first}",\"Id\":\"{second}\","Name":"Contoso"}}"#),
            format!(r#"{{"AppId":"invalid","AppId":"{first}","Name":"Contoso"}}"#),
            format!(r#"{{"Id":"invalid","Id":"{first}","Name":"Contoso"}}"#),
        ];

        for payload in payloads {
            let lines = vec![
                ImeLine {
                    line_number: 1,
                    timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                    timestamp_utc: None,
                    message: format!("Starting content download {payload}"),
                    component: None,
                    thread: None,
                    timezone_offset: None,
                },
                ImeLine {
                    line_number: 2,
                    timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                    timestamp_utc: None,
                    message: format!("Download completed successfully {payload}"),
                    component: None,
                    thread: None,
                    timezone_offset: None,
                },
            ];

            let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
            assert_eq!(downloads.len(), 1, "missing coverage record for {payload}");
            assert_eq!(
                downloads[0].content_id, "unknown",
                "attributed conflict from {payload}"
            );
        }
    }

    #[test]
    fn download_sibling_identity_objects_have_no_attribution() {
        let first = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let second = "11111111-2222-3333-4444-555555555555";
        let payloads = [
            format!(r#"[{{"AppId":"{first}"}},{{"AppId":"{second}"}}]"#),
            format!(r#"[{{"AppId":"{second}"}},{{"AppId":"{first}"}}]"#),
            format!(r#"[{{"Id":"{first}"}},{{"AppId":"{second}"}}]"#),
            format!(r#"[{{"AppId":"{second}"}},{{"Id":"{first}"}}]"#),
            format!(r#"{{"Items":[{{"Id":"{first}"}},{{"AppId":"{second}"}}]}}"#),
            format!(
                r#"{{"Left":{{"AppId":"{first}"}},"Right":{{"Metadata":{{"AppId":"{second}"}}}}}}"#
            ),
            format!(
                r#"{{"Left":{{"Metadata":{{"AppId":"{second}"}}}},"Right":{{"AppId":"{first}"}}}}"#
            ),
        ];

        for payload in payloads {
            let lines = vec![ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: format!("Download completed successfully {payload}"),
                component: None,
                thread: None,
                timezone_offset: None,
            }];

            let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
            assert_eq!(downloads.len(), 1, "missing coverage record for {payload}");
            assert_eq!(
                downloads[0].content_id, "unknown",
                "attributed sibling from {payload}"
            );
        }
    }

    #[test]
    fn downloads_do_not_take_names_outside_the_selected_identity_object() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let payloads = [
            format!(r#"[{{"AppId":"{app_guid}"}},{{"Name":"Sibling Name"}}]"#),
            format!(r#"{{"AppId":"{app_guid}","Metadata":{{"Name":"Nested Name"}}}}"#),
        ];

        for payload in payloads {
            let downloads = extract_downloads(
                &[ImeLine {
                    line_number: 1,
                    timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                    timestamp_utc: None,
                    message: format!("Download completed successfully {payload}"),
                    component: None,
                    thread: None,
                    timezone_offset: None,
                }],
                "C:/Logs/AppWorkload.log",
                &empty_registry(),
            );

            assert_eq!(downloads.len(), 1, "missing coverage record for {payload}");
            assert_eq!(downloads[0].content_id, app_guid);
            assert_eq!(
                downloads[0].name,
                format!("Download ({app_guid})"),
                "accepted out-of-scope name for {payload}"
            );
        }
    }

    #[test]
    fn selected_ancestor_does_not_take_a_repeated_descendant_identity_name() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let payload = format!(
            r#"{{"AppId":"{app_guid}","Metadata":{{"AppId":"{app_guid}","Name":"Descendant Name"}}}}"#
        );

        let download = completed_json_download(&payload);

        assert_eq!(download.content_id, app_guid);
        assert_eq!(download.name, format!("Download ({app_guid})"));
        assert_eq!(explicit_app_identity_context(&payload).local_name, None);
    }

    #[test]
    fn conflicting_duplicate_names_in_the_selected_object_fail_closed() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let payloads = [
            format!(r#"{{"AppId":"{app_guid}","Name":"First Name","Name":"Second Name"}}"#),
            format!(r#"{{"AppId":"{app_guid}","Name":"Second Name","Name":"First Name"}}"#),
        ];

        for payload in payloads {
            let download = completed_json_download(&payload);

            assert_eq!(download.content_id, app_guid);
            assert_eq!(
                download.name,
                format!("Download ({app_guid})"),
                "accepted conflicting name from {payload}"
            );
            assert_eq!(explicit_app_identity_context(&payload).local_name, None);
        }
    }

    #[test]
    fn identical_duplicate_names_are_deterministic() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let payload = format!(r#"{{"AppId":"{app_guid}","Name":"Same Name","Name":"Same Name"}}"#);

        let download = completed_json_download(&payload);

        assert_eq!(download.name, "Same Name");
    }

    #[test]
    fn application_name_precedes_name_in_either_field_order() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let payloads = [
            format!(r#"{{"AppId":"{app_guid}","ApplicationName":"Preferred","Name":"Fallback"}}"#),
            format!(r#"{{"AppId":"{app_guid}","Name":"Fallback","ApplicationName":"Preferred"}}"#),
        ];

        for payload in payloads {
            assert_eq!(completed_json_download(&payload).name, "Preferred");
        }
    }

    #[test]
    fn ingested_descendant_name_does_not_enrich_outer_selected_download() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let lines = vec![test_line(
            1,
            format!(
                r#"Download completed successfully {{"AppId":"{app_guid}","Metadata":{{"AppId":"{app_guid}","Name":"Descendant Name"}}}}"#
            ),
        )];
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&lines);
        assert_eq!(registry.resolve(app_guid), Some("Descendant Name"));

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &registry);

        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].content_id, app_guid);
        assert_eq!(downloads[0].name, format!("Download ({app_guid})"));
    }

    #[test]
    fn explicit_name_ambiguity_suppresses_existing_registry_enrichment() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let payloads = [
            format!(r#"{{"AppId":"{app_guid}","Name":"First Name","Name":"Second Name"}}"#),
            format!(r#"[{{"AppId":"{app_guid}"}},{{"Name":"Sibling Name"}}]"#),
        ];

        for payload in payloads {
            let lines = vec![
                test_line(
                    1,
                    format!(
                        r#"Observed identity {{"AppId":"{app_guid}","ApplicationName":"Trusted Registry Name"}}"#
                    ),
                ),
                test_line(2, format!("Download completed successfully {payload}")),
            ];
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&lines);
            assert_eq!(registry.resolve(app_guid), Some("Trusted Registry Name"));

            let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &registry);

            assert_eq!(downloads.len(), 1, "missing download for {payload}");
            assert_eq!(downloads[0].content_id, app_guid);
            assert_eq!(
                downloads[0].name,
                format!("Download ({app_guid})"),
                "enriched explicit ambiguous name for {payload}"
            );
        }
    }

    #[test]
    fn non_explicit_download_keeps_registry_fallback() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let lines = vec![
            test_line(
                1,
                format!(
                    r#"Observed identity {app_guid} {{"ApplicationName":"Trusted Registry Name"}}"#
                ),
            ),
            test_line(
                2,
                format!("Download completed successfully for app id: {app_guid}"),
            ),
        ];
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&lines);

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &registry);

        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].name, "Trusted Registry Name");
    }

    #[test]
    fn named_guid_fallback_is_shared_by_identity_and_download_extraction() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let message = format!(
            r#"Download completed successfully correlation {app_guid} {{"Name":"Local Fallback Name"}}"#
        );
        assert_eq!(extract_content_id(&message).as_deref(), Some(app_guid));

        let lines = vec![test_line(1, message)];
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&lines);
        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &registry);

        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].content_id, app_guid);
        assert_eq!(downloads[0].name, "Local Fallback Name");
    }

    #[test]
    fn explicit_same_scope_name_remains_valid_with_ingested_registry() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let lines = vec![test_line(
            1,
            format!(
                r#"Download completed successfully {{"AppId":"{app_guid}","Name":"Local Name"}}"#
            ),
        )];
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&lines);

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &registry);

        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].name, "Local Name");
    }

    #[test]
    fn retry_keeps_explicit_name_suppression_across_attempts() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let lines = vec![
            test_line(
                1,
                format!(
                    r#"Observed identity {{"AppId":"{app_guid}","ApplicationName":"Trusted Registry Name"}}"#
                ),
            ),
            test_line(
                2,
                format!(
                    r#"Starting content download {{"AppId":"{app_guid}","Metadata":{{"AppId":"{app_guid}","Name":"Unsafe Descendant"}}}}"#
                ),
            ),
            test_line(
                3,
                format!("Download failed, retrying content download for app id: {app_guid}"),
            ),
            test_line(
                4,
                format!("Download completed successfully for app id: {app_guid}"),
            ),
        ];
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&lines);
        assert_eq!(registry.resolve(app_guid), Some("Trusted Registry Name"));

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &registry);

        assert_eq!(downloads.len(), 2);
        assert!(
            downloads.iter().all(|download| {
                download.content_id == app_guid && download.name == format!("Download ({app_guid})")
            }),
            "retry outputs were not safely attributed: {downloads:#?}"
        );
    }

    #[test]
    fn retry_suppression_is_isolated_between_concurrent_content_ids() {
        let unsafe_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let safe_guid = "11111111-2222-3333-4444-555555555555";
        let lines = vec![
            test_line(
                1,
                format!(
                    r#"Observed identity {{"AppId":"{unsafe_guid}","ApplicationName":"Unsafe Registry Name"}}"#
                ),
            ),
            test_line(
                2,
                format!(
                    r#"Starting content download {{"AppId":"{unsafe_guid}","Metadata":{{"AppId":"{unsafe_guid}","Name":"Unsafe Descendant"}}}}"#
                ),
            ),
            test_line(
                3,
                format!(
                    r#"Starting content download {{"AppId":"{safe_guid}","Name":"Safe Local Name"}}"#
                ),
            ),
            test_line(
                4,
                format!("Download failed, retrying content download for app id: {unsafe_guid}"),
            ),
            test_line(
                5,
                format!("Download completed successfully for app id: {safe_guid}"),
            ),
            test_line(
                6,
                format!("Download completed successfully for app id: {unsafe_guid}"),
            ),
        ];
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&lines);

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &registry);

        assert_eq!(downloads.len(), 3);
        let unsafe_fallback = format!("Download ({unsafe_guid})");
        assert_eq!(
            downloads
                .iter()
                .filter(|download| download.content_id == unsafe_guid)
                .map(|download| download.name.as_str())
                .collect::<Vec<_>>(),
            vec![unsafe_fallback.as_str(), unsafe_fallback.as_str()]
        );
        assert_eq!(
            downloads
                .iter()
                .find(|download| download.content_id == safe_guid)
                .map(|download| download.name.as_str()),
            Some("Safe Local Name")
        );
    }
}
