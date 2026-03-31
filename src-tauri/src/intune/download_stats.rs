use std::collections::HashMap;
use std::path::Path;

use regex::Regex;

use super::guid_registry::{extract_app_id, extract_app_name, is_fallback_name, GuidRegistry};
use super::ime_parser::ImeLine;
use super::models::DownloadStat;
use super::timeline::parse_timestamp;
use std::sync::OnceLock;

fn download_re() -> &'static Regex {
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
fn size_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r#"(?i)(?:content\s+)?size[:\s]+([\d.]+)\s*(bytes|kb|mb|gb)"#).unwrap()
})
}
fn speed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r#"(?i)(?:speed|rate)[:\s]+([\d.]+)\s*(bytes?/s|kb/s|mb/s|bps|kbps|mbps)"#).unwrap()
})
}
fn do_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r#"(?i)(?:delivery\s+optimization|DO)[:\s]+([\d.]+)\s*%"#).unwrap())
}
fn content_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r#"(?i)(?:content|app|application)\s*(?:id)?[:\s]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#).unwrap()
})
}
fn download_complete_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r#"(?i)(?:download\s+(?:completed|finished|succeeded|done)|content\s+cached|staging\s+completed|hash\s+validation\s+succeeded)"#,
    )
    .unwrap()
})
}
fn download_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r#"(?i)(?:download\s+(?:failed|error)|failed\s+to\s+download|hash\s+validation\s+failed|hash\s+mismatch|staging\s+failed|content\s+not\s+found|unable\s+to\s+download|cancelled|aborted)"#,
    )
    .unwrap()
})
}
fn download_start_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r#"(?i)(?:starting|beginning|queued|requesting|resuming).*(?:download|content\s+download)"#,
    )
    .unwrap()
})
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
fn download_stall_re() -> &'static Regex {
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
            if let Some(stat) = finalize_download(
                active.remove(&content_id),
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
                PartialDownload::new(Some(content_id), display_name, timestamp_owned.clone()),
            );
            continue;
        }

        if analysis.is_start || analysis.is_progress {
            let entry = active.entry(content_id.clone()).or_insert_with(|| {
                PartialDownload::new(
                    Some(content_id.clone()),
                    display_name.clone(),
                    timestamp_owned.clone(),
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
            let name = if is_fallback_name(&raw_name) {
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
                timestamp_epoch: ts.as_deref().and_then(parse_timestamp).map(|dt| dt.and_utc().timestamp_millis()),
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

        Some(Self {
            content_id: extract_content_id(msg),
            display_name: extract_display_name(msg),
            size_bytes,
            speed_bps,
            do_percentage,
            duration_secs,
            is_retry: appworkload_retry_re().is_match(msg),
            is_start: download_start_re().is_match(msg),
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
    saw_progress: bool,
    saw_failure_signal: bool,
    saw_retry_signal: bool,
}

impl PartialDownload {
    fn new(
        content_id: Option<String>,
        display_name: Option<String>,
        start_time: Option<String>,
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

fn extract_content_id(msg: &str) -> Option<String> {
    // Primary: shared extraction from guid_registry (handles AppId, Id, etc.)
    extract_app_id(msg).or_else(|| {
        // Fallback: download-specific broader pattern (e.g. "content id: <GUID>")
        content_id_re()
            .captures(msg)
            .and_then(|captures| captures.get(1))
            .map(|value| value.as_str().to_string())
    })
}

fn extract_display_name(msg: &str) -> Option<String> {
    // Delegates to shared extraction in guid_registry (handles ApplicationName, Name, SetUpFilePath)
    extract_app_name(msg)
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
    let name = if is_fallback_name(&raw_name) {
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
        timestamp_epoch: ts.as_deref().and_then(parse_timestamp).map(|dt| dt.and_utc().timestamp_millis()),
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

    #[test]
    fn completed_download_is_recorded() {
        let lines = vec![
            ImeLine {
                line_number: 1,
                timestamp: Some("01-15-2024 10:00:00.000".to_string()),
                timestamp_utc: None,
                message: "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: "Download completed successfully. Content size: 5242880 bytes, speed: 1048576 Bps, Delivery Optimization: 75.5%".to_string(),
                component: None,
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
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:30.000".to_string()),
                timestamp_utc: None,
                message: "Content download stalled with no progress for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
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
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: "Download failed, retrying content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert!(!downloads[0].success);
    }

    #[test]
    fn ime_transition_template_is_ignored() {
        let lines = vec![ImeLine {
            line_number: 1,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
            timestamp_utc: None,
            message: "Adding new state transition - From: Install In Progress To: Download In Progress With Event: Download Started.".to_string(),
            component: None,
        }];

        let downloads = extract_downloads(&lines, "C:/Logs/IntuneManagementExtension.log", &empty_registry());
        assert!(downloads.is_empty());
    }

    #[test]
    fn appworkload_metadata_does_not_create_retry_failure() {
        let lines = vec![ImeLine {
            line_number: 1,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
            timestamp_utc: None,
            message: r#"RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"MaxRetries\":3,\"RetryIntervalInMinutes\":5,\"DownloadStartTimeUTC\":\"\\/Date(-62135578800000)\\/\"}"#.to_string(),
            component: None,
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
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: r#"Download completed successfully RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Contoso App\"}"#.to_string(),
                component: None,
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
            },
            ImeLine {
                line_number: 2,
                timestamp: Some("01-15-2024 10:00:05.000".to_string()),
                timestamp_utc: None,
                message: "Download completed successfully. Content size: 5242880 bytes, speed: 1048576 Bps, Delivery Optimization: 75.5%".to_string(),
                component: None,
            },
        ];

        let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
        assert_eq!(downloads.len(), 1);
        assert!(downloads[0].timestamp_epoch.is_some(), "timestamp_epoch should be populated");
    }

    #[test]
    fn escaped_json_fields_are_extracted_without_normalization() {
        let message = r#"Download completed successfully RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Contoso App\",\"SetUpFilePath\":\"C:\\Cache\\setup.exe\"}"#;

        // extract_content_id delegates to guid_registry::extract_app_id + content_id_re() fallback
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
}
