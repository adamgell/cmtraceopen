use super::models::{
    MacosUnifiedLogEntry, MacosUnifiedLogPreset, MacosUnifiedLogResult, MacosUnifiedLogTimeRange,
};

// ---------------------------------------------------------------------------
// Presets (cross-platform, always compiled)
// ---------------------------------------------------------------------------

/// Returns the hardcoded list of unified-log query presets.
pub fn get_presets() -> Vec<MacosUnifiedLogPreset> {
    vec![
        MacosUnifiedLogPreset {
            id: "mdm-client".to_string(),
            label: "MDM Client".to_string(),
            predicate: r#"process == "mdmclient""#.to_string(),
            description: "Apple MDM client process events (enrollment, profiles, commands)"
                .to_string(),
        },
        MacosUnifiedLogPreset {
            id: "managed-client".to_string(),
            label: "Managed Client Subsystem".to_string(),
            predicate: r#"subsystem == "com.apple.ManagedClient""#.to_string(),
            description: "Managed client subsystem (profile installation, policy evaluation)"
                .to_string(),
        },
        MacosUnifiedLogPreset {
            id: "install-activity".to_string(),
            label: "Install Activity".to_string(),
            predicate: r#"subsystem == "com.apple.install""#.to_string(),
            description: "Package installation activity (pkg installs, updates)".to_string(),
        },
        MacosUnifiedLogPreset {
            id: "intune-agent".to_string(),
            label: "Intune Agent Processes".to_string(),
            predicate:
                r#"process == "IntuneMdmAgent" OR process == "IntuneMdmDaemon" OR process == "CompanyPortal""#
                    .to_string(),
            description:
                "Intune MDM agent, daemon, and Company Portal process events".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Parsing helpers (cross-platform, always compiled, fully testable)
// ---------------------------------------------------------------------------

/// Parses ndjson output from `log show --style ndjson`.
///
/// Each line is a JSON object with fields like:
/// ```json
/// {
///   "timestamp": "2024-03-15 10:00:00.123456-0700",
///   "processImagePath": "/usr/libexec/mdmclient",
///   "subsystem": "com.apple.ManagedClient",
///   "category": "MDMDaemon",
///   "messageType": "Default",
///   "eventMessage": "Processing MDM command...",
///   "processID": 1234,
///   "threadID": 56789
/// }
/// ```
///
/// Returns (entries, total_matched, capped).
pub fn parse_ndjson_log_entries(
    output: &str,
    result_cap: usize,
) -> (Vec<MacosUnifiedLogEntry>, usize, bool) {
    let mut entries = Vec::new();
    let mut total_matched: usize = 0;
    let mut capped = false;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try to parse as JSON
        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        total_matched += 1;

        if entries.len() >= result_cap {
            capped = true;
            continue; // Keep counting total_matched but stop collecting
        }

        let timestamp = json
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Extract process name from the full image path
        let process = json
            .get("processImagePath")
            .and_then(|v| v.as_str())
            .map(|path| path.rsplit('/').next().unwrap_or(path).to_string())
            .unwrap_or_default();

        let subsystem = json
            .get("subsystem")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let category = json
            .get("category")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let level = json
            .get("messageType")
            .and_then(|v| v.as_str())
            .unwrap_or("Default")
            .to_string();

        let message = json
            .get("eventMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let pid = json
            .get("processID")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let tid = json.get("threadID").and_then(|v| v.as_u64());

        entries.push(MacosUnifiedLogEntry {
            timestamp,
            process,
            subsystem,
            category,
            level,
            message,
            pid,
            tid,
        });
    }

    (entries, total_matched, capped)
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn query_unified_log_impl(
    preset_id: &str,
    time_range: Option<MacosUnifiedLogTimeRange>,
    result_cap: usize,
) -> Result<MacosUnifiedLogResult, crate::error::AppError> {
    use std::process::Command;

    let presets = get_presets();
    let preset = presets.iter().find(|p| p.id == preset_id).ok_or_else(|| {
        crate::error::AppError::InvalidInput(format!("Unknown preset ID: '{}'", preset_id))
    })?;

    log::info!(
        "Querying unified log with preset '{}', cap={}",
        preset_id,
        result_cap
    );

    let mut cmd = Command::new("log");
    cmd.arg("show");
    cmd.args(["--predicate", &preset.predicate]);
    cmd.args(["--style", "ndjson"]);

    // Time range: use --start/--end if provided, otherwise --last 1h
    let effective_time_range = match &time_range {
        Some(tr) => {
            cmd.args(["--start", &tr.start]);
            cmd.args(["--end", &tr.end]);
            Some(tr.clone())
        }
        None => {
            cmd.args(["--last", "1h"]);
            None
        }
    };

    let output = cmd.output().map_err(crate::error::AppError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // log show may return non-zero with partial results, so warn but continue
        log::warn!("log show exited with status {}: {}", output.status, stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (entries, total_matched, capped) = parse_ndjson_log_entries(&stdout, result_cap);

    Ok(MacosUnifiedLogResult {
        entries,
        total_matched,
        capped,
        result_cap,
        predicate_used: preset.predicate.clone(),
        time_range: effective_time_range,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn query_unified_log_impl(
    _preset_id: &str,
    _time_range: Option<MacosUnifiedLogTimeRange>,
    _result_cap: usize,
) -> Result<MacosUnifiedLogResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "macOS Diagnostics is only available on macOS.".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_presets() {
        let presets = get_presets();
        assert_eq!(presets.len(), 4);
        assert_eq!(presets[0].id, "mdm-client");
        assert_eq!(presets[3].id, "intune-agent");
    }

    #[test]
    fn test_parse_ndjson_log_entries_basic() {
        let input = r#"{"timestamp":"2024-03-15 10:00:00.123456-0700","processImagePath":"/usr/libexec/mdmclient","subsystem":"com.apple.ManagedClient","category":"MDMDaemon","messageType":"Default","eventMessage":"Processing command","processID":1234,"threadID":56789}
{"timestamp":"2024-03-15 10:00:01.000000-0700","processImagePath":"/usr/bin/profiles","subsystem":"","category":"","messageType":"Error","eventMessage":"Profile install failed","processID":5678,"threadID":11111}"#;

        let (entries, total, capped) = parse_ndjson_log_entries(input, 5000);
        assert_eq!(entries.len(), 2);
        assert_eq!(total, 2);
        assert!(!capped);

        assert_eq!(entries[0].process, "mdmclient");
        assert_eq!(entries[0].level, "Default");
        assert_eq!(entries[0].message, "Processing command");
        assert_eq!(entries[0].pid, Some(1234));
        assert_eq!(
            entries[0].subsystem.as_deref(),
            Some("com.apple.ManagedClient")
        );

        assert_eq!(entries[1].process, "profiles");
        assert_eq!(entries[1].level, "Error");
        // Empty subsystem should be None
        assert!(entries[1].subsystem.is_none());
    }

    #[test]
    fn test_parse_ndjson_log_entries_capped() {
        let line = r#"{"timestamp":"2024-01-01 00:00:00.000000-0000","processImagePath":"/usr/bin/test","messageType":"Info","eventMessage":"msg","processID":1}"#;
        // Create 10 lines
        let input = std::iter::repeat(line)
            .take(10)
            .collect::<Vec<_>>()
            .join("\n");

        let (entries, total, capped) = parse_ndjson_log_entries(&input, 3);
        assert_eq!(entries.len(), 3);
        assert_eq!(total, 10);
        assert!(capped);
    }

    #[test]
    fn test_parse_ndjson_log_entries_empty() {
        let (entries, total, capped) = parse_ndjson_log_entries("", 5000);
        assert!(entries.is_empty());
        assert_eq!(total, 0);
        assert!(!capped);
    }

    #[test]
    fn test_parse_ndjson_log_entries_invalid_json_lines_skipped() {
        let input = "not json\n{\"timestamp\":\"2024-01-01\",\"processImagePath\":\"/bin/test\",\"messageType\":\"Info\",\"eventMessage\":\"ok\"}\nalso not json\n";
        let (entries, total, _) = parse_ndjson_log_entries(input, 5000);
        assert_eq!(entries.len(), 1);
        assert_eq!(total, 1);
    }

    #[test]
    fn test_parse_ndjson_extracts_process_name_from_path() {
        let input = r#"{"timestamp":"2024-01-01","processImagePath":"/usr/libexec/mdmclient","messageType":"Info","eventMessage":"test"}"#;
        let (entries, _, _) = parse_ndjson_log_entries(input, 5000);
        assert_eq!(entries[0].process, "mdmclient");
    }
}
