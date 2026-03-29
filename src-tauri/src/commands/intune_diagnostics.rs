use std::collections::{HashMap, HashSet};

use crate::error_db::lookup::lookup_error_code;
use crate::intune::models::{
    DownloadStat, EventLogAnalysis, IntuneDiagnosticCategory, IntuneDiagnosticInsight,
    IntuneDiagnosticSeverity, IntuneDiagnosticsConfidence, IntuneDiagnosticsConfidenceLevel,
    IntuneDiagnosticsCoverage, IntuneDiagnosticsFileCoverage, IntuneEvent, IntuneEventType,
    IntuneRemediationPriority, IntuneRepeatedFailureGroup, IntuneStatus, IntuneSummary,
    IntuneTimestampBounds,
};
use crate::intune::timeline;

use super::intune::{TimestampCandidate, update_timestamp_candidate};

#[derive(Debug, Clone)]
struct FailureReason {
    key: String,
    display: String,
}

#[derive(Debug, Clone)]
struct RepeatedFailureAccumulator {
    name: String,
    event_type: IntuneEventType,
    error_code: Option<String>,
    occurrences: u32,
    source_files: HashSet<String>,
    sample_event_ids: Vec<u64>,
    earliest: Option<TimestampCandidate>,
    latest: Option<TimestampCandidate>,
    reason_display: String,
}

pub(crate) fn build_repeated_failures(events: &[IntuneEvent]) -> Vec<IntuneRepeatedFailureGroup> {
    let mut groups: HashMap<String, RepeatedFailureAccumulator> = HashMap::new();

    for event in events
        .iter()
        .filter(|event| matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout))
    {
        let reason = normalize_failure_reason(event);
        let subject_key = event
            .guid
            .clone()
            .unwrap_or_else(|| normalize_group_label(&event.name));
        let key = format!("{:?}|{}|{}", event.event_type, subject_key, reason.key);

        let entry = groups
            .entry(key)
            .or_insert_with(|| RepeatedFailureAccumulator {
                name: event.name.clone(),
                event_type: event.event_type,
                error_code: event.error_code.clone(),
                occurrences: 0,
                source_files: HashSet::new(),
                sample_event_ids: Vec::new(),
                earliest: None,
                latest: None,
                reason_display: reason.display.clone(),
            });

        entry.occurrences += 1;
        entry.source_files.insert(event.source_file.clone());
        if entry.sample_event_ids.len() < 5 {
            entry.sample_event_ids.push(event.id);
        }
        if event.name.len() < entry.name.len() {
            entry.name = event.name.clone();
        }
        if entry.error_code.is_none() {
            entry.error_code = event.error_code.clone();
        }
        if let Some(timestamp) = event.start_time.as_deref().or(event.end_time.as_deref()) {
            update_timestamp_candidate(&mut entry.earliest, &mut entry.latest, timestamp);
        }
    }

    let mut repeated: Vec<IntuneRepeatedFailureGroup> = groups
        .into_iter()
        .filter_map(|(key, group)| {
            if group.occurrences < 2 {
                return None;
            }

            let mut source_files: Vec<String> = group.source_files.into_iter().collect();
            source_files.sort();

            let timestamp_bounds = match (group.earliest, group.latest) {
                (Some(first), Some(last)) => Some(IntuneTimestampBounds {
                    first_timestamp: Some(first.raw),
                    last_timestamp: Some(last.raw),
                }),
                _ => None,
            };

            Some(IntuneRepeatedFailureGroup {
                id: format!("repeated-{}", sanitize_identifier(&key)),
                name: format!("{}: {}", group.name, group.reason_display),
                event_type: group.event_type,
                error_code: group.error_code,
                occurrences: group.occurrences,
                timestamp_bounds,
                source_files,
                sample_event_ids: group.sample_event_ids,
            })
        })
        .collect();

    repeated.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    repeated
}

fn normalize_failure_reason(event: &IntuneEvent) -> FailureReason {
    if let Some(error_code) = &event.error_code {
        let lookup = lookup_error_code(error_code);
        let display = if lookup.found {
            format!("{} ({})", lookup.code_hex, lookup.description)
        } else {
            error_code.clone()
        };

        return FailureReason {
            key: format!("code:{}", sanitize_identifier(error_code)),
            display,
        };
    }

    let detail = event.detail.to_ascii_lowercase();
    let patterns = [
        ("access is denied", "access is denied"),
        ("permission denied", "permission denied"),
        ("unauthorized", "unauthorized"),
        ("not applicable", "not applicable"),
        ("will not be enforced", "will not be enforced"),
        ("requirement rule", "requirement rule blocked enforcement"),
        ("detection rule", "detection rule blocked enforcement"),
        ("hash validation failed", "hash validation failed"),
        ("hash mismatch", "hash mismatch"),
        ("cannot find path", "path not found"),
        ("path not found", "path not found"),
        ("file not found", "file not found"),
        ("execution policy", "execution policy blocked execution"),
        ("digitally signed", "script signing blocked execution"),
        (
            "running scripts is disabled",
            "script execution is disabled",
        ),
        ("timed out", "timed out"),
        ("timeout", "timed out"),
        ("stalled", "stalled"),
        ("retry exhausted", "retry exhausted"),
        ("installer execution failed", "installer execution failed"),
        ("failed to download", "download failed"),
    ];

    for (needle, label) in patterns {
        if detail.contains(needle) {
            return FailureReason {
                key: sanitize_identifier(label),
                display: label.to_string(),
            };
        }
    }

    let normalized = normalize_detail_snippet(&detail);
    FailureReason {
        key: sanitize_identifier(&normalized),
        display: normalized,
    }
}

fn normalize_detail_snippet(value: &str) -> String {
    let mut words = Vec::new();

    for token in value.split_whitespace() {
        let cleaned: String = token
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();

        if cleaned.is_empty() || cleaned.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        words.push(cleaned);
        if words.len() >= 8 {
            break;
        }
    }

    if words.is_empty() {
        "unspecified failure".to_string()
    } else {
        words.join(" ")
    }
}

pub(crate) fn sanitize_identifier(value: &str) -> String {
    let mut result = String::new();
    let mut last_was_dash = false;

    for ch in value.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };

        if mapped == '-' {
            if !last_was_dash {
                result.push(mapped);
            }
            last_was_dash = true;
        } else {
            result.push(mapped);
            last_was_dash = false;
        }
    }

    result.trim_matches('-').to_string()
}

pub(crate) fn build_diagnostics_confidence(
    summary: &IntuneSummary,
    coverage: &IntuneDiagnosticsCoverage,
    repeated_failures: &[IntuneRepeatedFailureGroup],
    events: &[IntuneEvent],
    event_log_analysis: &Option<EventLogAnalysis>,
) -> IntuneDiagnosticsConfidence {
    if summary.total_events == 0 && summary.total_downloads == 0 {
        return IntuneDiagnosticsConfidence {
            level: IntuneDiagnosticsConfidenceLevel::Unknown,
            score: None,
            reasons: vec!["No Intune events or download evidence were available.".to_string()],
        };
    }

    let mut score: f64 = 0.15;
    let mut reasons = Vec::new();
    let failed_events = events
        .iter()
        .filter(|event| matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout))
        .count();
    let distinct_source_kinds = distinct_source_kinds(&coverage.files);
    let contributing_files = coverage
        .files
        .iter()
        .filter(|file| file.event_count > 0 || file.download_count > 0)
        .count();

    if summary.total_events >= 20 {
        score += 0.25;
        reasons.push(format!(
            "{} events were extracted across the selected logs.",
            summary.total_events
        ));
    } else if summary.total_events >= 8 {
        score += 0.15;
        reasons.push(format!(
            "{} events were extracted across the selected logs.",
            summary.total_events
        ));
    } else if summary.total_events > 0 {
        score += 0.05;
        reasons.push(format!(
            "Only {} event(s) were extracted, so the evidence set is narrow.",
            summary.total_events
        ));
    }

    if failed_events >= 4 {
        score += 0.2;
        reasons.push(format!(
            "{} failed or timed-out event(s) were available for review.",
            failed_events
        ));
    } else if failed_events > 0 {
        score += 0.1;
        reasons.push(format!(
            "{} failed or timed-out event(s) were available for review.",
            failed_events
        ));
    }

    if distinct_source_kinds >= 3 {
        score += 0.2;
        reasons.push(format!(
            "Evidence spans {} distinct Intune log families.",
            distinct_source_kinds
        ));
    } else if distinct_source_kinds == 2 {
        score += 0.1;
        reasons.push("Evidence spans two distinct Intune log families.".to_string());
    }

    if coverage.timestamp_bounds.is_some() {
        score += 0.1;
        reasons.push(
            "Parsed timestamps were available for the overall diagnostics window.".to_string(),
        );
    }

    if !repeated_failures.is_empty() {
        score += 0.15;
        reasons.push(format!(
            "{} repeated failure group(s) were identified deterministically.",
            repeated_failures.len()
        ));
    }

    if coverage.has_rotated_logs {
        score += 0.05;
        reasons.push(
            "Rotated log segments were available, which improves continuity across retries."
                .to_string(),
        );
    }

    if contributing_files <= 1 {
        score -= 0.15;
        reasons.push("Evidence comes from a single contributing source file.".to_string());
    }

    if coverage.files.iter().any(|file| {
        (file.event_count > 0 || file.download_count > 0) && file.timestamp_bounds.is_none()
    }) {
        score -= 0.1;
        reasons.push("Some contributing files had no parseable timestamps, which weakens ordering confidence.".to_string());
    }

    if summary.total_events == 0 && summary.total_downloads > 0 {
        score -= 0.2;
        reasons.push(
            "Only download statistics were available; no correlated Intune events were extracted."
                .to_string(),
        );
    }

    if summary.in_progress + summary.pending > summary.failed + summary.succeeded
        && summary.total_events > 0
    {
        score -= 0.1;
        reasons.push("Most observed work is still pending or in progress, so the failure picture may be incomplete.".to_string());
    }

    if has_app_or_download_failures(events) && !has_source_kind(&coverage.files, "appworkload") {
        score -= 0.15;
        reasons.push(
            "AppWorkload evidence was not available for app or download failures.".to_string(),
        );
    }

    if has_policy_failures(events) && !has_source_kind(&coverage.files, "appactionprocessor") {
        score -= 0.15;
        reasons.push(
            "AppActionProcessor evidence was not available for applicability or policy failures."
                .to_string(),
        );
    }

    if has_script_failures(events)
        && !has_source_kind(&coverage.files, "agentexecutor")
        && !has_source_kind(&coverage.files, "healthscripts")
    {
        score -= 0.15;
        reasons.push("AgentExecutor or HealthScripts evidence was not available for script-related failures.".to_string());
    }

    // Event log evidence boosts
    if let Some(ref ela) = event_log_analysis {
        if ela.error_entry_count + ela.warning_entry_count > 0 {
            score += 0.15;
            reasons.push(format!(
                "Windows Event Log evidence available with {} error/warning entries across {} channel(s).",
                ela.error_entry_count + ela.warning_entry_count,
                ela.channel_summaries.len()
            ));
        }
        if !ela.correlation_links.is_empty() {
            let linked_ime_count = ela
                .correlation_links
                .iter()
                .filter(|l| l.linked_intune_event_id.is_some())
                .count();
            if linked_ime_count > 0 {
                score += 0.10;
                reasons.push(format!(
                    "Event log entries correlated with {} IME event(s).",
                    linked_ime_count
                ));
            }
        }
    }

    score = score.clamp(0.0, 1.0);
    let level = if score >= 0.75 {
        IntuneDiagnosticsConfidenceLevel::High
    } else if score >= 0.45 {
        IntuneDiagnosticsConfidenceLevel::Medium
    } else {
        IntuneDiagnosticsConfidenceLevel::Low
    };

    IntuneDiagnosticsConfidence {
        level,
        score: Some((score * 1000.0).round() / 1000.0),
        reasons,
    }
}

fn distinct_source_kinds(files: &[IntuneDiagnosticsFileCoverage]) -> usize {
    let mut kinds = HashSet::new();

    for file in files {
        if file.event_count == 0 && file.download_count == 0 {
            continue;
        }

        kinds.insert(source_kind_key(&file.file_path));
    }

    kinds.len()
}

fn has_source_kind(files: &[IntuneDiagnosticsFileCoverage], kind: &str) -> bool {
    files.iter().any(|file| {
        (file.event_count > 0 || file.download_count > 0)
            && source_kind_key(&file.file_path) == kind
    })
}

fn source_kind_key(file_path: &str) -> &'static str {
    let normalized = std::path::Path::new(file_path)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| file_path.to_ascii_lowercase());

    if normalized.contains("appworkload") {
        "appworkload"
    } else if normalized.contains("appactionprocessor") {
        "appactionprocessor"
    } else if normalized.contains("agentexecutor") {
        "agentexecutor"
    } else if normalized.contains("healthscripts") {
        "healthscripts"
    } else if normalized.contains("intunemanagementextension") {
        "intunemanagementextension"
    } else {
        "other"
    }
}

fn has_app_or_download_failures(events: &[IntuneEvent]) -> bool {
    events.iter().any(|event| {
        matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
            && matches!(
                event.event_type,
                IntuneEventType::Win32App
                    | IntuneEventType::WinGetApp
                    | IntuneEventType::ContentDownload
            )
    })
}

fn has_policy_failures(events: &[IntuneEvent]) -> bool {
    events.iter().any(|event| {
        event.event_type == IntuneEventType::PolicyEvaluation
            && matches!(
                event.status,
                IntuneStatus::Failed | IntuneStatus::Timeout | IntuneStatus::Pending
            )
    })
}

fn has_script_failures(events: &[IntuneEvent]) -> bool {
    events.iter().any(|event| {
        matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
            && matches!(
                event.event_type,
                IntuneEventType::PowerShellScript | IntuneEventType::Remediation
            )
    })
}

pub(crate) fn build_diagnostics(
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
    summary: &IntuneSummary,
) -> Vec<IntuneDiagnosticInsight> {
    let mut insights = Vec::new();

    let failed_download_events: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            event.event_type == IntuneEventType::ContentDownload
                && matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
        })
        .collect();
    let install_failures: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            matches!(
                event.event_type,
                IntuneEventType::Win32App | IntuneEventType::WinGetApp
            ) && matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
                && contains_any(
                    &event.detail,
                    &[
                        "install",
                        "installer",
                        "execution",
                        "enforcement",
                        "launching install",
                    ],
                )
        })
        .collect();
    let timed_out_events: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| event.status == IntuneStatus::Timeout)
        .collect();
    let script_failures: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            matches!(
                event.event_type,
                IntuneEventType::PowerShellScript | IntuneEventType::Remediation
            ) && matches!(event.status, IntuneStatus::Failed | IntuneStatus::Timeout)
        })
        .collect();
    let policy_events: Vec<&IntuneEvent> = events
        .iter()
        .filter(|event| {
            event.event_type == IntuneEventType::PolicyEvaluation
                && event.status != IntuneStatus::Success
        })
        .collect();

    if summary.failed_downloads > 0 {
        let download_case = classify_download_failure_case(&failed_download_events, downloads);
        let mut evidence = vec![format!(
            "{} download attempt(s) ended in failure, stall, or retry exhaustion.",
            summary.failed_downloads
        )];
        evidence.extend(top_failed_download_labels(downloads, 2));
        evidence.extend(top_event_detail_matches(&failed_download_events, 2));
        if let Some(retries) = repeated_retry_evidence(&failed_download_events) {
            evidence.push(retries);
        }
        if let Some(stall) = stalled_download_evidence(&failed_download_events) {
            evidence.push(stall);
        }
        evidence.extend(repeated_group_evidence(
            &failed_download_events,
            2,
            "Repeated failed download pattern",
        ));

        insights.push(IntuneDiagnosticInsight {
            id: "download-failures".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Download,
            remediation_priority: IntuneRemediationPriority::Immediate,
            title: download_case.title.to_string(),
            summary: download_case.summary.to_string(),
            likely_cause: Some(download_case.likely_cause.to_string()),
            evidence,
            next_checks: vec![
                "Review AppWorkload download, staging, and hash-validation lines for the affected content IDs.".to_string(),
                "Check whether the last download state is progressing, stalling, or immediately retrying for the same content.".to_string(),
                "Verify Delivery Optimization, proxy, VPN, or content-source reachability on the device.".to_string(),
            ],
            suggested_fixes: download_case
                .suggested_fixes
                .into_iter()
                .map(|item| item.to_string())
                .collect(),
            focus_areas: vec![
                "AppWorkload download and staging transitions".to_string(),
                "Delivery Optimization, proxy, and content reachability".to_string(),
                "IME cache health and package revision consistency".to_string(),
            ],
            affected_source_files: related_source_files(&failed_download_events, 4),
            related_error_codes: related_error_codes(&failed_download_events, 3),
        });
    }

    if !install_failures.is_empty() {
        let install_hint = best_error_hint(&install_failures);
        let mut evidence = vec![format!(
            "{} app install or enforcement event(s) failed after download or staging work began.",
            install_failures.len()
        )];
        evidence.extend(top_event_labels(&install_failures, 3));
        evidence.extend(top_event_detail_matches(&install_failures, 2));
        if let Some(error_hint) = &install_hint {
            evidence.push(format!(
                "Most specific error observed: {} ({})",
                error_hint.code, error_hint.description
            ));
        }

        insights.push(IntuneDiagnosticInsight {
            id: "install-enforcement-failures".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Install,
            remediation_priority: IntuneRemediationPriority::High,
            title: "App install or enforcement failures detected".to_string(),
            summary: "The workload progressed past content acquisition but failed during installer launch, enforcement, or completion tracking.".to_string(),
            likely_cause: Some(
                install_hint
                    .as_ref()
                    .map(|hint| format!("Installer enforcement is failing with {} ({}).", hint.code, hint.description))
                    .unwrap_or_else(|| "Installer launch, execution, or detection handoff is failing after content acquisition completed.".to_string()),
            ),
            evidence,
            next_checks: vec![
                "Inspect AppWorkload install and enforcement rows near the failure for the last successful phase before the installer returned control.".to_string(),
                "Compare the installer command, return-code mapping, and detection rule behavior for the affected app.".to_string(),
                "Correlate the failure with AgentExecutor or remediation activity if the deployment depends on prerequisite scripts.".to_string(),
            ],
            suggested_fixes: install_failure_suggested_fixes(install_hint),
            focus_areas: vec![
                "Installer command line and return-code mapping".to_string(),
                "Detection-rule accuracy after install".to_string(),
                "Prerequisite scripts and execution context".to_string(),
            ],
            affected_source_files: related_source_files(&install_failures, 4),
            related_error_codes: related_error_codes(&install_failures, 3),
        });
    }

    if !timed_out_events.is_empty() {
        let timeout_loops = repeated_failure_groups(&timed_out_events, 2);
        let mut evidence = vec![format!(
            "{} event(s) timed out before reporting a clean success or failure.",
            timed_out_events.len()
        )];
        evidence.extend(top_event_labels(&timed_out_events, 2));
        evidence.extend(repeated_group_evidence(
            &timed_out_events,
            2,
            "Timeout loop",
        ));

        let (title, summary) = if timeout_loops.is_empty() {
            (
                "Timed-out operations detected",
                "One or more app or script operations stalled long enough to be treated as failures.",
            )
        } else {
            (
                "Repeated timeout loop detected",
                "The same app or script path is timing out across multiple attempts, which suggests the retry cycle is repeating without a state change.",
            )
        };

        let mut suggested_fixes = vec![
            "Shorten or optimize long-running installers or scripts that routinely exceed the IME execution window.".to_string(),
            "Remove dependencies on user interaction, mapped drives, or transient network resources during enforcement.".to_string(),
        ];
        if !timeout_loops.is_empty() {
            suggested_fixes.push(
                "Break the retry loop by fixing the underlying block before forcing another sync; repeated retries with the same timeout rarely self-heal.".to_string(),
            );
        } else {
            suggested_fixes.push(
                "If the timeout is expected during first install, validate whether the assignment deadline or retry cadence needs adjustment.".to_string(),
            );
        }

        insights.push(IntuneDiagnosticInsight {
            id: "operation-timeouts".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Timeout,
            remediation_priority: if timeout_loops.is_empty() {
                IntuneRemediationPriority::High
            } else {
                IntuneRemediationPriority::Immediate
            },
            title: title.to_string(),
            summary: summary.to_string(),
            likely_cause: Some(if timeout_loops.is_empty() {
                "The operation is running long enough to hit IME timeout thresholds without a definitive completion signal.".to_string()
            } else {
                "The same timeout path is repeating across retries, which means the blocking condition is persisting between attempts.".to_string()
            }),
            evidence,
            next_checks: vec![
                "Inspect the matching event rows around the timeout for the last successful phase before the stall.".to_string(),
                "Check whether install commands, detection scripts, or remediation scripts are waiting on external resources or device state.".to_string(),
                "Look for repeated retries or follow-on failure codes in AppWorkload, AgentExecutor, or HealthScripts logs.".to_string(),
            ],
            suggested_fixes,
            focus_areas: vec![
                "Last successful phase before the stall".to_string(),
                "Installer or script wait conditions".to_string(),
                "External dependencies that never become ready".to_string(),
            ],
            affected_source_files: related_source_files(&timed_out_events, 4),
            related_error_codes: related_error_codes(&timed_out_events, 3),
        });
    }

    if !script_failures.is_empty() {
        let script_hint = best_error_hint(&script_failures);
        let script_case = classify_script_failure_case(&script_failures);
        let mut evidence = vec![format!(
            "{} script or remediation event(s) failed or timed out.",
            script_failures.len()
        )];
        evidence.extend(top_event_labels(&script_failures, 3));
        evidence.extend(top_event_detail_matches(&script_failures, 2));
        evidence.extend(repeated_group_evidence(
            &script_failures,
            2,
            "Recurring script failure",
        ));
        evidence.extend(script_scope_evidence(&script_failures));
        if let Some(error_hint) = &script_hint {
            evidence.push(format!(
                "Most specific script error observed: {} ({})",
                error_hint.code, error_hint.description
            ));
        }

        insights.push(IntuneDiagnosticInsight {
            id: "script-failures".to_string(),
            severity: IntuneDiagnosticSeverity::Error,
            category: IntuneDiagnosticCategory::Script,
            remediation_priority: IntuneRemediationPriority::High,
            title: script_case.title.to_string(),
            summary: script_case.summary.to_string(),
            likely_cause: Some(script_case.likely_cause.to_string()),
            evidence,
            next_checks: vec![
                "Review AgentExecutor and HealthScripts entries for stdout, stderr, and explicit exit-code lines around the affected script.".to_string(),
                "Separate detection-script failures from remediation-script failures before deciding whether the issue is logic, environment, or permissions.".to_string(),
                "Validate script prerequisites such as execution context, file paths, network access, and required modules or commands.".to_string(),
            ],
            suggested_fixes: script_failure_suggested_fixes(&script_failures, script_hint),
            focus_areas: vec![
                "AgentExecutor and HealthScripts output around failure".to_string(),
                "Execution context, paths, and dependency availability".to_string(),
                "Detection vs remediation script separation".to_string(),
            ],
            affected_source_files: related_source_files(&script_failures, 4),
            related_error_codes: related_error_codes(&script_failures, 3),
        });
    }

    if !policy_events.is_empty() {
        let policy_case = classify_policy_failure_case(&policy_events);
        let mut evidence = vec![format!(
            "{} policy or applicability event(s) did not end in success.",
            policy_events.len()
        )];
        evidence.extend(top_event_labels(&policy_events, 2));
        evidence.extend(top_event_detail_matches(&policy_events, 2));
        evidence.extend(repeated_group_evidence(
            &policy_events,
            2,
            "Repeated policy block",
        ));
        if let Some(reason) = applicability_reason_evidence(&policy_events) {
            evidence.push(reason);
        }

        insights.push(IntuneDiagnosticInsight {
            id: "policy-applicability".to_string(),
            severity: IntuneDiagnosticSeverity::Warning,
            category: IntuneDiagnosticCategory::Policy,
            remediation_priority: IntuneRemediationPriority::Medium,
            title: policy_case.title.to_string(),
            summary: policy_case.summary.to_string(),
            likely_cause: Some(policy_case.likely_cause.to_string()),
            evidence,
            next_checks: vec![
                "Review AppActionProcessor requirement-rule, detection-rule, and applicability lines for the affected app GUIDs.".to_string(),
                "Confirm the assignment intent, targeting, and any deadline or GRS behavior for the device or user.".to_string(),
                "Correlate policy-evaluation events with the later AppWorkload or AgentExecutor phases to see where enforcement stopped.".to_string(),
            ],
            suggested_fixes: policy_case
                .suggested_fixes
                .into_iter()
                .map(|item| item.to_string())
                .collect(),
            focus_areas: vec![
                "AppActionProcessor applicability and requirement evaluation".to_string(),
                "Assignment targeting and deployment intent".to_string(),
                "Detection-rule and applicability-rule truthfulness".to_string(),
            ],
            affected_source_files: related_source_files(&policy_events, 4),
            related_error_codes: related_error_codes(&policy_events, 3),
        });
    }

    if insights.is_empty() {
        if summary.in_progress > 0 || summary.pending > 0 {
            insights.push(IntuneDiagnosticInsight {
                id: "work-in-progress".to_string(),
                severity: IntuneDiagnosticSeverity::Info,
                category: IntuneDiagnosticCategory::State,
                remediation_priority: IntuneRemediationPriority::Monitor,
                title: "Workload still in progress".to_string(),
                summary: "The current IME snapshot shows pending or in-progress work without a dominant failure pattern yet.".to_string(),
                likely_cause: Some("The device is still moving through the current IME cycle, so a stable failure signature has not formed yet.".to_string()),
                evidence: vec![
                    format!("{} event(s) are still in progress.", summary.in_progress),
                    format!("{} event(s) are still pending.", summary.pending),
                ],
                next_checks: vec![
                    "Re-check the logs after the next IME processing cycle to confirm whether the pending work resolves or fails.".to_string(),
                    "Use the timeline ordering to identify the most recent active app, download, or script phase.".to_string(),
                ],
                suggested_fixes: vec![
                    "Allow the current IME cycle to finish before changing the deployment unless a repeated stall pattern appears.".to_string(),
                ],
                focus_areas: vec![
                    "Most recent active timeline items".to_string(),
                    "Whether progress converts into success or a stable failure".to_string(),
                ],
                affected_source_files: Vec::new(),
                related_error_codes: Vec::new(),
            });
        } else if summary.total_events > 0 {
            insights.push(IntuneDiagnosticInsight {
                id: "no-dominant-blocker".to_string(),
                severity: IntuneDiagnosticSeverity::Info,
                category: IntuneDiagnosticCategory::General,
                remediation_priority: IntuneRemediationPriority::Monitor,
                title: "No dominant blocker detected".to_string(),
                summary: "The analyzed IME logs do not show a strong failure cluster in downloads, scripts, policy evaluation, or timeouts.".to_string(),
                likely_cause: Some("The current evidence set is not clustered around a single dominant failure path, so more correlation is needed before changing packaging or targeting.".to_string()),
                evidence: vec![
                    format!("{} event(s) succeeded.", summary.succeeded),
                    format!("{} total event(s) were analyzed.", summary.total_events),
                ],
                next_checks: vec![
                    "Inspect the timeline for the last non-success event if the user still reports a problem.".to_string(),
                    "Correlate IME activity with device state, portal assignment status, or Windows Event Logs if symptoms continue.".to_string(),
                ],
                suggested_fixes: vec![
                    "Do not change packaging or targeting yet; gather one failing sample with adjacent logs before tuning heuristics further.".to_string(),
                ],
                focus_areas: vec![
                    "Last non-success timeline event".to_string(),
                    "Correlation with portal assignment state and device conditions".to_string(),
                ],
                affected_source_files: Vec::new(),
                related_error_codes: Vec::new(),
            });
        }
    }

    insights
}

fn related_source_files(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut files = Vec::new();

    for event in events {
        if files.contains(&event.source_file) {
            continue;
        }

        files.push(event.source_file.clone());
        if files.len() >= limit {
            break;
        }
    }

    files
}

fn related_error_codes(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut labels = Vec::new();

    for event in events {
        let Some(error_code) = &event.error_code else {
            continue;
        };

        let lookup = lookup_error_code(error_code);
        let label = if lookup.found {
            format!("{} ({})", lookup.code_hex, lookup.description)
        } else {
            format!("{} ({})", error_code, lookup.description)
        };

        if labels.contains(&label) {
            continue;
        }

        labels.push(label);
        if labels.len() >= limit {
            break;
        }
    }

    labels
}

fn top_failed_download_labels(downloads: &[DownloadStat], limit: usize) -> Vec<String> {
    let mut label_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for download in downloads.iter().filter(|download| !download.success) {
        let label = if download.name.trim().is_empty() {
            format!("Affected content ID: {}", download.content_id)
        } else {
            format!("Affected content: {}", download.name)
        };

        *label_counts.entry(label).or_insert(0) += 1;
    }

    let mut sorted_counts: Vec<(String, usize)> = label_counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| b.1.cmp(&a.1));

    sorted_counts
        .into_iter()
        .take(limit)
        .map(|(label, count)| {
            if count > 1 {
                format!("{} ({} times)", label, count)
            } else {
                label
            }
        })
        .collect()
}

#[derive(Clone)]
struct ErrorHint {
    code: String,
    description: String,
}

struct DownloadFailureCase {
    title: &'static str,
    summary: &'static str,
    likely_cause: &'static str,
    suggested_fixes: Vec<&'static str>,
}

fn classify_download_failure_case(
    events: &[&IntuneEvent],
    downloads: &[DownloadStat],
) -> DownloadFailureCase {
    if events.iter().any(|event| {
        event.status == IntuneStatus::Timeout
            || contains_any(
                &event.detail,
                &[
                    "stalled",
                    "not progressing",
                    "no progress",
                    "timed out",
                    "timeout",
                ],
            )
    }) {
        return DownloadFailureCase {
            title: "Content download stalled or timed out",
            summary: "The device started content acquisition, but AppWorkload shows the same payload stopping without forward progress before install-ready staging completed.",
            likely_cause: "Content transfer is starting but losing forward progress before staging completes.",
            suggested_fixes: vec![
                "Check for content-transfer stalls, Delivery Optimization blockage, or proxy/VPN interference before forcing another retry.",
                "If the same content repeatedly stalls, clear stale IME cache state on the test device and retry with fresh logs.",
                "Confirm the content source is reachable and the payload revision is still available in Intune.",
            ],
        };
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["hash validation", "hash mismatch", "hash"]))
    {
        return DownloadFailureCase {
            title: "Content hash or staging validation failed",
            summary: "The device downloaded content, but staging or hash verification indicates the package may be incomplete, stale, or mismatched.",
            likely_cause: "The downloaded payload does not match the content revision expected during staging or validation.",
            suggested_fixes: vec![
                "Re-upload or redistribute the app content in Intune so the device receives a clean package revision.",
                "Verify that the package contents and detection logic still match the deployed app version.",
                "Clear any stale cached content on the test device before retrying if hash mismatches keep repeating.",
            ],
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["staging", "content cached", "cache location"],
        )
    }) {
        return DownloadFailureCase {
            title: "Content staging failed after download",
            summary: "The workload reached caching or staging, but the local handoff into install-ready content did not complete successfully.",
            likely_cause: "The package transfer finished, but local cache handoff or disk-backed staging is failing.",
            suggested_fixes: vec![
                "Validate local disk space and permissions on the IME content cache path.",
                "Retry with a fresh content download if cached payloads appear stale or partially written.",
                "Check antivirus or endpoint protection exclusions if staging repeatedly stops after the download completes.",
            ],
        };
    }

    if repeated_retry_evidence(events).is_some() {
        return DownloadFailureCase {
            title: "Content download is retrying without completing",
            summary: "The same content is cycling through retry attempts, which points to a persistent transfer or staging blocker instead of a one-off transient miss.",
            likely_cause: "The retry loop is masking a persistent download or cache blocker that is not changing between attempts.",
            suggested_fixes: vec![
                "Review the first failed download attempt for the real cause instead of focusing only on the later retry lines.",
                "Validate network path, Delivery Optimization policy, and local cache health before forcing additional sync cycles.",
                "If retries begin after partial transfer, re-stage the content with a fresh package revision or cache reset on the test device.",
            ],
        };
    }

    if downloads
        .iter()
        .any(|download| !download.success && download.do_percentage == 0.0)
    {
        return DownloadFailureCase {
            title: "Content retrieval failed before local staging",
            summary: "The workload is failing during content acquisition rather than install, and the logs do not show healthy Delivery Optimization contribution.",
            likely_cause: "The device is failing before content ever reaches a healthy local cache or staging state.",
            suggested_fixes: vec![
                "Validate proxy, VPN, firewall, and Delivery Optimization reachability for the content source.",
                "Test the same deployment on a network path without restrictive content filtering.",
                "Confirm the app content is still available and correctly assigned in Intune.",
            ],
        };
    }

    DownloadFailureCase {
        title: "Content download failures detected",
        summary: "App content did not download cleanly, so enforcement may never reach install or detection stages.",
        likely_cause: "Content acquisition is failing early enough that install and detection phases cannot start reliably.",
        suggested_fixes: vec![
            "Confirm the app payload is still available and matches the expected content in Intune.",
            "Check device network reachability to Microsoft content endpoints and any proxy path in between.",
            "Retry with fresh logs after the next IME cycle to confirm whether this is a transient retrieval failure or a repeatable pattern.",
        ],
    }
}

fn best_error_hint(events: &[&IntuneEvent]) -> Option<ErrorHint> {
    for event in events {
        let Some(error_code) = &event.error_code else {
            continue;
        };

        let lookup = lookup_error_code(error_code);
        if lookup.found {
            return Some(ErrorHint {
                code: lookup.code_hex,
                description: lookup.description,
            });
        }

        return Some(ErrorHint {
            code: error_code.clone(),
            description: lookup.description,
        });
    }

    None
}

struct ScriptFailureCase {
    title: &'static str,
    summary: &'static str,
    likely_cause: &'static str,
}

fn classify_script_failure_case(events: &[&IntuneEvent]) -> ScriptFailureCase {
    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "execution policy",
                "digitally signed",
                "running scripts is disabled",
            ],
        )
    }) {
        return ScriptFailureCase {
            title: "Script execution policy or signing blocked execution",
            summary: "The script did not fail inside its own logic; PowerShell policy or signing requirements blocked it before it could run normally.",
            likely_cause: "PowerShell policy or signature requirements are preventing script startup.",
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["access is denied", "unauthorized", "permission denied"],
        )
    }) {
        return ScriptFailureCase {
            title: "Script execution failed due to permissions or access",
            summary: "The script path is being reached, but the execution context does not have access to one or more required resources.",
            likely_cause: "The IME execution context cannot reach or modify one of the resources the script expects.",
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "cannot find path",
                "path not found",
                "file not found",
                "module",
                "not recognized",
            ],
        )
    }) {
        return ScriptFailureCase {
            title: "Script dependency or path resolution failed",
            summary: "The script is calling a path, command, or module that is not available in the IME execution context on the device.",
            likely_cause: "One or more script dependencies are missing or resolved differently under IME.",
        };
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["parsererror", "syntax error", "exception"]))
    {
        return ScriptFailureCase {
            title: "Script syntax or runtime errors detected",
            summary: "The script started but then failed because of a parser, command, or runtime error rather than a packaging or download issue.",
            likely_cause: "The script is running but failing inside its own logic or command flow.",
        };
    }

    if repeated_failure_groups(events, 2).is_empty() {
        ScriptFailureCase {
            title: "Script execution failures detected",
            summary: "Detection or remediation logic returned a non-zero outcome or never completed, which can block compliance or app enforcement.",
            likely_cause: "Detection or remediation logic is failing consistently enough to block downstream enforcement decisions.",
        }
    } else {
        ScriptFailureCase {
            title: "Recurring script or remediation failures detected",
            summary: "The same detection or remediation path is failing across multiple attempts, which points to a persistent script issue instead of a one-time transient failure.",
            likely_cause: "The same script path is re-entering failure with no device-state change between attempts.",
        }
    }
}

struct PolicyFailureCase {
    title: &'static str,
    summary: &'static str,
    likely_cause: &'static str,
    suggested_fixes: Vec<&'static str>,
}

fn classify_policy_failure_case(events: &[&IntuneEvent]) -> PolicyFailureCase {
    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["not applicable", "will not be enforced"]))
    {
        return PolicyFailureCase {
            title: "Applicability blocked enforcement",
            summary: "AppActionProcessor shows the deployment was evaluated, but the app was rejected as not applicable before enforcement could continue.",
            likely_cause: "Applicability logic is determining the target is not eligible, so enforcement never starts.",
            suggested_fixes: vec![
                "Review assignment targeting and applicability conditions to confirm the device should actually qualify.",
                "If the device should be included, correct the applicability logic instead of forcing repeated retries.",
                "If the device should not be targeted, adjust the assignment scope so the block is intentional and reviewable.",
            ],
        };
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["requirement rule", "requirements"]))
    {
        return PolicyFailureCase {
            title: "Requirement rules blocked enforcement",
            summary: "The assignment reached policy evaluation, but a requirement-rule decision prevented the app from entering the enforcement path.",
            likely_cause: "Requirement-rule evaluation is filtering the device out before the install workflow begins.",
            suggested_fixes: vec![
                "Validate every requirement-rule input on the affected device, especially OS version, architecture, and custom script results.",
                "Re-test the rule with the same device context that IME uses instead of assuming portal targeting is enough.",
                "Simplify overly broad requirement logic if it is masking the real intended eligibility check.",
            ],
        };
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["detection rule", "detected", "already installed"],
        )
    }) {
        return PolicyFailureCase {
            title: "Detection-state evidence blocked enforcement",
            summary: "AppActionProcessor indicates the deployment was evaluated, but detection-state logic made IME treat the app as already present or otherwise not needing enforcement.",
            likely_cause: "Detection-state evidence is convincing IME that enforcement is unnecessary or already satisfied.",
            suggested_fixes: vec![
                "Verify that the detection rule is not falsely reporting success on the affected device.",
                "Compare detection-rule logic with the actual install footprint created by the package.",
                "If the app is truly installed, adjust the deployment intent instead of forcing another enforcement attempt.",
            ],
        };
    }

    PolicyFailureCase {
        title: "Policy applicability needs review",
        summary: "Assignment or applicability evaluation may be preventing enforcement even when content and scripts are available.",
        likely_cause: "The device is reaching policy evaluation, but assignment or applicability state is not lining up with the expected outcome.",
        suggested_fixes: vec![
            "Review assignment targeting, intent, and any deadlines or retry windows for the affected policy.",
            "Validate that prerequisite policies or dependent apps are not blocking the enforcement path.",
        ],
    }
}

fn install_failure_suggested_fixes(error_hint: Option<ErrorHint>) -> Vec<String> {
    let mut fixes = vec![
        "Validate the install command line, return-code mapping, and required install context for the affected app.".to_string(),
        "Check whether the detection rule is declaring failure because the installer succeeded but the post-install signal is wrong.".to_string(),
        "Review prerequisite scripts or dependencies if the installer only fails when launched by IME.".to_string(),
    ];

    if let Some(hint) = error_hint {
        let description = hint.description.to_ascii_lowercase();
        if description.contains("access is denied") {
            fixes.insert(
                0,
                "Run the installer in the same system or user context expected by Intune and fix any file, registry, or service permission gaps.".to_string(),
            );
        } else if description.contains("file not found") || description.contains("path not found") {
            fixes.insert(
                0,
                "Verify that the installer command references files that actually exist after IME staging and extraction.".to_string(),
            );
        }
    }

    fixes
}

fn script_failure_suggested_fixes(
    events: &[&IntuneEvent],
    error_hint: Option<ErrorHint>,
) -> Vec<String> {
    let detection_failures = events
        .iter()
        .any(|event| contains_any(&event.name, &["detection script", "detection"]));
    let remediation_failures = events
        .iter()
        .any(|event| contains_any(&event.name, &["remediation script", "remediation"]));

    let mut fixes = Vec::new();
    if detection_failures {
        fixes.push(
            "Correct detection-script logic first; a false negative there can block install success even when the app is already present.".to_string(),
        );
    }
    if remediation_failures {
        fixes.push(
            "If remediation failed, validate every command path and dependency under the same execution context IME uses on the device.".to_string(),
        );
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "execution policy",
                "digitally signed",
                "running scripts is disabled",
            ],
        )
    }) {
        fixes.push(
            "Adjust script signing or execution-policy handling so the script can run in the target IME context without bypass-only workarounds.".to_string(),
        );
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &[
                "cannot find path",
                "path not found",
                "file not found",
                "module",
                "not recognized",
            ],
        )
    }) {
        fixes.push(
            "Package all required script dependencies locally and validate every referenced command, module, and path under the exact IME context.".to_string(),
        );
    }

    if events
        .iter()
        .any(|event| event.status == IntuneStatus::Timeout)
        || !repeated_failure_groups(events, 2).is_empty()
    {
        fixes.push(
            "Stop repeated retry cycles until the blocking condition is fixed; recurring timeouts usually indicate the same script path is hanging on every attempt.".to_string(),
        );
    }

    if let Some(hint) = error_hint {
        let description = hint.description.to_ascii_lowercase();
        if description.contains("access is denied") {
            fixes.push(
                "Grant the script access to the filesystem, registry, certificate store, or service endpoints it needs, or move the action to a supported elevation context.".to_string(),
            );
        } else if description.contains("file not found") || description.contains("path not found") {
            fixes.push(
                "Package or create any required script dependencies locally before the script runs, and avoid relying on missing relative paths.".to_string(),
            );
        }
    }

    fixes.push(
        "Capture stdout and stderr from the failing script path and test the same logic outside IME to isolate environment assumptions.".to_string(),
    );
    fixes
}

fn top_event_detail_matches(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut evidence_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let name_re = regex::Regex::new(r#"(?i)\"(?:ApplicationName|Name)\"\s*:\s*\"([^\",\}]+)"#).ok();

    for event in events {
        let snippet = event.detail.trim();
        if snippet.is_empty() {
            continue;
        }

        let extracted_name = name_re
            .as_ref()
            .and_then(|re| re.captures(snippet).map(|caps| caps[1].trim().to_string()));

        let evidence = if let Some(name) = extracted_name {
            if event.event_type == IntuneEventType::PowerShellScript
                || event.event_type == IntuneEventType::Remediation
            {
                format!("Failing script: {}", name)
            } else if event.event_type == IntuneEventType::PolicyEvaluation {
                format!("Affected policy: {}", name)
            } else {
                format!("Failing app: {}", name)
            }
        } else {
            format!("Observed detail: {}", snippet)
        };

        *evidence_counts.entry(evidence).or_insert(0) += 1;
    }

    let mut sorted_counts: Vec<(String, usize)> = evidence_counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| b.1.cmp(&a.1));

    sorted_counts
        .into_iter()
        .take(limit)
        .map(|(evidence, count)| {
            if count > 1 {
                format!("{} ({} times)", evidence, count)
            } else {
                evidence
            }
        })
        .collect()
}

fn repeated_retry_evidence(events: &[&IntuneEvent]) -> Option<String> {
    let retry_count = events
        .iter()
        .filter(|event| {
            contains_any(
                &event.detail,
                &["retry", "retrying", "reattempt", "will retry"],
            )
        })
        .count();

    if retry_count > 0 {
        Some(format!(
            "Retry behavior was observed in {} failed download event(s).",
            retry_count
        ))
    } else {
        None
    }
}

fn stalled_download_evidence(events: &[&IntuneEvent]) -> Option<String> {
    let stall_count = events
        .iter()
        .filter(|event| {
            event.status == IntuneStatus::Timeout
                || contains_any(
                    &event.detail,
                    &[
                        "stalled",
                        "not progressing",
                        "no progress",
                        "timed out",
                        "timeout",
                    ],
                )
        })
        .count();

    if stall_count > 0 {
        Some(format!(
            "Stall or timeout evidence was observed in {} failed download event(s).",
            stall_count
        ))
    } else {
        None
    }
}

fn applicability_reason_evidence(events: &[&IntuneEvent]) -> Option<String> {
    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["not applicable", "will not be enforced"]))
    {
        return Some(
            "AppActionProcessor explicitly reported the app as not applicable or not enforceable for the evaluated target.".to_string(),
        );
    }

    if events
        .iter()
        .any(|event| contains_any(&event.detail, &["requirement rule", "requirements"]))
    {
        return Some(
            "Requirement-rule evidence appears in the policy-evaluation flow for the affected app."
                .to_string(),
        );
    }

    if events.iter().any(|event| {
        contains_any(
            &event.detail,
            &["detection rule", "already installed", "detected"],
        )
    }) {
        return Some(
            "Detection-rule evidence appears to be short-circuiting enforcement for the affected app.".to_string(),
        );
    }

    None
}

fn script_scope_evidence(events: &[&IntuneEvent]) -> Vec<String> {
    let detection_count = events
        .iter()
        .filter(|event| contains_any(&event.name, &["detection script", "detection"]))
        .count();
    let remediation_count = events
        .iter()
        .filter(|event| contains_any(&event.name, &["remediation script", "remediation"]))
        .count();
    let mut evidence = Vec::new();

    if detection_count > 0 {
        evidence.push(format!(
            "Detection-script failures observed: {} event(s).",
            detection_count
        ));
    }
    if remediation_count > 0 {
        evidence.push(format!(
            "Remediation-script failures observed: {} event(s).",
            remediation_count
        ));
    }

    evidence
}

fn repeated_group_evidence(
    events: &[&IntuneEvent],
    minimum_occurrences: usize,
    prefix: &str,
) -> Vec<String> {
    repeated_failure_groups(events, minimum_occurrences)
        .into_iter()
        .map(|group| {
            format!(
                "{}: {} ({} occurrence(s)).",
                prefix, group.label, group.occurrences
            )
        })
        .collect()
}

#[derive(Debug, Clone)]
struct RepeatedFailureGroup {
    label: String,
    occurrences: usize,
}

fn repeated_failure_groups(
    events: &[&IntuneEvent],
    minimum_occurrences: usize,
) -> Vec<RepeatedFailureGroup> {
    let mut counts: HashMap<String, (String, usize)> = HashMap::new();

    for event in events {
        let source_identity = timeline::normalized_source_identity(&event.source_file);
        let key = if let Some(guid) = &event.guid {
            format!("{}|{:?}|{}", source_identity, event.event_type, guid)
        } else {
            format!(
                "{}|{:?}|{}",
                source_identity,
                event.event_type,
                normalize_group_label(&event.name)
            )
        };

        let entry = counts.entry(key).or_insert_with(|| (event.name.clone(), 0));
        entry.1 += 1;
    }

    let mut groups: Vec<RepeatedFailureGroup> = counts
        .into_values()
        .filter_map(|(label, occurrences)| {
            if occurrences >= minimum_occurrences {
                Some(RepeatedFailureGroup { label, occurrences })
            } else {
                None
            }
        })
        .collect();

    groups.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then_with(|| left.label.cmp(&right.label))
    });
    groups.truncate(2);
    groups
}

pub(crate) fn normalize_group_label(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .take(8)
        .collect::<Vec<_>>()
        .join(" ")
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    let normalized = value.to_ascii_lowercase();
    terms
        .iter()
        .any(|term| normalized.contains(&term.to_ascii_lowercase()))
}

fn top_event_labels(events: &[&IntuneEvent], limit: usize) -> Vec<String> {
    let mut label_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for event in events {
        let mut label = event.name.clone();
        if let Some(error_code) = &event.error_code {
            label.push_str(&format!(" (error {})", error_code));
        }

        let evidence = format!("Affected event: {}", label);
        *label_counts.entry(evidence).or_insert(0) += 1;
    }

    let mut sorted_counts: Vec<(String, usize)> = label_counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| b.1.cmp(&a.1));

    sorted_counts
        .into_iter()
        .take(limit)
        .map(|(label, count)| {
            if count > 1 {
                format!("{} ({} times)", label, count)
            } else {
                label
            }
        })
        .collect()
}
