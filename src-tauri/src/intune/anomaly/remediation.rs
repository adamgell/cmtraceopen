use regex::Regex;

use super::knowledge_base::get_knowledge_base_links;
use super::models::{Anomaly, AnomalyKind, AnomalySeverity, CausalChain};
use crate::error_db::lookup::lookup_error_code;
use crate::intune::models::{
    IntuneDiagnosticCategory, IntuneDiagnosticInsight, IntuneDiagnosticSeverity, IntuneEvent,
    IntuneRemediationPriority,
};

/// Map an `AnomalyKind` to a kebab-case slug for building insight IDs.
fn kind_slug(kind: AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::MissingStep => "missing-step",
        AnomalyKind::OutOfOrderStep => "out-of-order-step",
        AnomalyKind::OrphanedStart => "orphaned-start",
        AnomalyKind::UnexpectedLoop => "unexpected-loop",
        AnomalyKind::DurationOutlier => "duration-outlier",
        AnomalyKind::FrequencySpike => "frequency-spike",
        AnomalyKind::FrequencyGap => "frequency-gap",
        AnomalyKind::DownloadPerformance => "download-performance",
        AnomalyKind::ErrorRateTrend => "error-rate-trend",
        AnomalyKind::SeverityEscalation => "severity-escalation",
        AnomalyKind::CrossSourceCorrelation => "cross-source-correlation",
        AnomalyKind::RootCauseCandidate => "root-cause-candidate",
    }
}

/// Map anomaly severity to diagnostic insight severity.
fn map_severity(s: AnomalySeverity) -> IntuneDiagnosticSeverity {
    match s {
        AnomalySeverity::Critical => IntuneDiagnosticSeverity::Error,
        AnomalySeverity::Warning => IntuneDiagnosticSeverity::Warning,
        AnomalySeverity::Info => IntuneDiagnosticSeverity::Info,
    }
}

/// Derive remediation priority from the anomaly's composite score.
fn map_priority(score: f64) -> IntuneRemediationPriority {
    if score >= 0.7 {
        IntuneRemediationPriority::Immediate
    } else if score >= 0.4 {
        IntuneRemediationPriority::High
    } else if score >= 0.2 {
        IntuneRemediationPriority::Medium
    } else {
        IntuneRemediationPriority::Monitor
    }
}

/// Choose the diagnostic category for a given anomaly kind.
///
/// For `DurationOutlier`, the category is `Download` when the flow context mentions
/// "download"; otherwise it defaults to `Install`.
fn map_category(anomaly: &Anomaly) -> IntuneDiagnosticCategory {
    match anomaly.kind {
        AnomalyKind::MissingStep
        | AnomalyKind::OutOfOrderStep
        | AnomalyKind::OrphanedStart
        | AnomalyKind::UnexpectedLoop => IntuneDiagnosticCategory::State,

        AnomalyKind::DurationOutlier => {
            let mentions_download = anomaly
                .flow_context
                .as_ref()
                .map(|fc| {
                    fc.expected_step.to_lowercase().contains("download")
                        || fc.lifecycle.to_lowercase().contains("download")
                })
                .unwrap_or(false)
                || anomaly.description.to_lowercase().contains("download");
            if mentions_download {
                IntuneDiagnosticCategory::Download
            } else {
                IntuneDiagnosticCategory::Install
            }
        }

        AnomalyKind::DownloadPerformance => IntuneDiagnosticCategory::Download,

        AnomalyKind::FrequencySpike
        | AnomalyKind::FrequencyGap
        | AnomalyKind::ErrorRateTrend
        | AnomalyKind::SeverityEscalation
        | AnomalyKind::CrossSourceCorrelation
        | AnomalyKind::RootCauseCandidate => IntuneDiagnosticCategory::General,
    }
}

/// Scan `text` for hex error codes matching `0x[0-9A-Fa-f]{8}` and enrich
/// each with its description from the built-in error database.
///
/// Returns the enriched text (codes appended with ` (DESCRIPTION)`) and a
/// `Vec` of `"0xCODE \u{2014} DESCRIPTION"` entries for `related_error_codes`.
pub fn enrich_error_codes(text: &str) -> (String, Vec<String>) {
    let re = Regex::new(r"0x[0-9A-Fa-f]{8}").expect("valid regex");
    let mut related = Vec::new();

    let enriched = re
        .replace_all(text, |caps: &regex::Captures| {
            let code = &caps[0];
            let result = lookup_error_code(code);
            if result.found {
                related.push(format!("{} \u{2014} {}", code, result.description));
                format!("{} ({})", code, result.description)
            } else {
                code.to_string()
            }
        })
        .into_owned();

    (enriched, related)
}

/// Build a playbook-based `IntuneDiagnosticInsight` for a single anomaly.
fn build_insight_for_anomaly(
    anomaly: &Anomaly,
    causal_chains: &[CausalChain],
    events: &[IntuneEvent],
) -> IntuneDiagnosticInsight {
    let id_prefix = &anomaly.id[..anomaly.id.len().min(8)];
    let id = format!("anomaly-{}-{}", kind_slug(anomaly.kind), id_prefix);

    let severity = map_severity(anomaly.severity);
    let category = map_category(anomaly);
    let remediation_priority = map_priority(anomaly.score);

    // Gather affected events for error-code enrichment and source files.
    let affected: Vec<&IntuneEvent> = events
        .iter()
        .filter(|e| anomaly.affected_event_ids.contains(&e.id))
        .collect();

    let mut source_files: Vec<String> = affected
        .iter()
        .map(|e| e.source_file.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    source_files.sort();

    // Collect error codes from affected events' detail and error_code fields.
    let mut extra_error_texts = Vec::new();
    for ev in &affected {
        if !ev.detail.is_empty() {
            extra_error_texts.push(ev.detail.as_str());
        }
        if let Some(ec) = &ev.error_code {
            extra_error_texts.push(ec.as_str());
        }
    }

    // Extract flow context fields for playbooks that use them.
    let expected_step = anomaly
        .flow_context
        .as_ref()
        .map(|fc| fc.expected_step.clone())
        .unwrap_or_default();
    let actual_step = anomaly
        .flow_context
        .as_ref()
        .and_then(|fc| fc.actual_step.clone())
        .unwrap_or_default();
    let lifecycle = anomaly
        .flow_context
        .as_ref()
        .map(|fc| fc.lifecycle.clone())
        .unwrap_or_default();
    let subject_guid = anomaly
        .flow_context
        .as_ref()
        .and_then(|fc| fc.subject_guid.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Build playbook fields based on kind.
    let (likely_cause, mut evidence, next_checks, suggested_fixes, focus_areas) = match anomaly.kind
    {
        AnomalyKind::MissingStep => (
            format!(
                "A required lifecycle phase ({}) was skipped for {} deployment {}",
                expected_step, lifecycle, subject_guid
            ),
            vec![
                anomaly.description.clone(),
                format!("Expected step: {}", expected_step),
                format!("Lifecycle: {}", lifecycle),
            ],
            vec![
                "Verify content is available on CDN/distribution point".to_string(),
                "Check if detection rule ran successfully".to_string(),
                "Review AppWorkload logs for the affected content ID".to_string(),
            ],
            vec![
                "Verify app content package is published and accessible".to_string(),
                "Check detection rule accuracy \u{2014} false positives skip install".to_string(),
                "Ensure prerequisite apps are installed first".to_string(),
            ],
            vec![
                "AppWorkload lifecycle transitions".to_string(),
                "Detection and applicability evaluation".to_string(),
            ],
        ),

        AnomalyKind::OutOfOrderStep => (
            format!(
                "Lifecycle step {} executed before expected prerequisite {}",
                actual_step, expected_step
            ),
            vec![
                anomaly.description.clone(),
                format!("Actual step: {}", actual_step),
                format!("Expected prerequisite: {}", expected_step),
            ],
            vec![
                "Verify app dependency ordering in Intune portal".to_string(),
                "Check for race conditions in parallel installations".to_string(),
            ],
            vec![
                "Review app dependency ordering in Intune portal".to_string(),
                "Check for race conditions in parallel app installations".to_string(),
                "Verify supersedence chain is correct".to_string(),
            ],
            vec!["App dependency and supersedence configuration".to_string()],
        ),

        AnomalyKind::OrphanedStart => (
            "An operation started but never completed \u{2014} may indicate IME service restart or crash".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Check IME service status around the event timestamp".to_string(),
                "Review Application event log for crashes".to_string(),
            ],
            vec![
                "Check Windows Event Log for IME service restarts during this period".to_string(),
                "Look for unrecorded timeout or crash in Application event log".to_string(),
                "Verify device wasn't rebooted mid-operation".to_string(),
            ],
            vec!["IME service health and continuity".to_string()],
        ),

        AnomalyKind::UnexpectedLoop => (
            "The same lifecycle phase repeated excessively, suggesting a retry storm or detection rule flapping".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Identify which detection rule is flapping".to_string(),
                "Check GRS schedule for stuck re-evaluation".to_string(),
            ],
            vec![
                "Investigate detection rule flapping \u{2014} ensure detection doesn't oscillate".to_string(),
                "Check if GRS (Global Reassessment Schedule) is stuck".to_string(),
                "Clear IME cache at C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Cache".to_string(),
                "Review app requirement rules for intermittent conditions".to_string(),
            ],
            vec![
                "Detection rule stability".to_string(),
                "GRS and re-evaluation scheduling".to_string(),
            ],
        ),

        AnomalyKind::DurationOutlier => {
            let (observed, mean, z_score) = anomaly
                .statistical_context
                .as_ref()
                .map(|sc| (sc.observed_value, sc.population_mean, sc.z_score))
                .unwrap_or((0.0, 0.0, 0.0));

            (
                format!(
                    "Operation took {:.0}s which is {:.1}x standard deviations above the mean of {:.1}s",
                    observed, z_score, mean
                ),
                vec![
                    anomaly.description.clone(),
                    format!("Observed: {:.1}s, Mean: {:.1}s, Z-score: {:.1}", observed, mean, z_score),
                ],
                vec![
                    "Compare with other devices in the same assignment group".to_string(),
                    "Check network conditions during the operation".to_string(),
                ],
                vec![
                    "Check network latency to CDN and content sources".to_string(),
                    "Verify Delivery Optimization peering configuration".to_string(),
                    "Review installer size and complexity".to_string(),
                    "Check for antivirus scanning delays on downloaded content".to_string(),
                ],
                vec!["Network and content delivery performance".to_string()],
            )
        }

        AnomalyKind::FrequencySpike => (
            "Abnormal burst of events detected \u{2014} may indicate policy churn or sync storm".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Review policy change history around the spike timestamp".to_string(),
                "Check sync interval configuration".to_string(),
            ],
            vec![
                "Check for recent policy changes causing rapid re-evaluation".to_string(),
                "Review sync interval configuration".to_string(),
                "Verify no manual sync spam from Company Portal".to_string(),
            ],
            vec!["Policy evaluation and sync scheduling".to_string()],
        ),

        AnomalyKind::FrequencyGap => (
            "Expected periodic events are missing \u{2014} device may have been offline or IME service was stopped".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Check IME service status during the gap".to_string(),
                "Review network connectivity logs".to_string(),
            ],
            vec![
                "Verify IME service health (IntuneManagementExtension service)".to_string(),
                "Check device network connectivity during the gap period".to_string(),
                "Review Windows Task Scheduler for IME scheduled tasks".to_string(),
            ],
            vec!["IME service availability and network connectivity".to_string()],
        ),

        AnomalyKind::DownloadPerformance => (
            "Content download performance is significantly below baseline".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Verify Delivery Optimization is enabled".to_string(),
                "Check proxy and firewall configuration".to_string(),
            ],
            vec![
                "Enable or verify Delivery Optimization configuration".to_string(),
                "Check proxy bypass settings for Windows Update and IME endpoints".to_string(),
                "Validate available bandwidth and network quality".to_string(),
                "Review DO group configuration for peer caching".to_string(),
            ],
            vec!["Delivery Optimization and network configuration".to_string()],
        ),

        AnomalyKind::ErrorRateTrend => (
            "Failure rate is increasing over time \u{2014} indicates a worsening condition".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Identify the time when the error rate started increasing".to_string(),
                "Correlate with policy or app version changes".to_string(),
            ],
            vec![
                "Investigate recent app version or policy changes that correlate with the trend".to_string(),
                "Compare this device's error pattern with other devices in the same group".to_string(),
                "Check for environmental changes (network, GPO, security software)".to_string(),
            ],
            vec!["Error trend analysis and environmental changes".to_string()],
        ),

        AnomalyKind::SeverityEscalation => (
            "Events escalated from success to failure \u{2014} a cascading failure pattern".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Find the inflection point in the event sequence".to_string(),
                "Check for dependency failures".to_string(),
            ],
            vec![
                "Identify the inflection point where status changed from success to failure".to_string(),
                "Check for cascading dependency failures between apps".to_string(),
                "Review the event sequence for the first failure and investigate root cause".to_string(),
            ],
            vec!["Cascading failure analysis".to_string()],
        ),

        AnomalyKind::CrossSourceCorrelation => (
            "Failure in one log source correlates with events in another source within 60 seconds".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Cross-reference Windows Event Log entries during the same period".to_string(),
                "Check for system-level errors in System event log".to_string(),
            ],
            vec![
                "Check Windows Event Log for system-level errors during the same period".to_string(),
                "Verify component handoff between IME subsystems".to_string(),
                "Correlate with Application and System event logs for broader context".to_string(),
            ],
            vec!["Cross-source event correlation".to_string()],
        ),

        AnomalyKind::RootCauseCandidate => (
            "This event consistently precedes failures \u{2014} it is a strong root cause candidate".to_string(),
            vec![anomaly.description.clone()],
            vec![
                "Investigate this event's error details in depth".to_string(),
                "Trace the causal chain to downstream failures".to_string(),
            ],
            vec![
                "Focus investigation on this event \u{2014} resolve it to potentially fix downstream failures".to_string(),
                "Check the causal chain to understand the failure propagation path".to_string(),
                "Review the root event's error details and status carefully".to_string(),
            ],
            vec!["Root cause identification and causal chain analysis".to_string()],
        ),
    };

    // Add causal chain evidence if this anomaly participates in any chain.
    for chain in causal_chains {
        if chain
            .chain_event_ids
            .iter()
            .any(|eid| anomaly.affected_event_ids.contains(eid))
        {
            evidence.push(format!("Part of causal chain: {}", chain.description));
        }
    }

    // Enrich the description for error codes and collect related codes.
    let (_, mut related_error_codes) = enrich_error_codes(&anomaly.description);

    // Also scan affected event details and error codes.
    for text in &extra_error_texts {
        let (_, codes) = enrich_error_codes(text);
        related_error_codes.extend(codes);
    }

    // Deduplicate related error codes.
    related_error_codes.sort();
    related_error_codes.dedup();

    let knowledge_base_links = get_knowledge_base_links(&anomaly.kind);

    IntuneDiagnosticInsight {
        id,
        severity,
        category,
        remediation_priority,
        title: anomaly.title.clone(),
        summary: anomaly.description.clone(),
        likely_cause: Some(likely_cause),
        evidence,
        next_checks,
        suggested_fixes,
        focus_areas,
        affected_source_files: source_files,
        related_error_codes,
        knowledge_base_links,
    }
}

/// Build diagnostic insights from anomaly analysis results.
///
/// Iterates over each anomaly and produces an [`IntuneDiagnosticInsight`]
/// with structured remediation guidance based on the anomaly's kind, severity,
/// and contextual data from the analysis pipeline.
pub fn build_anomaly_insights(
    anomalies: &[Anomaly],
    causal_chains: &[CausalChain],
    events: &[IntuneEvent],
) -> Vec<IntuneDiagnosticInsight> {
    anomalies
        .iter()
        .map(|a| build_insight_for_anomaly(a, causal_chains, events))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::anomaly::models::{
        AnomalySeverity, DetectionLayer, FlowAnomalyContext, StatisticalContext,
    };

    /// Helper to create a minimal anomaly with the given kind, score, and severity.
    fn make_anomaly(kind: AnomalyKind, score: f64, severity: AnomalySeverity) -> Anomaly {
        Anomaly {
            id: "abcdef1234567890".to_string(),
            kind,
            severity,
            score,
            title: format!("{} anomaly", kind.display_label()),
            description: "Test anomaly description".to_string(),
            affected_event_ids: vec![],
            affected_event_log_ids: vec![],
            detection_layer: DetectionLayer::FlowModel,
            score_factors: vec![],
            time_range: None,
            flow_context: None,
            statistical_context: None,
            enriched_error_codes: vec![],
        }
    }

    #[test]
    fn test_missing_step_playbook() {
        let mut anomaly = make_anomaly(AnomalyKind::MissingStep, 0.6, AnomalySeverity::Warning);
        anomaly.flow_context = Some(FlowAnomalyContext {
            expected_step: "HashValidation".to_string(),
            actual_step: None,
            lifecycle: "Win32App".to_string(),
            subject_guid: Some("abc-123".to_string()),
        });

        let insights = build_anomaly_insights(&[anomaly], &[], &[]);
        assert_eq!(insights.len(), 1);

        let insight = &insights[0];
        assert!(
            insight.id.starts_with("anomaly-missing-step-"),
            "ID was: {}",
            insight.id
        );
        assert!(insight.likely_cause.is_some());
        assert!(
            insight
                .likely_cause
                .as_ref()
                .unwrap()
                .contains("HashValidation"),
            "likely_cause was: {}",
            insight.likely_cause.as_ref().unwrap()
        );
        assert!(!insight.suggested_fixes.is_empty());
        assert!(!insight.next_checks.is_empty());
        assert_eq!(insight.category, IntuneDiagnosticCategory::State);
    }

    #[test]
    fn test_priority_mapping() {
        assert_eq!(map_priority(0.8), IntuneRemediationPriority::Immediate);
        assert_eq!(map_priority(0.7), IntuneRemediationPriority::Immediate);
        assert_eq!(map_priority(0.5), IntuneRemediationPriority::High);
        assert_eq!(map_priority(0.4), IntuneRemediationPriority::High);
        assert_eq!(map_priority(0.3), IntuneRemediationPriority::Medium);
        assert_eq!(map_priority(0.2), IntuneRemediationPriority::Medium);
        assert_eq!(map_priority(0.1), IntuneRemediationPriority::Monitor);
        assert_eq!(map_priority(0.0), IntuneRemediationPriority::Monitor);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            map_severity(AnomalySeverity::Critical),
            IntuneDiagnosticSeverity::Error
        );
        assert_eq!(
            map_severity(AnomalySeverity::Warning),
            IntuneDiagnosticSeverity::Warning
        );
        assert_eq!(
            map_severity(AnomalySeverity::Info),
            IntuneDiagnosticSeverity::Info
        );
    }

    #[test]
    fn test_enrich_error_codes() {
        let text = "error 0x80070005 occurred";
        let (enriched, related) = enrich_error_codes(text);
        // The error code should be enriched with its description.
        assert!(
            enriched.contains("0x80070005 ("),
            "enriched was: {}",
            enriched
        );
        assert!(
            enriched.contains("Access is denied"),
            "enriched was: {}",
            enriched
        );
        assert!(!related.is_empty());
        assert!(
            related[0].contains("0x80070005"),
            "related was: {:?}",
            related
        );
        assert!(
            related[0].contains("Access is denied"),
            "related was: {:?}",
            related
        );
    }

    #[test]
    fn test_causal_chain_evidence() {
        let mut anomaly = make_anomaly(AnomalyKind::RootCauseCandidate, 0.9, AnomalySeverity::Critical);
        anomaly.affected_event_ids = vec![10, 20];

        let chain = CausalChain {
            id: "chain-1".to_string(),
            root_event_id: 10,
            terminal_event_id: 30,
            chain_event_ids: vec![10, 20, 30],
            confidence: 0.85,
            description: "Download failure leads to install timeout".to_string(),
        };

        let insights = build_anomaly_insights(&[anomaly], &[chain], &[]);
        assert_eq!(insights.len(), 1);

        let has_chain_evidence = insights[0]
            .evidence
            .iter()
            .any(|e| e.contains("Part of causal chain:") && e.contains("Download failure leads to install timeout"));
        assert!(
            has_chain_evidence,
            "evidence was: {:?}",
            insights[0].evidence
        );
    }

    #[test]
    fn test_all_kinds_produce_insights() {
        let all_kinds = [
            AnomalyKind::MissingStep,
            AnomalyKind::OutOfOrderStep,
            AnomalyKind::OrphanedStart,
            AnomalyKind::UnexpectedLoop,
            AnomalyKind::DurationOutlier,
            AnomalyKind::FrequencySpike,
            AnomalyKind::FrequencyGap,
            AnomalyKind::DownloadPerformance,
            AnomalyKind::ErrorRateTrend,
            AnomalyKind::SeverityEscalation,
            AnomalyKind::CrossSourceCorrelation,
            AnomalyKind::RootCauseCandidate,
        ];

        let anomalies: Vec<Anomaly> = all_kinds
            .iter()
            .enumerate()
            .map(|(i, &kind)| {
                let mut a = make_anomaly(kind, 0.5, AnomalySeverity::Warning);
                // Give each a unique ID so the slug prefix is different.
                a.id = format!("{:016x}", i);
                // Add context for kinds that use it.
                if matches!(
                    kind,
                    AnomalyKind::MissingStep | AnomalyKind::OutOfOrderStep
                ) {
                    a.flow_context = Some(FlowAnomalyContext {
                        expected_step: "Detection".to_string(),
                        actual_step: Some("Download".to_string()),
                        lifecycle: "Win32App".to_string(),
                        subject_guid: Some("test-guid".to_string()),
                    });
                }
                if kind == AnomalyKind::DurationOutlier {
                    a.statistical_context = Some(StatisticalContext {
                        metric_name: "install_duration".to_string(),
                        observed_value: 300.0,
                        population_mean: 60.0,
                        population_stddev: 30.0,
                        z_score: 8.0,
                    });
                }
                a
            })
            .collect();

        let insights = build_anomaly_insights(&anomalies, &[], &[]);
        assert_eq!(insights.len(), 12, "Expected 12 insights, got {}", insights.len());

        for insight in &insights {
            assert!(!insight.id.is_empty(), "Insight ID should not be empty");
            assert!(
                insight.id.starts_with("anomaly-"),
                "Insight ID should start with 'anomaly-': {}",
                insight.id
            );
            assert!(
                insight.likely_cause.is_some(),
                "likely_cause should be set for {}",
                insight.id
            );
            assert!(
                !insight.suggested_fixes.is_empty(),
                "suggested_fixes should not be empty for {}",
                insight.id
            );
            assert!(
                !insight.next_checks.is_empty(),
                "next_checks should not be empty for {}",
                insight.id
            );
        }
    }
}
