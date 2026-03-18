//! Layer 1: Expected Flow Modeling
//!
//! Detects lifecycle deviations in Intune deployments by:
//! 1. Grouping events by GUID (app deployment identity)
//! 2. Matching each group to a lifecycle template
//! 3. Detecting missing steps, out-of-order steps, orphaned starts, unexpected loops
//! 4. Building causal chains from failures back to root causes

use std::collections::HashMap;

use chrono::NaiveDateTime;

use super::models::{
    Anomaly, AnomalyKind, AnomalySeverity, AnomalyTimeRange, CausalChain, DetectionLayer,
    FlowAnomalyContext,
};
use crate::intune::models::{IntuneEvent, IntuneEventType, IntuneStatus};
use crate::intune::timeline;

// ---------------------------------------------------------------------------
// Lifecycle definitions
// ---------------------------------------------------------------------------

/// The type of lifecycle expected for a GUID group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleKind {
    Win32App,
    WinGetApp,
    Script,
    Remediation,
}

impl LifecycleKind {
    /// Display label used in anomaly descriptions.
    fn label(&self) -> &'static str {
        match self {
            Self::Win32App => "Win32App",
            Self::WinGetApp => "WinGetApp",
            Self::Script => "Script",
            Self::Remediation => "Remediation",
        }
    }

    /// Expected ordered phases for this lifecycle type.
    fn expected_phases(&self) -> &'static [&'static str] {
        match self {
            Self::Win32App => &["Download", "Staging", "HashValidation", "Install"],
            Self::WinGetApp => &["Download", "Install"],
            Self::Script => &["Execution"],
            Self::Remediation => &["Detection", "Remediation"],
        }
    }
}

// ---------------------------------------------------------------------------
// Phase extraction
// ---------------------------------------------------------------------------

/// Extract the lifecycle phase from an event name.
///
/// For AppWorkload events the name follows patterns like:
///   "AppWorkload Download (abc12345)" -> "Download"
///   "AppWorkload Hash Validation (abc12345)" -> "HashValidation"
///   "AppWorkload Download Retry (abc12345)" -> "DownloadRetry"
///
/// For non-AppWorkload events the event_type is used as a fallback.
fn extract_phase(event: &IntuneEvent) -> String {
    let name = &event.name;

    if let Some(rest) = name.strip_prefix("AppWorkload ") {
        // Find the portion between "AppWorkload " and the opening parenthesis.
        let phase_part = if let Some(idx) = rest.find('(') {
            rest[..idx].trim()
        } else {
            rest.trim()
        };

        // Collapse multi-word phases into PascalCase (e.g. "Hash Validation" -> "HashValidation",
        // "Download Retry" -> "DownloadRetry", "Download Stall" -> "DownloadStall").
        let collapsed: String = phase_part
            .split_whitespace()
            .map(|w| {
                let mut chars = w.chars();
                match chars.next() {
                    Some(c) => {
                        let mut s = c.to_uppercase().to_string();
                        s.push_str(&chars.as_str().to_lowercase());
                        s
                    }
                    None => String::new(),
                }
            })
            .collect();

        if collapsed.is_empty() {
            return fallback_phase(event);
        }

        // "Winget" from "AppWorkload WinGet (...)" is a WinGet lifecycle event; normalize.
        if collapsed == "Winget" || collapsed == "WinGet" {
            return "WinGet".to_string();
        }

        return collapsed;
    }

    fallback_phase(event)
}

/// Fallback phase derived from event type for non-AppWorkload events.
fn fallback_phase(event: &IntuneEvent) -> String {
    match event.event_type {
        IntuneEventType::PowerShellScript => "Execution".to_string(),
        IntuneEventType::Remediation => {
            // Use event name heuristic: names containing "detection" map to detection phase.
            let lower_name = event.name.to_ascii_lowercase();
            if lower_name.contains("detection") {
                "Detection".to_string()
            } else {
                "Remediation".to_string()
            }
        }
        IntuneEventType::Esp => "Esp".to_string(),
        IntuneEventType::SyncSession => "Sync".to_string(),
        IntuneEventType::PolicyEvaluation => "PolicyEvaluation".to_string(),
        IntuneEventType::ContentDownload => "Download".to_string(),
        _ => "Unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle type determination
// ---------------------------------------------------------------------------

/// Determine the lifecycle type from the set of events in a GUID group.
fn determine_lifecycle(events: &[&IntuneEvent]) -> LifecycleKind {
    let mut win32 = 0u32;
    let mut winget = 0u32;
    let mut script = 0u32;
    let mut remediation = 0u32;

    for event in events {
        match event.event_type {
            IntuneEventType::Win32App | IntuneEventType::ContentDownload => win32 += 1,
            IntuneEventType::WinGetApp => winget += 1,
            IntuneEventType::PowerShellScript => script += 1,
            IntuneEventType::Remediation => remediation += 1,
            _ => {}
        }

        // WinGet phase from AppWorkload name overrides ContentDownload type.
        if extract_phase(event) == "WinGet" {
            winget += 1;
        }
    }

    if winget > 0 && winget >= win32 {
        LifecycleKind::WinGetApp
    } else if script > 0 && script >= win32 && script >= remediation {
        LifecycleKind::Script
    } else if remediation > 0 && remediation >= win32 {
        LifecycleKind::Remediation
    } else {
        LifecycleKind::Win32App
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce a short version of a GUID for use in anomaly IDs.
fn guid_short(guid: &str) -> String {
    // Take the first 8 characters or the first segment before a dash.
    if let Some(seg) = guid.split('-').next() {
        seg.to_string()
    } else {
        guid.chars().take(8).collect()
    }
}

/// Build an `AnomalyTimeRange` from a set of events by finding the earliest
/// start_time and latest end_time (or start_time if end_time is absent).
fn time_range_for(events: &[&IntuneEvent]) -> Option<AnomalyTimeRange> {
    let mut earliest: Option<(NaiveDateTime, &str)> = None;
    let mut latest: Option<(NaiveDateTime, &str)> = None;

    for event in events {
        for ts in [event.start_time.as_deref(), event.end_time.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(parsed) = timeline::parse_timestamp(ts) {
                match &earliest {
                    Some((cur, _)) if parsed >= *cur => {}
                    _ => earliest = Some((parsed, ts)),
                }
                match &latest {
                    Some((cur, _)) if parsed <= *cur => {}
                    _ => latest = Some((parsed, ts)),
                }
            }
        }
    }

    match (earliest, latest) {
        (Some((_, start)), Some((_, end))) => Some(AnomalyTimeRange {
            start: start.to_string(),
            end: end.to_string(),
        }),
        _ => None,
    }
}

/// Threshold for how many times the same phase can repeat before it is
/// considered an unexpected loop.
const LOOP_THRESHOLD: usize = 3;

// ---------------------------------------------------------------------------
// Core detection
// ---------------------------------------------------------------------------

/// Run flow anomaly detection across all events.
///
/// Returns detected anomalies and causal chains linking failures back to
/// earlier events in the same GUID group.
pub fn detect_flow_anomalies(events: &[IntuneEvent]) -> (Vec<Anomaly>, Vec<CausalChain>) {
    let mut anomalies = Vec::new();
    let mut causal_chains = Vec::new();

    // Step 1: Group events by GUID (skip events with no guid).
    let mut groups: HashMap<String, Vec<&IntuneEvent>> = HashMap::new();
    for event in events {
        if let Some(ref guid) = event.guid {
            groups.entry(guid.clone()).or_default().push(event);
        }
    }

    // Step 2: Analyze each group.
    for (guid, group_events) in &groups {
        let short = guid_short(guid);
        let lifecycle = determine_lifecycle(group_events);
        let expected = lifecycle.expected_phases();

        // Extract observed phases in chronological order (events should already
        // be sorted by the timeline builder, but sort locally to be safe).
        let mut sorted_events: Vec<&IntuneEvent> = group_events.clone();
        sorted_events.sort_by_key(|e| {
            e.start_time
                .as_deref()
                .and_then(timeline::parse_timestamp)
        });

        let observed_phases: Vec<String> = sorted_events.iter().map(|e| extract_phase(e)).collect();
        let time_range = time_range_for(&sorted_events);
        let affected_ids: Vec<u64> = sorted_events.iter().map(|e| e.id).collect();

        // 2a: Missing steps
        for &step in expected {
            if !observed_phases.iter().any(|p| p == step) {
                let anomaly_id = format!("flow-{}-missing-{}", short, step.to_lowercase());
                anomalies.push(Anomaly {
                    id: anomaly_id,
                    kind: AnomalyKind::MissingStep,
                    severity: AnomalySeverity::Warning,
                    score: 0.0,
                    title: format!("Missing {} step", step),
                    description: format!(
                        "{} lifecycle for GUID {} is missing the expected '{}' step. \
                         Observed phases: [{}].",
                        lifecycle.label(),
                        &guid[..guid.len().min(8)],
                        step,
                        observed_phases.join(", ")
                    ),
                    affected_event_ids: affected_ids.clone(),
                    affected_event_log_ids: Vec::new(),
                    detection_layer: DetectionLayer::FlowModel,
                    score_factors: Vec::new(),
                    time_range: time_range.clone(),
                    flow_context: Some(FlowAnomalyContext {
                        expected_step: step.to_string(),
                        actual_step: None,
                        lifecycle: lifecycle.label().to_string(),
                        subject_guid: Some(guid.clone()),
                    }),
                    statistical_context: None,
                });
            }
        }

        // 2b: Out-of-order steps
        // Walk the observed phases and verify that each recognized phase appears
        // no earlier in the expected sequence than the previous recognized phase.
        let mut last_expected_idx: Option<usize> = None;
        for (obs_idx, phase) in observed_phases.iter().enumerate() {
            if let Some(expected_pos) = expected.iter().position(|&s| s == phase.as_str()) {
                if let Some(prev_pos) = last_expected_idx {
                    if expected_pos < prev_pos {
                        let prev_phase = expected[prev_pos];
                        let anomaly_id = format!(
                            "flow-{}-order-{}-before-{}",
                            short,
                            phase.to_lowercase(),
                            prev_phase.to_lowercase()
                        );
                        anomalies.push(Anomaly {
                            id: anomaly_id,
                            kind: AnomalyKind::OutOfOrderStep,
                            severity: AnomalySeverity::Warning,
                            score: 0.0,
                            title: format!("'{}' occurred before '{}'", phase, prev_phase),
                            description: format!(
                                "{} lifecycle for GUID {}: '{}' was observed at position {} \
                                 but '{}' (which should come first) was at an earlier position.",
                                lifecycle.label(),
                                &guid[..guid.len().min(8)],
                                phase,
                                obs_idx,
                                prev_phase,
                            ),
                            affected_event_ids: affected_ids.clone(),
                            affected_event_log_ids: Vec::new(),
                            detection_layer: DetectionLayer::FlowModel,
                            score_factors: Vec::new(),
                            time_range: time_range.clone(),
                            flow_context: Some(FlowAnomalyContext {
                                expected_step: prev_phase.to_string(),
                                actual_step: Some(phase.clone()),
                                lifecycle: lifecycle.label().to_string(),
                                subject_guid: Some(guid.clone()),
                            }),
                            statistical_context: None,
                        });
                    }
                }
                last_expected_idx = Some(expected_pos);
            }
        }

        // 2c: Orphaned starts — InProgress events with no end_time
        for event in &sorted_events {
            if event.status == IntuneStatus::InProgress && event.end_time.is_none() {
                let phase = extract_phase(event);
                let anomaly_id = format!("flow-{}-orphan-{}", short, phase.to_lowercase());
                let event_time_range = event.start_time.as_ref().map(|st| AnomalyTimeRange {
                    start: st.clone(),
                    end: st.clone(),
                });
                anomalies.push(Anomaly {
                    id: anomaly_id,
                    kind: AnomalyKind::OrphanedStart,
                    severity: AnomalySeverity::Info,
                    score: 0.0,
                    title: format!("Orphaned '{}' start", phase),
                    description: format!(
                        "{} lifecycle for GUID {}: '{}' started (InProgress) but never completed. \
                         No matching end event was found.",
                        lifecycle.label(),
                        &guid[..guid.len().min(8)],
                        phase,
                    ),
                    affected_event_ids: vec![event.id],
                    affected_event_log_ids: Vec::new(),
                    detection_layer: DetectionLayer::FlowModel,
                    score_factors: Vec::new(),
                    time_range: event_time_range,
                    flow_context: Some(FlowAnomalyContext {
                        expected_step: phase,
                        actual_step: None,
                        lifecycle: lifecycle.label().to_string(),
                        subject_guid: Some(guid.clone()),
                    }),
                    statistical_context: None,
                });
            }
        }

        // 2d: Unexpected loops — same phase appearing more than LOOP_THRESHOLD times
        let mut phase_counts: HashMap<&str, usize> = HashMap::new();
        for phase in &observed_phases {
            *phase_counts.entry(phase.as_str()).or_insert(0) += 1;
        }
        for (phase, count) in &phase_counts {
            if *count > LOOP_THRESHOLD {
                let anomaly_id = format!("flow-{}-loop-{}", short, phase.to_lowercase());
                anomalies.push(Anomaly {
                    id: anomaly_id,
                    kind: AnomalyKind::UnexpectedLoop,
                    severity: AnomalySeverity::Warning,
                    score: 0.0,
                    title: format!("'{}' repeated {} times", phase, count),
                    description: format!(
                        "{} lifecycle for GUID {}: '{}' was observed {} times \
                         (threshold: {}). This may indicate a retry loop or stuck process.",
                        lifecycle.label(),
                        &guid[..guid.len().min(8)],
                        phase,
                        count,
                        LOOP_THRESHOLD,
                    ),
                    affected_event_ids: affected_ids.clone(),
                    affected_event_log_ids: Vec::new(),
                    detection_layer: DetectionLayer::FlowModel,
                    score_factors: Vec::new(),
                    time_range: time_range.clone(),
                    flow_context: Some(FlowAnomalyContext {
                        expected_step: phase.to_string(),
                        actual_step: None,
                        lifecycle: lifecycle.label().to_string(),
                        subject_guid: Some(guid.clone()),
                    }),
                    statistical_context: None,
                });
            }
        }

        // 2e: Causal chain — if the last event is Failed or Timeout, build a chain
        //     from the first event through to the terminal failure.
        if let Some(last_event) = sorted_events.last() {
            if matches!(
                last_event.status,
                IntuneStatus::Failed | IntuneStatus::Timeout
            ) && sorted_events.len() >= 2
            {
                let first_event = sorted_events[0];
                let chain_ids: Vec<u64> = sorted_events.iter().map(|e| e.id).collect();
                let status_label = match last_event.status {
                    IntuneStatus::Failed => "failure",
                    IntuneStatus::Timeout => "timeout",
                    _ => "failure",
                };
                let chain_id = format!("chain-{}-{}", short, status_label);
                let error_info = last_event
                    .error_code
                    .as_deref()
                    .map(|c| format!(" (error {})", c))
                    .unwrap_or_default();

                causal_chains.push(CausalChain {
                    id: chain_id,
                    root_event_id: first_event.id,
                    terminal_event_id: last_event.id,
                    chain_event_ids: chain_ids,
                    confidence: compute_chain_confidence(&sorted_events),
                    description: format!(
                        "{} lifecycle for GUID {}: {} at '{}'{} traced back through {} events \
                         to '{}' at the start of the lifecycle.",
                        lifecycle.label(),
                        &guid[..guid.len().min(8)],
                        status_label,
                        extract_phase(last_event),
                        error_info,
                        sorted_events.len(),
                        extract_phase(first_event),
                    ),
                });
            }
        }
    }

    (anomalies, causal_chains)
}

/// Compute a confidence score for a causal chain.
///
/// Confidence is higher when:
/// - The chain has more events (more corroborating evidence)
/// - Events have timestamps (temporal ordering is verified)
/// - There are error codes (concrete failure evidence)
fn compute_chain_confidence(events: &[&IntuneEvent]) -> f64 {
    let mut score = 0.5; // base confidence

    // More events in the chain = more corroboration
    let event_boost = (events.len() as f64 - 1.0).min(4.0) * 0.05;
    score += event_boost;

    // Events with timestamps give better temporal confidence
    let timestamped = events
        .iter()
        .filter(|e| e.start_time.is_some())
        .count();
    let ts_ratio = timestamped as f64 / events.len() as f64;
    score += ts_ratio * 0.2;

    // Terminal event has an error code
    if let Some(last) = events.last() {
        if last.error_code.is_some() {
            score += 0.1;
        }
    }

    score.min(1.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::models::{IntuneEvent, IntuneEventType, IntuneStatus};

    /// Helper to build a minimal `IntuneEvent` for testing.
    fn make_event(
        id: u64,
        event_type: IntuneEventType,
        name: &str,
        guid: &str,
        status: IntuneStatus,
        start_time: Option<&str>,
        end_time: Option<&str>,
        error_code: Option<&str>,
    ) -> IntuneEvent {
        IntuneEvent {
            id,
            event_type,
            name: name.to_string(),
            guid: Some(guid.to_string()),
            status,
            start_time: start_time.map(|s| s.to_string()),
            end_time: end_time.map(|s| s.to_string()),
            duration_secs: None,
            error_code: error_code.map(|s| s.to_string()),
            detail: String::new(),
            source_file: "test.log".to_string(),
            line_number: id as u32,
        }
    }

    const TEST_GUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    #[test]
    fn test_complete_lifecycle_no_anomalies() {
        let events = vec![
            make_event(
                0,
                IntuneEventType::Win32App,
                "AppWorkload Download (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:00:00.000"),
                Some("01-01-2024 10:01:00.000"),
                None,
            ),
            make_event(
                1,
                IntuneEventType::Win32App,
                "AppWorkload Staging (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:01:00.000"),
                Some("01-01-2024 10:02:00.000"),
                None,
            ),
            make_event(
                2,
                IntuneEventType::Win32App,
                "AppWorkload Hash Validation (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:02:00.000"),
                Some("01-01-2024 10:03:00.000"),
                None,
            ),
            make_event(
                3,
                IntuneEventType::Win32App,
                "AppWorkload Install (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:03:00.000"),
                Some("01-01-2024 10:04:00.000"),
                None,
            ),
        ];

        let (anomalies, chains) = detect_flow_anomalies(&events);

        assert!(
            anomalies.is_empty(),
            "Expected no anomalies for a complete Win32App lifecycle, got: {:?}",
            anomalies.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
        assert!(
            chains.is_empty(),
            "Expected no causal chains for a successful lifecycle"
        );
    }

    #[test]
    fn test_missing_download_step() {
        // Win32App lifecycle that jumps straight to Staging without Download.
        let events = vec![
            make_event(
                0,
                IntuneEventType::Win32App,
                "AppWorkload Staging (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:01:00.000"),
                Some("01-01-2024 10:02:00.000"),
                None,
            ),
            make_event(
                1,
                IntuneEventType::Win32App,
                "AppWorkload Hash Validation (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:02:00.000"),
                Some("01-01-2024 10:03:00.000"),
                None,
            ),
            make_event(
                2,
                IntuneEventType::Win32App,
                "AppWorkload Install (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:03:00.000"),
                Some("01-01-2024 10:04:00.000"),
                None,
            ),
        ];

        let (anomalies, _chains) = detect_flow_anomalies(&events);

        let missing: Vec<&Anomaly> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::MissingStep)
            .collect();

        assert_eq!(missing.len(), 1, "Expected exactly one MissingStep anomaly");
        assert!(missing[0].title.contains("Download"));
        assert_eq!(missing[0].detection_layer, DetectionLayer::FlowModel);

        let ctx = missing[0].flow_context.as_ref().unwrap();
        assert_eq!(ctx.expected_step, "Download");
        assert_eq!(ctx.lifecycle, "Win32App");
        assert_eq!(ctx.subject_guid.as_deref(), Some(TEST_GUID));
    }

    #[test]
    fn test_orphaned_start() {
        // An InProgress event with no end_time should be flagged as orphaned.
        let events = vec![
            make_event(
                0,
                IntuneEventType::Win32App,
                "AppWorkload Download (abc12345)",
                TEST_GUID,
                IntuneStatus::InProgress,
                Some("01-01-2024 10:00:00.000"),
                None, // no end_time
                None,
            ),
        ];

        let (anomalies, _chains) = detect_flow_anomalies(&events);

        let orphans: Vec<&Anomaly> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::OrphanedStart)
            .collect();

        assert_eq!(orphans.len(), 1, "Expected exactly one OrphanedStart anomaly");
        assert!(orphans[0].title.contains("Download"));
        assert_eq!(orphans[0].severity, AnomalySeverity::Info);
        assert_eq!(orphans[0].affected_event_ids, vec![0]);
    }

    #[test]
    fn test_unexpected_loop() {
        // The same Download phase appearing 4 times (exceeding the threshold of 3).
        let events: Vec<IntuneEvent> = (0..4)
            .map(|i| {
                make_event(
                    i,
                    IntuneEventType::Win32App,
                    "AppWorkload Download (abc12345)",
                    TEST_GUID,
                    IntuneStatus::Success,
                    Some(&format!("01-01-2024 10:0{}:00.000", i)),
                    Some(&format!("01-01-2024 10:0{}:30.000", i)),
                    None,
                )
            })
            .collect();

        let (anomalies, _chains) = detect_flow_anomalies(&events);

        let loops: Vec<&Anomaly> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnexpectedLoop)
            .collect();

        assert_eq!(
            loops.len(),
            1,
            "Expected exactly one UnexpectedLoop anomaly"
        );
        assert!(loops[0].title.contains("Download"));
        assert!(loops[0].title.contains("4"));
        assert_eq!(loops[0].severity, AnomalySeverity::Warning);
    }

    #[test]
    fn test_causal_chain_from_failure() {
        // A lifecycle that starts with Download but ends with a failed Install.
        let events = vec![
            make_event(
                0,
                IntuneEventType::Win32App,
                "AppWorkload Download (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:00:00.000"),
                Some("01-01-2024 10:01:00.000"),
                None,
            ),
            make_event(
                1,
                IntuneEventType::Win32App,
                "AppWorkload Staging (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:01:00.000"),
                Some("01-01-2024 10:02:00.000"),
                None,
            ),
            make_event(
                2,
                IntuneEventType::Win32App,
                "AppWorkload Hash Validation (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:02:00.000"),
                Some("01-01-2024 10:03:00.000"),
                None,
            ),
            make_event(
                3,
                IntuneEventType::Win32App,
                "AppWorkload Install (abc12345)",
                TEST_GUID,
                IntuneStatus::Failed,
                Some("01-01-2024 10:03:00.000"),
                Some("01-01-2024 10:04:00.000"),
                Some("0x80070005"),
            ),
        ];

        let (anomalies, chains) = detect_flow_anomalies(&events);

        // No lifecycle anomalies (all steps present and in order), but there should
        // be a causal chain because the terminal event is Failed.
        let missing = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::MissingStep)
            .count();
        assert_eq!(missing, 0, "All steps are present");

        assert_eq!(chains.len(), 1, "Expected exactly one causal chain");
        let chain = &chains[0];
        assert_eq!(chain.root_event_id, 0);
        assert_eq!(chain.terminal_event_id, 3);
        assert_eq!(chain.chain_event_ids, vec![0, 1, 2, 3]);
        assert!(chain.confidence > 0.5, "Confidence should be above baseline");
        assert!(chain.confidence <= 1.0);
        assert!(chain.description.contains("failure"));
        assert!(chain.description.contains("0x80070005"));
    }

    #[test]
    fn test_events_without_guid_are_skipped() {
        let event = IntuneEvent {
            id: 0,
            event_type: IntuneEventType::Win32App,
            name: "AppWorkload Download (abc12345)".to_string(),
            guid: None, // no guid
            status: IntuneStatus::InProgress,
            start_time: Some("01-01-2024 10:00:00.000".to_string()),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: String::new(),
            source_file: "test.log".to_string(),
            line_number: 1,
        };

        let (anomalies, chains) = detect_flow_anomalies(&[event]);

        assert!(anomalies.is_empty(), "Events without GUID should be skipped");
        assert!(chains.is_empty());
    }

    #[test]
    fn test_out_of_order_step() {
        // Install happens before Staging in a Win32App lifecycle.
        let events = vec![
            make_event(
                0,
                IntuneEventType::Win32App,
                "AppWorkload Download (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:00:00.000"),
                Some("01-01-2024 10:01:00.000"),
                None,
            ),
            make_event(
                1,
                IntuneEventType::Win32App,
                "AppWorkload Install (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:01:00.000"),
                Some("01-01-2024 10:02:00.000"),
                None,
            ),
            make_event(
                2,
                IntuneEventType::Win32App,
                "AppWorkload Staging (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:02:00.000"),
                Some("01-01-2024 10:03:00.000"),
                None,
            ),
            make_event(
                3,
                IntuneEventType::Win32App,
                "AppWorkload Hash Validation (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:03:00.000"),
                Some("01-01-2024 10:04:00.000"),
                None,
            ),
        ];

        let (anomalies, _chains) = detect_flow_anomalies(&events);

        let ooo: Vec<&Anomaly> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::OutOfOrderStep)
            .collect();

        assert!(
            !ooo.is_empty(),
            "Expected at least one OutOfOrderStep anomaly when Install precedes Staging"
        );
        assert_eq!(ooo[0].detection_layer, DetectionLayer::FlowModel);
    }

    #[test]
    fn test_winget_lifecycle() {
        // WinGetApp lifecycle: Download -> Install should produce no anomalies.
        let events = vec![
            make_event(
                0,
                IntuneEventType::WinGetApp,
                "AppWorkload Download (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:00:00.000"),
                Some("01-01-2024 10:01:00.000"),
                None,
            ),
            make_event(
                1,
                IntuneEventType::WinGetApp,
                "AppWorkload Install (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:01:00.000"),
                Some("01-01-2024 10:02:00.000"),
                None,
            ),
        ];

        let (anomalies, chains) = detect_flow_anomalies(&events);

        assert!(
            anomalies.is_empty(),
            "Complete WinGetApp lifecycle should have no anomalies, got: {:?}",
            anomalies.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
        assert!(chains.is_empty());
    }

    #[test]
    fn test_extract_phase_patterns() {
        let cases = vec![
            ("AppWorkload Download (abc12345)", "Download"),
            ("AppWorkload Staging (abc12345)", "Staging"),
            ("AppWorkload Hash Validation (abc12345)", "HashValidation"),
            ("AppWorkload Install (abc12345)", "Install"),
            ("AppWorkload Download Retry (abc12345)", "DownloadRetry"),
            ("AppWorkload Download Stall (abc12345)", "DownloadStall"),
        ];

        for (name, expected_phase) in cases {
            let event = make_event(
                0,
                IntuneEventType::Win32App,
                name,
                TEST_GUID,
                IntuneStatus::Success,
                None,
                None,
                None,
            );
            assert_eq!(
                extract_phase(&event),
                expected_phase,
                "Failed for name: {}",
                name
            );
        }
    }

    #[test]
    fn test_timeout_produces_causal_chain() {
        let events = vec![
            make_event(
                0,
                IntuneEventType::Win32App,
                "AppWorkload Download (abc12345)",
                TEST_GUID,
                IntuneStatus::Success,
                Some("01-01-2024 10:00:00.000"),
                Some("01-01-2024 10:01:00.000"),
                None,
            ),
            make_event(
                1,
                IntuneEventType::Win32App,
                "AppWorkload Install (abc12345)",
                TEST_GUID,
                IntuneStatus::Timeout,
                Some("01-01-2024 10:01:00.000"),
                Some("01-01-2024 12:01:00.000"),
                None,
            ),
        ];

        let (_anomalies, chains) = detect_flow_anomalies(&events);

        assert_eq!(chains.len(), 1);
        assert!(chains[0].description.contains("timeout"));
        assert_eq!(chains[0].terminal_event_id, 1);
    }
}
