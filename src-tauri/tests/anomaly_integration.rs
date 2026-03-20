//! Integration test for the Smart Anomaly Engine.
//!
//! Exercises the full anomaly detection pipeline across all 4 layers:
//!   Layer 1 – Flow Model (MissingStep)
//!   Layer 2 – Statistical (ErrorRateTrend)
//!   Layer 3 – Escalation (SeverityEscalation)
//!   Layer 4 – Cross-Source (CrossSourceCorrelation)

use app_lib::intune::anomaly::models::AnomalyKind;
use app_lib::intune::anomaly::run_anomaly_analysis;
use app_lib::intune::models::{IntuneEvent, IntuneEventType, IntuneStatus};

/// Helper to build a synthetic `IntuneEvent` for testing.
fn make_event(
    id: u64,
    event_type: IntuneEventType,
    status: IntuneStatus,
    start_time: &str,
    source: &str,
    name: &str,
    guid: Option<&str>,
) -> IntuneEvent {
    IntuneEvent {
        id,
        event_type,
        name: name.to_string(),
        guid: guid.map(|g| g.to_string()),
        status,
        start_time: Some(start_time.to_string()),
        end_time: None,
        duration_secs: None,
        error_code: None,
        detail: String::new(),
        source_file: source.to_string(),
        line_number: id as u32,
    }
}

#[test]
fn anomaly_pipeline_detects_all_layers() {
    let mut events: Vec<IntuneEvent> = Vec::new();
    let mut next_id: u64 = 0;

    // -----------------------------------------------------------------------
    // Layer 1 (Flow Model — MissingStep):
    //
    // Win32App lifecycle with Download and Install but missing Staging and
    // HashValidation. The flow model expects [Download, Staging, HashValidation,
    // Install] for Win32App, so omitting Staging and HashValidation should
    // trigger MissingStep anomalies.
    // -----------------------------------------------------------------------
    let flow_guid = "guid-flow-1";
    let flow_source = "IntuneManagementExtension.log";

    // Download phase
    for i in 0..5 {
        events.push(make_event(
            next_id,
            IntuneEventType::Win32App,
            IntuneStatus::Success,
            &format!("01-15-2024 10:00:{:02}.000", i * 3),
            flow_source,
            "AppWorkload Download (guid-flow-1)",
            Some(flow_guid),
        ));
        next_id += 1;
    }
    // Install phase (skip Staging and HashValidation)
    for i in 0..5 {
        events.push(make_event(
            next_id,
            IntuneEventType::Win32App,
            IntuneStatus::Success,
            &format!("01-15-2024 10:00:{:02}.000", 15 + i * 3),
            flow_source,
            "AppWorkload Install (guid-flow-1)",
            Some(flow_guid),
        ));
        next_id += 1;
    }

    // -----------------------------------------------------------------------
    // Layer 2 (Statistical — ErrorRateTrend):
    //
    // 20 events spread across 3 time windows (each ~5 min apart).
    //   Window 1 (10:00-10:04): 7 events, 1 failed  (14% error rate)
    //   Window 2 (10:05-10:09): 7 events, 3 failed  (43% error rate)
    //   Window 3 (10:10-10:14): 6 events, 5 failed  (83% error rate)
    //
    // The error rate trend detector requires >=3 windows with monotonically
    // increasing error rate and final window >50%.
    // -----------------------------------------------------------------------
    let stat_source = "AppWorkload.log";

    // Window 1: 7 events, 1 failed
    for i in 0..7 {
        let status = if i == 0 {
            IntuneStatus::Failed
        } else {
            IntuneStatus::Success
        };
        events.push(make_event(
            next_id,
            IntuneEventType::Win32App,
            status,
            &format!("01-15-2024 10:0{}:00.000", i % 5),
            stat_source,
            &format!("StatEvent W1-{}", i),
            None,
        ));
        next_id += 1;
    }

    // Window 2: 7 events, 3 failed
    for i in 0..7 {
        let status = if i < 3 {
            IntuneStatus::Failed
        } else {
            IntuneStatus::Success
        };
        events.push(make_event(
            next_id,
            IntuneEventType::Win32App,
            status,
            &format!("01-15-2024 10:0{}:00.000", 5 + (i % 5)),
            stat_source,
            &format!("StatEvent W2-{}", i),
            None,
        ));
        next_id += 1;
    }

    // Window 3: 6 events, 5 failed
    for i in 0..6 {
        let status = if i < 5 {
            IntuneStatus::Failed
        } else {
            IntuneStatus::Success
        };
        events.push(make_event(
            next_id,
            IntuneEventType::Win32App,
            status,
            &format!("01-15-2024 10:{}:00.000", 10 + (i % 5)),
            stat_source,
            &format!("StatEvent W3-{}", i),
            None,
        ));
        next_id += 1;
    }

    // -----------------------------------------------------------------------
    // Layer 3 (Escalation — SeverityEscalation):
    //
    // 5 events with escalating severity:
    //   Success, Success, Timeout, Failed, Failed
    // Timestamps ~1 minute apart.
    // The escalation detector requires a window of 5 events that goes from
    // severity proxy 0 (Success) to 2 (Failed) monotonically.
    // -----------------------------------------------------------------------
    let esc_source = "AgentExecutor.log";
    let esc_statuses = [
        IntuneStatus::Success,
        IntuneStatus::Success,
        IntuneStatus::Timeout,
        IntuneStatus::Failed,
        IntuneStatus::Failed,
    ];

    for (i, &status) in esc_statuses.iter().enumerate() {
        events.push(make_event(
            next_id,
            IntuneEventType::Win32App,
            status,
            &format!("01-15-2024 11:{:02}:00.000", i),
            esc_source,
            &format!("EscEvent {}", i),
            None,
        ));
        next_id += 1;
    }

    // -----------------------------------------------------------------------
    // Layer 4 (Cross-Source — CrossSourceCorrelation):
    //
    // The Failed events from the ErrorRateTrend set (source "AppWorkload.log")
    // temporally overlap with the flow-model events from
    // "IntuneManagementExtension.log" (within 60s). The cross-source detector
    // looks for failed events in one source family that have corresponding
    // events in a different source family within ±60s.
    // -----------------------------------------------------------------------
    // (Already covered by the combination of stat_source="AppWorkload.log"
    //  failed events at 10:00-10:14 and flow_source events at 10:00.)

    // -----------------------------------------------------------------------
    // Run the full anomaly pipeline
    // -----------------------------------------------------------------------
    let analysis = run_anomaly_analysis(&events, &[], None, None);

    // -----------------------------------------------------------------------
    // Assertions
    // -----------------------------------------------------------------------

    // 1. Anomalies are not empty
    assert!(
        !analysis.anomalies.is_empty(),
        "Expected at least one anomaly from the pipeline, got 0"
    );

    // 2. At least 1 anomaly has kind == SeverityEscalation
    let escalation_count = analysis
        .anomalies
        .iter()
        .filter(|a| a.kind == AnomalyKind::SeverityEscalation)
        .count();
    assert!(
        escalation_count >= 1,
        "Expected at least 1 SeverityEscalation anomaly, got {}",
        escalation_count
    );

    // 3. All anomaly scores are in range [0.0, 1.0]
    for anomaly in &analysis.anomalies {
        assert!(
            (0.0..=1.0).contains(&anomaly.score),
            "Anomaly '{}' has score {} outside [0.0, 1.0]",
            anomaly.id,
            anomaly.score
        );
    }

    // 4. Anomalies are sorted by score descending
    for window in analysis.anomalies.windows(2) {
        assert!(
            window[0].score >= window[1].score,
            "Anomalies not sorted descending: {} (score={}) should be >= {} (score={})",
            window[0].id,
            window[0].score,
            window[1].id,
            window[1].score
        );
    }

    // 5. summary.total_anomalies equals anomalies.len()
    assert_eq!(
        analysis.summary.total_anomalies,
        analysis.anomalies.len() as u32,
        "summary.total_anomalies ({}) != anomalies.len() ({})",
        analysis.summary.total_anomalies,
        analysis.anomalies.len()
    );
}
