use chrono::NaiveDateTime;

use super::models::{Anomaly, AnomalyKind, AnomalySeverity, DetectionLayer, ScoreFactor};
use crate::intune::models::{IntuneEvent, IntuneStatus};
use crate::intune::timeline;

// ---------------------------------------------------------------------------
// Factor weights
// ---------------------------------------------------------------------------

const WEIGHT_KIND: f64 = 0.30;
const WEIGHT_FREQUENCY: f64 = 0.20;
const WEIGHT_IMPACT: f64 = 0.25;
const WEIGHT_CONFIDENCE: f64 = 0.15;
const WEIGHT_RECENCY: f64 = 0.10;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Score all anomalies and sort by score descending.
///
/// For each anomaly this function:
/// 1. Computes a composite score (0.0 to 1.0) from five weighted factors.
/// 2. Populates `anomaly.score_factors` with the contributing factors.
/// 3. Assigns severity based on score thresholds, keeping the higher of the
///    existing severity and the score-derived severity.
pub fn score_anomalies(anomalies: &mut [Anomaly], events: &[IntuneEvent]) {
    // Pre-compute timeline bounds once across all events.
    let timeline_bounds = compute_timeline_bounds(events);

    for anomaly in anomalies.iter_mut() {
        let kind_value = kind_weight(anomaly.kind);
        let frequency_value = frequency_score(&anomaly.affected_event_ids);
        let impact_value = impact_score(&anomaly.affected_event_ids, events);
        let confidence_value = confidence_score(anomaly.detection_layer, &anomaly.statistical_context);
        let recency_value = recency_score(anomaly, events, &timeline_bounds);

        // Populate score factors.
        anomaly.score_factors = vec![
            ScoreFactor {
                factor: "Kind Weight".to_string(),
                weight: WEIGHT_KIND,
                value: kind_value,
                explanation: format!(
                    "{} anomalies have base weight {:.2}",
                    anomaly.kind.display_label(),
                    kind_value
                ),
            },
            ScoreFactor {
                factor: "Frequency".to_string(),
                weight: WEIGHT_FREQUENCY,
                value: frequency_value,
                explanation: format!(
                    "{} affected events (score {:.2})",
                    anomaly.affected_event_ids.len(),
                    frequency_value
                ),
            },
            ScoreFactor {
                factor: "Impact".to_string(),
                weight: WEIGHT_IMPACT,
                value: impact_value,
                explanation: format!(
                    "{:.0}% of affected events failed or timed out",
                    impact_value * 100.0
                ),
            },
            ScoreFactor {
                factor: "Confidence".to_string(),
                weight: WEIGHT_CONFIDENCE,
                value: confidence_value,
                explanation: format!(
                    "{:?} detection layer confidence {:.2}",
                    anomaly.detection_layer, confidence_value
                ),
            },
            ScoreFactor {
                factor: "Recency".to_string(),
                weight: WEIGHT_RECENCY,
                value: recency_value,
                explanation: format!("Recency factor {:.2}", recency_value),
            },
        ];

        // Composite score clamped to [0.0, 1.0].
        let raw_score = kind_value * WEIGHT_KIND
            + frequency_value * WEIGHT_FREQUENCY
            + impact_value * WEIGHT_IMPACT
            + confidence_value * WEIGHT_CONFIDENCE
            + recency_value * WEIGHT_RECENCY;

        anomaly.score = raw_score.clamp(0.0, 1.0);

        // Severity assignment — keep the higher of existing vs score-derived.
        let derived_severity = if anomaly.score >= 0.7 {
            AnomalySeverity::Critical
        } else if anomaly.score >= 0.4 {
            AnomalySeverity::Warning
        } else {
            AnomalySeverity::Info
        };

        if derived_severity > anomaly.severity {
            anomaly.severity = derived_severity;
        }
    }
}

// ---------------------------------------------------------------------------
// Factor 1: Kind Weight
// ---------------------------------------------------------------------------

fn kind_weight(kind: AnomalyKind) -> f64 {
    match kind {
        AnomalyKind::ErrorRateTrend => 0.9,
        AnomalyKind::RootCauseCandidate => 0.85,
        AnomalyKind::SeverityEscalation => 0.8,
        AnomalyKind::UnexpectedLoop => 0.8,
        AnomalyKind::MissingStep => 0.7,
        AnomalyKind::CrossSourceCorrelation => 0.7,
        AnomalyKind::OutOfOrderStep => 0.6,
        AnomalyKind::FrequencySpike => 0.6,
        AnomalyKind::DurationOutlier => 0.5,
        AnomalyKind::DownloadPerformance => 0.5,
        AnomalyKind::OrphanedStart => 0.4,
        AnomalyKind::FrequencyGap => 0.3,
    }
}

// ---------------------------------------------------------------------------
// Factor 2: Frequency
// ---------------------------------------------------------------------------

fn frequency_score(affected_event_ids: &[u64]) -> f64 {
    (affected_event_ids.len() as f64 / 10.0).min(1.0)
}

// ---------------------------------------------------------------------------
// Factor 3: Impact
// ---------------------------------------------------------------------------

fn impact_score(affected_event_ids: &[u64], events: &[IntuneEvent]) -> f64 {
    if affected_event_ids.is_empty() {
        return 0.0;
    }

    let failed_count = affected_event_ids
        .iter()
        .filter(|id| {
            events
                .iter()
                .find(|e| e.id == **id)
                .is_some_and(|e| {
                    matches!(e.status, IntuneStatus::Failed | IntuneStatus::Timeout)
                })
        })
        .count();

    failed_count as f64 / affected_event_ids.len().max(1) as f64
}

// ---------------------------------------------------------------------------
// Factor 4: Confidence
// ---------------------------------------------------------------------------

fn confidence_score(
    layer: DetectionLayer,
    statistical_context: &Option<super::models::StatisticalContext>,
) -> f64 {
    match layer {
        DetectionLayer::FlowModel => 1.0,
        DetectionLayer::Statistical => {
            if let Some(ctx) = statistical_context {
                (ctx.z_score.abs() / 4.0).min(1.0)
            } else {
                0.7
            }
        }
        DetectionLayer::Escalation => 0.8,
        DetectionLayer::CrossSource => 0.7,
    }
}

// ---------------------------------------------------------------------------
// Factor 5: Recency
// ---------------------------------------------------------------------------

/// Pre-computed timeline bounds for recency scoring.
struct TimelineBounds {
    first: Option<NaiveDateTime>,
    last: Option<NaiveDateTime>,
}

fn compute_timeline_bounds(events: &[IntuneEvent]) -> TimelineBounds {
    let mut first: Option<NaiveDateTime> = None;
    let mut last: Option<NaiveDateTime> = None;

    for event in events {
        if let Some(ref ts) = event.start_time {
            if let Some(parsed) = timeline::parse_timestamp(ts) {
                first = Some(first.map_or(parsed, |f: NaiveDateTime| f.min(parsed)));
                last = Some(last.map_or(parsed, |l: NaiveDateTime| l.max(parsed)));
            }
        }
        if let Some(ref ts) = event.end_time {
            if let Some(parsed) = timeline::parse_timestamp(ts) {
                first = Some(first.map_or(parsed, |f: NaiveDateTime| f.min(parsed)));
                last = Some(last.map_or(parsed, |l: NaiveDateTime| l.max(parsed)));
            }
        }
    }

    TimelineBounds { first, last }
}

fn recency_score(
    anomaly: &Anomaly,
    events: &[IntuneEvent],
    bounds: &TimelineBounds,
) -> f64 {
    let (first, last) = match (bounds.first, bounds.last) {
        (Some(f), Some(l)) => (f, l),
        _ => return 0.5,
    };

    let total_span = (last - first).num_seconds() as f64;
    if total_span <= 0.0 {
        return 0.5;
    }

    // Try to get a representative timestamp for the anomaly:
    // 1. The anomaly's time_range.end
    // 2. The first affected event's start_time
    let anomaly_time: Option<NaiveDateTime> = anomaly
        .time_range
        .as_ref()
        .and_then(|tr| timeline::parse_timestamp(&tr.end))
        .or_else(|| {
            anomaly
                .affected_event_ids
                .first()
                .and_then(|id| events.iter().find(|e| e.id == *id))
                .and_then(|e| e.start_time.as_deref())
                .and_then(timeline::parse_timestamp)
        });

    match anomaly_time {
        Some(at) => {
            let age_from_newest = (last - at).num_seconds() as f64;
            let raw = 1.0 - (age_from_newest / total_span);
            raw.clamp(0.3, 1.0)
        }
        None => 0.5,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::anomaly::models::{
        Anomaly, AnomalyKind, AnomalySeverity, AnomalyTimeRange, DetectionLayer,
    };
    use crate::intune::models::{IntuneEvent, IntuneEventType, IntuneStatus};

    /// Helper to build a minimal `IntuneEvent`.
    fn make_event(id: u64, status: IntuneStatus, start_time: Option<&str>) -> IntuneEvent {
        IntuneEvent {
            id,
            event_type: IntuneEventType::Win32App,
            name: format!("event-{id}"),
            guid: None,
            status,
            start_time: start_time.map(String::from),
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: String::new(),
            source_file: "test.log".to_string(),
            line_number: 1,
        }
    }

    /// Helper to build a minimal `Anomaly`.
    fn make_anomaly(
        kind: AnomalyKind,
        layer: DetectionLayer,
        severity: AnomalySeverity,
        affected_ids: Vec<u64>,
        time_range: Option<AnomalyTimeRange>,
    ) -> Anomaly {
        Anomaly {
            id: "test-anomaly".to_string(),
            kind,
            severity,
            score: 0.0,
            title: "Test".to_string(),
            description: "Test anomaly".to_string(),
            affected_event_ids: affected_ids,
            affected_event_log_ids: Vec::new(),
            detection_layer: layer,
            score_factors: Vec::new(),
            time_range,
            flow_context: None,
            statistical_context: None,
            enriched_error_codes: vec![],
        }
    }

    #[test]
    fn test_score_range() {
        // Create events covering a timeline.
        let events = vec![
            make_event(1, IntuneStatus::Success, Some("2025-01-01 00:00:00.000")),
            make_event(2, IntuneStatus::Failed, Some("2025-01-01 12:00:00.000")),
            make_event(3, IntuneStatus::Success, Some("2025-01-02 00:00:00.000")),
        ];

        // Build anomalies of several kinds to exercise different weight paths.
        let mut anomalies = vec![
            make_anomaly(
                AnomalyKind::ErrorRateTrend,
                DetectionLayer::Statistical,
                AnomalySeverity::Info,
                vec![1, 2, 3],
                None,
            ),
            make_anomaly(
                AnomalyKind::FrequencyGap,
                DetectionLayer::FlowModel,
                AnomalySeverity::Info,
                vec![1],
                None,
            ),
            make_anomaly(
                AnomalyKind::OrphanedStart,
                DetectionLayer::CrossSource,
                AnomalySeverity::Info,
                vec![],
                None,
            ),
        ];

        score_anomalies(&mut anomalies, &events);

        for a in &anomalies {
            assert!(
                (0.0..=1.0).contains(&a.score),
                "Score {} out of range for {:?}",
                a.score,
                a.kind
            );
            assert_eq!(
                a.score_factors.len(),
                5,
                "Expected 5 score factors, got {}",
                a.score_factors.len()
            );
        }
    }

    #[test]
    fn test_high_impact_raises_score() {
        let events = vec![
            make_event(1, IntuneStatus::Failed, Some("2025-01-01 00:00:00.000")),
            make_event(2, IntuneStatus::Failed, Some("2025-01-01 01:00:00.000")),
            make_event(3, IntuneStatus::Timeout, Some("2025-01-01 02:00:00.000")),
            make_event(4, IntuneStatus::Success, Some("2025-01-01 03:00:00.000")),
            make_event(5, IntuneStatus::Success, Some("2025-01-01 04:00:00.000")),
            make_event(6, IntuneStatus::Success, Some("2025-01-01 05:00:00.000")),
        ];

        let mut all_failed = make_anomaly(
            AnomalyKind::MissingStep,
            DetectionLayer::FlowModel,
            AnomalySeverity::Info,
            vec![1, 2, 3],
            None,
        );

        let mut all_success = make_anomaly(
            AnomalyKind::MissingStep,
            DetectionLayer::FlowModel,
            AnomalySeverity::Info,
            vec![4, 5, 6],
            None,
        );

        score_anomalies(std::slice::from_mut(&mut all_failed), &events);
        score_anomalies(std::slice::from_mut(&mut all_success), &events);

        assert!(
            all_failed.score > all_success.score,
            "All-failed score ({}) should exceed all-success score ({})",
            all_failed.score,
            all_success.score
        );
    }

    #[test]
    fn test_severity_assignment() {
        let events = vec![
            make_event(1, IntuneStatus::Failed, Some("2025-01-01 00:00:00.000")),
            make_event(2, IntuneStatus::Failed, Some("2025-01-01 01:00:00.000")),
            make_event(3, IntuneStatus::Failed, Some("2025-01-01 02:00:00.000")),
            make_event(4, IntuneStatus::Failed, Some("2025-01-01 03:00:00.000")),
            make_event(5, IntuneStatus::Failed, Some("2025-01-01 04:00:00.000")),
            make_event(6, IntuneStatus::Failed, Some("2025-01-01 05:00:00.000")),
            make_event(7, IntuneStatus::Failed, Some("2025-01-01 06:00:00.000")),
            make_event(8, IntuneStatus::Failed, Some("2025-01-01 07:00:00.000")),
            make_event(9, IntuneStatus::Failed, Some("2025-01-01 08:00:00.000")),
            make_event(10, IntuneStatus::Failed, Some("2025-01-01 09:00:00.000")),
        ];

        // High-weight kind + many failed events => should be Critical.
        let mut critical_anomaly = make_anomaly(
            AnomalyKind::ErrorRateTrend,
            DetectionLayer::FlowModel,
            AnomalySeverity::Info,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            None,
        );

        // Low-weight kind + no affected events => should be Info.
        let mut info_anomaly = make_anomaly(
            AnomalyKind::FrequencyGap,
            DetectionLayer::CrossSource,
            AnomalySeverity::Info,
            vec![],
            None,
        );

        score_anomalies(std::slice::from_mut(&mut critical_anomaly), &events);
        score_anomalies(std::slice::from_mut(&mut info_anomaly), &events);

        assert_eq!(
            critical_anomaly.severity,
            AnomalySeverity::Critical,
            "High-impact anomaly should be Critical, score={}",
            critical_anomaly.score
        );
        assert_eq!(
            info_anomaly.severity,
            AnomalySeverity::Info,
            "Low-impact anomaly should be Info, score={}",
            info_anomaly.score
        );

        // Verify the score-derived severity never downgrades an existing higher severity.
        let mut pre_set_critical = make_anomaly(
            AnomalyKind::FrequencyGap,
            DetectionLayer::CrossSource,
            AnomalySeverity::Critical,
            vec![],
            None,
        );
        score_anomalies(std::slice::from_mut(&mut pre_set_critical), &events);
        assert_eq!(
            pre_set_critical.severity,
            AnomalySeverity::Critical,
            "Pre-set Critical should not be downgraded"
        );
    }
}
