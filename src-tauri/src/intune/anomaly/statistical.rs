use std::collections::HashMap;

use chrono::NaiveDateTime;

use super::models::{
    Anomaly, AnomalyKind, AnomalySeverity, AnomalyTimeRange, DetectionLayer, StatisticalContext,
};
use crate::intune::models::{DownloadStat, IntuneEvent, IntuneEventType, IntuneStatus};
use crate::intune::timeline;

// ---------------------------------------------------------------------------
// Welford's online algorithm for numerically stable mean/stddev
// ---------------------------------------------------------------------------

struct WelfordState {
    count: usize,
    mean: f64,
    m2: f64,
}

impl WelfordState {
    fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn stddev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        (self.m2 / (self.count - 1) as f64).sqrt()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a phase tag from an event name (e.g. "Download", "Install") or
/// fall back to the event type debug name.
fn phase_tag(event: &IntuneEvent) -> String {
    let keywords = [
        "Download",
        "Install",
        "Detection",
        "Compliance",
        "Applicability",
        "Uninstall",
        "Execution",
    ];
    for kw in &keywords {
        if event.name.contains(kw) {
            return (*kw).to_string();
        }
    }
    format!("{:?}", event.event_type)
}

/// Format an event type as a stable string key.
fn event_type_key(et: IntuneEventType) -> String {
    format!("{:?}", et)
}

/// Parse the best available timestamp from an event (prefer start_time).
fn event_timestamp(event: &IntuneEvent) -> Option<NaiveDateTime> {
    event
        .start_time
        .as_deref()
        .and_then(timeline::parse_timestamp)
        .or_else(|| {
            event
                .end_time
                .as_deref()
                .and_then(timeline::parse_timestamp)
        })
}

/// Compute a simple anomaly score from the z-score (clamped to 0.0-1.0).
fn score_from_z(z: f64) -> f64 {
    // Map |z| 2..5 to 0.4..1.0
    let abs_z = z.abs();
    ((abs_z - 2.0) / 3.0 * 0.6 + 0.4).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect statistical anomalies across Intune events and download stats.
///
/// This implements Layer 2 of the anomaly detection pipeline, covering:
/// 1. Duration outliers (z-score on per-phase durations)
/// 2. Frequency spikes and gaps (event count per time window)
/// 3. Download performance outliers and stalled downloads
/// 4. Error rate trending (monotonically increasing failure rate)
pub fn detect_statistical_anomalies(
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    detect_duration_outliers(events, &mut anomalies);

    // Parse all event timestamps once for the time-windowed analyses.
    let parsed_timestamps = collect_event_timestamps(events);
    if let Some((window_size, window_count, span_start)) =
        compute_window_params(&parsed_timestamps)
    {
        detect_frequency_anomalies(
            events,
            &parsed_timestamps,
            window_size,
            window_count,
            span_start,
            &mut anomalies,
        );
        detect_error_rate_trend(
            events,
            &parsed_timestamps,
            window_size,
            window_count,
            span_start,
            &mut anomalies,
        );
    }

    detect_download_outliers(downloads, &mut anomalies);

    anomalies
}

// ---------------------------------------------------------------------------
// 1. Duration Outliers
// ---------------------------------------------------------------------------

fn detect_duration_outliers(events: &[IntuneEvent], anomalies: &mut Vec<Anomaly>) {
    // Group events by (event_type, phase_tag) where duration_secs is present.
    let mut groups: HashMap<(IntuneEventType, String), Vec<(usize, &IntuneEvent)>> = HashMap::new();

    for (idx, event) in events.iter().enumerate() {
        if event.duration_secs.is_some() {
            let key = (event.event_type, phase_tag(event));
            groups.entry(key).or_default().push((idx, event));
        }
    }

    for ((et, tag), group) in &groups {
        if group.len() < 5 {
            continue;
        }

        // Compute mean and stddev via Welford.
        let mut state = WelfordState::new();
        for &(_, event) in group {
            if let Some(d) = event.duration_secs {
                state.update(d);
            }
        }

        let stddev = state.stddev();
        if stddev < f64::EPSILON {
            continue;
        }

        for &(idx, event) in group {
            if let Some(duration) = event.duration_secs {
                let z = (duration - state.mean) / stddev;
                if z.abs() > 2.0 {
                    let is_failed = matches!(
                        event.status,
                        IntuneStatus::Failed | IntuneStatus::Timeout
                    );
                    let severity = if z.abs() > 3.0 && is_failed {
                        AnomalySeverity::Critical
                    } else {
                        AnomalySeverity::Warning
                    };

                    let id =
                        format!("stat-duration-{}-{}-{}", event_type_key(*et), tag, idx);

                    let title = format!(
                        "Duration outlier: {} ({:.1}s, z={:.2})",
                        event.name, duration, z
                    );
                    let description = format!(
                        "Event \"{}\" took {:.1}s (mean={:.1}s, stddev={:.1}s, z-score={:.2}). \
                         This is significantly {} than typical for {} events.",
                        event.name,
                        duration,
                        state.mean,
                        stddev,
                        z,
                        if z > 0.0 { "longer" } else { "shorter" },
                        tag
                    );

                    anomalies.push(Anomaly {
                        id,
                        kind: AnomalyKind::DurationOutlier,
                        severity,
                        score: score_from_z(z),
                        title,
                        description,
                        affected_event_ids: vec![event.id],
                        affected_event_log_ids: Vec::new(),
                        detection_layer: DetectionLayer::Statistical,
                        score_factors: Vec::new(),
                        time_range: build_time_range(event.start_time.as_deref(), event.end_time.as_deref()),
                        flow_context: None,
                        statistical_context: Some(StatisticalContext {
                            metric_name: format!("duration_secs({}/{})", event_type_key(*et), tag),
                            observed_value: duration,
                            population_mean: state.mean,
                            population_stddev: stddev,
                            z_score: z,
                        }),
                        enriched_error_codes: vec![],
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Frequency Analysis
// ---------------------------------------------------------------------------

/// Collect parsed timestamps for all events that have one.
fn collect_event_timestamps(events: &[IntuneEvent]) -> Vec<(usize, NaiveDateTime)> {
    events
        .iter()
        .enumerate()
        .filter_map(|(i, e)| event_timestamp(e).map(|ts| (i, ts)))
        .collect()
}

/// Compute window parameters: (window_size_secs, window_count, span_start).
fn compute_window_params(
    parsed: &[(usize, NaiveDateTime)],
) -> Option<(f64, usize, NaiveDateTime)> {
    if parsed.is_empty() {
        return None;
    }
    let min_ts = parsed.iter().map(|(_, ts)| *ts).min().unwrap();
    let max_ts = parsed.iter().map(|(_, ts)| *ts).max().unwrap();
    let span_secs = (max_ts - min_ts).num_seconds() as f64;
    if span_secs <= 0.0 {
        return None;
    }
    let window_size = (span_secs / 20.0).max(300.0);
    let window_count = ((span_secs / window_size).ceil() as usize).max(1);
    Some((window_size, window_count, min_ts))
}

fn detect_frequency_anomalies(
    events: &[IntuneEvent],
    parsed: &[(usize, NaiveDateTime)],
    window_size: f64,
    window_count: usize,
    span_start: NaiveDateTime,
    anomalies: &mut Vec<Anomaly>,
) {
    // Build per-event-type window counts.
    let mut type_windows: HashMap<IntuneEventType, Vec<u32>> = HashMap::new();

    for &(idx, ts) in parsed {
        let offset_secs = (ts - span_start).num_seconds() as f64;
        let window_idx = ((offset_secs / window_size) as usize).min(window_count - 1);
        let et = events[idx].event_type;
        let counts = type_windows
            .entry(et)
            .or_insert_with(|| vec![0u32; window_count]);
        counts[window_idx] += 1;
    }

    for (et, counts) in &type_windows {
        if counts.is_empty() {
            continue;
        }

        let mut state = WelfordState::new();
        for &c in counts {
            state.update(c as f64);
        }
        let stddev = state.stddev();

        // Frequency Spikes
        if stddev > f64::EPSILON {
            let threshold = state.mean + 2.0 * stddev;
            for (wi, &count) in counts.iter().enumerate() {
                if (count as f64) > threshold {
                    let z = (count as f64 - state.mean) / stddev;
                    let window_start_secs = wi as f64 * window_size;
                    let window_end_secs = window_start_secs + window_size;

                    let start_ts = span_start
                        + chrono::Duration::seconds(window_start_secs as i64);
                    let end_ts = span_start
                        + chrono::Duration::seconds(window_end_secs as i64);

                    anomalies.push(Anomaly {
                        id: format!("stat-freq-spike-{}-{}", event_type_key(*et), wi),
                        kind: AnomalyKind::FrequencySpike,
                        severity: AnomalySeverity::Warning,
                        score: score_from_z(z),
                        title: format!(
                            "Frequency spike: {} {:?} events in window {}",
                            count, et, wi
                        ),
                        description: format!(
                            "{} {:?} events occurred in a {:.0}s window \
                             (mean={:.1}, stddev={:.1}, z={:.2}). This burst \
                             may indicate retry storms or cascading failures.",
                            count, et, window_size, state.mean, stddev, z
                        ),
                        affected_event_ids: Vec::new(),
                        affected_event_log_ids: Vec::new(),
                        detection_layer: DetectionLayer::Statistical,
                        score_factors: Vec::new(),
                        time_range: Some(AnomalyTimeRange {
                            start: start_ts.format("%Y-%m-%d %H:%M:%S").to_string(),
                            end: end_ts.format("%Y-%m-%d %H:%M:%S").to_string(),
                        }),
                        flow_context: None,
                        statistical_context: Some(StatisticalContext {
                            metric_name: format!("event_count_per_window({})", event_type_key(*et)),
                            observed_value: count as f64,
                            population_mean: state.mean,
                            population_stddev: stddev,
                            z_score: z,
                        }),
                        enriched_error_codes: vec![],
                    });
                }
            }
        }

        // Frequency Gaps: count == 0 with both neighbors > 0
        for wi in 1..counts.len().saturating_sub(1) {
            if counts[wi] == 0 && counts[wi - 1] > 0 && counts[wi + 1] > 0 {
                let window_start_secs = wi as f64 * window_size;
                let window_end_secs = window_start_secs + window_size;

                let start_ts =
                    span_start + chrono::Duration::seconds(window_start_secs as i64);
                let end_ts =
                    span_start + chrono::Duration::seconds(window_end_secs as i64);

                anomalies.push(Anomaly {
                    id: format!("stat-freq-gap-{}-{}", event_type_key(*et), wi),
                    kind: AnomalyKind::FrequencyGap,
                    severity: AnomalySeverity::Info,
                    score: 0.3,
                    title: format!(
                        "Activity gap: no {:?} events in window {}",
                        et, wi
                    ),
                    description: format!(
                        "No {:?} events occurred during a {:.0}s window despite \
                         activity in both neighboring windows. This could indicate \
                         a service interruption or connectivity issue.",
                        et, window_size
                    ),
                    affected_event_ids: Vec::new(),
                    affected_event_log_ids: Vec::new(),
                    detection_layer: DetectionLayer::Statistical,
                    score_factors: Vec::new(),
                    time_range: Some(AnomalyTimeRange {
                        start: start_ts.format("%Y-%m-%d %H:%M:%S").to_string(),
                        end: end_ts.format("%Y-%m-%d %H:%M:%S").to_string(),
                    }),
                    flow_context: None,
                    statistical_context: Some(StatisticalContext {
                        metric_name: format!("event_count_per_window({})", event_type_key(*et)),
                        observed_value: 0.0,
                        population_mean: state.mean,
                        population_stddev: stddev,
                        z_score: if stddev > f64::EPSILON {
                            -state.mean / stddev
                        } else {
                            0.0
                        },
                    }),
                        enriched_error_codes: vec![],
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Download Performance Outliers
// ---------------------------------------------------------------------------

fn detect_download_outliers(downloads: &[DownloadStat], anomalies: &mut Vec<Anomaly>) {
    // Statistical outliers on speed_bps (need N >= 3)
    if downloads.len() >= 3 {
        let mut state = WelfordState::new();
        for dl in downloads {
            state.update(dl.speed_bps);
        }
        let stddev = state.stddev();

        if stddev > f64::EPSILON {
            let low_threshold = state.mean - 2.0 * stddev;
            for (i, dl) in downloads.iter().enumerate() {
                if dl.speed_bps < low_threshold {
                    let z = (dl.speed_bps - state.mean) / stddev;
                    anomalies.push(Anomaly {
                        id: format!("stat-dl-speed-{}", i),
                        kind: AnomalyKind::DownloadPerformance,
                        severity: AnomalySeverity::Warning,
                        score: score_from_z(z),
                        title: format!(
                            "Slow download: {} ({:.0} B/s, z={:.2})",
                            dl.name, dl.speed_bps, z
                        ),
                        description: format!(
                            "Download \"{}\" ({}) at {:.0} B/s is significantly \
                             slower than the population mean of {:.0} B/s \
                             (stddev={:.0}, z={:.2}).",
                            dl.name, dl.content_id, dl.speed_bps, state.mean, stddev, z
                        ),
                        affected_event_ids: Vec::new(),
                        affected_event_log_ids: Vec::new(),
                        detection_layer: DetectionLayer::Statistical,
                        score_factors: Vec::new(),
                        time_range: dl.timestamp.as_deref().map(|ts| AnomalyTimeRange {
                            start: ts.to_string(),
                            end: ts.to_string(),
                        }),
                        flow_context: None,
                        statistical_context: Some(StatisticalContext {
                            metric_name: "download_speed_bps".to_string(),
                            observed_value: dl.speed_bps,
                            population_mean: state.mean,
                            population_stddev: stddev,
                            z_score: z,
                        }),
                        enriched_error_codes: vec![],
                    });
                }
            }
        }
    }

    // Stalled download detection (heuristic, not population-dependent)
    for (i, dl) in downloads.iter().enumerate() {
        if dl.duration_secs > 300.0 && dl.speed_bps < 10240.0 {
            // Check we haven't already flagged this as a statistical outlier
            let already_flagged = anomalies
                .iter()
                .any(|a| a.id == format!("stat-dl-speed-{}", i));

            let id = if already_flagged {
                format!("stat-dl-stalled-{}", i)
            } else {
                format!("stat-dl-speed-{}", i)
            };

            anomalies.push(Anomaly {
                id,
                kind: AnomalyKind::DownloadPerformance,
                severity: AnomalySeverity::Critical,
                score: 0.9,
                title: format!(
                    "Stalled download: {} ({:.0}s at {:.0} B/s)",
                    dl.name, dl.duration_secs, dl.speed_bps
                ),
                description: format!(
                    "Download \"{}\" appears stalled: {:.0}s elapsed with only \
                     {:.0} B/s throughput (< 10 KB/s). This often indicates \
                     network connectivity issues or Delivery Optimization problems.",
                    dl.name, dl.duration_secs, dl.speed_bps
                ),
                affected_event_ids: Vec::new(),
                affected_event_log_ids: Vec::new(),
                detection_layer: DetectionLayer::Statistical,
                score_factors: Vec::new(),
                time_range: dl.timestamp.as_deref().map(|ts| AnomalyTimeRange {
                    start: ts.to_string(),
                    end: ts.to_string(),
                }),
                flow_context: None,
                statistical_context: Some(StatisticalContext {
                    metric_name: "download_stalled".to_string(),
                    observed_value: dl.speed_bps,
                    population_mean: 10240.0,
                    population_stddev: 0.0,
                    z_score: 0.0,
                }),
                        enriched_error_codes: vec![],
            });
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Error Rate Trending
// ---------------------------------------------------------------------------

fn detect_error_rate_trend(
    events: &[IntuneEvent],
    parsed: &[(usize, NaiveDateTime)],
    window_size: f64,
    window_count: usize,
    span_start: NaiveDateTime,
    anomalies: &mut Vec<Anomaly>,
) {
    if window_count < 3 {
        return;
    }

    // Compute per-window: total events and error events.
    let mut totals = vec![0u32; window_count];
    let mut errors = vec![0u32; window_count];

    for &(idx, ts) in parsed {
        let offset_secs = (ts - span_start).num_seconds() as f64;
        let wi = ((offset_secs / window_size) as usize).min(window_count - 1);
        totals[wi] += 1;
        if matches!(
            events[idx].status,
            IntuneStatus::Failed | IntuneStatus::Timeout
        ) {
            errors[wi] += 1;
        }
    }

    // Compute error rates per window.
    let rates: Vec<f64> = totals
        .iter()
        .zip(errors.iter())
        .map(|(&t, &e)| {
            if t > 0 {
                e as f64 / t as f64
            } else {
                0.0
            }
        })
        .collect();

    // Check the last 3 windows for monotonically increasing error rate
    // with the last window exceeding 0.5.
    let n = rates.len();
    if n >= 3 {
        let r1 = rates[n - 3];
        let r2 = rates[n - 2];
        let r3 = rates[n - 1];

        if r1 < r2 && r2 < r3 && r3 > 0.5 {
            let last_window_start = (n - 3) as f64 * window_size;
            let last_window_end = n as f64 * window_size;

            let start_ts =
                span_start + chrono::Duration::seconds(last_window_start as i64);
            let end_ts =
                span_start + chrono::Duration::seconds(last_window_end as i64);

            anomalies.push(Anomaly {
                id: format!("stat-error-trend-{}-{}", n - 3, n - 1),
                kind: AnomalyKind::ErrorRateTrend,
                severity: AnomalySeverity::Critical,
                score: 0.95,
                title: format!(
                    "Increasing error rate: {:.0}% -> {:.0}% -> {:.0}%",
                    r1 * 100.0,
                    r2 * 100.0,
                    r3 * 100.0
                ),
                description: format!(
                    "Error rate is monotonically increasing across the last 3 \
                     time windows ({:.0}% -> {:.0}% -> {:.0}%). The final window \
                     has a {:.0}% failure rate, indicating a deteriorating system \
                     state that may require immediate attention.",
                    r1 * 100.0,
                    r2 * 100.0,
                    r3 * 100.0,
                    r3 * 100.0
                ),
                affected_event_ids: Vec::new(),
                affected_event_log_ids: Vec::new(),
                detection_layer: DetectionLayer::Statistical,
                score_factors: Vec::new(),
                time_range: Some(AnomalyTimeRange {
                    start: start_ts.format("%Y-%m-%d %H:%M:%S").to_string(),
                    end: end_ts.format("%Y-%m-%d %H:%M:%S").to_string(),
                }),
                flow_context: None,
                statistical_context: Some(StatisticalContext {
                    metric_name: "error_rate_trend".to_string(),
                    observed_value: r3,
                    population_mean: rates.iter().sum::<f64>() / rates.len() as f64,
                    population_stddev: 0.0,
                    z_score: 0.0,
                }),
                        enriched_error_codes: vec![],
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn build_time_range(start: Option<&str>, end: Option<&str>) -> Option<AnomalyTimeRange> {
    match (start, end) {
        (Some(s), Some(e)) => Some(AnomalyTimeRange {
            start: s.to_string(),
            end: e.to_string(),
        }),
        (Some(s), None) => Some(AnomalyTimeRange {
            start: s.to_string(),
            end: s.to_string(),
        }),
        (None, Some(e)) => Some(AnomalyTimeRange {
            start: e.to_string(),
            end: e.to_string(),
        }),
        (None, None) => None,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::models::{IntuneEvent, IntuneEventType, IntuneStatus};

    /// Helper to build a minimal IntuneEvent with a duration.
    fn make_event(
        id: u64,
        name: &str,
        event_type: IntuneEventType,
        status: IntuneStatus,
        duration_secs: Option<f64>,
        start_time: Option<&str>,
    ) -> IntuneEvent {
        IntuneEvent {
            id,
            event_type,
            name: name.to_string(),
            guid: None,
            status,
            start_time: start_time.map(|s| s.to_string()),
            end_time: None,
            duration_secs,
            error_code: None,
            detail: String::new(),
            source_file: "test.log".to_string(),
            line_number: 0,
        }
    }

    fn make_download(
        idx: usize,
        speed_bps: f64,
        duration_secs: f64,
        success: bool,
    ) -> DownloadStat {
        DownloadStat {
            content_id: format!("content-{}", idx),
            name: format!("App {}", idx),
            size_bytes: (speed_bps * duration_secs) as u64,
            speed_bps,
            do_percentage: 0.0,
            duration_secs,
            success,
            timestamp: Some("2025-01-15 10:00:00.000".to_string()),
        }
    }

    #[test]
    fn test_duration_outlier_detection() {
        // Create a group of 20 events with similar durations, plus one outlier.
        // A larger population dilutes the outlier's effect on stddev, ensuring
        // the z-score exceeds 3.0 so we get Critical severity.
        let mut events: Vec<IntuneEvent> = (0..20)
            .map(|i| {
                make_event(
                    i,
                    "Download App",
                    IntuneEventType::Win32App,
                    IntuneStatus::Success,
                    Some(10.0 + (i as f64) * 0.2), // 10.0 .. 13.8, tight cluster
                    None,
                )
            })
            .collect();

        // Add a massive outlier.
        events.push(make_event(
            99,
            "Download App",
            IntuneEventType::Win32App,
            IntuneStatus::Failed,
            Some(200.0), // way outside the cluster
            None,
        ));

        let anomalies = detect_statistical_anomalies(&events, &[]);

        let duration_outliers: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::DurationOutlier)
            .collect();

        assert!(
            !duration_outliers.is_empty(),
            "Should detect at least one duration outlier"
        );

        // The outlier event (id=99) should be flagged.
        assert!(
            duration_outliers
                .iter()
                .any(|a| a.affected_event_ids.contains(&99)),
            "Outlier event id=99 should be flagged"
        );

        // Severity should be Critical because z > 3.0 and status is Failed.
        let outlier_99 = duration_outliers
            .iter()
            .find(|a| a.affected_event_ids.contains(&99))
            .unwrap();
        assert_eq!(outlier_99.severity, AnomalySeverity::Critical);

        // Statistical context should be populated.
        let ctx = outlier_99.statistical_context.as_ref().unwrap();
        assert!(ctx.z_score > 2.0, "z-score should exceed 2.0");
        assert!(ctx.population_stddev > 0.0);
    }

    #[test]
    fn test_no_outlier_small_population() {
        // Fewer than 5 events with durations should produce no duration outliers.
        let events: Vec<IntuneEvent> = (0..4)
            .map(|i| {
                make_event(
                    i,
                    "Install Package",
                    IntuneEventType::Win32App,
                    IntuneStatus::Success,
                    Some(if i == 3 { 999.0 } else { 10.0 }),
                    None,
                )
            })
            .collect();

        let anomalies = detect_statistical_anomalies(&events, &[]);

        let duration_outliers: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::DurationOutlier)
            .collect();

        assert!(
            duration_outliers.is_empty(),
            "Groups with N < 5 should not produce duration outliers"
        );
    }

    #[test]
    fn test_download_stalled_detection() {
        let downloads = vec![
            make_download(0, 500_000.0, 30.0, true),   // normal
            make_download(1, 1_000_000.0, 20.0, true),  // normal
            make_download(2, 800_000.0, 25.0, true),    // normal
            make_download(3, 5000.0, 600.0, false),      // stalled: > 300s AND < 10240 B/s
        ];

        let anomalies = detect_statistical_anomalies(&[], &downloads);

        let stalled: Vec<_> = anomalies
            .iter()
            .filter(|a| {
                a.kind == AnomalyKind::DownloadPerformance
                    && a.severity == AnomalySeverity::Critical
            })
            .collect();

        assert!(
            !stalled.is_empty(),
            "Should detect the stalled download (>300s, <10KB/s)"
        );

        // Verify the stalled anomaly mentions "stalled" or has critical severity.
        assert!(
            stalled.iter().any(|a| a.title.contains("Stalled") || a.title.contains("stalled")),
            "Stalled download anomaly title should mention 'stalled'"
        );
    }

    #[test]
    fn test_error_rate_trend() {
        // Create events spread across enough time to generate windows,
        // with increasing error rates in the last 3 windows.
        //
        // We'll use 20 windows of 300s each = 6000s total span.
        // Place events at specific timestamps to control the error rates.
        let _base = "2025-01-15 10:00:00.000";

        let mut events = Vec::new();
        let mut id_counter: u64 = 0;

        // Fill early windows (0..17) with mostly successful events.
        for wi in 0..17 {
            let offset = wi * 300 + 50; // middle of each window
            let ts = format!("2025-01-15 {:02}:{:02}:00.000", 10 + offset / 3600, (offset % 3600) / 60);
            for _ in 0..10 {
                events.push(make_event(
                    id_counter,
                    "Sync",
                    IntuneEventType::SyncSession,
                    IntuneStatus::Success,
                    None,
                    Some(&ts),
                ));
                id_counter += 1;
            }
        }

        // Window 17: 10% error rate (low)
        let ts17_offset = 17 * 300 + 50;
        let ts17 = format!(
            "2025-01-15 {:02}:{:02}:00.000",
            10 + ts17_offset / 3600,
            (ts17_offset % 3600) / 60
        );
        for i in 0..10 {
            let status = if i < 1 {
                IntuneStatus::Failed
            } else {
                IntuneStatus::Success
            };
            events.push(make_event(
                id_counter,
                "Sync",
                IntuneEventType::SyncSession,
                status,
                None,
                Some(&ts17),
            ));
            id_counter += 1;
        }

        // Window 18: 30% error rate
        let ts18_offset = 18 * 300 + 50;
        let ts18 = format!(
            "2025-01-15 {:02}:{:02}:00.000",
            10 + ts18_offset / 3600,
            (ts18_offset % 3600) / 60
        );
        for i in 0..10 {
            let status = if i < 3 {
                IntuneStatus::Failed
            } else {
                IntuneStatus::Success
            };
            events.push(make_event(
                id_counter,
                "Sync",
                IntuneEventType::SyncSession,
                status,
                None,
                Some(&ts18),
            ));
            id_counter += 1;
        }

        // Window 19: 70% error rate (> 0.5, and monotonically increasing)
        let ts19_offset = 19 * 300 + 50;
        let ts19 = format!(
            "2025-01-15 {:02}:{:02}:00.000",
            10 + ts19_offset / 3600,
            (ts19_offset % 3600) / 60
        );
        for i in 0..10 {
            let status = if i < 7 {
                IntuneStatus::Failed
            } else {
                IntuneStatus::Success
            };
            events.push(make_event(
                id_counter,
                "Sync",
                IntuneEventType::SyncSession,
                status,
                None,
                Some(&ts19),
            ));
            id_counter += 1;
        }

        // Need a final timestamp to anchor the span end.
        let ts_end = format!(
            "2025-01-15 {:02}:{:02}:00.000",
            10 + (20 * 300) / 3600,
            ((20 * 300) % 3600) / 60
        );
        events.push(make_event(
            id_counter,
            "Sync",
            IntuneEventType::SyncSession,
            IntuneStatus::Success,
            None,
            Some(&ts_end),
        ));

        let anomalies = detect_statistical_anomalies(&events, &[]);

        let trend: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::ErrorRateTrend)
            .collect();

        assert!(
            !trend.is_empty(),
            "Should detect increasing error rate trend"
        );

        assert_eq!(
            trend[0].severity,
            AnomalySeverity::Critical,
            "Error rate trend should be Critical severity"
        );

        let ctx = trend[0].statistical_context.as_ref().unwrap();
        assert!(
            ctx.observed_value > 0.5,
            "Last window error rate should exceed 0.5"
        );
    }
}
