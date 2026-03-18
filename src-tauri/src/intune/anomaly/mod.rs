pub mod flow_model;
pub mod models;
pub mod scoring;
pub mod statistical;

use models::AnomalyAnalysis;

use super::models::{DownloadStat, EventLogAnalysis, IntuneEvent};

/// Run the full anomaly analysis pipeline on structured Intune data.
///
/// This is the main entry point called from the Intune analysis pipeline.
/// It runs all detection layers and produces a scored, sorted result.
pub fn run_anomaly_analysis(
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
    _event_log_analysis: Option<&EventLogAnalysis>,
) -> AnomalyAnalysis {
    let mut analysis = AnomalyAnalysis::default();

    // Layer 1 – Flow model: lifecycle deviation + causal chains
    let (flow_anomalies, causal_chains) = flow_model::detect_flow_anomalies(events);
    analysis.anomalies.extend(flow_anomalies);
    analysis.causal_chains = causal_chains;

    // Layer 2 – Statistical: duration/frequency outliers, download perf, error trends
    let stat_anomalies = statistical::detect_statistical_anomalies(events, downloads);
    analysis.anomalies.extend(stat_anomalies);

    // TODO: Layer 3 – Escalation
    // TODO: Layer 4 – Cross-source

    // Layer 5 – Scoring: compute composite scores and assign severity
    scoring::score_anomalies(&mut analysis.anomalies, events);

    // Sort anomalies by score descending
    analysis
        .anomalies
        .sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    analysis.compute_summary();
    analysis
}
