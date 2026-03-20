pub mod cross_source;
pub mod escalation;
pub mod flow_model;
pub mod knowledge_base;
pub mod models;
pub mod remediation;
pub mod scoring;
pub mod statistical;

use models::AnomalyAnalysis;

use super::models::{DownloadStat, EventLogAnalysis, IntuneEvent};
use crate::parser::etl::EtlEvent;

/// Run the full anomaly analysis pipeline on structured Intune data.
///
/// This is the main entry point called from the Intune analysis pipeline.
/// It runs all detection layers and produces a scored, sorted result.
pub fn run_anomaly_analysis(
    events: &[IntuneEvent],
    downloads: &[DownloadStat],
    event_log_analysis: Option<&EventLogAnalysis>,
    etl_events: Option<&[EtlEvent]>,
) -> AnomalyAnalysis {
    let mut analysis = AnomalyAnalysis::default();

    // Layer 1 – Flow model: lifecycle deviation + causal chains
    let (flow_anomalies, causal_chains) = flow_model::detect_flow_anomalies(events);
    analysis.anomalies.extend(flow_anomalies);
    analysis.causal_chains = causal_chains;

    // Layer 2 – Statistical: duration/frequency outliers, download perf, error trends
    let stat_anomalies = statistical::detect_statistical_anomalies(events, downloads);
    analysis.anomalies.extend(stat_anomalies);

    // Layer 3 – Escalation: severity escalation chains
    let escalation_anomalies = escalation::detect_escalation_anomalies(events);
    analysis.anomalies.extend(escalation_anomalies);
    // Layer 4 – Cross-source: correlate failures across log sources
    let cross_source_anomalies = cross_source::detect_cross_source_anomalies(events, event_log_analysis, etl_events);
    analysis.anomalies.extend(cross_source_anomalies);

    // Layer 5 – Scoring: compute composite scores and assign severity
    scoring::score_anomalies(&mut analysis.anomalies, events);

    // Post-process: enrich error codes in anomaly descriptions
    for anomaly in &mut analysis.anomalies {
        let (enriched_desc, codes) = remediation::enrich_error_codes(&anomaly.description);
        if !codes.is_empty() {
            anomaly.description = enriched_desc;
            anomaly.enriched_error_codes = codes;
        }
    }

    // Sort anomalies by score descending
    analysis
        .anomalies
        .sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    analysis.compute_summary();
    analysis
}
