use serde::{Deserialize, Serialize};

/// The kind of anomaly detected by the analysis engine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    /// Expected lifecycle step never occurred.
    MissingStep,
    /// Step happened before its prerequisite.
    OutOfOrderStep,
    /// Start event with no matching end.
    OrphanedStart,
    /// Same step repeated more than threshold times.
    UnexpectedLoop,
    /// Duration exceeds population mean + 2*stddev.
    DurationOutlier,
    /// Event count per window exceeds threshold.
    FrequencySpike,
    /// Expected periodic events missing from window.
    FrequencyGap,
    /// Download speed/DO% outside normal range.
    DownloadPerformance,
    /// Error rate increasing across consecutive windows.
    ErrorRateTrend,
    /// Info → Warning → Error chain detected.
    SeverityEscalation,
    /// Normal event in source A coincides with failure in source B.
    CrossSourceCorrelation,
    /// Event consistently precedes failures.
    RootCauseCandidate,
}

impl AnomalyKind {
    /// Human-readable label for display.
    pub fn display_label(&self) -> &'static str {
        match self {
            Self::MissingStep => "Missing Step",
            Self::OutOfOrderStep => "Out of Order",
            Self::OrphanedStart => "Orphaned Start",
            Self::UnexpectedLoop => "Unexpected Loop",
            Self::DurationOutlier => "Duration Outlier",
            Self::FrequencySpike => "Frequency Spike",
            Self::FrequencyGap => "Frequency Gap",
            Self::DownloadPerformance => "Download Issue",
            Self::ErrorRateTrend => "Error Rate Trend",
            Self::SeverityEscalation => "Severity Escalation",
            Self::CrossSourceCorrelation => "Cross-Source",
            Self::RootCauseCandidate => "Root Cause",
        }
    }
}

/// Severity of the anomaly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnomalySeverity {
    Info,
    Warning,
    Critical,
}

/// Which detection layer produced this anomaly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DetectionLayer {
    FlowModel,
    Statistical,
    Escalation,
    CrossSource,
}

/// A factor contributing to the composite anomaly score.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreFactor {
    pub factor: String,
    pub weight: f64,
    pub value: f64,
    pub explanation: String,
}

/// Timestamp range for an anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyTimeRange {
    pub start: String,
    pub end: String,
}

/// Context for flow-model anomalies (missing/out-of-order steps).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowAnomalyContext {
    pub expected_step: String,
    pub actual_step: Option<String>,
    pub lifecycle: String,
    pub subject_guid: Option<String>,
}

/// Context for statistical anomalies (duration/frequency outliers).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticalContext {
    pub metric_name: String,
    pub observed_value: f64,
    pub population_mean: f64,
    pub population_stddev: f64,
    pub z_score: f64,
}

/// A single detected anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anomaly {
    pub id: String,
    pub kind: AnomalyKind,
    pub severity: AnomalySeverity,
    /// Composite anomaly score 0.0–1.0.
    pub score: f64,
    pub title: String,
    pub description: String,
    /// IDs of IntuneEvents involved.
    pub affected_event_ids: Vec<u64>,
    /// IDs of EventLogEntries involved.
    #[serde(default)]
    pub affected_event_log_ids: Vec<u64>,
    pub detection_layer: DetectionLayer,
    pub score_factors: Vec<ScoreFactor>,
    pub time_range: Option<AnomalyTimeRange>,
    pub flow_context: Option<FlowAnomalyContext>,
    pub statistical_context: Option<StatisticalContext>,
    /// Error codes found in this anomaly's description, enriched with human-readable names.
    #[serde(default)]
    pub enriched_error_codes: Vec<String>,
}

/// A causal chain linking a root event to a downstream failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CausalChain {
    pub id: String,
    /// First event in the chain (potential root cause).
    pub root_event_id: u64,
    /// Terminal event in the chain (the observed failure).
    pub terminal_event_id: u64,
    /// Ordered sequence of event IDs forming the chain.
    pub chain_event_ids: Vec<u64>,
    /// Confidence in this causal chain, 0.0–1.0.
    pub confidence: f64,
    pub description: String,
}

/// Summary statistics for the anomaly analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AnomalySummary {
    pub total_anomalies: u32,
    pub critical_count: u32,
    pub warning_count: u32,
    pub info_count: u32,
    pub causal_chain_count: u32,
}

/// Top-level anomaly analysis result.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyAnalysis {
    pub anomalies: Vec<Anomaly>,
    pub causal_chains: Vec<CausalChain>,
    pub summary: AnomalySummary,
}

impl AnomalyAnalysis {
    /// Build the summary from the current anomalies and causal chains.
    pub fn compute_summary(&mut self) {
        let mut critical = 0u32;
        let mut warning = 0u32;
        let mut info = 0u32;
        for a in &self.anomalies {
            match a.severity {
                AnomalySeverity::Critical => critical += 1,
                AnomalySeverity::Warning => warning += 1,
                AnomalySeverity::Info => info += 1,
            }
        }
        self.summary = AnomalySummary {
            total_anomalies: self.anomalies.len() as u32,
            critical_count: critical,
            warning_count: warning,
            info_count: info,
            causal_chain_count: self.causal_chains.len() as u32,
        };
    }
}
