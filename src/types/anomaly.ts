export type AnomalyKind =
  | "MissingStep"
  | "OutOfOrderStep"
  | "OrphanedStart"
  | "UnexpectedLoop"
  | "DurationOutlier"
  | "FrequencySpike"
  | "FrequencyGap"
  | "DownloadPerformance"
  | "ErrorRateTrend"
  | "SeverityEscalation"
  | "CrossSourceCorrelation"
  | "RootCauseCandidate";

export type AnomalySeverity = "Info" | "Warning" | "Critical";

export type DetectionLayer = "FlowModel" | "Statistical" | "Escalation" | "CrossSource";

export interface ScoreFactor {
  factor: string;
  weight: number;
  value: number;
  explanation: string;
}

export interface AnomalyTimeRange {
  start: string;
  end: string;
}

export interface FlowAnomalyContext {
  expectedStep: string;
  actualStep: string | null;
  lifecycle: string;
  subjectGuid: string | null;
}

export interface StatisticalContext {
  metricName: string;
  observedValue: number;
  populationMean: number;
  populationStddev: number;
  zScore: number;
}

export interface Anomaly {
  id: string;
  kind: AnomalyKind;
  severity: AnomalySeverity;
  score: number;
  title: string;
  description: string;
  affectedEventIds: number[];
  affectedEventLogIds: number[];
  detectionLayer: DetectionLayer;
  scoreFactors: ScoreFactor[];
  timeRange: AnomalyTimeRange | null;
  flowContext: FlowAnomalyContext | null;
  statisticalContext: StatisticalContext | null;
  enrichedErrorCodes: string[];
}

export interface CausalChain {
  id: string;
  rootEventId: number;
  terminalEventId: number;
  chainEventIds: number[];
  confidence: number;
  description: string;
}

export interface AnomalySummary {
  totalAnomalies: number;
  criticalCount: number;
  warningCount: number;
  infoCount: number;
  causalChainCount: number;
}

export interface AnomalyAnalysis {
  anomalies: Anomaly[];
  causalChains: CausalChain[];
  summary: AnomalySummary;
}
