export type IntuneEventType =
  | "Win32App"
  | "WinGetApp"
  | "PowerShellScript"
  | "Remediation"
  | "Esp"
  | "SyncSession"
  | "PolicyEvaluation"
  | "ContentDownload"
  | "Other";

export type IntuneStatus =
  | "Success"
  | "Failed"
  | "InProgress"
  | "Pending"
  | "Timeout"
  | "Unknown";

export interface IntuneEvent {
  id: number;
  eventType: IntuneEventType;
  name: string;
  guid: string | null;
  status: IntuneStatus;
  startTime: string | null;
  endTime: string | null;
  durationSecs: number | null;
  errorCode: string | null;
  detail: string;
  sourceFile: string;
  lineNumber: number;
}

export interface DownloadStat {
  contentId: string;
  name: string;
  sizeBytes: number;
  speedBps: number;
  doPercentage: number;
  durationSecs: number;
  success: boolean;
  timestamp: string | null;
}

export interface IntuneTimestampBounds {
  firstTimestamp: string | null;
  lastTimestamp: string | null;
}

export interface IntuneDiagnosticsFileCoverage {
  filePath: string;
  eventCount: number;
  downloadCount: number;
  timestampBounds: IntuneTimestampBounds | null;
  isRotatedSegment: boolean;
  rotationGroup: string | null;
}

export interface IntuneDominantSource {
  filePath: string;
  eventCount: number;
  eventShare: number | null;
}

export type IntuneLogSourceKind =
  | "appworkload"
  | "appactionprocessor"
  | "agentexecutor"
  | "healthscripts"
  | "clienthealth"
  | "clientcertcheck"
  | "devicehealthmonitoring"
  | "sensor"
  | "win32appinventory"
  | "intunemanagementextension"
  | "other";

export interface IntuneSourceFamilySummary {
  kind: IntuneLogSourceKind;
  label: string;
  fileCount: number;
  contributingFileCount: number;
  eventCount: number;
  downloadCount: number;
}

export interface IntuneDiagnosticsCoverage {
  files: IntuneDiagnosticsFileCoverage[];
  timestampBounds: IntuneTimestampBounds | null;
  hasRotatedLogs: boolean;
  dominantSource: IntuneDominantSource | null;
}

export type IntuneDiagnosticsConfidenceLevel =
  | "Unknown"
  | "Low"
  | "Medium"
  | "High";

export interface IntuneDiagnosticsConfidence {
  level: IntuneDiagnosticsConfidenceLevel;
  score: number | null;
  reasons: string[];
}

export interface IntuneRepeatedFailureGroup {
  id: string;
  name: string;
  eventType: IntuneEventType;
  errorCode: string | null;
  occurrences: number;
  timestampBounds: IntuneTimestampBounds | null;
  sourceFiles: string[];
  sampleEventIds: number[];
}

export interface IntuneSummary {
  totalEvents: number;
  win32Apps: number;
  wingetApps: number;
  scripts: number;
  remediations: number;
  succeeded: number;
  failed: number;
  inProgress: number;
  pending: number;
  timedOut: number;
  totalDownloads: number;
  successfulDownloads: number;
  failedDownloads: number;
  failedScripts: number;
  logTimeSpan: string | null;
}

export type IntuneDiagnosticSeverity = "Info" | "Warning" | "Error";

export interface IntuneDiagnosticInsight {
  id: string;
  severity: IntuneDiagnosticSeverity;
  title: string;
  summary: string;
  evidence: string[];
  nextChecks: string[];
  suggestedFixes: string[];
}

export interface IntuneSourceContext {
  analyzedPath: string | null;
  includedFiles: string[];
}

export interface IntuneSourceSelection {
  filePath: string | null;
  lineNumber: number | null;
}

export interface IntuneTimelineScope {
  filePath: string | null;
}

export type IntuneAnalysisPhase = "idle" | "analyzing" | "ready" | "empty" | "error";

export type IntuneAnalysisSourceKind = "file" | "folder" | "known" | "unknown";

export interface IntuneAnalysisState {
  phase: IntuneAnalysisPhase;
  requestedPath: string | null;
  requestedKind: IntuneAnalysisSourceKind | null;
  message: string;
  detail: string | null;
  lastError: string | null;
}

export interface IntuneAnalysisResult {
  events: IntuneEvent[];
  downloads: DownloadStat[];
  summary: IntuneSummary;
  diagnostics: IntuneDiagnosticInsight[];
  sourceFile: string;
  sourceFiles: string[];
  diagnosticsCoverage: IntuneDiagnosticsCoverage;
  diagnosticsConfidence: IntuneDiagnosticsConfidence;
  repeatedFailures: IntuneRepeatedFailureGroup[];
}

export interface IntuneResultMetadata {
  diagnosticsCoverage: IntuneDiagnosticsCoverage;
  diagnosticsConfidence: IntuneDiagnosticsConfidence;
  repeatedFailures: IntuneRepeatedFailureGroup[];
}
