import type { EvidenceBundleMetadata } from "../../types/evidence";
import type { EventLogAnalysis, IntuneTimestampBounds } from "../../types/event-log";

// Re-export so existing consumers don't break
export type { IntuneTimestampBounds } from "../../types/event-log";

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
  startTimeEpoch: number | null;
  endTimeEpoch: number | null;
  scriptBody?: string | null;
  parentAppGuid?: string | null;
}

export interface DetectionRuleMetadata {
  detectionType: number;
  scriptBody?: string | null;
  enforceSignatureCheck?: boolean | null;
  runAs32Bit?: boolean | null;
}

export interface ReturnCodeEntry {
  returnCode: number;
  type: number;
}

export interface AppPolicyMetadata {
  id: string;
  name: string;
  intent?: number | null;
  targetType?: number | null;
  installCommandLine?: string | null;
  uninstallCommandLine?: string | null;
  detectionRules: DetectionRuleMetadata[];
  returnCodes: ReturnCodeEntry[];
  requirementRules?: string | null;
  installBehavior?: number | null;
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
  timestampEpoch: number | null;
}

/** Canonical ordering of Intune status values (lower = more severe). */
export const STATUS_RANK: Record<string, number> = {
  Failed: 0,
  Timeout: 1,
  InProgress: 2,
  Pending: 3,
  Success: 4,
  Unknown: 5,
};

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

export type IntuneDiagnosticCategory =
  | "Download"
  | "Install"
  | "Timeout"
  | "Script"
  | "Policy"
  | "State"
  | "General";

export type IntuneRemediationPriority =
  | "Monitor"
  | "Medium"
  | "High"
  | "Immediate";

export interface IntuneDiagnosticInsight {
  id: string;
  severity: IntuneDiagnosticSeverity;
  category: IntuneDiagnosticCategory;
  remediationPriority: IntuneRemediationPriority;
  title: string;
  summary: string;
  likelyCause: string | null;
  evidence: string[];
  nextChecks: string[];
  suggestedFixes: string[];
  focusAreas: string[];
  affectedSourceFiles: string[];
  relatedErrorCodes: string[];
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

export type IntuneTimeWindowPreset =
  | "all"
  | "last-hour"
  | "last-6-hours"
  | "last-day"
  | "last-7-days";

export type IntuneAnalysisPhase = "idle" | "analyzing" | "ready" | "empty" | "error";

export type IntuneAnalysisSourceKind = "file" | "folder" | "known" | "unknown";

export type IntuneAnalysisProgressStage =
  | "resolving"
  | "enumerating"
  | "reading-file"
  | "completed-file"
  | "parsing-event-logs"
  | "finalizing";

export interface IntuneAnalysisProgress {
  stage: IntuneAnalysisProgressStage;
  currentFile: string | null;
  completedFiles: number;
  totalFiles: number | null;
}

export interface IntuneAnalysisProgressEvent extends IntuneAnalysisProgress {
  requestId: string;
  message: string;
  detail: string | null;
}

export interface IntuneAnalysisState {
  phase: IntuneAnalysisPhase;
  requestedPath: string | null;
  requestedKind: IntuneAnalysisSourceKind | null;
  requestId: string | null;
  message: string;
  detail: string | null;
  lastError: string | null;
  progress: IntuneAnalysisProgress | null;
}

export type GuidNameSource = "SetUpFilePath" | "NameField" | "ApplicationName" | "GraphApi";

export type GuidCategory = "app" | "script" | "remediation" | "unknown";

export interface GuidRegistryEntry {
  name: string;
  source: GuidNameSource;
  category?: GuidCategory;
  publisher?: string;
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
  evidenceBundle?: EvidenceBundleMetadata | null;
  eventLogAnalysis?: EventLogAnalysis | null;
  guidRegistry: Record<string, GuidRegistryEntry>;
  policyMetadata?: Record<string, AppPolicyMetadata>;
}

export interface IntuneResultMetadata {
  diagnosticsCoverage: IntuneDiagnosticsCoverage;
  diagnosticsConfidence: IntuneDiagnosticsConfidence;
  repeatedFailures: IntuneRepeatedFailureGroup[];
  evidenceBundle?: EvidenceBundleMetadata | null;
  eventLogAnalysis?: EventLogAnalysis | null;
  policyMetadata?: Record<string, AppPolicyMetadata>;
  guidRegistry?: Record<string, GuidRegistryEntry>;
}
