export type SecureBootStage =
  | "stage0"
  | "stage1"
  | "stage2"
  | "stage3"
  | "stage4"
  | "stage5";

export type DataSource = "liveScan" | "logImport" | "both";

export type DiagnosticSeverity = "info" | "warning" | "error";

export type LogSource = "detect" | "remediate" | "system";

export type LogLevel = "info" | "warning" | "error" | "success";

export type TimelineEventType =
  | "stageTransition"
  | "remediationResult"
  | "error"
  | "fallback"
  | "sessionStart"
  | "sessionEnd"
  | "diagnosticData"
  | "info";

export interface TimelineEntry {
  timestamp: string;
  source: LogSource;
  level: LogLevel;
  eventType: TimelineEventType;
  message: string;
  stage: SecureBootStage | null;
  errorCode: string | null;
}

export interface LogSession {
  source: LogSource;
  startedAt: string;
  endedAt: string | null;
  resultStage: SecureBootStage | null;
  resultOutcome: string | null;
  entries: TimelineEntry[];
}

export interface SecureBootScanState {
  secureBootEnabled: boolean | null;

  // UEFI CA 2023 opt-in state
  managedOptIn: number | null;
  availableUpdates: number | null;
  uefiCa2023Capable: number | null;
  uefiCa2023Status: number | null;
  uefiCa2023Error: number | null;
  managedOptInDate: string | null;

  // DiagTrack / telemetry
  telemetryLevel: number | null;
  diagtrackRunning: boolean | null;
  diagtrackStartType: string | null;

  // TPM
  tpmPresent: boolean | null;
  tpmEnabled: boolean | null;
  tpmActivated: boolean | null;
  tpmSpecVersion: string | null;

  // BitLocker
  bitlockerProtectionOn: boolean | null;
  bitlockerEncryptionStatus: string | null;
  bitlockerKeyProtectors: string[];

  // Disk
  diskPartitionStyle: string | null;

  // Payload / task
  payloadFolderExists: boolean | null;
  payloadBinCount: number | null;
  scheduledTaskExists: boolean | null;
  scheduledTaskLastRun: string | null;
  scheduledTaskLastResult: string | null;

  // WinCS
  wincsAvailable: boolean | null;

  // Pending reboot
  pendingRebootSources: string[];

  // Device / OS identity
  deviceName: string | null;
  osCaption: string | null;
  osBuild: string | null;
  oemManufacturer: string | null;
  oemModel: string | null;
  firmwareVersion: string | null;
  firmwareDate: string | null;

  // Raw dump for debugging
  rawRegistryDump: string | null;
}

export interface DiagnosticFinding {
  ruleId: string;
  severity: DiagnosticSeverity;
  title: string;
  detail: string;
  recommendation: string;
}

export interface ScriptExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface SecureBootAnalysisResult {
  stage: SecureBootStage;
  dataSource: DataSource;
  scanState: SecureBootScanState;
  sessions: LogSession[];
  timeline: TimelineEntry[];
  diagnostics: DiagnosticFinding[];
  scriptResult: ScriptExecutionResult | null;
}

export interface SecureBootAnalysisState {
  phase: "idle" | "analyzing" | "done" | "error";
  message: string;
  detail: string | null;
}

export type SecureBootTabId = "diagnostics" | "timeline" | "raw";
