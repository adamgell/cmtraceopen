export type SysmonEventType =
  | "ProcessCreate"
  | "FileCreateTime"
  | "NetworkConnect"
  | "ServiceStateChange"
  | "ProcessTerminate"
  | "DriverLoad"
  | "ImageLoad"
  | "CreateRemoteThread"
  | "RawAccessRead"
  | "ProcessAccess"
  | "FileCreate"
  | "RegistryAddOrDelete"
  | "RegistryValueSet"
  | "RegistryRename"
  | "FileCreateStreamHash"
  | "ConfigChange"
  | "PipeCreated"
  | "PipeConnected"
  | "WmiFilter"
  | "WmiConsumer"
  | "WmiBinding"
  | "DnsQuery"
  | "FileDelete"
  | "ClipboardChange"
  | "ProcessTampering"
  | "FileDeleteDetected"
  | "FileBlockExecutable"
  | "FileBlockShredding"
  | "FileExecutableDetected"
  | "Error"
  | "Unknown";

export type SysmonSeverity = "Info" | "Warning" | "Error";

export interface SysmonEvent {
  id: number;
  eventId: number;
  eventType: SysmonEventType;
  eventTypeDisplay: string;
  severity: SysmonSeverity;
  timestamp: string;
  timestampMs: number | null;
  computer: string | null;
  recordId: number;

  // Common fields
  ruleName?: string | null;
  utcTime?: string | null;
  processGuid?: string | null;
  processId?: number | null;
  image?: string | null;
  commandLine?: string | null;
  user?: string | null;
  hashes?: string | null;
  parentImage?: string | null;
  parentCommandLine?: string | null;
  parentProcessId?: number | null;

  // File events
  targetFilename?: string | null;

  // Network events
  protocol?: string | null;
  sourceIp?: string | null;
  sourcePort?: number | null;
  destinationIp?: string | null;
  destinationPort?: number | null;
  destinationHostname?: string | null;

  // Registry events
  targetObject?: string | null;
  details?: string | null;

  // DNS events
  queryName?: string | null;
  queryResults?: string | null;

  // Process access
  sourceImage?: string | null;
  targetImage?: string | null;
  grantedAccess?: string | null;

  message: string;
  sourceFile: string;
}

export interface SysmonEventTypeCount {
  eventId: number;
  eventType: SysmonEventType;
  displayName: string;
  count: number;
}

export interface SysmonSummary {
  totalEvents: number;
  eventTypeCounts: SysmonEventTypeCount[];
  uniqueProcesses: number;
  uniqueComputers: number;
  earliestTimestamp: string | null;
  latestTimestamp: string | null;
  sourceFiles: string[];
  parseErrors: number;
}

export interface SysmonConfig {
  schemaVersion: string | null;
  hashAlgorithms: string | null;
  found: boolean;
  lastConfigChange: string | null;
  configurationXml: string | null;
  sysmonVersion: string | null;
  activeEventTypes: SysmonEventTypeCount[];
}

export interface TimeBucket {
  timestamp: string;
  timestampMs: number;
  count: number;
}

export interface RankedItem {
  name: string;
  count: number;
}

export interface SecuritySummary {
  totalWarnings: number;
  totalErrors: number;
  eventsByType: RankedItem[];
}

export interface SysmonDashboardData {
  timelineMinute: TimeBucket[];
  timelineHourly: TimeBucket[];
  timelineDaily: TimeBucket[];
  topProcesses: RankedItem[];
  topDestinations: RankedItem[];
  topPorts: RankedItem[];
  topDnsQueries: RankedItem[];
  securityEvents: SecuritySummary;
  topTargetFiles: RankedItem[];
  topRegistryKeys: RankedItem[];
}

export interface SysmonAnalysisResult {
  events: SysmonEvent[];
  summary: SysmonSummary;
  config: SysmonConfig;
  dashboard: SysmonDashboardData;
  sourcePath: string;
}
