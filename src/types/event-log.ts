export interface IntuneTimestampBounds {
  firstTimestamp: string | null;
  lastTimestamp: string | null;
}

export type EventLogSeverity =
  | "Critical"
  | "Error"
  | "Warning"
  | "Information"
  | "Verbose"
  | "Unknown";

/**
 * Typed channel enum. Serde serializes Rust unit variants as plain strings
 * and data variants as `{ "VariantName": data }`.
 */
export type EventLogChannel =
  | "DeviceManagementAdmin"
  | "DeviceManagementOperational"
  | "Autopilot"
  | "AadOperational"
  | "DeliveryOptimizationOperational"
  | "ManagementService"
  | "ProvisioningDiagnosticsAdmin"
  | "ShellCoreOperational"
  | "TimeServiceOperational"
  | "UserDeviceRegistrationAdmin"
  | "CryptoDpapiOperational"
  | "KerberosOperational"
  | "SystemLog"
  | { Other: string };

export interface EventLogEntry {
  id: number;
  channel: EventLogChannel;
  channelDisplay: string;
  provider: string;
  eventId: number;
  severity: EventLogSeverity;
  timestamp: string;
  computer: string | null;
  message: string;
  correlationActivityId: string | null;
  sourceFile: string;
}

export interface EventLogChannelSummary {
  channel: EventLogChannel;
  channelDisplay: string;
  entryCount: number;
  errorCount: number;
  warningCount: number;
  timestampBounds: IntuneTimestampBounds | null;
  sourceFile: string;
}

export type EventLogCorrelationKind =
  | "TimeWindowChannelMatch"
  | "ErrorCodeMatch"
  | "EnrollmentContextMatch";

export interface EventLogCorrelationLink {
  eventLogEntryId: number;
  linkedIntuneEventId: number | null;
  linkedDiagnosticId: string | null;
  correlationKind: EventLogCorrelationKind;
  timeDeltaSecs: number | null;
}

export type EventLogAnalysisSource = "Bundle" | "Live";

export type EventLogLiveQueryStatus = "Success" | "Empty" | "Failed";

export interface EventLogLiveQueryChannelResult {
  channel: EventLogChannel;
  channelDisplay: string;
  channelPath: string;
  sourceFile: string;
  status: EventLogLiveQueryStatus;
  entryCount: number;
  errorMessage: string | null;
}

export interface EventLogLiveQueryMetadata {
  attemptedChannelCount: number;
  successfulChannelCount: number;
  channelsWithResultsCount: number;
  failedChannelCount: number;
  perChannelEntryLimit: number;
  channels: EventLogLiveQueryChannelResult[];
}

export interface EventLogAnalysis {
  sourceKind: EventLogAnalysisSource;
  entries: EventLogEntry[];
  channelSummaries: EventLogChannelSummary[];
  correlationLinks: EventLogCorrelationLink[];
  parsedFileCount: number;
  totalEntryCount: number;
  errorEntryCount: number;
  warningEntryCount: number;
  timestampBounds: IntuneTimestampBounds | null;
  liveQuery: EventLogLiveQueryMetadata | null;
}
