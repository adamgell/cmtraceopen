export type EtlEventCategory =
  | "ProcessElevation"
  | "ProcessCreation"
  | "DriverMessage"
  | "Telemetry"
  | "EPMStateChange"
  | "UACPrompt"
  | "Other";

export interface EtlEvent {
  timestamp: string;
  provider: string;
  providerGuid: string;
  eventId: number;
  processId: number;
  threadId: number;
  message: string | null;
  category: EtlEventCategory;
  elevationData: ElevationData | null;
  telemetryData: TelemetryData | null;
  rawData: Record<string, string>;
}

export interface ElevationData {
  fileName: string | null;
  filePath: string | null;
  publisher: string | null;
  userName: string | null;
  elevationType: string | null;
  result: string | null;
  userJustification: string | null;
  hashValue: string | null;
  fileVersion: string | null;
  fileDescription: string | null;
  fileProductName: string | null;
  ruleId: string | null;
  policyId: string | null;
  childProcessBehavior: string | null;
  processType: string | null;
  parentProcessName: string | null;
  isBackgroundProcess: boolean | null;
}

export interface TelemetryData {
  componentName: string | null;
  correlationId: string | null;
  eventName: string | null;
  eventMessage: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  errorStackTrace: string | null;
  customJson: string | null;
  appInfoId: string | null;
  appInfoVersion: string | null;
}
