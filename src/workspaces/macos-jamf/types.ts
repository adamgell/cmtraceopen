import type { FdaStatus, MacosLogFileEntry, MacosMdmProfile } from "../macos-diag/types";

export type JamfPolicyTrigger =
  | { type: "recurringCheckIn" }
  | { type: "event"; value: string }
  | { type: "manual" }
  | { type: "startup" }
  | { type: "login" }
  | { type: "logout" }
  | { type: "policyId"; value: string }
  | { type: "other"; value: string };

export type JamfPolicyResult =
  | { type: "success" }
  | { type: "failure"; value: string }
  | { type: "inProgress" }
  | { type: "unknown" };

export interface JamfPolicyEvent {
  timestamp: string;
  trigger: JamfPolicyTrigger;
  policyId: string | null;
  policyName: string | null;
  result: JamfPolicyResult;
  durationMs: number | null;
  rawLineOffset: number;
  rawLine: string;
}

export interface JamfPolicyLogResult {
  events: JamfPolicyEvent[];
  totalLines: number;
  unparsedLines: number;
  sourcePath: string;
}

export interface JamfDirectoryStatus {
  jamfLog: boolean;
  jamfAppSupport: boolean;
  jamfReceipts: boolean;
  jamfUserLogs: boolean;
  selfServiceLog: boolean;
  connectLog: boolean;
  connectUserLogs: boolean;
}

export interface JamfEnvironment {
  jamfInstalled: boolean;
  jamfVersion: string | null;
  jssUrl: string | null;
  lastCheckIn: string | null;
  mdmProfilePresent: boolean;
  mdmOrganization: string | null;
  jamfConnectInstalled: boolean;
  jamfConnectVersion: string | null;
  jamfConnectIdp: string | null;
  fdaStatus: FdaStatus;
  directories: JamfDirectoryStatus;
  summary: string;
}

export interface JamfSelfServiceEvent {
  timestamp: string;
  action: string;
  itemName: string | null;
  result: string | null;
  rawLine: string;
}

export interface JamfConnectEvent {
  timestamp: string;
  eventType: string;
  idp: string | null;
  user: string | null;
  message: string;
  rawLine: string;
}

export interface JamfLogScanResult {
  files: MacosLogFileEntry[];
  scannedDirectories: string[];
  totalSizeBytes: number;
}

export interface JamfProfilesResult {
  profiles: MacosMdmProfile[];
  matchedOrganization: string | null;
}

export type MacosJamfTabId =
  | "overview"
  | "policies"
  | "profiles"
  | "self-service"
  | "connect"
  | "logs";
