export type FdaStatus = "granted" | "notGranted" | "unknown";
export type MacosDiagTabId = "intune-logs" | "profiles" | "defender" | "packages" | "unified-log";

export interface MacosDiagEnvironment {
  macosVersion: string;
  macosBuild: string;
  fullDiskAccess: FdaStatus;
  tools: MacosDiagToolAvailability;
  directories: MacosDiagDirectoryStatus;
  summary: string;
}

export interface MacosDiagToolAvailability {
  profiles: boolean;
  mdatp: boolean;
  pkgutil: boolean;
  logCommand: boolean;
}

export interface MacosDiagDirectoryStatus {
  intuneSystemLogs: boolean;
  intuneUserLogs: boolean;
  companyPortalLogs: boolean;
  intuneScriptsLogs: boolean;
  defenderLogs: boolean;
  defenderDiag: boolean;
}

export interface MacosLogFileEntry {
  path: string;
  fileName: string;
  sizeBytes: number;
  modifiedUnixMs: number | null;
  sourceDirectory: string;
}

export interface MacosIntuneLogScanResult {
  files: MacosLogFileEntry[];
  scannedDirectories: string[];
  totalSizeBytes: number;
}

export interface MacosMdmProfile {
  profileIdentifier: string;
  profileDisplayName: string;
  profileOrganization: string | null;
  profileType: string | null;
  profileUuid: string | null;
  installDate: string | null;
  payloads: MacosMdmPayload[];
  isManaged: boolean;
  verificationState: string | null;
  description: string | null;
  source: string | null;
  removalDisallowed: boolean | null;
}

export interface MacosMdmPayload {
  payloadIdentifier: string;
  payloadDisplayName: string | null;
  payloadType: string;
  payloadUuid: string | null;
  payloadData: string | null;
  payloadDescription: string | null;
  payloadVersion: number | null;
}

export interface MacosEnrollmentStatus {
  enrolled: boolean;
  mdmServer: string | null;
  enrollmentType: string | null;
  rawOutput: string;
}

export interface MacosProfilesResult {
  profiles: MacosMdmProfile[];
  enrollmentStatus: MacosEnrollmentStatus;
  rawOutput: string;
}

export interface MacosDefenderHealthStatus {
  healthy: boolean | null;
  healthIssues: string[];
  realTimeProtectionEnabled: boolean | null;
  definitionsStatus: string | null;
  engineVersion: string | null;
  appVersion: string | null;
  rawOutput: string;
}

export interface MacosDefenderResult {
  health: MacosDefenderHealthStatus | null;
  logFiles: MacosLogFileEntry[];
  diagFiles: MacosLogFileEntry[];
}

export interface MacosPackageInfo {
  packageId: string;
  version: string;
  volume: string | null;
  location: string | null;
  installTime: string | null;
}

export interface MacosPackageFiles {
  packageId: string;
  files: string[];
  fileCount: number;
}

export interface MacosPackagesResult {
  packages: MacosPackageInfo[];
  totalCount: number;
  microsoftCount: number;
}

export interface MacosUnifiedLogPreset {
  id: string;
  label: string;
  predicate: string;
  description: string;
}

export interface MacosUnifiedLogEntry {
  timestamp: string;
  process: string;
  subsystem: string | null;
  category: string | null;
  level: string;
  message: string;
  pid: number | null;
  tid: number | null;
}

export interface MacosUnifiedLogResult {
  entries: MacosUnifiedLogEntry[];
  totalMatched: number;
  capped: boolean;
  resultCap: number;
  predicateUsed: string;
  timeRange: MacosUnifiedLogTimeRange | null;
}

export interface MacosUnifiedLogTimeRange {
  start: string;
  end: string;
}
