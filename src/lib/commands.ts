import { invoke } from "@tauri-apps/api/core";
import type {
  AggregateParseResult,
  FolderListingResult,
  KnownSourceMetadata,
  LogFormat,
  LogSource,
  ParseResult,
  WorkspaceId,
} from "../types/log";
import type {
  EvidenceArtifactPreview,
  EvidenceBundleDetails,
  EvidenceArtifactIntakeKind,
} from "../types/evidence";
import type { RegistryParseResult } from "../types/registry";
import type { IntuneAnalysisResult } from "../workspaces/intune/types";
import type { SysmonAnalysisResult } from "../workspaces/sysmon/types";
import type {
  DsregcmdAnalysisResult,
  DsregcmdCaptureResult,
  DsregcmdResolvedSource,
} from "../workspaces/dsregcmd/types";
import type {
  EspAppFlipBackup,
  EspAppFlipResult,
  EspDiagnosticsSnapshot,
  EspElevationState,
  EspGraphOverlay,
  EspGraphRequest,
  EspRelaunchResult,
  EspSessionEnvelope,
} from "../workspaces/esp-diagnostics/types";

export interface FileAssociationPromptStatus {
  supported: boolean;
  shouldPrompt: boolean;
  isAssociated: boolean;
}

export interface SystemDateTimePreferences {
  datePattern: string;
  timePattern: string;
  amDesignator: string | null;
  pmDesignator: string | null;
}

export interface AnalyzeIntuneLogsOptions {
  includeLiveEventLogs?: boolean;
}

export interface UpdatePolicy {
  updateChecksDisabledByPolicy: boolean;
}

const normalizedCommandErrorMessages = new WeakMap<Error, string>();

/**
 * True only for plain data objects — those whose prototype is `Object.prototype`
 * or `null`. Serialized Rust command errors (e.g. `{ kind, path, message }`)
 * arrive this way, whereas class instances (`Error`, custom classes) do not and
 * must keep falling back. The prototype probe is wrapped so a hostile Proxy that
 * traps `getPrototypeOf` and throws is contained rather than allowed to escape.
 */
function isPlainDataObject(error: object): boolean {
  let prototype: unknown;
  try {
    prototype = Object.getPrototypeOf(error);
  } catch {
    return false;
  }
  return prototype === Object.prototype || prototype === null;
}

/**
 * Reads an own string DATA property without ever invoking a getter.
 *
 * Accessor descriptors (a `get`/`set`) are ignored outright, so a hostile
 * `message` getter is never called. A forged data descriptor — e.g. a Proxy
 * `getOwnPropertyDescriptor` trap that fabricates a value — is rejected unless a
 * direct read of the same own property agrees; a genuine plain data object
 * always agrees, and the direct read cannot trigger a getter because accessor
 * descriptors were already discarded.
 */
function readOwnStringData(error: object, key: string): string | null {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(error, key);
  } catch {
    return null;
  }
  if (
    !descriptor ||
    typeof descriptor.get === "function" ||
    typeof descriptor.set === "function"
  ) {
    return null;
  }
  const value = descriptor.value;
  if (typeof value !== "string") {
    return null;
  }
  let directValue: unknown;
  try {
    directValue = (error as Record<string, unknown>)[key];
  } catch {
    return null;
  }
  if (directValue !== value) {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/** Turns a Rust error `kind` identifier (e.g. `sourceNotFound`) into a readable phrase. */
function humanizeErrorKind(kind: string): string {
  const spaced = kind
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (spaced.length === 0) {
    return kind;
  }
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

/**
 * Extracts the backend reason from a plain-data-object rejection (serialized
 * Rust enum error), preferring `message` and otherwise deriving it from `kind`.
 * Returns null for anything that is not a plain data object so the caller keeps
 * the safe fallback.
 */
function getPlainDataErrorMessage(error: object): string | null {
  if (!isPlainDataObject(error)) {
    return null;
  }
  const message = readOwnStringData(error, "message");
  if (message !== null) {
    return message;
  }
  const kind = readOwnStringData(error, "kind");
  if (kind !== null) {
    return humanizeErrorKind(kind);
  }
  return null;
}

export function getSafeErrorMessage(
  error: unknown,
  fallback = "The operation failed.",
): string {
  if (typeof error === "string") {
    return error.trim() || fallback;
  }

  if (
    (typeof error === "object" && error !== null) ||
    typeof error === "function"
  ) {
    // Trusted, self-normalized command errors are recorded by exact identity;
    // this WeakMap channel cannot invoke Proxy traps.
    const trusted = normalizedCommandErrorMessages.get(error as Error);
    if (trusted !== undefined) {
      return trusted;
    }

    // Serialized Rust command errors arrive as plain data objects. Surface their
    // precise reason while keeping the hostile-Proxy protection intact: only
    // plain-prototype objects are inspected, no getter is ever invoked, and a
    // forged descriptor value is rejected. Class instances, functions, Proxies,
    // and accessor-only objects fall through to the safe fallback.
    if (typeof error === "object") {
      const plainMessage = getPlainDataErrorMessage(error);
      if (plainMessage !== null) {
        return plainMessage;
      }
    }

    return fallback;
  }

  return fallback;
}

function normalizeCommandInvokeError(
  commandName: string,
  error: unknown,
): Error {
  const message = getSafeErrorMessage(
    error,
    `Command '${commandName}' failed.`,
  );
  const missingCommandPattern = new RegExp(
    `command\\s+${commandName}\\s+not found`,
    "i",
  );

  let normalizedMessage = message;
  if (missingCommandPattern.test(message)) {
    normalizedMessage = `The running desktop backend does not expose '${commandName}'. Restart CMTrace Open so the frontend and Tauri backend are on the same build.`;
  }

  const normalizedError = new Error(normalizedMessage);
  normalizedCommandErrorMessages.set(normalizedError, normalizedMessage);
  return normalizedError;
}

async function invokeCommand<T>(
  commandName: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invoke<T>(commandName, args);
  } catch (error) {
    throw normalizeCommandInvokeError(commandName, error);
  }
}

export async function openLogFile(path: string): Promise<ParseResult> {
  return invokeCommand<ParseResult>("open_log_file", { path });
}

/** Parse multiple files in parallel on the Rust side (Rayon thread pool).
 *  Returns all results in a single IPC response — eliminates N-1 round-trips. */
export async function parseFilesBatch(paths: string[]): Promise<ParseResult[]> {
  return invokeCommand<ParseResult[]>("parse_files_batch", { paths });
}

export async function listLogFolder(
  path: string,
): Promise<FolderListingResult> {
  return invokeCommand<FolderListingResult>("list_log_folder", { path });
}

export async function inspectEvidenceBundle(
  path: string,
): Promise<EvidenceBundleDetails> {
  return invokeCommand<EvidenceBundleDetails>("inspect_evidence_bundle", {
    path,
  });
}

export async function inspectEvidenceArtifact(
  path: string,
  intakeKind: EvidenceArtifactIntakeKind,
  originPath?: string | null,
): Promise<EvidenceArtifactPreview> {
  return invokeCommand<EvidenceArtifactPreview>("inspect_evidence_artifact", {
    path,
    intakeKind,
    originPath: originPath ?? null,
  });
}

export async function parseRegistryFile(
  path: string,
): Promise<RegistryParseResult> {
  return invokeCommand<RegistryParseResult>("parse_registry_file", { path });
}

export async function getKnownLogSources(): Promise<KnownSourceMetadata[]> {
  return invokeCommand<KnownSourceMetadata[]>("get_known_log_sources");
}

export async function openLogSourceFile(
  source: LogSource,
): Promise<ParseResult> {
  if (source.kind === "file") {
    return openLogFile(source.path);
  }

  if (source.kind === "known" && source.pathKind === "file") {
    return openLogFile(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a single file path.`,
  );
}

export async function listLogSourceFolder(
  source: LogSource,
): Promise<FolderListingResult> {
  if (source.kind === "folder") {
    return listLogFolder(source.path);
  }

  if (source.kind === "known" && source.pathKind === "folder") {
    return listLogFolder(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a folder path.`,
  );
}

export async function openLogFolderAggregate(
  path: string,
): Promise<AggregateParseResult> {
  return invokeCommand<AggregateParseResult>("open_log_folder_aggregate", {
    path,
  });
}

export async function openLogSourceFolderAggregate(
  source: LogSource,
): Promise<AggregateParseResult> {
  if (source.kind === "folder") {
    return openLogFolderAggregate(source.path);
  }

  if (source.kind === "known" && source.pathKind === "folder") {
    return openLogFolderAggregate(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a folder path.`,
  );
}

export async function startTail(
  path: string,
  format: LogFormat,
  byteOffset: number,
  nextId: number,
  nextLine: number,
): Promise<void> {
  return invokeCommand<void>("start_tail", {
    path,
    format,
    byteOffset,
    nextId,
    nextLine,
  });
}

export async function stopTail(path: string): Promise<void> {
  return invokeCommand<void>("stop_tail", { path });
}

export async function pauseTail(path: string): Promise<void> {
  return invokeCommand<void>("pause_tail", { path });
}

export async function resumeTail(path: string): Promise<void> {
  return invokeCommand<void>("resume_tail", { path });
}

export async function analyzeIntuneLogs(
  path: string,
  requestId: string,
  options?: AnalyzeIntuneLogsOptions & { graphApiEnabled?: boolean },
): Promise<IntuneAnalysisResult> {
  return invokeCommand<IntuneAnalysisResult>("analyze_intune_logs", {
    path,
    requestId,
    includeLiveEventLogs: options?.includeLiveEventLogs ?? false,
    graphApiEnabled: options?.graphApiEnabled ?? false,
  });
}

export async function analyzeSysmonLogs(
  path: string,
  requestId: string,
  options?: { includeLiveEventLogs?: boolean },
): Promise<SysmonAnalysisResult> {
  return invokeCommand<SysmonAnalysisResult>("analyze_sysmon_logs", {
    path,
    requestId,
    includeLiveEventLogs: options?.includeLiveEventLogs ?? false,
  });
}

export async function analyzeDsregcmd(
  input: string,
  bundlePath?: string | null,
): Promise<DsregcmdAnalysisResult> {
  return invokeCommand<DsregcmdAnalysisResult>("analyze_dsregcmd", {
    input,
    bundlePath: bundlePath ?? null,
  });
}

export async function captureDsregcmd(): Promise<DsregcmdCaptureResult> {
  return invokeCommand<DsregcmdCaptureResult>("capture_dsregcmd");
}

export async function inspectPathKind(
  path: string,
): Promise<"file" | "folder" | "unknown"> {
  return invokeCommand<"file" | "folder" | "unknown">("inspect_path_kind", {
    path,
  });
}

export async function writeTextOutputFile(
  path: string,
  contents: string,
): Promise<void> {
  return invokeCommand<void>("write_text_output_file", { path, contents });
}

export async function loadDsregcmdSource(
  kind: "file" | "folder",
  path: string,
): Promise<DsregcmdResolvedSource> {
  return invokeCommand<DsregcmdResolvedSource>("load_dsregcmd_source", {
    kind,
    path,
  });
}

export async function getInitialFilePaths(): Promise<string[]> {
  return invokeCommand<string[]>("get_initial_file_paths");
}

export async function getInitialWorkspace(): Promise<WorkspaceId | null> {
  return invokeCommand<WorkspaceId | null>("get_initial_workspace");
}

export async function getAvailableWorkspaces(): Promise<WorkspaceId[]> {
  return invokeCommand<WorkspaceId[]>("get_available_workspaces");
}

export async function getUpdatePolicy(): Promise<UpdatePolicy> {
  return invokeCommand<UpdatePolicy>("get_update_policy");
}

export interface DnsLoggingStatus {
  dnsServerInstalled: boolean;
  debugLoggingEnabled: boolean;
  logFilePath: string | null;
  dhcpServerInstalled: boolean;
}

export async function checkDnsLoggingStatus(): Promise<DnsLoggingStatus> {
  return invokeCommand<DnsLoggingStatus>("check_dns_logging_status");
}

export async function enableDnsDebugLogging(): Promise<string> {
  return invokeCommand<string>("enable_dns_debug_logging");
}

export interface DnsDhcpCollectionProgress {
  requestId: string;
  message: string;
  currentServer: string | null;
  completedServers: number;
  totalServers: number;
}

export interface DnsDhcpServerResult {
  server: string;
  status: string;
  filesCollected: number;
  bytesCopied: number;
  errors: string[];
}

export interface DnsDhcpCollectionResult {
  bundlePath: string;
  servers: DnsDhcpServerResult[];
  totalFiles: number;
  totalBytes: number;
  durationMs: number;
}

export async function collectDnsDhcpFromDomain(
  requestId: string,
  outputRoot?: string,
  servers?: string[],
): Promise<DnsDhcpCollectionResult> {
  return invokeCommand<DnsDhcpCollectionResult>(
    "collect_dns_dhcp_from_domain",
    {
      requestId,
      outputRoot: outputRoot ?? null,
      servers: servers ?? null,
    },
  );
}

export async function getFileAssociationPromptStatus(): Promise<FileAssociationPromptStatus> {
  return invokeCommand<FileAssociationPromptStatus>(
    "get_file_association_prompt_status",
  );
}

export async function associateLogFilesWithApp(): Promise<void> {
  return invokeCommand<void>("associate_log_files_with_app");
}

export async function setFileAssociationPromptSuppressed(
  suppressed: boolean,
): Promise<void> {
  return invokeCommand<void>("set_file_association_prompt_suppressed", {
    suppressed,
  });
}

export async function getSystemDateTimePreferences(): Promise<SystemDateTimePreferences> {
  return invokeCommand<SystemDateTimePreferences>(
    "get_system_date_time_preferences",
  );
}

// --- Diagnostics Collection ---

export interface CollectionResult {
  bundlePath: string;
  bundleId: string;
  artifactCounts: {
    collected: number;
    missing: number;
    failed: number;
    total: number;
  };
  durationMs: number;
  gaps: Array<{
    artifactId: string;
    category: string;
    reason: string;
  }>;
}

export async function collectDiagnostics(
  requestId: string,
  outputRoot?: string | null,
  enabledFamilies?: string[] | null,
): Promise<CollectionResult> {
  return invokeCommand<CollectionResult>("collect_diagnostics", {
    requestId,
    outputRoot: outputRoot ?? null,
    enabledFamilies: enabledFamilies ?? null,
  });
}

// --- ESP Diagnostics ---

export async function getEspElevationState(): Promise<EspElevationState> {
  return invokeCommand<EspElevationState>("get_esp_elevation_state");
}

export async function analyzeEspEvidence(
  path: string,
  requestId: string,
): Promise<EspDiagnosticsSnapshot> {
  return invokeCommand<EspDiagnosticsSnapshot>("analyze_esp_evidence", {
    path,
    requestId,
  });
}

export async function startEspDiagnosticsSession(
  requestId: string,
): Promise<EspSessionEnvelope> {
  return invokeCommand<EspSessionEnvelope>("start_esp_diagnostics_session", {
    requestId,
  });
}

export async function getEspDiagnosticsSession(
  sessionId: string,
): Promise<EspSessionEnvelope> {
  return invokeCommand<EspSessionEnvelope>("get_esp_diagnostics_session", {
    sessionId,
  });
}

export async function stopEspDiagnosticsSession(
  sessionId: string,
): Promise<void> {
  return invokeCommand<void>("stop_esp_diagnostics_session", { sessionId });
}

export async function restartEspAsAdministrator(): Promise<EspRelaunchResult> {
  return invokeCommand<EspRelaunchResult>("restart_esp_as_administrator");
}

export async function graphFetchEspDiagnostics(
  request: EspGraphRequest,
): Promise<EspGraphOverlay> {
  return invokeCommand<EspGraphOverlay>("graph_fetch_esp_diagnostics", {
    request,
  });
}

export async function espFlipAppInstalled(
  appId: string,
): Promise<EspAppFlipResult> {
  return invokeCommand<EspAppFlipResult>("esp_flip_app_installed", { appId });
}

export async function espRestoreAppState(
  backup: EspAppFlipBackup,
): Promise<void> {
  return invokeCommand<void>("esp_restore_app_state", { backup });
}

export async function graphCancelEspDiagnostics(
  requestId: string,
): Promise<void> {
  return invokeCommand<void>("graph_cancel_esp_diagnostics", { requestId });
}

// --- Graph API (Windows only, opt-in) ---

export interface GraphAuthCapabilities {
  managedDevices: boolean;
  serviceConfig: boolean;
  apps: boolean;
  configuration: boolean;
  scripts: boolean;
}

export interface GraphAuthStatus {
  isAuthenticated: boolean;
  userPrincipalName: string | null;
  tenantId: string | null;
  grantedScopes: string[];
  missingScopes: string[];
  expiresAt: number | null;
  capabilities: GraphAuthCapabilities;
  error: string | null;
}

export type GraphPermissionUpgradeOutcome =
  "upgraded" | "unchanged" | "cancelled" | "denied" | "failed" | "stale";

export interface GraphPermissionUpgradeResult {
  outcome: GraphPermissionUpgradeOutcome;
  status: GraphAuthStatus;
  message: string | null;
}

export interface GraphAppInfo {
  id: string;
  displayName: string;
  publisher: string | null;
  odataType: string | null;
}

export interface GraphResolutionResult {
  resolved: Record<string, GraphAppInfo>;
  notFound: string[];
  errors: string[];
}

export async function graphAuthenticate(): Promise<GraphAuthStatus> {
  return invokeCommand<GraphAuthStatus>("graph_authenticate");
}

export async function graphRequestMissingPermissions(): Promise<GraphPermissionUpgradeResult> {
  return invokeCommand<GraphPermissionUpgradeResult>(
    "graph_request_missing_permissions",
  );
}

export async function graphGetAuthStatus(): Promise<GraphAuthStatus> {
  return invokeCommand<GraphAuthStatus>("graph_get_auth_status");
}

export async function graphSignOut(): Promise<void> {
  return invokeCommand<void>("graph_sign_out");
}

export async function graphResolveGuids(
  guids: string[],
): Promise<GraphResolutionResult> {
  return invokeCommand<GraphResolutionResult>("graph_resolve_guids", { guids });
}

export async function graphFetchAllApps(): Promise<GraphAppInfo[]> {
  return invokeCommand<GraphAppInfo[]>("graph_fetch_all_apps");
}

// --- macOS Diagnostics ---

import type {
  MacosDiagEnvironment,
  MacosIntuneLogScanResult,
  MacosProfilesResult,
  MacosDefenderResult,
  MacosPackagesResult,
  MacosPackageInfo,
  MacosPackageFiles,
  MacosUnifiedLogResult,
} from "../workspaces/macos-diag/types";

export async function macosScanEnvironment(): Promise<MacosDiagEnvironment> {
  return invokeCommand<MacosDiagEnvironment>("macos_scan_environment");
}

export async function macosScanIntuneLogs(): Promise<MacosIntuneLogScanResult> {
  return invokeCommand<MacosIntuneLogScanResult>("macos_scan_intune_logs");
}

export async function macosListProfiles(): Promise<MacosProfilesResult> {
  return invokeCommand<MacosProfilesResult>("macos_list_profiles");
}

export async function macosInspectDefender(): Promise<MacosDefenderResult> {
  return invokeCommand<MacosDefenderResult>("macos_inspect_defender");
}

export async function macosListPackages(): Promise<MacosPackagesResult> {
  return invokeCommand<MacosPackagesResult>("macos_list_packages");
}

export async function macosGetPackageInfo(
  packageId: string,
): Promise<MacosPackageInfo> {
  return invokeCommand<MacosPackageInfo>("macos_get_package_info", {
    packageId,
  });
}

export async function macosGetPackageFiles(
  packageId: string,
): Promise<MacosPackageFiles> {
  return invokeCommand<MacosPackageFiles>("macos_get_package_files", {
    packageId,
  });
}

export async function macosQueryUnifiedLog(
  presetId: string,
  timeRangeMinutes: number,
  resultCap: number,
): Promise<MacosUnifiedLogResult> {
  const now = new Date();
  const start = new Date(now.getTime() - timeRangeMinutes * 60 * 1000);
  const fmt = (d: Date) =>
    `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  const timeRange = { start: fmt(start), end: fmt(now) };
  return invokeCommand<MacosUnifiedLogResult>("macos_query_unified_log", {
    presetId,
    timeRange,
    resultCap,
  });
}

// --- Secure Boot ---

import type { SecureBootAnalysisResult } from "../workspaces/secureboot/types";

export async function analyzeSecureBoot(
  path?: string | null,
): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("analyze_secureboot", {
    path: path ?? null,
  });
}

export async function rescanSecureBoot(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("rescan_secureboot", {});
}

export async function runSecureBootDetection(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>(
    "run_secureboot_detection",
    {},
  );
}

export async function runSecureBootRemediation(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>(
    "run_secureboot_remediation",
    {},
  );
}
