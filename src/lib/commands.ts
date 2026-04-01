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
import type { EvidenceArtifactPreview, EvidenceBundleDetails, EvidenceArtifactIntakeKind } from "../types/evidence";
import type { RegistryParseResult } from "../types/registry";
import type { IntuneAnalysisResult } from "../types/intune";
import type { SysmonAnalysisResult } from "../types/sysmon";
import type {
  DsregcmdAnalysisResult,
  DsregcmdCaptureResult,
  DsregcmdResolvedSource,
} from "../types/dsregcmd";

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

function getInvokeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

function normalizeCommandInvokeError(commandName: string, error: unknown): Error {
  const message = getInvokeErrorMessage(error);
  const missingCommandPattern = new RegExp(`command\\s+${commandName}\\s+not found`, "i");

  if (missingCommandPattern.test(message)) {
    return new Error(
      `The running desktop backend does not expose '${commandName}'. Restart CMTrace Open so the frontend and Tauri backend are on the same build.`
    );
  }

  return error instanceof Error ? error : new Error(message);
}

async function invokeCommand<T>(commandName: string, args?: Record<string, unknown>): Promise<T> {
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

export async function listLogFolder(path: string): Promise<FolderListingResult> {
  return invokeCommand<FolderListingResult>("list_log_folder", { path });
}

export async function inspectEvidenceBundle(
  path: string
): Promise<EvidenceBundleDetails> {
  return invokeCommand<EvidenceBundleDetails>("inspect_evidence_bundle", { path });
}

export async function inspectEvidenceArtifact(
  path: string,
  intakeKind: EvidenceArtifactIntakeKind,
  originPath?: string | null
): Promise<EvidenceArtifactPreview> {
  return invokeCommand<EvidenceArtifactPreview>("inspect_evidence_artifact", {
    path,
    intakeKind,
    originPath: originPath ?? null,
  });
}

export async function parseRegistryFile(path: string): Promise<RegistryParseResult> {
  return invokeCommand<RegistryParseResult>("parse_registry_file", { path });
}

export async function getKnownLogSources(): Promise<KnownSourceMetadata[]> {
  return invokeCommand<KnownSourceMetadata[]>("get_known_log_sources");
}

export async function openLogSourceFile(source: LogSource): Promise<ParseResult> {
  if (source.kind === "file") {
    return openLogFile(source.path);
  }

  if (source.kind === "known" && source.pathKind === "file") {
    return openLogFile(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a single file path.`
  );
}

export async function listLogSourceFolder(
  source: LogSource
): Promise<FolderListingResult> {
  if (source.kind === "folder") {
    return listLogFolder(source.path);
  }

  if (source.kind === "known" && source.pathKind === "folder") {
    return listLogFolder(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a folder path.`
  );
}

export async function openLogFolderAggregate(
  path: string
): Promise<AggregateParseResult> {
  return invokeCommand<AggregateParseResult>("open_log_folder_aggregate", { path });
}

export async function openLogSourceFolderAggregate(
  source: LogSource
): Promise<AggregateParseResult> {
  if (source.kind === "folder") {
    return openLogFolderAggregate(source.path);
  }

  if (source.kind === "known" && source.pathKind === "folder") {
    return openLogFolderAggregate(source.defaultPath);
  }

  throw new Error(
    `Source kind '${source.kind}' does not resolve to a folder path.`
  );
}

export async function startTail(
  path: string,
  format: LogFormat,
  byteOffset: number,
  nextId: number,
  nextLine: number
): Promise<void> {
  return invokeCommand<void>("start_tail", { path, format, byteOffset, nextId, nextLine });
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
  options?: AnalyzeIntuneLogsOptions
): Promise<IntuneAnalysisResult> {
  return invokeCommand<IntuneAnalysisResult>("analyze_intune_logs", {
    path,
    requestId,
    includeLiveEventLogs: options?.includeLiveEventLogs ?? false,
  });
}

export async function analyzeSysmonLogs(
  path: string,
  requestId: string,
  options?: { includeLiveEventLogs?: boolean }
): Promise<SysmonAnalysisResult> {
  return invokeCommand<SysmonAnalysisResult>("analyze_sysmon_logs", {
    path,
    requestId,
    includeLiveEventLogs: options?.includeLiveEventLogs ?? false,
  });
}

export async function analyzeDsregcmd(
  input: string,
  bundlePath?: string | null
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
  path: string
): Promise<"file" | "folder" | "unknown"> {
  return invokeCommand<"file" | "folder" | "unknown">("inspect_path_kind", { path });
}

export async function writeTextOutputFile(
  path: string,
  contents: string
): Promise<void> {
  return invokeCommand<void>("write_text_output_file", { path, contents });
}

export async function loadDsregcmdSource(
  kind: "file" | "folder",
  path: string
): Promise<DsregcmdResolvedSource> {
  return invokeCommand<DsregcmdResolvedSource>("load_dsregcmd_source", {
    kind,
    path,
  });
}

export async function getInitialFilePaths(): Promise<string[]> {
  return invokeCommand<string[]>("get_initial_file_paths");
}

export async function getAvailableWorkspaces(): Promise<WorkspaceId[]> {
  return invokeCommand<WorkspaceId[]>("get_available_workspaces");
}

export async function getFileAssociationPromptStatus(): Promise<FileAssociationPromptStatus> {
  return invokeCommand<FileAssociationPromptStatus>("get_file_association_prompt_status");
}

export async function associateLogFilesWithApp(): Promise<void> {
  return invokeCommand<void>("associate_log_files_with_app");
}

export async function setFileAssociationPromptSuppressed(
  suppressed: boolean
): Promise<void> {
  return invokeCommand<void>("set_file_association_prompt_suppressed", { suppressed });
}

export async function getSystemDateTimePreferences(): Promise<SystemDateTimePreferences> {
  return invokeCommand<SystemDateTimePreferences>("get_system_date_time_preferences");
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
} from "../types/macos-diag";

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

export async function macosGetPackageInfo(packageId: string): Promise<MacosPackageInfo> {
  return invokeCommand<MacosPackageInfo>("macos_get_package_info", { packageId });
}

export async function macosGetPackageFiles(packageId: string): Promise<MacosPackageFiles> {
  return invokeCommand<MacosPackageFiles>("macos_get_package_files", { packageId });
}

export async function macosQueryUnifiedLog(
  presetId: string,
  timeRangeMinutes: number,
  resultCap: number
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
