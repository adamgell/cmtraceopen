import { invoke } from "@tauri-apps/api/core";
import type {
  FolderListingResult,
  KnownSourceMetadata,
  LogFormat,
  LogSource,
  ParseResult,
} from "../types/log";
import type { IntuneAnalysisResult } from "../types/intune";

export async function openLogFile(path: string): Promise<ParseResult> {
  return invoke<ParseResult>("open_log_file", { path });
}

export async function listLogFolder(path: string): Promise<FolderListingResult> {
  return invoke<FolderListingResult>("list_log_folder", { path });
}

export async function getKnownLogSources(): Promise<KnownSourceMetadata[]> {
  return invoke<KnownSourceMetadata[]>("get_known_log_sources");
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

export async function startTail(
  path: string,
  format: LogFormat,
  byteOffset: number,
  nextId: number,
  nextLine: number
): Promise<void> {
  return invoke("start_tail", { path, format, byteOffset, nextId, nextLine });
}

export async function stopTail(path: string): Promise<void> {
  return invoke("stop_tail", { path });
}

export async function pauseTail(path: string): Promise<void> {
  return invoke("pause_tail", { path });
}

export async function resumeTail(path: string): Promise<void> {
  return invoke("resume_tail", { path });
}

export async function analyzeIntuneLogs(
  path: string
): Promise<IntuneAnalysisResult> {
  return invoke<IntuneAnalysisResult>("analyze_intune_logs", { path });
}
