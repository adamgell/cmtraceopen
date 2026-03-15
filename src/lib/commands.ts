import { invoke } from "@tauri-apps/api/core";
import type {
  FolderListingResult,
  KnownSourceMetadata,
  LogFormat,
  LogSource,
  ParseResult,
} from "../types/log";
import type { EvidenceArtifactPreview, EvidenceBundleDetails, EvidenceArtifactIntakeKind } from "../types/evidence";
import type { IntuneAnalysisResult } from "../types/intune";
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

export async function openLogFile(path: string): Promise<ParseResult> {
  return invoke<ParseResult>("open_log_file", { path });
}

export async function listLogFolder(path: string): Promise<FolderListingResult> {
  return invoke<FolderListingResult>("list_log_folder", { path });
}

export async function inspectEvidenceBundle(
  path: string
): Promise<EvidenceBundleDetails> {
  return invoke<EvidenceBundleDetails>("inspect_evidence_bundle", { path });
}

export async function inspectEvidenceArtifact(
  path: string,
  intakeKind: EvidenceArtifactIntakeKind,
  originPath?: string | null
): Promise<EvidenceArtifactPreview> {
  return invoke<EvidenceArtifactPreview>("inspect_evidence_artifact", {
    path,
    intakeKind,
    originPath: originPath ?? null,
  });
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

export async function analyzeDsregcmd(
  input: string,
  bundlePath?: string | null
): Promise<DsregcmdAnalysisResult> {
  return invoke<DsregcmdAnalysisResult>("analyze_dsregcmd", {
    input,
    bundlePath: bundlePath ?? null,
  });
}

export async function captureDsregcmd(): Promise<DsregcmdCaptureResult> {
  return invoke<DsregcmdCaptureResult>("capture_dsregcmd");
}

export async function inspectPathKind(
  path: string
): Promise<"file" | "folder" | "unknown"> {
  return invoke<"file" | "folder" | "unknown">("inspect_path_kind", { path });
}

export async function writeTextOutputFile(
  path: string,
  contents: string
): Promise<void> {
  return invoke("write_text_output_file", { path, contents });
}

export async function loadDsregcmdSource(
  kind: "file" | "folder",
  path: string
): Promise<DsregcmdResolvedSource> {
  return invoke<DsregcmdResolvedSource>("load_dsregcmd_source", {
    kind,
    path,
  });
}

export async function getInitialFilePath(): Promise<string | null> {
  return invoke<string | null>("get_initial_file_path");
}

export async function getFileAssociationPromptStatus(): Promise<FileAssociationPromptStatus> {
  return invoke<FileAssociationPromptStatus>("get_file_association_prompt_status");
}

export async function associateLogFilesWithApp(): Promise<void> {
  return invoke("associate_log_files_with_app");
}

export async function setFileAssociationPromptSuppressed(
  suppressed: boolean
): Promise<void> {
  return invoke("set_file_association_prompt_suppressed", { suppressed });
}
