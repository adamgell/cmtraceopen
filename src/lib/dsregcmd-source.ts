import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { exists, readTextFile, stat } from "@tauri-apps/plugin-fs";
import type {
  DsregcmdAnalysisResult,
  DsregcmdSourceContext,
  DsregcmdSourceDescriptor,
} from "../types/dsregcmd";
import { analyzeDsregcmd, captureDsregcmd } from "./commands";
import { useDsregcmdStore } from "../stores/dsregcmd-store";

const EVIDENCE_RELATIVE_PATH = ["evidence", "command-output", "dsregcmd-status.txt"];
const TOP_LEVEL_FALLBACK_FILE = "dsregcmd-status.txt";

function getBaseName(path: string | null): string {
  if (!path) {
    return "";
  }

  return path.split(/[\\/]/).pop() ?? path;
}

function getPathSeparator(path: string): string {
  return path.includes("\\") && !path.includes("/") ? "\\" : "/";
}

function joinNativePath(basePath: string, ...parts: string[]): string {
  const separator = getPathSeparator(basePath);
  const normalizedBase = basePath.replace(/[\\/]+$/, "");
  const normalizedParts = parts.map((part) => part.replace(/^[\\/]+|[\\/]+$/g, ""));
  return [normalizedBase, ...normalizedParts].join(separator);
}

function buildSourceContext(
  source: DsregcmdSourceDescriptor,
  rawInput: string,
  resolvedPath: string | null,
  evidenceFilePath: string | null
): DsregcmdSourceContext {
  const displayLabel =
    source.kind === "clipboard"
      ? "Clipboard"
      : source.kind === "capture"
        ? "Live capture"
        : source.kind === "text"
          ? source.label
          : getBaseName(resolvedPath ?? source.path) || resolvedPath || source.path;

  return {
    source,
    requestedPath: "path" in source ? source.path : null,
    resolvedPath,
    evidenceFilePath,
    displayLabel,
    rawLineCount: rawInput.length === 0 ? 0 : rawInput.split(/\r?\n/).length,
    rawCharCount: rawInput.length,
  };
}

async function resolveFolderEvidenceFilePath(folderPath: string): Promise<string> {
  const evidencePath = joinNativePath(folderPath, ...EVIDENCE_RELATIVE_PATH);
  if (await exists(evidencePath)) {
    return evidencePath;
  }

  const topLevelPath = joinNativePath(folderPath, TOP_LEVEL_FALLBACK_FILE);
  if (await exists(topLevelPath)) {
    return topLevelPath;
  }

  throw new Error(
    `Folder does not contain dsregcmd evidence. Expected '${EVIDENCE_RELATIVE_PATH.join("/")}' or '${TOP_LEVEL_FALLBACK_FILE}'.`
  );
}

async function readDsregcmdSource(source: DsregcmdSourceDescriptor): Promise<{
  rawInput: string;
  resolvedPath: string | null;
  evidenceFilePath: string | null;
}> {
  switch (source.kind) {
    case "file": {
      const rawInput = await readTextFile(source.path);
      return {
        rawInput,
        resolvedPath: source.path,
        evidenceFilePath: source.path,
      };
    }
    case "folder": {
      const evidenceFilePath = await resolveFolderEvidenceFilePath(source.path);
      const rawInput = await readTextFile(evidenceFilePath);
      return {
        rawInput,
        resolvedPath: evidenceFilePath,
        evidenceFilePath,
      };
    }
    case "clipboard": {
      const rawInput = await readText();
      return {
        rawInput,
        resolvedPath: null,
        evidenceFilePath: null,
      };
    }
    case "capture": {
      const rawInput = await captureDsregcmd();
      return {
        rawInput,
        resolvedPath: null,
        evidenceFilePath: null,
      };
    }
    case "text": {
      throw new Error("Text sources must be analyzed with analyzeDsregcmdText().");
    }
  }
}

export async function analyzeDsregcmdText(
  input: string,
  label = "Manual dsregcmd text"
): Promise<DsregcmdAnalysisResult> {
  const source: DsregcmdSourceDescriptor = { kind: "text", label };
  const store = useDsregcmdStore.getState();
  store.beginAnalysis(source, label);

  try {
    if (!input.trim()) {
      throw new Error("dsregcmd input was empty.");
    }

    const result = await analyzeDsregcmd(input);
    const context = buildSourceContext(source, input, null, null);
    useDsregcmdStore.getState().setResults(input, result, context);
    return result;
  } catch (error) {
    useDsregcmdStore.getState().failAnalysis(error);
    throw error;
  }
}

export async function analyzeDsregcmdSource(
  source: DsregcmdSourceDescriptor
): Promise<DsregcmdAnalysisResult> {
  const store = useDsregcmdStore.getState();
  store.beginAnalysis(source, "path" in source ? source.path : null);

  try {
    const { rawInput, resolvedPath, evidenceFilePath } = await readDsregcmdSource(source);

    if (!rawInput.trim()) {
      throw new Error("The selected dsregcmd source did not contain any text.");
    }

    const result = await analyzeDsregcmd(rawInput);
    const context = buildSourceContext(source, rawInput, resolvedPath, evidenceFilePath);
    useDsregcmdStore.getState().setResults(rawInput, result, context);
    return result;
  } catch (error) {
    useDsregcmdStore.getState().failAnalysis(error);
    throw error;
  }
}

export async function analyzeDsregcmdPath(
  path: string,
  options: { preferFolder?: boolean; fallbackToFolder?: boolean } = {}
): Promise<DsregcmdAnalysisResult> {
  const tryFolderFirst = options.preferFolder === true;

  try {
    const fileInfo = await stat(path);

    if (fileInfo.isDirectory) {
      return analyzeDsregcmdSource({ kind: "folder", path });
    }

    return analyzeDsregcmdSource({ kind: "file", path });
  } catch (error) {
    if (tryFolderFirst) {
      throw error;
    }

    if (options.fallbackToFolder === false) {
      throw error;
    }

    console.info("[dsregcmd-source] retrying dropped path as folder source", {
      path,
      error,
    });
    return analyzeDsregcmdSource({ kind: "folder", path });
  }
}

export function canRefreshDsregcmdSource(source: DsregcmdSourceDescriptor | null): boolean {
  return source !== null;
}

export async function refreshCurrentDsregcmdSource(): Promise<boolean> {
  const state = useDsregcmdStore.getState();
  const { source } = state.sourceContext;
  const { rawInput } = state;

  if (!source) {
    return false;
  }

  if (source.kind === "text") {
    await analyzeDsregcmdText(rawInput, source.label);
    return true;
  }

  await analyzeDsregcmdSource(source);
  return true;
}
