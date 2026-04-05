import { readText } from "@tauri-apps/plugin-clipboard-manager";
import type {
  DsregcmdAnalysisResult,
  DsregcmdSourceContext,
  DsregcmdSourceDescriptor,
} from "../workspaces/dsregcmd/types";
import { analyzeDsregcmd, captureDsregcmd, loadDsregcmdSource } from "./commands";
import { getBaseName } from "./file-paths";
import { useDsregcmdStore } from "../workspaces/dsregcmd/dsregcmd-store";

function buildSourceContext(
  source: DsregcmdSourceDescriptor,
  rawInput: string,
  resolvedPath: string | null,
  evidenceFilePath: string | null,
  bundlePath: string | null
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
    bundlePath,
    evidenceFilePath,
    displayLabel,
    rawLineCount: rawInput.length === 0 ? 0 : rawInput.split(/\r?\n/).length,
    rawCharCount: rawInput.length,
  };
}

async function readDsregcmdSource(source: DsregcmdSourceDescriptor): Promise<{
  rawInput: string;
  resolvedPath: string | null;
  evidenceFilePath: string | null;
  bundleRootPath: string | null;
}> {
  switch (source.kind) {
    case "file": {
      const loadedSource = await loadDsregcmdSource("file", source.path);
      return {
        rawInput: loadedSource.input,
        resolvedPath: loadedSource.resolvedPath,
        evidenceFilePath: loadedSource.evidenceFilePath,
        bundleRootPath: loadedSource.bundlePath,
      };
    }
    case "folder": {
      const loadedSource = await loadDsregcmdSource("folder", source.path);
      return {
        rawInput: loadedSource.input,
        resolvedPath: loadedSource.resolvedPath,
        evidenceFilePath: loadedSource.evidenceFilePath,
        bundleRootPath: loadedSource.bundlePath,
      };
    }
    case "clipboard": {
      const rawInput = await readText();
      return {
        rawInput,
        resolvedPath: null,
        evidenceFilePath: null,
        bundleRootPath: null,
      };
    }
    case "capture": {
      const captureResult = await captureDsregcmd();
      return {
        rawInput: captureResult.input,
        resolvedPath: captureResult.evidenceFilePath,
        evidenceFilePath: captureResult.evidenceFilePath,
        bundleRootPath: captureResult.bundlePath,
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

    const result = await analyzeDsregcmd(input, null);
    const context = buildSourceContext(source, input, null, null, null);
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
    const { rawInput, resolvedPath, evidenceFilePath, bundleRootPath } =
      await readDsregcmdSource(source);

    if (!rawInput.trim()) {
      throw new Error("The selected dsregcmd source did not contain any text.");
    }

    const result = await analyzeDsregcmd(
      rawInput,
      bundleRootPath
    );
    const context = buildSourceContext(
      source,
      rawInput,
      resolvedPath,
      evidenceFilePath,
      bundleRootPath
    );
    useDsregcmdStore.getState().setResults(rawInput, result, context);
    return result;
  } catch (error) {
    useDsregcmdStore.getState().failAnalysis(error);
    throw error;
  }
}

export async function analyzeDsregcmdPath(
  path: string,
  options: { fallbackToFolder?: boolean } = {}
): Promise<DsregcmdAnalysisResult> {
  try {
    return analyzeDsregcmdSource({ kind: "file", path });
  } catch (error) {
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
