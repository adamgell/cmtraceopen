import {
  getKnownLogSources,
  listLogSourceFolder,
  openLogFile,
  openLogSourceFile,
  stopTail,
} from "./commands";
import { useLogStore } from "../stores/log-store";
import type {
  FolderEntry,
  KnownSourceMetadata,
  LogSource,
  ParseResult,
} from "../types/log";

export interface LoadLogSourceOptions {
  selectedFilePath?: string | null;
}

export interface LoadPathAsLogSourceOptions extends LoadLogSourceOptions {
  preferFolder?: boolean;
  fallbackToFolder?: boolean;
}

export interface LoadLogSourceResult {
  source: LogSource;
  entries: FolderEntry[];
  selectedFilePath: string | null;
  parseResult: ParseResult | null;
}

const KNOWN_SOURCE_BY_PRESET_MENU_ID: Record<string, string> = {
  "preset.windows.ime": "windows-intune-ime-logs",
};

const KNOWN_SOURCE_BY_MENU_ID: Record<string, string> = {};

export interface KnownSourceCatalogActionIds {
  sourceId?: string | null;
  presetMenuId?: string | null;
  menuId?: string | null;
}

interface RankedEntry {
  entry: FolderEntry;
  patternIndex: number;
  isCanonicalName: boolean;
  isPreferredActiveLog: boolean;
}

function getBaseName(path: string | null): string {
  if (!path) {
    return "";
  }

  return path.split(/[\\/]/).pop() ?? path;
}

function wildcardPatternToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const wildcard = escaped.replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${wildcard}$`, "i");
}

function extractCanonicalNamesFromPattern(pattern: string): string[] {
  if (!pattern.includes("*") && !pattern.includes("?")) {
    return [pattern.toLowerCase()];
  }

  if (pattern.endsWith("*.log") && !pattern.slice(0, -5).includes("?")) {
    const prefix = pattern.slice(0, -5);

    if (prefix.length > 0 && !prefix.includes("*")) {
      return [`${prefix}.log`.toLowerCase()];
    }
  }

  return [];
}

function looksLikeRotatedLogFile(fileName: string): boolean {
  const lowerName = fileName.toLowerCase();

  return (
    /\.lo_$/.test(lowerName) ||
    /\.(bak|old|tmp|zip)$/.test(lowerName) ||
    /\.\d+$/.test(lowerName) ||
    /[-_](\d{8}|\d{4}[-_]\d{2}[-_]\d{2})([-_.]\d+)?\.log$/.test(lowerName) ||
    /archive/.test(lowerName)
  );
}

function isPreferredActiveLogFile(fileName: string): boolean {
  const lowerName = fileName.toLowerCase();

  return lowerName.endsWith(".log") && !looksLikeRotatedLogFile(fileName);
}

function rankDefaultFileCandidates(
  entries: FolderEntry[],
  metadata: KnownSourceMetadata
): RankedEntry[] {
  const files = entries.filter((entry) => !entry.isDir);

  if (files.length === 0) {
    return [];
  }

  const patternList = metadata.filePatterns.length > 0 ? metadata.filePatterns : ["*.log"];
  const compiledPatterns = patternList.map((pattern) => ({
    pattern,
    regex: wildcardPatternToRegExp(pattern),
  }));

  const canonicalNames = new Set(
    patternList.flatMap((pattern) => extractCanonicalNamesFromPattern(pattern))
  );

  const ranked = files
    .map((entry) => {
      const firstMatchingPatternIndex = compiledPatterns.findIndex(({ regex }) =>
        regex.test(entry.name)
      );

      if (firstMatchingPatternIndex < 0) {
        return null;
      }

      return {
        entry,
        patternIndex: firstMatchingPatternIndex,
        isCanonicalName: canonicalNames.has(entry.name.toLowerCase()),
        isPreferredActiveLog: isPreferredActiveLogFile(entry.name),
      } satisfies RankedEntry;
    })
    .filter((item): item is RankedEntry => item !== null);

  ranked.sort((left, right) => {
    if (left.patternIndex !== right.patternIndex) {
      return left.patternIndex - right.patternIndex;
    }

    if (left.isCanonicalName !== right.isCanonicalName) {
      return left.isCanonicalName ? -1 : 1;
    }

    if (left.isPreferredActiveLog !== right.isPreferredActiveLog) {
      return left.isPreferredActiveLog ? -1 : 1;
    }

    const leftModified = left.entry.modifiedUnixMs ?? -1;
    const rightModified = right.entry.modifiedUnixMs ?? -1;

    if (leftModified !== rightModified) {
      return rightModified - leftModified;
    }

    return left.entry.name.localeCompare(right.entry.name);
  });

  return ranked;
}

function selectDefaultKnownFolderFilePath(
  entries: FolderEntry[],
  metadata: KnownSourceMetadata
): string | null {
  const ranked = rankDefaultFileCandidates(entries, metadata);
  return ranked[0]?.entry.path ?? null;
}

function classifySourceError(error: unknown): { kind: "missing" | "error"; message: string } {
  const message = error instanceof Error ? error.message : String(error);

  if (
    /not found|cannot find|no such file|os error 2|os error 3|access is denied|permission denied|os error 5/i.test(
      message
    )
  ) {
    return {
      kind: "missing",
      message,
    };
  }

  return {
    kind: "error",
    message,
  };
}

function setAwaitingSelectionStatus(source: LogSource, entries: FolderEntry[]): void {
  const state = useLogStore.getState();

  if (entries.length === 0) {
    state.setSourceStatus({
      kind: "empty",
      message: "Source loaded, but no files were found.",
    });
    return;
  }

  if (source.kind === "known") {
    state.setSourceStatus({
      kind: "awaiting-file-selection",
      message: "Source loaded. Select a file from the sidebar.",
      detail: "No default file matched strongly enough to auto-open.",
    });
    return;
  }

  state.setSourceStatus({
    kind: "awaiting-file-selection",
    message: "Folder loaded. Select a file from the sidebar.",
  });
}

export function getLogSourcePath(source: LogSource): string {
  if (source.kind === "known") {
    return source.defaultPath;
  }

  return source.path;
}

async function stopCurrentTailIfNeeded(nextFilePath: string | null): Promise<void> {
  const currentPath = useLogStore.getState().openFilePath;

  if (!currentPath) {
    return;
  }

  if (nextFilePath && currentPath === nextFilePath) {
    return;
  }

  await stopTail(currentPath).catch((error) => {
    console.warn("[log-source] failed to stop current tail", {
      currentPath,
      error,
    });
  });
}

function applyParseResultToStore(
  source: LogSource,
  selectedFilePath: string,
  result: ParseResult
): void {
  const state = useLogStore.getState();

  state.setActiveSource(source);
  state.setSelectedSourceFilePath(selectedFilePath);
  state.setEntries(result.entries);
  state.setFormatDetected(result.formatDetected);
  state.setParserSelection(result.parserSelection);
  state.setTotalLines(result.totalLines);
  state.setByteOffset(result.byteOffset);
  state.selectEntry(null);
  state.setSourceStatus({
    kind: "loaded",
    message: `Loaded ${getBaseName(selectedFilePath)}.`,
  });
}

function clearSelectedFileState(source: LogSource, entries: FolderEntry[]): void {
  const state = useLogStore.getState();

  state.setActiveSource(source);
  state.setSourceEntries(entries);
  state.clearActiveFile();
}
async function recoverFromSelectedFileLoadFailure(
  source: LogSource,
  entries: FolderEntry[],
  selectedFilePath: string,
  error: unknown
): Promise<LoadLogSourceResult> {
  const state = useLogStore.getState();
  const { kind, message } = classifySourceError(error);

  console.warn("[log-source] selected source file failed to load", {
    source,
    selectedFilePath,
    error,
  });

  await stopCurrentTailIfNeeded(null);
  clearSelectedFileState(source, entries);

  state.setSourceStatus({
    kind: "awaiting-file-selection",
    message:
      kind === "missing"
        ? `Selected file is no longer available: ${getBaseName(selectedFilePath)}.`
        : `Could not load selected file: ${getBaseName(selectedFilePath)}.`,
    detail:
      kind === "missing"
        ? "The source was reloaded without that file. Select another file from the sidebar."
        : message,
  });

  return {
    source,
    entries,
    selectedFilePath: null,
    parseResult: null,
  };
}


export interface RefreshSourceContext {
  source: LogSource;
  selectedFilePath: string | null;
}

export function getCurrentRefreshSourceContext(): RefreshSourceContext | null {
  const state = useLogStore.getState();
  const source =
    state.activeSource ??
    (state.openFilePath ? { kind: "file", path: state.openFilePath } : null);

  if (!source) {
    return null;
  }

  return {
    source,
    selectedFilePath: state.selectedSourceFilePath ?? null,
  };
}

export async function refreshCurrentLogSource(trigger: string): Promise<boolean> {
  const context = getCurrentRefreshSourceContext();

  if (!context) {
    console.info("[log-source] skipped refresh because no active source context", {
      trigger,
    });
    return false;
  }

  console.info("[log-source] refreshing active source context", {
    trigger,
    source: context.source,
    selectedFilePath: context.selectedFilePath,
  });

  await loadLogSource(context.source, {
    selectedFilePath: context.selectedFilePath,
  });
  return true;
}
export async function refreshKnownLogSources(): Promise<KnownSourceMetadata[]> {
  console.info("[log-source] refreshing known source metadata");

  const sources = await getKnownLogSources();
  useLogStore.getState().setKnownSources(sources);

  return sources;
}

export function resolveKnownSourceIdFromCatalogAction(
  ids: KnownSourceCatalogActionIds
): string | null {
  const explicitSourceId = ids.sourceId?.trim();

  if (explicitSourceId) {
    return explicitSourceId;
  }

  if (ids.presetMenuId) {
    const presetSourceId = KNOWN_SOURCE_BY_PRESET_MENU_ID[ids.presetMenuId];

    if (presetSourceId) {
      return presetSourceId;
    }
  }

  if (ids.menuId) {
    const menuSourceId = KNOWN_SOURCE_BY_MENU_ID[ids.menuId];

    if (menuSourceId) {
      return menuSourceId;
    }
  }

  return null;
}

export async function getKnownSourceMetadataById(
  sourceId: string
): Promise<KnownSourceMetadata | null> {
  const state = useLogStore.getState();
  const knownSources =
    state.knownSources.length > 0 ? state.knownSources : await refreshKnownLogSources();

  return knownSources.find((source) => source.id === sourceId) ?? null;
}
export async function loadSelectedLogFile(
  filePath: string,
  source: LogSource
): Promise<ParseResult> {
  const state = useLogStore.getState();

  console.info("[log-source] loading selected file", {
    sourceKind: source.kind,
    filePath,
  });

  state.setLoading(true);
  state.setSourceStatus({
    kind: "loading",
    message: `Loading ${getBaseName(filePath)}...`,
  });
  await stopCurrentTailIfNeeded(filePath);

  try {
    const result = await openLogFile(filePath);
    applyParseResultToStore(source, result.filePath, result);
    return result;
  } finally {
    state.setLoading(false);
  }
}

export async function loadPathAsLogSource(
  path: string,
  options: LoadPathAsLogSourceOptions = {}
): Promise<LoadLogSourceResult> {
  const loadOptions: LoadLogSourceOptions = {
    selectedFilePath: options.selectedFilePath ?? null,
  };

  const primarySource: LogSource = options.preferFolder
    ? { kind: "folder", path }
    : { kind: "file", path };

  try {
    return await loadLogSource(primarySource, loadOptions);
  } catch (error) {
    const allowFolderFallback = options.fallbackToFolder !== false;

    if (options.preferFolder || !allowFolderFallback) {
      throw error;
    }

    console.info("[log-source] retrying path as folder source", { path });
    return loadLogSource({ kind: "folder", path }, loadOptions);
  }
}

export async function loadLogSource(
  source: LogSource,
  options: LoadLogSourceOptions = {}
): Promise<LoadLogSourceResult> {
  const state = useLogStore.getState();

  console.info("[log-source] loading source container", {
    source,
    selectedFilePath: options.selectedFilePath ?? null,
  });

  state.setLoading(true);
  state.setSourceStatus({
    kind: "loading",
    message: "Loading source...",
  });

  try {
    if (source.kind === "file") {
      await stopCurrentTailIfNeeded(source.path);
      const result = await openLogSourceFile(source);

      state.setSourceEntries([]);
      applyParseResultToStore(source, result.filePath, result);

      return {
        source,
        entries: [],
        selectedFilePath: result.filePath,
        parseResult: result,
      };
    }

    if (source.kind === "folder") {
      const listing = await listLogSourceFolder(source);
      const requestedFilePath = options.selectedFilePath ?? null;

      state.setActiveSource(source);
      state.setSourceEntries(listing.entries);

      if (!requestedFilePath) {
        await stopCurrentTailIfNeeded(null);
        clearSelectedFileState(source, listing.entries);
        setAwaitingSelectionStatus(source, listing.entries);

        return {
          source,
          entries: listing.entries,
          selectedFilePath: null,
          parseResult: null,
        };
      }

      try {
        const result = await loadSelectedLogFile(requestedFilePath, source);

        return {
          source,
          entries: listing.entries,
          selectedFilePath: result.filePath,
          parseResult: result,
        };
      } catch (error) {
        return recoverFromSelectedFileLoadFailure(source, listing.entries, requestedFilePath, error);
      }
    }

    const knownSources =
      state.knownSources.length > 0
        ? state.knownSources
        : await refreshKnownLogSources();

    const metadata = knownSources.find((item) => item.id === source.sourceId);

    if (!metadata) {
      throw new Error(`Known source '${source.sourceId}' was not found.`);
    }

    if (source.pathKind === "file") {
      await stopCurrentTailIfNeeded(source.defaultPath);
      const result = await openLogSourceFile(source);

      state.setSourceEntries([]);
      applyParseResultToStore(source, result.filePath, result);

      return {
        source,
        entries: [],
        selectedFilePath: result.filePath,
        parseResult: result,
      };
    }

    const listing = await listLogSourceFolder(source);
    const requestedFilePath = options.selectedFilePath ?? null;
    const autoSelectedFilePath =
      requestedFilePath ?? selectDefaultKnownFolderFilePath(listing.entries, metadata);

    state.setActiveSource(source);
    state.setSourceEntries(listing.entries);

    if (!autoSelectedFilePath) {
      await stopCurrentTailIfNeeded(null);
      clearSelectedFileState(source, listing.entries);
      setAwaitingSelectionStatus(source, listing.entries);

      return {
        source,
        entries: listing.entries,
        selectedFilePath: null,
        parseResult: null,
      };
    }

    try {
      const result = await loadSelectedLogFile(autoSelectedFilePath, source);

      if (!requestedFilePath) {
        state.setSourceStatus({
          kind: "auto-selected-file",
          message: `Loaded default file: ${getBaseName(result.filePath)}.`,
          detail: `Preset matched file patterns for '${metadata.label}'.`,
        });
      }

      return {
        source,
        entries: listing.entries,
        selectedFilePath: result.filePath,
        parseResult: result,
      };
    } catch (error) {
      if (requestedFilePath) {
        return recoverFromSelectedFileLoadFailure(source, listing.entries, requestedFilePath, error);
      }

      const { kind, message } = classifySourceError(error);

      console.warn("[log-source] auto-selected file failed to load", {
        source,
        filePath: autoSelectedFilePath,
        error,
      });

      await stopCurrentTailIfNeeded(null);
      clearSelectedFileState(source, listing.entries);
      state.setSourceStatus({
        kind: "awaiting-file-selection",
        message:
          kind === "missing"
            ? "Preset opened, but the default file no longer exists."
            : "Preset opened, but default file could not be read.",
        detail:
          kind === "missing"
            ? "Select another file from the sidebar or reload the source."
            : message,
      });

      return {
        source,
        entries: listing.entries,
        selectedFilePath: null,
        parseResult: null,
      };
    }
  } catch (error) {
    const { kind, message } = classifySourceError(error);

    state.setActiveSource(source);
    state.setSourceEntries([]);
    state.clearActiveFile();
    state.setSourceStatus({
      kind,
      message:
        kind === "missing"
          ? `Source path is missing or inaccessible: ${getLogSourcePath(source)}`
          : "Failed to load source.",
      detail: message,
    });

    console.error("[log-source] failed to load source", {
      source,
      error,
    });
    throw error;
  } finally {
    state.setLoading(false);
  }
}


