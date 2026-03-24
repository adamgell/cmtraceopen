import {
  getKnownLogSources,
  listLogSourceFolder,
  openLogFile,
  openLogSourceFolderAggregate,
  openLogSourceFile,
  stopTail,
} from "./commands";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import type {
  AggregateParseResult,
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

function getBaseName(path: string | null): string {
  if (!path) {
    return "";
  }

  return path.split(/[\\/]/).pop() ?? path;
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

export function getLogSourcePath(source: LogSource): string {
  if (source.kind === "known") {
    return source.defaultPath;
  }

  return source.path;
}

async function stopCurrentTailIfNeeded(nextFilePath: string | null): Promise<void> {
  const state = useLogStore.getState();
  const currentPaths =
    state.sourceOpenMode === "aggregate-folder"
      ? state.aggregateFiles.map((file) => file.filePath)
      : state.openFilePath
        ? [state.openFilePath]
        : [];

  if (currentPaths.length === 0) {
    return;
  }

  if (nextFilePath && currentPaths.length === 1 && currentPaths[0] === nextFilePath) {
    return;
  }

  await Promise.all(
    currentPaths.map((currentPath) =>
      stopTail(currentPath).catch((error) => {
        console.warn("[log-source] failed to stop current tail", {
          currentPath,
          error,
        });
      })
    )
  );
}

function applyParseResultToStore(
  source: LogSource,
  selectedFilePath: string,
  result: ParseResult
): void {
  const state = useLogStore.getState();

  state.setActiveSource(source);
  state.setSelectedSourceFilePath(selectedFilePath);
  state.setSourceOpenMode("single-file");
  state.setAggregateFiles([]);
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

  // Open (or switch to) a tab for the loaded file
  const fileName = selectedFilePath.split(/[\\/]/).pop() ?? selectedFilePath;
  useUiStore.getState().openTab(selectedFilePath, fileName);
}

function clearSelectedFileState(source: LogSource, entries: FolderEntry[]): void {
  const state = useLogStore.getState();

  state.setActiveSource(source);
  state.setSourceEntries(entries);
  state.clearActiveFile();
}

function applyAggregateParseResultToStore(
  source: LogSource,
  entries: FolderEntry[],
  result: AggregateParseResult
): void {
  const state = useLogStore.getState();

  state.setActiveSource(source);
  state.setSourceEntries(entries);
  state.setSelectedSourceFilePath(null);
  state.setSourceOpenMode("aggregate-folder");
  state.setAggregateFiles(result.files);
  state.setEntries(result.entries);
  state.setFormatDetected(null);
  state.setParserSelection(null);
  state.setTotalLines(result.totalLines);
  state.setByteOffset(0);
  state.selectEntry(null);
  state.setSourceStatus(
    result.files.length === 0
      ? {
        kind: "empty",
        message: "Source loaded, but no files were found.",
      }
      : {
        kind: "loaded",
        message: `Loaded ${result.files.length} file${result.files.length === 1 ? "" : "s"} from ${getBaseName(result.folderPath)}.`,
        detail: "Folder opened as a merged aggregate view.",
      }
  );
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
      state.setBundleMetadata(null);
      applyParseResultToStore(source, result.filePath, result);

      return {
        source,
        entries: [],
        selectedFilePath: result.filePath,
        parseResult: result,
      };
    }

    const requestedFilePath = options.selectedFilePath ?? null;

    if (source.kind === "folder") {
      const listing = await listLogSourceFolder(source);

      state.setActiveSource(source);
      state.setSourceEntries(listing.entries);
      state.setBundleMetadata(listing.bundleMetadata ?? null);

      if (!requestedFilePath) {
        await stopCurrentTailIfNeeded(null);
        const aggregateResult = await openLogSourceFolderAggregate(source);
        applyAggregateParseResultToStore(source, listing.entries, aggregateResult);

        return {
          source,
          entries: listing.entries,
          selectedFilePath: null,
          parseResult: null,
        };
      }

      return recoverOrLoadSelectedFolderFile(source, listing.entries, requestedFilePath);
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
      state.setBundleMetadata(null);
      applyParseResultToStore(source, result.filePath, result);

      return {
        source,
        entries: [],
        selectedFilePath: result.filePath,
        parseResult: result,
      };
    }

    const listing = await listLogSourceFolder(source);

    state.setActiveSource(source);
    state.setSourceEntries(listing.entries);
    state.setBundleMetadata(listing.bundleMetadata ?? null);

    if (!requestedFilePath) {
      await stopCurrentTailIfNeeded(null);
      const aggregateResult = await openLogSourceFolderAggregate(source);
      applyAggregateParseResultToStore(source, listing.entries, aggregateResult);

      return {
        source,
        entries: listing.entries,
        selectedFilePath: null,
        parseResult: null,
      };
    }

    return recoverOrLoadSelectedFolderFile(source, listing.entries, requestedFilePath);
  } catch (error) {
    const { kind, message } = classifySourceError(error);

    state.setActiveSource(source);
    state.setSourceEntries([]);
    state.setBundleMetadata(null);
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

async function recoverOrLoadSelectedFolderFile(
  source: LogSource,
  entries: FolderEntry[],
  requestedFilePath: string
): Promise<LoadLogSourceResult> {
  try {
    const result = await loadSelectedLogFile(requestedFilePath, source);

    return {
      source,
      entries,
      selectedFilePath: result.filePath,
      parseResult: result,
    };
  } catch (error) {
    return recoverFromSelectedFileLoadFailure(source, entries, requestedFilePath, error);
  }
}


