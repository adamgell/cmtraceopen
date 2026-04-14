import {
  getKnownLogSources,
  listLogSourceFolder,
  openLogFile,
  openLogSourceFile,
  parseFilesBatch,
  parseRegistryFile,
  stopTail,
} from "./commands";
import { useLogStore, setCachedTabSnapshot, getCachedTabSnapshot } from "../stores/log-store";
import { getColumnsForParser, getColumnsForAggregate } from "./column-config";
import { getBaseName } from "./file-paths";
import { useUiStore, type TabSourceContext } from "../stores/ui-store";
import { useFilterStore } from "../stores/filter-store";
import type {
  FolderEntry,
  KnownSourceMetadata,
  LogEntry,
  LogSource,
  ParseResult,
} from "../types/log";

function buildTabSourceContext(source: LogSource): TabSourceContext {
  return {
    sourceKind: source.kind,
    sourcePath:
      source.kind === "file"
        ? null
        : source.kind === "folder"
          ? source.path
          : source.defaultPath,
    source,
  };
}

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

async function applyParseResultToStore(
  source: LogSource,
  selectedFilePath: string,
  result: ParseResult
): Promise<void> {
  const state = useLogStore.getState();

  // Registry files use a dedicated viewer — load structured data instead of log entries
  if (result.parserSelection?.parser === "registry") {
    state.setActiveSource(source);
    state.setSelectedSourceFilePath(selectedFilePath);
    state.setSourceOpenMode("single-file");
    state.setAggregateFiles([]);
    state.setEntries([]);
    state.setFormatDetected(result.formatDetected);
    state.setParserSelection(result.parserSelection);
    state.setSourceStatus({
      kind: "loaded",
      message: `Loaded ${getBaseName(selectedFilePath)}.`,
    });

    // Cache a minimal snapshot so tab switching works
    setCachedTabSnapshot(selectedFilePath, {
      entries: [],
      formatDetected: result.formatDetected,
      parserSelection: result.parserSelection,
      totalLines: 0,
      byteOffset: 0,
      selectedSourceFilePath: selectedFilePath,
      sourceOpenMode: "single-file",
      activeColumns: [],
    });

    const fileName = selectedFilePath.split(/[\\/]/).pop() ?? selectedFilePath;
    useUiStore.getState().openTab(selectedFilePath, fileName, buildTabSourceContext(source), "registry");

    // Load registry data asynchronously — the RegistryViewer component will pick it up
    try {
      const { setCachedRegistry } = await import("../stores/registry-store");
      const regData = await parseRegistryFile(selectedFilePath);
      setCachedRegistry(selectedFilePath, regData);
      const { useRegistryStore } = await import("../stores/registry-store");
      useRegistryStore.getState().setRegistryData(regData);
    } catch (err) {
      console.error("[log-source] failed to load registry file", err);
    }
    return;
  }

  state.setActiveSource(source);
  state.setSelectedSourceFilePath(selectedFilePath);
  state.setSourceOpenMode("single-file");
  state.setAggregateFiles([]);
  state.setEntries(result.entries);
  state.setFormatDetected(result.formatDetected);
  state.setParserSelection(result.parserSelection);
  state.setTotalLines(result.totalLines);
  state.setByteOffset(result.byteOffset);
  const columns = getColumnsForParser(result.parserSelection.parser);
  state.setActiveColumns(columns);
  useUiStore.getState().resetColumnWidths();
  state.selectEntry(null);
  state.setSourceStatus({
    kind: "loaded",
    message: `Loaded ${getBaseName(selectedFilePath)}.`,
  });

  // Cache the parsed snapshot so tab switches are instant (no re-parse)
  setCachedTabSnapshot(selectedFilePath, {
    entries: result.entries,
    formatDetected: result.formatDetected,
    parserSelection: result.parserSelection,
    totalLines: result.totalLines,
    byteOffset: result.byteOffset,
    selectedSourceFilePath: selectedFilePath,
    sourceOpenMode: "single-file",
    activeColumns: columns,
  });

  // Open (or switch to) a tab for the loaded file
  const fileName = selectedFilePath.split(/[\\/]/).pop() ?? selectedFilePath;
  useUiStore.getState().openTab(selectedFilePath, fileName, buildTabSourceContext(source));
}

function clearSelectedFileState(source: LogSource, entries: FolderEntry[]): void {
  const state = useLogStore.getState();

  state.setActiveSource(source);
  state.setSourceEntries(entries);
  state.clearActiveFile();
}

/**
 * Progressive folder loader: sends ALL file paths to Rust in a single IPC call,
 * where Rayon parses them in parallel across all CPU cores. This eliminates
 * N-1 IPC round-trips and leverages true OS-thread parallelism.
 *
 * The UI shows an indeterminate progress spinner during the single IPC call,
 * then caches all results for instant tab switching.
 */
async function loadFolderProgressive(
  source: LogSource,
  folderEntries: FolderEntry[]
): Promise<void> {
  const state = useLogStore.getState();
  const fileEntries = folderEntries.filter((e) => !e.isDir);
  const folderPath = getLogSourcePath(source) ?? "folder";
  const folderName = getBaseName(folderPath);

  if (fileEntries.length === 0) {
    state.setActiveSource(source);
    state.setSourceEntries(folderEntries);
    state.setSelectedSourceFilePath(null);
    state.setSourceOpenMode("aggregate-folder");
    state.setAggregateFiles([]);
    state.setEntries([]);
    state.selectEntry(null);
    state.setFolderLoadProgress(null);
    state.setSourceStatus({
      kind: "empty",
      message: "Source loaded, but no files were found.",
    });
    return;
  }

  // Show loading overlay with progress tracking
  const totalFiles = fileEntries.length;
  state.setFolderLoadProgress({ current: 0, total: totalFiles, currentFile: "" });
  state.setSourceStatus({
    kind: "loading",
    message: `Parsing ${totalFiles} files from ${folderName}...`,
    detail: "Files are being parsed in parallel batches",
  });

  const startTime = performance.now();

  // Parse files in batches to avoid IPC / memory pressure crashes on large
  // evidence bundles (200+ files).  Each batch is sent as a single IPC call
  // and parsed in parallel on Rust's Rayon thread pool.
  const BATCH_SIZE = 30;
  const allResults: ParseResult[] = [];
  const paths = fileEntries.map((e) => e.path);

  const totalBatches = Math.ceil(paths.length / BATCH_SIZE);
  console.info(`[log-source] starting batched parse: ${totalFiles} files in ${totalBatches} batches of ${BATCH_SIZE}`);

  for (let offset = 0; offset < paths.length; offset += BATCH_SIZE) {
    const batchIndex = Math.floor(offset / BATCH_SIZE) + 1;
    const batch = paths.slice(offset, offset + BATCH_SIZE);

    console.info(`[log-source] batch ${batchIndex}/${totalBatches} — sending ${batch.length} files to Rust:`, batch);

    // Yield to the browser so React can paint progress updates (driven
    // by real-time "parse-progress" events from Rust) before we kick off
    // the next batch IPC call.
    await new Promise((r) => setTimeout(r, 0));

    const batchStart = performance.now();
    const batchResults = await parseFilesBatch(batch);
    const batchMs = Math.round(performance.now() - batchStart);

    console.info(`[log-source] batch ${batchIndex}/${totalBatches} — completed ${batchResults.length} files in ${batchMs} ms`);

    allResults.push(...batchResults);
  }

  const parseMs = Math.round(performance.now() - startTime);
  console.info(`[log-source] all batches complete in ${parseMs} ms — assembling aggregate view`);

  // Yield so the "Finalizing..." progress text renders before the heavy
  // in-memory assembly work below.
  await new Promise((r) => setTimeout(r, 0));

  // Cache each file's entries for instant tab switching
  for (const result of allResults) {
    const fileColumns = getColumnsForParser(result.parserSelection.parser);
    setCachedTabSnapshot(result.filePath, {
      entries: result.entries,
      formatDetected: result.formatDetected,
      parserSelection: result.parserSelection,
      totalLines: result.totalLines,
      byteOffset: result.byteOffset,
      selectedSourceFilePath: result.filePath,
      sourceOpenMode: "single-file",
      activeColumns: fileColumns,
    });
  }

  // Build aggregate view — use Array.concat or indexed copy instead of
  // push(...spread) to avoid blowing the JS call stack on large entry arrays.
  const aggregateFiles: import("../types/log").AggregateParsedFileResult[] = [];
  let totalLines = 0;
  let totalEntryCount = 0;

  for (const result of allResults) {
    totalLines += result.totalLines;
    totalEntryCount += result.entries.length;
    aggregateFiles.push({
      filePath: result.filePath,
      totalLines: result.totalLines,
      parseErrors: result.parseErrors,
      fileSize: result.fileSize,
      byteOffset: result.byteOffset,
    });
  }

  // Pre-allocate and copy with sequential IDs in one pass
  const allEntries = new Array<LogEntry>(totalEntryCount);
  let writeIndex = 0;
  for (const result of allResults) {
    for (let j = 0; j < result.entries.length; j++) {
      allEntries[writeIndex] = { ...result.entries[j], id: writeIndex };
      writeIndex++;
    }
  }

  // Apply the final aggregate state
  state.setActiveSource(source);
  state.setSourceEntries(folderEntries);
  state.setSelectedSourceFilePath(null);
  state.setSourceOpenMode("aggregate-folder");
  state.setAggregateFiles(aggregateFiles);
  state.setEntries(allEntries);
  state.setFormatDetected(null);
  state.setParserSelection(null);
  state.setTotalLines(totalLines);
  state.setByteOffset(0);
  // Derive aggregate columns from the union of all parsers + filePath
  const aggregateColumns = getColumnsForAggregate(
    allResults.map((r) => r.parserSelection.parser)
  );
  state.setActiveColumns(aggregateColumns);
  useUiStore.getState().resetColumnWidths();
  state.selectEntry(null);
  state.setFolderLoadProgress(null);
  state.setSourceStatus({
    kind: "loaded",
    message: `Loaded ${aggregateFiles.length} file${aggregateFiles.length === 1 ? "" : "s"} from ${folderName}.`,
    detail: `Parsed in ${parseMs} ms (parallel).`,
  });

  console.info("[log-source] batch folder load complete", {
    fileCount: aggregateFiles.length,
    totalEntries: allEntries.length,
    parseMs,
  });
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

  // Check cache first — if the file was already parsed (e.g., during folder
  // batch load), skip the IPC call entirely and apply from cache.
  const cached = getCachedTabSnapshot(filePath);
  if (cached) {
    // Registry files from cache — load via the registry pipeline
    if (cached.parserSelection?.parser === "registry") {
      console.info("[log-source] loadSelectedLogFile registry from cache", { filePath });
      state.setSelectedSourceFilePath(filePath);
      state.setSourceOpenMode("single-file");
      state.setEntries([]);
      state.setFormatDetected(cached.formatDetected);
      state.setParserSelection(cached.parserSelection);
      state.setSourceStatus({
        kind: "loaded",
        message: `Loaded ${getBaseName(filePath)}.`,
      });
      const fileName = filePath.split(/[\\/]/).pop() ?? filePath;
      useUiStore.getState().openTab(filePath, fileName, buildTabSourceContext(source), "registry");

      // Load registry data
      const { getCachedRegistry, setCachedRegistry, useRegistryStore } = await import("../stores/registry-store");
      let regData = getCachedRegistry(filePath);
      if (!regData) {
        regData = await parseRegistryFile(filePath);
        setCachedRegistry(filePath, regData);
      }
      useRegistryStore.getState().setRegistryData(regData);

      return {
        entries: [],
        formatDetected: cached.formatDetected ?? null,
        parserSelection: cached.parserSelection ?? null,
        totalLines: 0,
        parseErrors: 0,
        filePath,
        fileSize: 0,
        byteOffset: 0,
      } as ParseResult;
    }

    console.info("[log-source] loadSelectedLogFile from cache (instant)", { filePath });

    state.setEntries(cached.entries);
    state.setSelectedSourceFilePath(cached.selectedSourceFilePath);
    state.setOpenFilePath(filePath);
    state.setFormatDetected(cached.formatDetected);
    state.setParserSelection(cached.parserSelection);
    state.setTotalLines(cached.totalLines);
    state.setByteOffset(cached.byteOffset);
    state.setSourceOpenMode(cached.sourceOpenMode);
    state.setActiveColumns(cached.activeColumns);
    state.selectEntry(null);
    state.setSourceStatus({
      kind: "loaded",
      message: `Loaded ${getBaseName(filePath)} from cache.`,
    });

    // Open/switch to a tab for this file
    const fileName = filePath.split(/[\\/]/).pop() ?? filePath;
    useUiStore.getState().openTab(filePath, fileName, buildTabSourceContext(source));

    // Return a synthetic ParseResult to satisfy callers
    return {
      entries: cached.entries,
      formatDetected: cached.formatDetected ?? null,
      parserSelection: cached.parserSelection ?? null,
      totalLines: cached.totalLines,
      parseErrors: 0,
      filePath,
      fileSize: 0,
      byteOffset: cached.byteOffset,
    } as ParseResult;
  }

  console.info("[log-source] loading selected file (IPC)", {
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
    await applyParseResultToStore(source, result.filePath, result);
    return result;
  } finally {
    state.setLoading(false);
  }
}

/**
 * Fast-path tab switch: restores parsed entries from an in-memory cache when
 * available (zero IPC, instant). Falls back to re-loading from disk on cache
 * miss. For folder/known-source tabs, also restores the sidebar folder listing.
 */
export async function switchToTab(
  filePath: string,
  sourceContext: TabSourceContext | null
): Promise<void> {
  const logState = useLogStore.getState();
  const currentPath = logState.openFilePath;

  // Already showing this file — nothing to do
  if (currentPath === filePath) return;

  // ── Registry tab: restore from registry cache ──────────────────────
  {
    const uiTabs = useUiStore.getState().openTabs;
    const tab = uiTabs.find((t) => t.filePath === filePath);
    if (tab?.fileKind === "registry") {
      logState.setOpenFilePath(filePath);
      logState.setSelectedSourceFilePath(filePath);
      logState.setEntries([]);
      logState.setSourceOpenMode("single-file");

      // Restore sidebar context
      if (sourceContext && sourceContext.sourceKind !== "file") {
        await restoreFolderContext(logState, sourceContext);
      } else if (sourceContext?.sourceKind === "file") {
        logState.setActiveSource(sourceContext.source);
        logState.setSourceEntries([]);
        logState.setBundleMetadata(null);
      }

      // Restore registry data from cache (or reload)
      const { getCachedRegistry, setCachedRegistry, useRegistryStore } = await import("../stores/registry-store");
      const cachedReg = getCachedRegistry(filePath);
      if (cachedReg) {
        useRegistryStore.getState().setRegistryData(cachedReg);
      } else {
        const regData = await parseRegistryFile(filePath);
        setCachedRegistry(filePath, regData);
        useRegistryStore.getState().setRegistryData(regData);
      }
      return;
    }
  }

  // ── Try cache first (instant, no IPC) ──────────────────────────────
  const cached = getCachedTabSnapshot(filePath);
  if (cached) {
    console.info("[log-source] tab switch from cache (instant)", { filePath });

    // Restore sidebar folder context if switching between sources
    if (sourceContext && sourceContext.sourceKind !== "file") {
      await restoreFolderContext(logState, sourceContext);
    } else if (sourceContext?.sourceKind === "file") {
      // Standalone file — clear folder sidebar state
      logState.setActiveSource(sourceContext.source);
      logState.setSourceEntries([]);
      logState.setBundleMetadata(null);
    }

    // Swap parsed entries into the store — this is the fast path
    logState.setEntries(cached.entries);
    logState.setSelectedSourceFilePath(cached.selectedSourceFilePath);
    logState.setSourceOpenMode(cached.sourceOpenMode);
    logState.setFormatDetected(cached.formatDetected);
    logState.setParserSelection(cached.parserSelection);
    logState.setTotalLines(cached.totalLines);
    logState.setByteOffset(cached.byteOffset);
    logState.setActiveColumns(cached.activeColumns);
    useUiStore.getState().resetColumnWidths();
    logState.setAggregateFiles([]);
    logState.selectEntry(null);
    logState.setSourceStatus({
      kind: "loaded",
      message: `Loaded ${getBaseName(filePath)}.`,
    });
    return;
  }

  // ── Cache miss — fall back to IPC load ─────────────────────────────
  console.info("[log-source] tab switch cache miss, loading from disk", { filePath });

  // No source context (legacy tab) — fall back to the old path
  if (!sourceContext) {
    await loadPathAsLogSource(filePath);
    return;
  }

  const { source } = sourceContext;

  if (sourceContext.sourceKind === "file") {
    // Standalone file — load directly
    await loadLogSource(source);
    return;
  }

  // Folder or known-source tab — restore sidebar then load the file
  await restoreFolderContext(logState, sourceContext);
  await loadSelectedLogFile(filePath, source);
}

/** Restore the sidebar folder listing if the active source changed. */
async function restoreFolderContext(
  logState: ReturnType<typeof useLogStore.getState>,
  sourceContext: TabSourceContext
): Promise<void> {
  const { source } = sourceContext;
  const currentSource = logState.activeSource;
  const sourceChanged =
    !currentSource ||
    currentSource.kind !== source.kind ||
    getLogSourcePath(currentSource) !== getLogSourcePath(source);

  if (sourceChanged) {
    console.info("[log-source] restoring folder context", {
      sourceKind: source.kind,
      sourcePath: getLogSourcePath(source),
    });

    const listing = await listLogSourceFolder(source);
    logState.setActiveSource(source);
    logState.setSourceEntries(listing.entries);
    logState.setBundleMetadata(listing.bundleMetadata ?? null);
  }
}

/**
 * Load multiple files as a merged aggregate view.
 * Reuses the same batch-parse + merge logic as folder loading.
 */
export async function loadFilesAsLogSource(paths: string[]): Promise<void> {
  if (paths.length === 0) return;

  // Single file — use normal single-file flow
  if (paths.length === 1) {
    await loadPathAsLogSource(paths[0], { fallbackToFolder: false });
    return;
  }

  const state = useLogStore.getState();

  // Clean up current state before starting the parse
  await stopCurrentTailIfNeeded(null);
  useFilterStore.getState().clearFilter();

  state.setLoading(true);
  state.setFolderLoadProgress({ current: 0, total: paths.length, currentFile: "" });
  state.setSourceStatus({
    kind: "loading",
    message: `Parsing ${paths.length} files...`,
    detail: "Files are being parsed in parallel",
  });

  const startTime = performance.now();

  try {
    const results = await parseFilesBatch(paths);
    const parseMs = Math.round(performance.now() - startTime);

    // Cache each file for instant tab switching
    for (const result of results) {
      const fileColumns = getColumnsForParser(result.parserSelection.parser);
      setCachedTabSnapshot(result.filePath, {
        entries: result.entries,
        formatDetected: result.formatDetected,
        parserSelection: result.parserSelection,
        totalLines: result.totalLines,
        byteOffset: result.byteOffset,
        selectedSourceFilePath: result.filePath,
        sourceOpenMode: "single-file",
        activeColumns: fileColumns,
      });
    }

    // Build aggregate view — avoid push(...spread) to prevent call stack overflow
    const aggregateFiles: import("../types/log").AggregateParsedFileResult[] = [];
    let totalLines = 0;
    let totalEntryCount = 0;

    for (const result of results) {
      totalLines += result.totalLines;
      totalEntryCount += result.entries.length;
      aggregateFiles.push({
        filePath: result.filePath,
        totalLines: result.totalLines,
        parseErrors: result.parseErrors,
        fileSize: result.fileSize,
        byteOffset: result.byteOffset,
      });
    }

    // Pre-allocate and copy with sequential IDs in one pass
    const allEntries = new Array<LogEntry>(totalEntryCount);
    let writeIndex = 0;
    for (const result of results) {
      for (let j = 0; j < result.entries.length; j++) {
        allEntries[writeIndex] = { ...result.entries[j], id: writeIndex };
        writeIndex++;
      }
    }

    // Derive a common parent folder for the multi-file source so the sidebar
    // treats this as folder-like and refresh/reload work correctly.
    const commonDir = getCommonDirectory(paths);
    const source: LogSource = { kind: "folder", path: commonDir };

    // Build sidebar entries from the file list
    const folderEntries: FolderEntry[] = results.map((r) => ({
      path: r.filePath,
      name: r.filePath.split(/[\\/]/).pop() ?? r.filePath,
      isDir: false,
      sizeBytes: r.fileSize,
      modifiedUnixMs: 0,
    }));

    state.setActiveSource(source);
    state.setSourceEntries(folderEntries);
    state.setSelectedSourceFilePath(null);
    state.setSourceOpenMode("aggregate-folder");
    state.setAggregateFiles(aggregateFiles);
    state.setEntries(allEntries);
    state.setFormatDetected(null);
    state.setParserSelection(null);
    state.setBundleMetadata(null);
    state.setTotalLines(totalLines);
    state.setByteOffset(0);
    const aggregateColumns = getColumnsForAggregate(
      results.map((r) => r.parserSelection.parser)
    );
    state.setActiveColumns(aggregateColumns);
    useUiStore.getState().resetColumnWidths();
    state.selectEntry(null);
    state.setFolderLoadProgress(null);

    useUiStore.getState().ensureLogViewVisible("multi-file-open");

    state.setSourceStatus({
      kind: "loaded",
      message: `Loaded ${aggregateFiles.length} files.`,
      detail: `Parsed in ${parseMs} ms (parallel).`,
    });
  } finally {
    state.setLoading(false);
    state.setFolderLoadProgress(null);
  }
}

/** Derive the longest common directory prefix from a list of file paths. */
function getCommonDirectory(paths: string[]): string {
  if (paths.length === 0) return "";
  if (paths.length === 1) {
    const parts = paths[0].split(/[\\/]/);
    parts.pop(); // remove filename
    return parts.join("/") || "/";
  }

  const split = paths.map((p) => p.split(/[\\/]/));
  const minLen = Math.min(...split.map((s) => s.length));
  let common = 0;
  for (let i = 0; i < minLen; i++) {
    if (split.every((s) => s[i] === split[0][i])) {
      common = i + 1;
    } else {
      break;
    }
  }

  // At minimum, return the directory portion (exclude the filename segment)
  const commonParts = split[0].slice(0, common);
  return commonParts.join("/") || "/";
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
      await applyParseResultToStore(source, result.filePath, result);

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
        await loadFolderProgressive(source, listing.entries);

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
      await applyParseResultToStore(source, result.filePath, result);

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
      await loadFolderProgressive(source, listing.entries);

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
