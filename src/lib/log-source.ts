import {
  getKnownLogSources,
  inspectPathKind,
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
import { offerElevationForSourceFailure } from "./elevation-recovery";
import {
  readAccessDenied,
  type AccessDeniedClassification,
} from "./source-error";
import { useUiStore, type TabSourceContext } from "../stores/ui-store";
import { useFilterStore } from "../stores/filter-store";
import type {
  FolderEntry,
  KnownSourceMetadata,
  LogEntry,
  LogSource,
  ParseResult,
} from "../types/log";
import type { RegistryParseResult } from "../types/registry";

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
let tabSwitchGeneration = 0;

function isCurrentTabSwitch(generation: number): boolean {
  return generation === tabSwitchGeneration;
}

export interface KnownSourceCatalogActionIds {
  sourceId?: string | null;
  presetMenuId?: string | null;
  menuId?: string | null;
}


/**
 * Sort a source failure into the category the status line reports.
 *
 * Exported for tests: the split between "missing" and "error" is the whole
 * point of the Access Denied work, and it is far easier to pin here than
 * through a full source load.
 */
export function classifySourceError(error: unknown): {
  kind: "missing" | "error";
  message: string;
  accessDenied: AccessDeniedClassification | null;
} {
  // A backend verdict wins outright. It comes from the OS error kind/code, so
  // unlike the text match below it stays correct on a localized Windows install.
  const accessDenied = readAccessDenied(error);
  if (accessDenied) {
    // "error", not "missing": the source exists, we are simply not allowed to
    // read it, and telling the user it is missing sends them looking for the
    // wrong problem.
    return { kind: "error", message: accessDenied.message, accessDenied };
  }

  const message = error instanceof Error ? error.message : String(error);

  // Fallback for failures that never reached the classifier. Only genuine
  // not-found wording counts as missing.
  // The error codes are anchored: unanchored, "os error 2" also matches
  // "os error 21" (is-a-directory) and "os error 32" (sharing violation),
  // neither of which means the source is gone.
  if (
    /not found|cannot find|no such file|os error 2\b|os error 3\b/i.test(message)
  ) {
    return {
      kind: "missing",
      message,
      accessDenied: null,
    };
  }

  // Everything else, including permission wording with no structured verdict,
  // is a generic error. Calling a permission refusal "missing" is the exact
  // misclassification this work exists to remove: it sends the user looking for
  // a file that is sitting right where they left it. It still carries no
  // verdict, so it never offers elevation off localized message text either.
  return {
    kind: "error",
    message,
    accessDenied: null,
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
  result: ParseResult,
  switchGeneration: number,
): Promise<boolean> {
  if (!isCurrentTabSwitch(switchGeneration)) return false;
  const state = useLogStore.getState();
  // Registry files use a dedicated viewer — load structured data instead of log entries
  if (result.parserSelection?.parser === "registry") {
    let registryData: RegistryParseResult;
    try {
      registryData = await parseRegistryFile(selectedFilePath);
    } catch (err) {
      if (!isCurrentTabSwitch(switchGeneration)) return false;
      console.error("[log-source] failed to load registry file", err);
      throw err;
    }
    const { setCachedRegistry, useRegistryStore } = await import("../stores/registry-store");
    if (!isCurrentTabSwitch(switchGeneration)) return false;

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
    setCachedRegistry(selectedFilePath, registryData);
    useRegistryStore.getState().setRegistryData(registryData);
    return true;
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
  return true;
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
  folderEntries: FolderEntry[],
  loadGeneration: number,
): Promise<void> {
  if (!isCurrentTabSwitch(loadGeneration)) return;
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
  state.setFolderLoadRequestId(loadGeneration);
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
    if (!isCurrentTabSwitch(loadGeneration)) return;

    const batchStart = performance.now();
    const batchResults = await parseFilesBatch(batch, loadGeneration, offset);
    if (!isCurrentTabSwitch(loadGeneration)) return;
    const batchMs = Math.round(performance.now() - batchStart);

    console.info(`[log-source] batch ${batchIndex}/${totalBatches} — completed ${batchResults.length} files in ${batchMs} ms`);

    allResults.push(...batchResults);
  }

  const parseMs = Math.round(performance.now() - startTime);
  console.info(`[log-source] all batches complete in ${parseMs} ms — assembling aggregate view`);

  // Yield so the "Finalizing..." progress text renders before the heavy
  // in-memory assembly work below.
  await new Promise((r) => setTimeout(r, 0));
  if (!isCurrentTabSwitch(loadGeneration)) return;

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

  if (!isCurrentTabSwitch(loadGeneration)) return;
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
/**
 * Recover from a selected file that would not load inside a folder source.
 *
 * The folder listing itself succeeded, so this is a recovery rather than a
 * rethrow and the failure never reaches `loadLogSource`'s catch. That makes it
 * the second place an Access Denied verdict has to be honoured: dropping it here
 * reported a protected file as a generic load failure and left the user with no
 * route to elevation, which is the same misreport the folder lane exists to
 * prevent.
 */
async function recoverFromSelectedFileLoadFailure(
  source: LogSource,
  entries: FolderEntry[],
  selectedFilePath: string,
  error: unknown,
  loadGeneration: number,
): Promise<LoadLogSourceResult | null> {
  if (!isCurrentTabSwitch(loadGeneration)) {
    return null;
  }
  const state = useLogStore.getState();
  const { kind, message, accessDenied } = classifySourceError(error);

  console.warn("[log-source] selected source file failed to load", {
    source,
    selectedFilePath,
    error,
  });

  if (!isCurrentTabSwitch(loadGeneration)) {
    return null;
  }
  await stopCurrentTailIfNeeded(null);
  if (!isCurrentTabSwitch(loadGeneration)) {
    return null;
  }
  clearSelectedFileState(source, entries);

  state.setSourceStatus({
    kind: "awaiting-file-selection",
    message: accessDenied
      ? `Access to this file was denied: ${getBaseName(selectedFilePath)}.`
      : kind === "missing"
        ? `Selected file is no longer available: ${getBaseName(selectedFilePath)}.`
        : `Could not load selected file: ${getBaseName(selectedFilePath)}.`,
    detail:
      !accessDenied && kind === "missing"
        ? "The source was reloaded without that file. Select another file from the sidebar."
        : message,
  });

  if (accessDenied) {
    // The file, not the folder: elevating and reopening the folder would land
    // on the same refusal. Fire and forget, matching `loadLogSource`.
    void offerElevationForSourceFailure({
      error,
      source: { kind: "file", path: selectedFilePath },
    });
  }

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

  const result = await loadLogSource(context.source, {
    selectedFilePath: context.selectedFilePath,
  });
  return result !== null;
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
  source: LogSource,
  switchGeneration?: number,
): Promise<ParseResult | null> {
  const loadGeneration = switchGeneration ?? ++tabSwitchGeneration;
  if (switchGeneration !== undefined && !isCurrentTabSwitch(switchGeneration)) return null;
  const state = useLogStore.getState();
  state.setFolderLoadProgress(null);
  // Check cache first — if the file was already parsed (e.g., during folder
  // batch load), skip the IPC call entirely and apply from cache.
  const cached = getCachedTabSnapshot(filePath);
  if (cached) {
    // Registry files from cache — load via the registry pipeline
    if (cached.parserSelection?.parser === "registry") {
      console.info("[log-source] loadSelectedLogFile registry from cache", { filePath });

      const { getCachedRegistry, setCachedRegistry, useRegistryStore } = await import("../stores/registry-store");
      if (!isCurrentTabSwitch(loadGeneration)) return null;

      let regData = getCachedRegistry(filePath);
      if (!regData) {
        regData = await parseRegistryFile(filePath);
        if (!isCurrentTabSwitch(loadGeneration)) return null;
        setCachedRegistry(filePath, regData);
      }
      if (!isCurrentTabSwitch(loadGeneration)) return null;

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

  if (!isCurrentTabSwitch(loadGeneration)) return null;
  state.setLoading(true);
  state.setSourceStatus({
    kind: "loading",
    message: `Loading ${getBaseName(filePath)}...`,
  });

  try {
    if (!isCurrentTabSwitch(loadGeneration)) return null;
    await stopCurrentTailIfNeeded(filePath);
    if (!isCurrentTabSwitch(loadGeneration)) return null;

    let result: ParseResult;
    try {
      result = await openLogFile(filePath);
    } catch (error) {
      if (!isCurrentTabSwitch(loadGeneration)) return null;
      throw error;
    }
    if (!isCurrentTabSwitch(loadGeneration)) return null;
    const applied = await applyParseResultToStore(
      source,
      result.filePath,
      result,
      loadGeneration,
    );
    return applied ? result : null;
  } finally {
    if (isCurrentTabSwitch(loadGeneration)) {
      state.setLoading(false);
    }
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
  const generation = ++tabSwitchGeneration;
  logState.setLoading(false);
  logState.setFolderLoadProgress(null);

  // Already showing this file — invalidate any older pending switch and stop
  // its loading indicator.
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
        if (
          !(await restoreFolderContext(
            sourceContext,
            generation,
          ))
        ) {
          return;
        }
      } else if (sourceContext?.sourceKind === "file") {
        logState.setActiveSource(sourceContext.source);
        logState.setSourceEntries([]);
        logState.setBundleMetadata(null);
      }

      // Restore registry data from cache (or reload)
      const { getCachedRegistry, setCachedRegistry, useRegistryStore } = await import("../stores/registry-store");
      if (!isCurrentTabSwitch(generation)) return;
      const cachedReg = getCachedRegistry(filePath);
      if (cachedReg) {
        useRegistryStore.getState().setRegistryData(cachedReg);
      } else {
        const regData = await parseRegistryFile(filePath);
        if (!isCurrentTabSwitch(generation)) return;
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

    const standaloneSource =
      sourceContext?.sourceKind === "file"
        ? sourceContext.source
        : sourceContext === null
          ? { kind: "file" as const, path: filePath }
          : null;
    if (standaloneSource) {
      logState.setActiveSource(standaloneSource);
      logState.setSourceEntries([]);
      logState.setBundleMetadata(null);
    }

    logState.setEntries(cached.entries);
    logState.setSelectedSourceFilePath(cached.selectedSourceFilePath);
    logState.setOpenFilePath(filePath);
    logState.setFormatDetected(cached.formatDetected);
    logState.setParserSelection(cached.parserSelection);
    logState.setTotalLines(cached.totalLines);
    logState.setByteOffset(cached.byteOffset);
    logState.setActiveColumns(cached.activeColumns);
    useUiStore.getState().resetColumnWidths();
    logState.setAggregateFiles([]);
    logState.setSourceOpenMode(cached.sourceOpenMode);
    logState.selectEntry(null);
    logState.setSourceStatus({
      kind: "loaded",
      message: `Loaded ${getBaseName(filePath)}.`,
    });

    if (sourceContext && sourceContext.sourceKind !== "file") {
      try {
        const restored = await restoreFolderContext(
          sourceContext,
          generation,
        );
        if (!restored) return;
      } catch (error) {
        console.warn("[log-source] folder context restore failed after tab switch", {
          filePath,
          error,
        });
      }
    }
    return;
  }
  // Migrated tabs retain a file path but no source context. Resolve the path
  // through the same lane selector, then use the generation-aware file loader.
  if (!sourceContext) {
    const legacySource = await resolveSourceForPath(filePath, false, false);
    if (!isCurrentTabSwitch(generation)) return;
    await loadSelectedLogFile(filePath, legacySource, generation);
    if (!isCurrentTabSwitch(generation)) return;
    logState.setSourceEntries([]);
    logState.setBundleMetadata(null);
    return;
  }

  const { source } = sourceContext;

  if (sourceContext.sourceKind === "file") {
    // Standalone file — load directly
    await loadSelectedLogFile(filePath, source, generation);
    if (!isCurrentTabSwitch(generation)) return;
    logState.setSourceEntries([]);
    logState.setBundleMetadata(null);
    return;
  }

  // Folder or known-source tab — restore sidebar then load the file
  if (
    !(await restoreFolderContext(
      sourceContext,
      generation,
    ))
  ) {
    return;
  }
  await loadSelectedLogFile(filePath, source, generation);
}

/** Restore the sidebar folder listing if the active source changed. */
async function restoreFolderContext(
  sourceContext: TabSourceContext,
  restoreGeneration: number,
): Promise<boolean> {
  if (!isCurrentTabSwitch(restoreGeneration)) return false;
  const logState = useLogStore.getState();

  const { source } = sourceContext;
  const currentSource = logState.activeSource;
  const sourceChanged =
    !currentSource ||
    currentSource.kind !== source.kind ||
    getLogSourcePath(currentSource) !== getLogSourcePath(source);

  if (!sourceChanged) {
    return true;
  }

  console.info("[log-source] restoring folder context", {
    sourceKind: source.kind,
    sourcePath: getLogSourcePath(source),
  });

  const listing = await listLogSourceFolder(source);
  if (!isCurrentTabSwitch(restoreGeneration)) return false;
  logState.setActiveSource(source);
  logState.setSourceEntries(listing.entries);
  logState.setBundleMetadata(listing.bundleMetadata ?? null);
  return true;
}

/**
 * Load multiple files as a merged aggregate view.
 * Reuses the same batch-parse + merge logic as folder loading.
 */
export async function loadFilesAsLogSource(paths: string[]): Promise<boolean> {
  if (paths.length === 0) return true;

  // Single file — use normal single-file flow
  if (paths.length === 1) {
    const result = await loadPathAsLogSource(paths[0], {
      fallbackToFolder: false,
    });
    return result !== null;
  }
  const loadGeneration = ++tabSwitchGeneration;

  const state = useLogStore.getState();
  state.setFolderLoadProgress(null);
  state.setFolderLoadRequestId(loadGeneration);

  // Clean up current state before starting the parse
  if (!isCurrentTabSwitch(loadGeneration)) return false;
  await stopCurrentTailIfNeeded(null);
  if (!isCurrentTabSwitch(loadGeneration)) return false;
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
    const results = await parseFilesBatch(paths, loadGeneration, 0);
    if (!isCurrentTabSwitch(loadGeneration)) return false;
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

    if (!isCurrentTabSwitch(loadGeneration)) return false;
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
    return true;
  } finally {
    if (isCurrentTabSwitch(loadGeneration)) {
      state.setLoading(false);
      state.setFolderLoadProgress(null);
    }
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

/**
 * Choose the lane a raw, user-supplied path should be opened through.
 *
 * The kind is established before the lane is picked, and that ordering is the
 * whole point. The file lane ends at `open_log_file`, and on Windows opening a
 * directory without `FILE_FLAG_BACKUP_SEMANTICS` fails with
 * `ERROR_ACCESS_DENIED`, which the backend classifier would otherwise have to
 * distinguish from a genuine permission refusal. A folder that reached the file
 * lane therefore raised "Restart as administrator?", and confirming it
 * re-attempted the very same folder as a file, so the prompt could never
 * succeed.
 *
 * Living here rather than at any one caller is deliberate: every entry point
 * that turns a dropped, pasted, restored, or argv-supplied path into a source
 * goes through `loadPathAsLogSource`, so one guard covers all of them. The
 * Intune and ESP workspaces already probe the kind the same way before building
 * their own source.
 *
 * An explicitly file-only request also keeps the file lane even if the path now
 * names a directory. That preserves the caller's declared scope, which is
 * especially important for a one-time elevation restore. A probe that cannot
 * answer likewise keeps the historical file-first behaviour.
 */
async function resolveSourceForPath(
  path: string,
  preferFolder: boolean,
  allowFolder: boolean
): Promise<LogSource> {
  if (preferFolder) {
    return { kind: "folder", path };
  }
  if (!allowFolder) {
    return { kind: "file", path };
  }

  let pathKind: "file" | "folder" | "unknown";
  try {
    pathKind = await inspectPathKind(path);
  } catch (error) {
    console.warn("[log-source] could not determine path kind, assuming file", {
      path,
      error,
    });
    pathKind = "unknown";
  }

  return pathKind === "folder"
    ? { kind: "folder", path }
    : { kind: "file", path };
}

export async function loadPathAsLogSource(
  path: string,
  options: LoadPathAsLogSourceOptions = {}
): Promise<LoadLogSourceResult | null> {
  const probeGeneration = ++tabSwitchGeneration;
  useLogStore.getState().setFolderLoadProgress(null);
  const loadOptions: LoadLogSourceOptions = {
    selectedFilePath: options.selectedFilePath ?? null,
  };

  const primarySource = await resolveSourceForPath(
    path,
    options.preferFolder === true,
    options.fallbackToFolder !== false
  );
  if (!isCurrentTabSwitch(probeGeneration)) return null;

  try {
    return await loadLogSource(primarySource, loadOptions, probeGeneration);
  } catch (error) {
    if (!isCurrentTabSwitch(probeGeneration)) return null;
    const allowFolderFallback = options.fallbackToFolder !== false;

    // Keyed off the lane actually taken, not off `preferFolder`: the kind probe
    // can also select the folder lane, and retrying a folder as a folder would
    // just repeat the same failure.
    if (primarySource.kind === "folder" || !allowFolderFallback) {
      throw error;
    }

    if (!isCurrentTabSwitch(probeGeneration)) return null;
    console.info("[log-source] retrying path as folder source", { path });
    return loadLogSource({ kind: "folder", path }, loadOptions, probeGeneration);
  }
}

export async function loadLogSource(
  source: LogSource,
  options: LoadLogSourceOptions = {},
  existingGeneration?: number,
): Promise<LoadLogSourceResult | null> {
  // A new source load supersedes any pending tab restoration. Path probes pass
  // their already-claimed generation through so a current load error can still
  // take its documented folder fallback.
  const loadGeneration = existingGeneration ?? ++tabSwitchGeneration;
  const state = useLogStore.getState();
  state.setFolderLoadProgress(null);

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
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }
      await stopCurrentTailIfNeeded(source.path);
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }
      const result = await openLogSourceFile(source);
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }

      state.setSourceEntries([]);
      state.setBundleMetadata(null);
      const applied = await applyParseResultToStore(
        source,
        result.filePath,
        result,
        loadGeneration,
      );
      if (!applied) {
        return null;
      }

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
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }

      state.setActiveSource(source);
      state.setSourceEntries(listing.entries);
      state.setBundleMetadata(listing.bundleMetadata ?? null);

      if (!requestedFilePath) {
        if (!isCurrentTabSwitch(loadGeneration)) {
          return null;
        }
        await stopCurrentTailIfNeeded(null);
        if (!isCurrentTabSwitch(loadGeneration)) {
          return null;
        }
        await loadFolderProgressive(source, listing.entries, loadGeneration);
        if (!isCurrentTabSwitch(loadGeneration)) {
          return null;
        }

        return {
          source,
          entries: listing.entries,
          selectedFilePath: null,
          parseResult: null,
        };
      }

      return recoverOrLoadSelectedFolderFile(
        source,
        listing.entries,
        requestedFilePath,
        loadGeneration,
      );
    }

    const knownSources =
      state.knownSources.length > 0
        ? state.knownSources
        : await refreshKnownLogSources();
    if (!isCurrentTabSwitch(loadGeneration)) {
      return null;
    }

    const metadata = knownSources.find((item) => item.id === source.sourceId);

    if (!metadata) {
      throw new Error(`Known source '${source.sourceId}' was not found.`);
    }

    if (source.pathKind === "file") {
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }
      await stopCurrentTailIfNeeded(source.defaultPath);
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }
      const result = await openLogSourceFile(source);
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }

      state.setSourceEntries([]);
      state.setBundleMetadata(null);
      const applied = await applyParseResultToStore(
        source,
        result.filePath,
        result,
        loadGeneration,
      );
      if (!applied) {
        return null;
      }

      return {
        source,
        entries: [],
        selectedFilePath: result.filePath,
        parseResult: result,
      };
    }

    const listing = await listLogSourceFolder(source);
    if (!isCurrentTabSwitch(loadGeneration)) {
      return null;
    }

    state.setActiveSource(source);
    state.setSourceEntries(listing.entries);
    state.setBundleMetadata(listing.bundleMetadata ?? null);

    if (!requestedFilePath) {
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }
      await stopCurrentTailIfNeeded(null);
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }
      await loadFolderProgressive(source, listing.entries, loadGeneration);
      if (!isCurrentTabSwitch(loadGeneration)) {
        return null;
      }

      return {
        source,
        entries: listing.entries,
        selectedFilePath: null,
        parseResult: null,
      };
    }

    return recoverOrLoadSelectedFolderFile(
      source,
      listing.entries,
      requestedFilePath,
      loadGeneration,
    );
  } catch (error) {
    if (!isCurrentTabSwitch(loadGeneration)) {
      return null;
    }
    const { kind, message, accessDenied } = classifySourceError(error);

    state.setActiveSource(source);
    state.setSourceEntries([]);
    state.setBundleMetadata(null);
    state.clearActiveFile();
    state.setFolderLoadProgress(null);
    state.setSourceStatus({
      kind,
      message: accessDenied
        ? // Prefer the backend's own bounded path: it is the thing that was
          // actually denied, already length-capped for the IPC payload, and for
          // a known source it is the resolved path rather than the catalog
          // default the frontend would otherwise print.
          accessDenied.path
          ? `Access to this source was denied: ${accessDenied.path}`
          : "Access to this source was denied."
        : kind === "missing"
          ? `Source path is missing or inaccessible: ${getLogSourcePath(source)}`
          : "Failed to load source.",
      detail: message,
    });

    console.error("[log-source] failed to load source", {
      source,
      error,
    });

    if (accessDenied) {
      // Fire and forget: the offer is a suggestion, and the original error must
      // propagate unchanged to whoever called us.
      void offerElevationForSourceFailure({ error, source });
    }

    throw error;
  } finally {
    if (isCurrentTabSwitch(loadGeneration)) {
      state.setLoading(false);
    }
  }
}

async function recoverOrLoadSelectedFolderFile(
  source: LogSource,
  entries: FolderEntry[],
  requestedFilePath: string,
  loadGeneration: number,
): Promise<LoadLogSourceResult | null> {
  try {
    const result = await loadSelectedLogFile(
      requestedFilePath,
      source,
      loadGeneration,
    );
    if (!result || !isCurrentTabSwitch(loadGeneration)) {
      return null;
    }

    return {
      source,
      entries,
      selectedFilePath: result.filePath,
      parseResult: result,
    };
  } catch (error) {
    return recoverFromSelectedFileLoadFailure(
      source,
      entries,
      requestedFilePath,
      error,
      loadGeneration,
    );
  }
}
