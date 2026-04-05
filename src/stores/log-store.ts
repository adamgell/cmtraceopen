import { create } from "zustand";
import type {
  AggregateParsedFileResult,
  EvidenceBundleMetadata,
  FolderEntry,
  KnownSourceMetadata,
  KnownSourceToolbarFamily,
  LogEntry,
  LogFormat,
  LogSource,
  ParserSelectionInfo,
} from "../types/log";
import {
  type ColumnId,
  DEFAULT_COLUMNS,
  getColumnDef,
} from "../lib/column-config";
import { formatLogEntryTimestamp } from "../lib/date-time-format";
import { getBaseName } from "../lib/file-paths";
import { buildGuidNameMap, mergeGuidNameMap } from "../lib/guid-name-map";
import {
  type MergedTabState,
  type CorrelatedEntry,
  assignFileColors,
  buildMergeCacheKey,
  mergeEntries,
  filterByVisibility,
  findCorrelatedEntries,
} from "../lib/merge-entries";
import {
  type DiffState,
  type DiffSource,
  classifyEntries,
  filterByTimeRange,
} from "../lib/diff-entries";

export type { MergedTabState, CorrelatedEntry };
export type { DiffState, DiffSource };

/**
 * Snapshot of parsed file state — cached in memory so tab switches
 * can restore instantly without re-reading / re-parsing the file.
 */
export interface TabEntrySnapshot {
  entries: LogEntry[];
  formatDetected: LogFormat | null;
  parserSelection: ParserSelectionInfo | null;
  totalLines: number;
  byteOffset: number;
  selectedSourceFilePath: string | null;
  sourceOpenMode: SourceOpenMode;
  activeColumns: ColumnId[];
}

/** Module-level cache: filePath → parsed snapshot. Lives outside Zustand to avoid triggering re-renders. */
const tabEntryCache = new Map<string, TabEntrySnapshot>();

const TAB_CACHE_MAX_SIZE = 30;

export function getCachedTabSnapshot(filePath: string): TabEntrySnapshot | undefined {
  return tabEntryCache.get(filePath);
}

export function setCachedTabSnapshot(filePath: string, snapshot: TabEntrySnapshot): void {
  // Evict oldest if at capacity
  if (tabEntryCache.size >= TAB_CACHE_MAX_SIZE && !tabEntryCache.has(filePath)) {
    const oldestKey = tabEntryCache.keys().next().value;
    if (oldestKey) tabEntryCache.delete(oldestKey);
  }
  tabEntryCache.set(filePath, snapshot);
}

export function clearCachedTabSnapshot(filePath: string): void {
  tabEntryCache.delete(filePath);
}

export function clearAllTabSnapshots(): void {
  tabEntryCache.clear();
}

export type SourceStatusKind =
  | "idle"
  | "loading"
  | "loaded"
  | "auto-selected-file"
  | "awaiting-file-selection"
  | "empty"
  | "missing"
  | "error";

export interface SourceStatus {
  kind: SourceStatusKind;
  message: string;
  detail?: string;
}

export interface StreamStateSnapshot {
  mode: "idle" | "loading" | "live" | "paused";
  label: string;
}

export interface ParserSelectionDisplay {
  parserLabel: string;
  implementationLabel: string;
  provenanceLabel: string;
  qualityLabel: string;
  framingLabel: string;
  dateOrderLabel: string | null;
}

export type SourceOpenMode = "single-file" | "aggregate-folder" | "merged" | "diff" | null;


const UNGROUPED_TOOLBAR_GROUP_ID = "ungrouped";
const UNGROUPED_TOOLBAR_GROUP_LABEL = "Other Sources";
const LAST_SORT_ORDER = Number.MAX_SAFE_INTEGER;

/**
 * Build a test function for the find query.
 * Returns null if the query is empty or (in regex mode) invalid.
 */
function buildFindMatcher(
  query: string,
  caseSensitive: boolean,
  useRegex: boolean
): ((text: string) => boolean) | null {
  if (!query) return null;

  if (useRegex) {
    try {
      const flags = caseSensitive ? "" : "i";
      const re = new RegExp(query, flags);
      return (text) => re.test(text);
    } catch {
      return null; // invalid regex
    }
  }

  const needle = caseSensitive ? query : query.toLowerCase();
  return (text) => {
    const haystack = caseSensitive ? text : text.toLowerCase();
    return haystack.includes(needle);
  };
}

/**
 * Collect all entry text values that should be searched,
 * based on the currently active columns.
 */
function getSearchableText(entry: LogEntry, columns: ColumnId[]): string {
  const parts: string[] = [entry.message];

  for (const colId of columns) {
    if (colId === "message" || colId === "severity" || colId === "lineNumber") continue;
    if (colId === "dateTime") {
      const ts = formatLogEntryTimestamp(entry);
      if (ts) parts.push(ts);
      continue;
    }
    const def = getColumnDef(colId);
    if (def) {
      const val = def.accessor(entry);
      if (val != null) parts.push(String(val));
    }
  }

  return parts.join(" ");
}

/**
 * Scan all entries and return ordered array of matching entry IDs.
 */
function computeFindMatches(
  entries: LogEntry[],
  query: string,
  caseSensitive: boolean,
  useRegex: boolean,
  activeColumns: ColumnId[]
): number[] {
  const matcher = buildFindMatcher(query.trim(), caseSensitive, useRegex);
  if (!matcher) return [];

  const matchIds: number[] = [];
  for (const entry of entries) {
    const text = getSearchableText(entry, activeColumns);
    if (matcher(text)) {
      matchIds.push(entry.id);
    }
  }
  return matchIds;
}

export function hasSourceContext(
  activeSource: LogSource | null,
  openFilePath: string | null
): boolean {
  return activeSource !== null || openFilePath !== null;
}

export function getStreamStateSnapshot(
  isLoading: boolean,
  isPaused: boolean,
  activeSource: LogSource | null,
  openFilePath: string | null
): StreamStateSnapshot {
  if (isLoading) {
    return {
      mode: "loading",
      label: "Loading",
    };
  }

  if (!hasSourceContext(activeSource, openFilePath)) {
    return {
      mode: "idle",
      label: "Idle",
    };
  }

  if (isPaused) {
    return {
      mode: "paused",
      label: "Paused",
    };
  }

  return {
    mode: "live",
    label: "Live",
  };
}

export function getActiveSourcePath(source: LogSource | null): string | null {
  if (!source) {
    return null;
  }

  if (source.kind === "known") {
    return source.defaultPath;
  }

  return source.path;
}

export function getActiveSourceLabel(
  source: LogSource | null,
  knownSources: KnownSourceMetadata[]
): string {
  if (!source) {
    return "No source selected";
  }

  if (source.kind === "known") {
    return knownSources.find((item) => item.id === source.sourceId)?.label ?? source.sourceId;
  }

  return getBaseName(source.path) || source.path;
}

export function getSourceFailureReason(status: SourceStatus): string | null {
  if (status.kind !== "missing" && status.kind !== "error") {
    return null;
  }

  return status.detail ?? status.message;
}

function getParserLabel(parser: ParserSelectionInfo["parser"]): string {
  switch (parser) {
    case "ccm":
      return "CCM";
    case "simple":
      return "Simple";
    case "timestamped":
      return "Timestamped";
    case "plain":
      return "Plain text";
    case "iisW3c":
      return "IIS W3C";
    case "panther":
      return "Panther";
    case "cbs":
      return "CBS";
    case "dism":
      return "DISM";
    case "reportingEvents":
      return "ReportingEvents";
    case "msi":
      return "MSI";
    case "psadtLegacy":
      return "PSADT Legacy";
    case "intuneMacOs":
      return "Intune macOS";
    case "dhcp":
      return "DHCP Server";
    case "burn":
      return "WiX/Burn";
    case "registry":
      return "Registry";
  }
}

function getImplementationLabel(
  implementation: ParserSelectionInfo["implementation"]
): string {
  switch (implementation) {
    case "ccm":
      return "CCM parser";
    case "simple":
      return "Simple parser";
    case "genericTimestamped":
      return "Generic timestamped parser";
    case "iisW3c":
      return "IIS W3C Extended Log parser";
    case "reportingEvents":
      return "ReportingEvents parser";
    case "plainText":
      return "Plain text parser";
    case "msi":
      return "MSI verbose parser";
    case "psadtLegacy":
      return "PSADT Legacy parser";
    case "intuneMacOs":
      return "Intune macOS pipe-delimited parser";
    case "dhcp":
      return "DHCP Server CSV parser";
    case "burn":
      return "WiX/Burn bootstrapper parser";
    case "registry":
      return "Windows Registry export parser";
  }
}

function getProvenanceLabel(
  provenance: ParserSelectionInfo["provenance"]
): string {
  switch (provenance) {
    case "dedicated":
      return "Dedicated";
    case "heuristic":
      return "Heuristic";
    case "fallback":
      return "Fallback";
  }
}

function getQualityLabel(quality: ParserSelectionInfo["parseQuality"]): string {
  switch (quality) {
    case "structured":
      return "Structured";
    case "semiStructured":
      return "Semi-structured";
    case "textFallback":
      return "Text fallback";
  }
}

function getFramingLabel(framing: ParserSelectionInfo["recordFraming"]): string {
  switch (framing) {
    case "physicalLine":
      return "Physical lines";
    case "logicalRecord":
      return "Logical records";
  }
}

function getDateOrderLabel(
  dateOrder: ParserSelectionInfo["dateOrder"]
): string | null {
  switch (dateOrder) {
    case "monthFirst":
      return "Month-first dates";
    case "dayFirst":
      return "Day-first dates";
    default:
      return null;
  }
}

export function getParserSelectionDisplay(
  selection: ParserSelectionInfo | null
): ParserSelectionDisplay | null {
  if (!selection) {
    return null;
  }

  return {
    parserLabel: getParserLabel(selection.parser),
    implementationLabel: getImplementationLabel(selection.implementation),
    provenanceLabel: getProvenanceLabel(selection.provenance),
    qualityLabel: getQualityLabel(selection.parseQuality),
    framingLabel: getFramingLabel(selection.recordFraming),
    dateOrderLabel: getDateOrderLabel(selection.dateOrder),
  };
}

function buildAggregateFileOrder(files: AggregateParsedFileResult[]): Record<string, number> {
  return Object.fromEntries(files.map((file, index) => [file.filePath, index]));
}

function compareMergedLogEntries(
  left: LogEntry,
  right: LogEntry,
  fileOrder: Record<string, number>
): number {
  if (left.timestamp != null && right.timestamp != null && left.timestamp !== right.timestamp) {
    return left.timestamp - right.timestamp;
  }

  if (left.timestamp != null && right.timestamp == null) {
    return -1;
  }

  if (left.timestamp == null && right.timestamp != null) {
    return 1;
  }

  const leftOrder = fileOrder[left.filePath] ?? Number.MAX_SAFE_INTEGER;
  const rightOrder = fileOrder[right.filePath] ?? Number.MAX_SAFE_INTEGER;

  if (leftOrder !== rightOrder) {
    return leftOrder - rightOrder;
  }

  if (left.lineNumber !== right.lineNumber) {
    return left.lineNumber - right.lineNumber;
  }

  return left.message.localeCompare(right.message);
}

function buildToolbarKnownSourceFamilies(
  sources: KnownSourceMetadata[]
): KnownSourceToolbarFamily[] {
  const families = new Map<string, KnownSourceToolbarFamily>();

  for (const source of sources) {
    const grouping = source.grouping;
    const familyId = grouping?.familyId ?? UNGROUPED_TOOLBAR_GROUP_ID;
    const familyLabel = grouping?.familyLabel ?? UNGROUPED_TOOLBAR_GROUP_LABEL;
    const groupId = grouping
      ? `${grouping.familyId}:${grouping.groupId}`
      : UNGROUPED_TOOLBAR_GROUP_ID;
    const groupLabel = grouping?.groupLabel ?? UNGROUPED_TOOLBAR_GROUP_LABEL;
    const groupOrder = grouping?.groupOrder ?? LAST_SORT_ORDER;
    const familySortOrder = grouping?.groupOrder ?? LAST_SORT_ORDER;

    let family = families.get(familyId);
    if (!family) {
      family = {
        id: familyId,
        label: familyLabel,
        sortOrder: familySortOrder,
        groups: [],
      };
      families.set(familyId, family);
    }

    if (familySortOrder < family.sortOrder) {
      family.sortOrder = familySortOrder;
    }

    let group = family.groups.find((g) => g.id === groupId);
    if (!group) {
      group = {
        id: groupId,
        label: groupLabel,
        sortOrder: groupOrder,
        sources: [],
      };
      family.groups.push(group);
    }

    group.sources.push(source);
  }

  return Array.from(families.values())
    .map((family) => ({
      ...family,
      groups: family.groups
        .map((group) => ({
          ...group,
          sources: [...group.sources].sort((a, b) => {
            const aOrder = a.grouping?.sourceOrder ?? LAST_SORT_ORDER;
            const bOrder = b.grouping?.sourceOrder ?? LAST_SORT_ORDER;
            return aOrder !== bOrder
              ? aOrder - bOrder
              : a.label.localeCompare(b.label);
          }),
        }))
        .sort((a, b) =>
          a.sortOrder !== b.sortOrder
            ? a.sortOrder - b.sortOrder
            : a.label.localeCompare(b.label)
        ),
    }))
    .sort((a, b) =>
      a.sortOrder !== b.sortOrder
        ? a.sortOrder - b.sortOrder
        : a.label.localeCompare(b.label)
    );
}

interface LogState {
  entries: LogEntry[];
  selectedId: number | null;
  isPaused: boolean;
  isLoading: boolean;
  sourceOpenMode: SourceOpenMode;
  formatDetected: LogFormat | null;
  parserSelection: ParserSelectionInfo | null;
  totalLines: number;
  /** Currently selected/tailed file path. */
  openFilePath: string | null;
  /** Broad source container (file, folder, or known source). */
  activeSource: LogSource | null;
  /** Folder entries for folder-like sources. */
  sourceEntries: FolderEntry[];
  /** Evidence bundle metadata when the active folder is a recognized bundle root. */
  bundleMetadata: EvidenceBundleMetadata | null;
  /** Known source metadata catalog for menu/sidebar usage. */
  knownSources: KnownSourceMetadata[];
  /** Toolbar-ready grouped known source catalog. */
  knownSourceToolbarFamilies: KnownSourceToolbarFamily[];
  /** Selected file inside the active source container. */
  selectedSourceFilePath: string | null;
  /** Included files when the active source is loaded as an aggregate folder stream. */
  aggregateFiles: AggregateParsedFileResult[];
  /** User-visible source loading/selection state. */
  sourceStatus: SourceStatus;
  highlightText: string;
  highlightCaseSensitive: boolean;
  findQuery: string;
  findCaseSensitive: boolean;
  findUseRegex: boolean;
  findRegexError: string | null;
  findMatchIds: number[];
  findCurrentIndex: number;
  /** Byte offset in the file after initial parse — used to start tailing */
  byteOffset: number;
  /** Which columns to show — derived from detected parser, not a user preference. */
  activeColumns: ColumnId[];
  /** Folder loading progress (0–1) while progressive loading is active, null otherwise. */
  folderLoadProgress: number | null;
  /** Name of the file currently being parsed during folder loading. */
  folderLoadCurrentFile: string | null;
  /** Total file count in the current folder load. */
  folderLoadTotalFiles: number | null;
  /** Number of files completed so far. */
  folderLoadCompletedFiles: number | null;
  /** GUID→app name map built from "Get policies" log entries. */
  guidNameMap: Record<string, string>;
  mergedTabState: MergedTabState | null;
  correlationWindowMs: number;
  autoCorrelate: boolean;
  correlatedEntries: CorrelatedEntry[];
  diffState: DiffState | null;
  /** Pending scroll target set by deployment workspace — consumed by LogListView after load. */
  pendingScrollTarget: { filePath: string; lineNumber: number } | null;

  hasActiveSource: () => boolean;
  canRefreshSource: () => boolean;
  hasFindSession: () => boolean;
  setEntries: (entries: LogEntry[]) => void;
  appendEntries: (entries: LogEntry[]) => void;
  selectEntry: (id: number | null) => void;
  togglePause: () => void;
  setLoading: (loading: boolean) => void;
  setFormatDetected: (format: LogFormat | null) => void;
  setParserSelection: (selection: ParserSelectionInfo | null) => void;
  setTotalLines: (count: number) => void;
  setOpenFilePath: (path: string | null) => void;
  setActiveSource: (source: LogSource | null) => void;
  setSourceEntries: (entries: FolderEntry[]) => void;
  setBundleMetadata: (metadata: EvidenceBundleMetadata | null) => void;
  setKnownSources: (sources: KnownSourceMetadata[]) => void;
  setSelectedSourceFilePath: (path: string | null) => void;
  setSourceStatus: (status: SourceStatus) => void;
  clearSourceStatus: () => void;
  setByteOffset: (offset: number) => void;
  setActiveColumns: (columns: ColumnId[]) => void;
  setSourceOpenMode: (mode: SourceOpenMode) => void;
  setAggregateFiles: (files: AggregateParsedFileResult[]) => void;
  setHighlightText: (text: string) => void;
  setHighlightCaseSensitive: (sensitive: boolean) => void;
  setFindQuery: (text: string) => void;
  setFindCaseSensitive: (sensitive: boolean) => void;
  setFindUseRegex: (useRegex: boolean) => void;
  recomputeFindMatches: () => void;
  appendAggregateEntries: (filePath: string, entries: LogEntry[]) => void;
  findNext: (trigger: string) => void;
  findPrevious: (trigger: string) => void;
  clearFind: () => void;
  clearActiveFile: () => void;
  clear: () => void;
  setFolderLoadProgress: (progress: {
    current: number;
    total: number;
    currentFile: string;
  } | null) => void;
  setPendingScrollTarget: (target: { filePath: string; lineNumber: number } | null) => void;
  createMergedTab: (sourceFilePaths: string[]) => void;
  closeMergedTab: () => void;
  setFileVisibility: (filePath: string, visible: boolean) => void;
  setAllFileVisibility: (visible: boolean) => void;
  setCorrelationWindowMs: (ms: number) => void;
  setAutoCorrelate: (enabled: boolean) => void;
  updateCorrelation: () => void;
  createDiff: (sourceA: DiffSource, sourceB: DiffSource) => void;
  closeDiff: () => void;
  setDiffDisplayMode: (mode: "side-by-side" | "unified") => void;
}

/** Debounced version of recomputeAndSetMatches for keystroke-driven updates. */
let recomputeTimer: ReturnType<typeof setTimeout> | null = null;
const RECOMPUTE_DEBOUNCE_MS = 150;

function debouncedRecomputeAndSetMatches(): void {
  if (recomputeTimer !== null) clearTimeout(recomputeTimer);
  recomputeTimer = setTimeout(() => {
    recomputeTimer = null;
    recomputeAndSetMatches();
  }, RECOMPUTE_DEBOUNCE_MS);
}

/** Recompute matches and update store state. Called on query/option changes. */
function recomputeAndSetMatches(): void {
  const state = useLogStore.getState();
  const query = state.findQuery.trim();

  if (!query) {
    useLogStore.setState({ findMatchIds: [], findCurrentIndex: -1, findRegexError: null });
    return;
  }

  // Validate regex before computing
  if (state.findUseRegex) {
    try {
      new RegExp(query, state.findCaseSensitive ? "" : "i");
    } catch (e) {
      useLogStore.setState({
        findMatchIds: [],
        findCurrentIndex: -1,
        findRegexError: e instanceof Error ? e.message : "Invalid regex",
      });
      return;
    }
  }

  const matchIds = computeFindMatches(
    state.entries,
    query,
    state.findCaseSensitive,
    state.findUseRegex,
    state.activeColumns
  );

  // Try to keep current position near the previously selected entry
  let newIndex = -1;
  if (matchIds.length > 0) {
    if (state.selectedId !== null) {
      const idx = matchIds.indexOf(state.selectedId);
      if (idx >= 0) {
        newIndex = idx;
      } else {
        // Find the nearest match after the current selection by entry order
        const selectedEntryIdx = state.entries.findIndex((e) => e.id === state.selectedId);
        if (selectedEntryIdx >= 0) {
          const entryIdToIndex = new Map(state.entries.map((e, i) => [e.id, i]));
          let candidateIndex = -1;
          for (let i = 0; i < matchIds.length; i++) {
            const matchEntryIdx = entryIdToIndex.get(matchIds[i]);
            if (matchEntryIdx !== undefined && matchEntryIdx > selectedEntryIdx) {
              candidateIndex = i;
              break;
            }
          }
          newIndex = candidateIndex >= 0 ? candidateIndex : 0;
        } else {
          newIndex = 0;
        }
      }
    } else {
      newIndex = 0;
    }
  }

  useLogStore.setState({
    findMatchIds: matchIds,
    findCurrentIndex: newIndex,
    findRegexError: null,
    ...(newIndex >= 0 ? { selectedId: matchIds[newIndex] } : {}),
  });
}

export const useLogStore = create<LogState>((set, get) => ({
  entries: [],
  selectedId: null,
  isPaused: false,
  isLoading: false,
  sourceOpenMode: null,
  formatDetected: null,
  parserSelection: null,
  totalLines: 0,
  openFilePath: null,
  activeSource: null,
  sourceEntries: [],
  bundleMetadata: null,
  knownSources: [],
  knownSourceToolbarFamilies: [],
  selectedSourceFilePath: null,
  aggregateFiles: [],
  sourceStatus: {
    kind: "idle",
    message: "Ready",
  },
  highlightText: "",
  highlightCaseSensitive: false,
  findQuery: "",
  findCaseSensitive: false,
  findUseRegex: false,
  findRegexError: null,
  findMatchIds: [],
  findCurrentIndex: -1,
  byteOffset: 0,
  folderLoadProgress: null,
  folderLoadCurrentFile: null,
  folderLoadTotalFiles: null,
  folderLoadCompletedFiles: null,
  activeColumns: DEFAULT_COLUMNS,
  guidNameMap: {},
  mergedTabState: null,
  correlationWindowMs: 1000,
  autoCorrelate: true,
  correlatedEntries: [],
  diffState: null,
  pendingScrollTarget: null,

  hasActiveSource: () => {
    const state = get();
    return hasSourceContext(state.activeSource, state.openFilePath);
  },
  canRefreshSource: () => {
    const state = get();
    return !state.isLoading && hasSourceContext(state.activeSource, state.openFilePath);
  },
  hasFindSession: () => get().findQuery.trim().length > 0 && get().findMatchIds.length > 0,
  setEntries: (entries) => {
    set((state) => ({
      entries,
      guidNameMap: buildGuidNameMap(entries),
      selectedId:
        state.selectedId !== null && !entries.some((entry) => entry.id === state.selectedId)
          ? null
          : state.selectedId,
    }));
    recomputeAndSetMatches();
  },
  appendEntries: (newEntries) => {
    set((state) => ({
      entries: [...state.entries, ...newEntries],
      totalLines: state.totalLines + newEntries.length,
      guidNameMap: mergeGuidNameMap(state.guidNameMap, newEntries),
    }));
    recomputeAndSetMatches();
  },
  appendAggregateEntries: (filePath, newEntries) => {
    set((state) => {
      const nextId = state.entries.reduce(
        (maxId, entry) => Math.max(maxId, entry.id),
        -1
      ) + 1;
      const entriesWithIds = newEntries.map((entry, index) => ({
        ...entry,
        filePath,
        id: nextId + index,
      }));
      const fileOrder = buildAggregateFileOrder(state.aggregateFiles);
      const entries = [...state.entries, ...entriesWithIds].sort((left, right) =>
        compareMergedLogEntries(left, right, fileOrder)
      );

      return {
        entries,
        totalLines: state.totalLines + entriesWithIds.length,
        guidNameMap: mergeGuidNameMap(state.guidNameMap, newEntries),
      };
    });
    recomputeAndSetMatches();
  },
  selectEntry: (id) => {
    set({ selectedId: id });
    setTimeout(() => useLogStore.getState().updateCorrelation(), 0);
  },
  togglePause: () => set((state) => ({ isPaused: !state.isPaused })),
  setLoading: (loading) => set({ isLoading: loading }),
  setFormatDetected: (format) => set({ formatDetected: format }),
  setParserSelection: (selection) => set({ parserSelection: selection }),
  setTotalLines: (count) => set({ totalLines: count }),
  setSourceOpenMode: (mode) => set({ sourceOpenMode: mode }),
  setAggregateFiles: (files) => set({ aggregateFiles: files }),
  setOpenFilePath: (path) =>
    set({ openFilePath: path, selectedSourceFilePath: path }),
  setActiveSource: (source) => set({ activeSource: source }),
  setSourceEntries: (entries) => set({ sourceEntries: entries }),
  setBundleMetadata: (metadata) => set({ bundleMetadata: metadata }),
  setKnownSources: (sources) =>
    set({
      knownSources: sources,
      knownSourceToolbarFamilies: buildToolbarKnownSourceFamilies(sources),
    }),
  setSelectedSourceFilePath: (path) =>
    set({ selectedSourceFilePath: path, openFilePath: path }),
  setSourceStatus: (status) => set({ sourceStatus: status }),
  clearSourceStatus: () =>
    set({
      sourceStatus: {
        kind: "idle",
        message: "Ready",
      },
    }),
  setByteOffset: (offset) => set({ byteOffset: offset }),
  setActiveColumns: (columns) => {
    set({ activeColumns: columns });
    recomputeAndSetMatches();
  },
  setHighlightText: (text) => set({ highlightText: text }),
  setHighlightCaseSensitive: (sensitive) =>
    set({ highlightCaseSensitive: sensitive }),
  setFindQuery: (text) => {
    set({ findQuery: text });
    debouncedRecomputeAndSetMatches();
  },
  setFindCaseSensitive: (sensitive) => {
    set({ findCaseSensitive: sensitive });
    recomputeAndSetMatches();
  },
  setFindUseRegex: (useRegex) => {
    set({ findUseRegex: useRegex });
    recomputeAndSetMatches();
  },
  recomputeFindMatches: () => recomputeAndSetMatches(),
  findNext: (_trigger) => {
    const state = get();
    if (state.findMatchIds.length === 0) return;
    const nextIndex = (state.findCurrentIndex + 1) % state.findMatchIds.length;
    set({ findCurrentIndex: nextIndex, selectedId: state.findMatchIds[nextIndex] });
  },
  findPrevious: (_trigger) => {
    const state = get();
    if (state.findMatchIds.length === 0) return;
    const prevIndex = state.findCurrentIndex <= 0
      ? state.findMatchIds.length - 1
      : state.findCurrentIndex - 1;
    set({ findCurrentIndex: prevIndex, selectedId: state.findMatchIds[prevIndex] });
  },
  clearFind: () => set({
    findQuery: "",
    findMatchIds: [],
    findCurrentIndex: -1,
    findRegexError: null,
  }),
  clearActiveFile: () =>
    set({
      entries: [],
      selectedId: null,
      isPaused: false,
      sourceOpenMode: null,
      formatDetected: null,
      parserSelection: null,
      totalLines: 0,
      openFilePath: null,
      selectedSourceFilePath: null,
      aggregateFiles: [],
      activeColumns: DEFAULT_COLUMNS,
      byteOffset: 0,
      guidNameMap: {},
      mergedTabState: null,
      correlatedEntries: [],
      diffState: null,
      findMatchIds: [],
      findCurrentIndex: -1,
      findRegexError: null,
      pendingScrollTarget: null,
    }),
  clear: () =>
    set({
      entries: [],
      selectedId: null,
      isPaused: false,
      sourceOpenMode: null,
      formatDetected: null,
      parserSelection: null,
      totalLines: 0,
      openFilePath: null,
      activeSource: null,
      sourceEntries: [],
      bundleMetadata: null,
      knownSources: [],
      knownSourceToolbarFamilies: [],
      selectedSourceFilePath: null,
      aggregateFiles: [],
      activeColumns: DEFAULT_COLUMNS,
      sourceStatus: {
        kind: "idle",
        message: "Ready",
      },
      byteOffset: 0,
      guidNameMap: {},
      mergedTabState: null,
      correlatedEntries: [],
      diffState: null,
      findMatchIds: [],
      findCurrentIndex: -1,
      findRegexError: null,
      pendingScrollTarget: null,
    }),
  setFolderLoadProgress: (progress) =>
    set(
      progress
        ? {
            folderLoadProgress: progress.current / progress.total,
            folderLoadCurrentFile: progress.currentFile,
            folderLoadTotalFiles: progress.total,
            folderLoadCompletedFiles: progress.current,
          }
        : {
            folderLoadProgress: null,
            folderLoadCurrentFile: null,
            folderLoadTotalFiles: null,
            folderLoadCompletedFiles: null,
          }
    ),
  setPendingScrollTarget: (target) => set({ pendingScrollTarget: target }),

  createMergedTab: (sourceFilePaths) => {
    const entriesByFile: Record<string, LogEntry[]> = {};
    const entryCounts: Record<string, number> = {};

    for (const fp of sourceFilePaths) {
      const snapshot = getCachedTabSnapshot(fp);
      if (snapshot) {
        entriesByFile[fp] = snapshot.entries;
        entryCounts[fp] = snapshot.entries.length;
      }
    }

    const validPaths = Object.keys(entriesByFile);
    if (validPaths.length < 2) return;

    const colorAssignments = assignFileColors(validPaths);
    const fileVisibility: Record<string, boolean> = {};
    for (const fp of validPaths) {
      fileVisibility[fp] = true;
    }

    const merged = mergeEntries(entriesByFile);
    const cacheKey = buildMergeCacheKey(validPaths, entryCounts);

    set({
      mergedTabState: {
        sourceFilePaths: validPaths,
        colorAssignments,
        fileVisibility,
        mergedEntries: merged,
        cacheKey,
      },
      entries: filterByVisibility(merged, fileVisibility),
      sourceOpenMode: "merged" as SourceOpenMode,
      selectedId: null,
      correlatedEntries: [],
    });
  },

  closeMergedTab: () => {
    set({
      mergedTabState: null,
      entries: [],
      sourceOpenMode: null,
      selectedId: null,
      correlatedEntries: [],
    });
  },

  setFileVisibility: (filePath, visible) => {
    set((state) => {
      if (!state.mergedTabState) return {};
      const fileVisibility = {
        ...state.mergedTabState.fileVisibility,
        [filePath]: visible,
      };
      return {
        mergedTabState: { ...state.mergedTabState, fileVisibility },
        entries: filterByVisibility(state.mergedTabState.mergedEntries, fileVisibility),
        selectedId: null,
        correlatedEntries: [],
      };
    });
    recomputeAndSetMatches();
  },

  setAllFileVisibility: (visible) => {
    set((state) => {
      if (!state.mergedTabState) return {};
      const fileVisibility: Record<string, boolean> = {};
      for (const fp of state.mergedTabState.sourceFilePaths) {
        fileVisibility[fp] = visible;
      }
      return {
        mergedTabState: { ...state.mergedTabState, fileVisibility },
        entries: visible ? state.mergedTabState.mergedEntries : [],
        selectedId: null,
        correlatedEntries: [],
      };
    });
    recomputeAndSetMatches();
  },

  setCorrelationWindowMs: (ms) => {
    set({ correlationWindowMs: ms });
    setTimeout(() => useLogStore.getState().updateCorrelation(), 0);
  },

  setAutoCorrelate: (enabled) => {
    set({ autoCorrelate: enabled });
    setTimeout(() => useLogStore.getState().updateCorrelation(), 0);
  },

  updateCorrelation: () => {
    const state = useLogStore.getState();
    if (!state.mergedTabState || !state.autoCorrelate || state.selectedId == null) {
      if (state.correlatedEntries.length > 0) {
        useLogStore.setState({ correlatedEntries: [] });
      }
      return;
    }

    const selectedEntry = state.entries.find((e) => e.id === state.selectedId);
    if (!selectedEntry) {
      useLogStore.setState({ correlatedEntries: [] });
      return;
    }

    const correlated = findCorrelatedEntries(
      state.mergedTabState.mergedEntries,
      selectedEntry,
      state.correlationWindowMs,
      state.mergedTabState.colorAssignments
    );
    useLogStore.setState({ correlatedEntries: correlated });
  },

  createDiff: (sourceA, sourceB) => {
    // Get entries from cache
    const snapshotA = getCachedTabSnapshot(sourceA.filePath);
    const snapshotB = getCachedTabSnapshot(sourceB.filePath);
    if (!snapshotA || !snapshotB) return;

    let entriesA = snapshotA.entries;
    let entriesB = snapshotB.entries;

    // Apply time range filter if specified
    if (sourceA.startTime != null && sourceA.endTime != null) {
      entriesA = filterByTimeRange(entriesA, sourceA.startTime, sourceA.endTime);
    }
    if (sourceB.startTime != null && sourceB.endTime != null) {
      entriesB = filterByTimeRange(entriesB, sourceB.startTime, sourceB.endTime);
    }

    // Reassign IDs to avoid collisions between files
    let nextId = 0;
    entriesA = entriesA.map((e) => ({ ...e, id: nextId++ }));
    entriesB = entriesB.map((e) => ({ ...e, id: nextId++ }));

    const { commonKeys, onlyAKeys, onlyBKeys, entryClassification, stats } =
      classifyEntries(entriesA, entriesB);

    set({
      diffState: {
        mode: sourceA.filePath === sourceB.filePath ? "time-range" : "two-file",
        sourceA,
        sourceB,
        displayMode: "side-by-side",
        entriesA,
        entriesB,
        commonKeys,
        onlyAKeys,
        onlyBKeys,
        entryClassification,
        stats,
      },
      sourceOpenMode: "diff" as SourceOpenMode,
      selectedId: null,
    });
  },

  closeDiff: () => {
    set({
      diffState: null,
      sourceOpenMode: null,
      selectedId: null,
    });
  },

  setDiffDisplayMode: (mode) => {
    set((state) => {
      if (!state.diffState) return {};
      return { diffState: { ...state.diffState, displayMode: mode } };
    });
  },
}));
