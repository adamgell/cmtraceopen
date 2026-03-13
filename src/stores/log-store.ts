import { create } from "zustand";
import type {
  FolderEntry,
  KnownSourceMetadata,
  LogEntry,
  LogFormat,
  LogSource,
  ParserSelectionInfo,
} from "../types/log";

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

export interface KnownSourceToolbarGroup {
  id: string;
  label: string;
  sortOrder: number;
  sources: KnownSourceMetadata[];
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

type FindDirection = "forward" | "backward";

const UNGROUPED_TOOLBAR_GROUP_ID = "ungrouped";
const UNGROUPED_TOOLBAR_GROUP_LABEL = "Other Sources";
const LAST_SORT_ORDER = Number.MAX_SAFE_INTEGER;

function normalizeFindText(text: string, caseSensitive: boolean): string {
  return caseSensitive ? text : text.toLowerCase();
}

function runFindSearch(
  entries: LogEntry[],
  selectedId: number | null,
  searchText: string,
  caseSensitive: boolean,
  direction: FindDirection
): { entry: LogEntry; wrapped: boolean } | null {
  if (entries.length === 0 || searchText.length === 0) {
    return null;
  }

  const selectedIndex =
    selectedId === null ? -1 : entries.findIndex((entry) => entry.id === selectedId);
  const totalCount = entries.length;
  const expectedText = normalizeFindText(searchText, caseSensitive);

  let currentIndex =
    direction === "forward"
      ? (selectedIndex + 1) % totalCount
      : selectedIndex <= 0
        ? totalCount - 1
        : selectedIndex - 1;

  let wrapped = false;

  for (let i = 0; i < totalCount; i += 1) {
    const entry = entries[currentIndex];
    const message = normalizeFindText(entry.message, caseSensitive);

    if (message.includes(expectedText)) {
      return {
        entry,
        wrapped,
      };
    }

    if (direction === "forward") {
      currentIndex = (currentIndex + 1) % totalCount;
      if (currentIndex === 0) {
        wrapped = true;
      }
    } else {
      currentIndex = currentIndex <= 0 ? totalCount - 1 : currentIndex - 1;
      if (currentIndex === totalCount - 1) {
        wrapped = true;
      }
    }
  }

  return null;
}

export function getBaseName(path: string | null): string {
  if (!path) {
    return "";
  }

  return path.split(/[\\/]/).pop() ?? path;
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
    case "panther":
      return "Panther";
    case "cbs":
      return "CBS";
    case "dism":
      return "DISM";
    case "reportingEvents":
      return "ReportingEvents";
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
    case "reportingEvents":
      return "ReportingEvents parser";
    case "plainText":
      return "Plain text parser";
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

function buildToolbarKnownSourceGroups(
  sources: KnownSourceMetadata[]
): KnownSourceToolbarGroup[] {
  const groups = new Map<string, KnownSourceToolbarGroup>();

  for (const source of sources) {
    const grouping = source.grouping;
    const groupId = grouping
      ? `${grouping.familyId}:${grouping.groupId}`
      : UNGROUPED_TOOLBAR_GROUP_ID;
    const groupLabel = grouping
      ? `${grouping.familyLabel} / ${grouping.groupLabel}`
      : UNGROUPED_TOOLBAR_GROUP_LABEL;
    const groupOrder = grouping?.groupOrder ?? LAST_SORT_ORDER;

    const existingGroup = groups.get(groupId);

    if (existingGroup) {
      existingGroup.sources.push(source);
      continue;
    }

    groups.set(groupId, {
      id: groupId,
      label: groupLabel,
      sortOrder: groupOrder,
      sources: [source],
    });
  }

  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      sources: [...group.sources].sort((left, right) => {
        const leftOrder = left.grouping?.sourceOrder ?? LAST_SORT_ORDER;
        const rightOrder = right.grouping?.sourceOrder ?? LAST_SORT_ORDER;

        if (leftOrder !== rightOrder) {
          return leftOrder - rightOrder;
        }

        return left.label.localeCompare(right.label);
      }),
    }))
    .sort((left, right) => {
      if (left.sortOrder !== right.sortOrder) {
        return left.sortOrder - right.sortOrder;
      }

      return left.label.localeCompare(right.label);
    });
}

interface LogState {
  entries: LogEntry[];
  selectedId: number | null;
  isPaused: boolean;
  isLoading: boolean;
  formatDetected: LogFormat | null;
  parserSelection: ParserSelectionInfo | null;
  totalLines: number;
  /** Currently selected/tailed file path. */
  openFilePath: string | null;
  /** Broad source container (file, folder, or known source). */
  activeSource: LogSource | null;
  /** Folder entries for folder-like sources. */
  sourceEntries: FolderEntry[];
  /** Known source metadata catalog for menu/sidebar usage. */
  knownSources: KnownSourceMetadata[];
  /** Toolbar-ready grouped known source catalog. */
  knownSourceToolbarGroups: KnownSourceToolbarGroup[];
  /** Selected file inside the active source container. */
  selectedSourceFilePath: string | null;
  /** User-visible source loading/selection state. */
  sourceStatus: SourceStatus;
  highlightText: string;
  highlightCaseSensitive: boolean;
  findQuery: string;
  findCaseSensitive: boolean;
  findStatusText: string;
  findLastMatchId: number | null;
  /** Byte offset in the file after initial parse — used to start tailing */
  byteOffset: number;

  hasActiveSource: () => boolean;
  canRefreshSource: () => boolean;
  hasFindSession: () => boolean;
  setEntries: (entries: LogEntry[]) => void;
  appendEntries: (entries: LogEntry[]) => void;
  selectEntry: (id: number | null) => void;
  togglePause: () => void;
  setLoading: (loading: boolean) => void;
  setFormatDetected: (format: LogFormat) => void;
  setParserSelection: (selection: ParserSelectionInfo | null) => void;
  setTotalLines: (count: number) => void;
  setOpenFilePath: (path: string | null) => void;
  setActiveSource: (source: LogSource | null) => void;
  setSourceEntries: (entries: FolderEntry[]) => void;
  setKnownSources: (sources: KnownSourceMetadata[]) => void;
  setSelectedSourceFilePath: (path: string | null) => void;
  setSourceStatus: (status: SourceStatus) => void;
  clearSourceStatus: () => void;
  setByteOffset: (offset: number) => void;
  setHighlightText: (text: string) => void;
  setHighlightCaseSensitive: (sensitive: boolean) => void;
  setFindQuery: (text: string) => void;
  setFindCaseSensitive: (sensitive: boolean) => void;
  findNext: (trigger: string) => boolean;
  findPrevious: (trigger: string) => boolean;
  clearFindStatus: () => void;
  clearActiveFile: () => void;
  clear: () => void;
}

function runSharedFind(trigger: string, direction: FindDirection): boolean {
  const state = useLogStore.getState();
  const query = state.findQuery.trim();

  if (!query) {
    console.info("[log-store] skipping find because no active query", {
      trigger,
      direction,
    });
    state.clearFindStatus();
    return false;
  }

  const result = runFindSearch(
    state.entries,
    state.selectedId,
    query,
    state.findCaseSensitive,
    direction
  );

  if (!result) {
    console.info("[log-store] find returned no matches", {
      trigger,
      direction,
      query,
      caseSensitive: state.findCaseSensitive,
      entriesCount: state.entries.length,
    });

    useLogStore.setState({
      findStatusText: "Not found",
      findLastMatchId: null,
    });
    return false;
  }

  console.info("[log-store] find matched entry", {
    trigger,
    direction,
    query,
    caseSensitive: state.findCaseSensitive,
    entryId: result.entry.id,
    lineNumber: result.entry.lineNumber,
    wrapped: result.wrapped,
  });

  useLogStore.setState({
    selectedId: result.entry.id,
    findLastMatchId: result.entry.id,
    findStatusText: result.wrapped ? `Found (wrapped) at line ${result.entry.lineNumber}` : "",
  });
  return true;
}

export const useLogStore = create<LogState>((set, get) => ({
  entries: [],
  selectedId: null,
  isPaused: false,
  isLoading: false,
  formatDetected: null,
  parserSelection: null,
  totalLines: 0,
  openFilePath: null,
  activeSource: null,
  sourceEntries: [],
  knownSources: [],
  knownSourceToolbarGroups: [],
  selectedSourceFilePath: null,
  sourceStatus: {
    kind: "idle",
    message: "Ready",
  },
  highlightText: "",
  highlightCaseSensitive: false,
  findQuery: "",
  findCaseSensitive: false,
  findStatusText: "",
  findLastMatchId: null,
  byteOffset: 0,

  hasActiveSource: () => {
    const state = get();
    return hasSourceContext(state.activeSource, state.openFilePath);
  },
  canRefreshSource: () => {
    const state = get();
    return !state.isLoading && hasSourceContext(state.activeSource, state.openFilePath);
  },
  hasFindSession: () => get().findQuery.trim().length > 0,
  setEntries: (entries) =>
    set((state) => ({
      entries,
      selectedId:
        state.selectedId !== null && !entries.some((entry) => entry.id === state.selectedId)
          ? null
          : state.selectedId,
    })),
  appendEntries: (newEntries) =>
    set((state) => ({
      entries: [...state.entries, ...newEntries],
      totalLines: state.totalLines + newEntries.length,
    })),
  selectEntry: (id) => set({ selectedId: id }),
  togglePause: () => set((state) => ({ isPaused: !state.isPaused })),
  setLoading: (loading) => set({ isLoading: loading }),
  setFormatDetected: (format) => set({ formatDetected: format }),
  setParserSelection: (selection) => set({ parserSelection: selection }),
  setTotalLines: (count) => set({ totalLines: count }),
  setOpenFilePath: (path) =>
    set({ openFilePath: path, selectedSourceFilePath: path }),
  setActiveSource: (source) => set({ activeSource: source }),
  setSourceEntries: (entries) => set({ sourceEntries: entries }),
  setKnownSources: (sources) =>
    set({
      knownSources: sources,
      knownSourceToolbarGroups: buildToolbarKnownSourceGroups(sources),
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
  setHighlightText: (text) => set({ highlightText: text }),
  setHighlightCaseSensitive: (sensitive) =>
    set({ highlightCaseSensitive: sensitive }),
  setFindQuery: (text) =>
    set({
      findQuery: text,
      findStatusText: "",
      findLastMatchId: null,
    }),
  setFindCaseSensitive: (sensitive) =>
    set({
      findCaseSensitive: sensitive,
      findStatusText: "",
      findLastMatchId: null,
    }),
  findNext: (trigger) => runSharedFind(trigger, "forward"),
  findPrevious: (trigger) => runSharedFind(trigger, "backward"),
  clearFindStatus: () => set({ findStatusText: "" }),
  clearActiveFile: () =>
    set({
      entries: [],
      selectedId: null,
      isPaused: false,
      formatDetected: null,
      parserSelection: null,
      totalLines: 0,
      openFilePath: null,
      selectedSourceFilePath: null,
      byteOffset: 0,
      findStatusText: "",
      findLastMatchId: null,
    }),
  clear: () =>
    set({
      entries: [],
      selectedId: null,
      isPaused: false,
      formatDetected: null,
      parserSelection: null,
      totalLines: 0,
      openFilePath: null,
      activeSource: null,
      sourceEntries: [],
      knownSources: [],
      knownSourceToolbarGroups: [],
      selectedSourceFilePath: null,
      sourceStatus: {
        kind: "idle",
        message: "Ready",
      },
      byteOffset: 0,
      findStatusText: "",
      findLastMatchId: null,
    }),
}));
