import { create } from "zustand";
import {
  assertParseResultShape,
  formatCoverageGap,
  mergeCoverageGaps,
  mergeStructuredCoverageGaps,
  sourceCoverageMessages,
} from "./evtx-coverage";
import type { EvtxTimeZoneMode } from "./evtx-time";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  EvtxRecord,
  EvtxChannelInfo,
  EvtxCoverageGap,
  EvtxLevel,
  EvtxParseResult,
  EvtxTimeWindow,
  EventLogSourceCoverage,
  EventLogSourceManifest,
  EventQueryFilterSubset,
  EvtxClearResult,
  EvtxLiveMode,
  EvtxTailBatch,
  EvtxTailStatus,
} from "./types";
import { EVTX_TIME_WINDOW_MS } from "./types";
import type { LogEntry } from "../../types/log";
import type { UnifiedTimeline } from "./unified-timeline";

// Re-exported so callers have one import site; the implementations live in a Tauri-free module.
export { parseEventIdFilter, selectVisibleRecords } from "./evtx-filter";
import {
  DEFAULT_QUICK_FILTER,
  parseEventIdSelectors,
  type EvtxBeforeLoadCriteria,
  type EvtxEventIdSelector,
  type EvtxGroupField,
  type EvtxQuickFilter,
} from "./evtx-filter";
import {
  defaultColumnConfig,
  moveColumn,
  sanitizeColumnConfig,
  toggleColumn,
  type EvtxColumnConfig,
  type EvtxColumnId,
} from "./evtx-columns";

type ServerFilter = EventQueryFilterSubset & {
  eventIds?: EvtxEventIdSelector[];
  eventIdMode?: "include";
};
function compareStoredRecords(a: EvtxRecord, b: EvtxRecord): number {
  const aTextId = a.eventRecordIdText?.trim();
  const bTextId = b.eventRecordIdText?.trim();
  const aId = aTextId && !/^0+$/.test(aTextId) ? aTextId : String(a.eventRecordId);
  const bId = bTextId && !/^0+$/.test(bTextId) ? bTextId : String(b.eventRecordId);
  return (
    a.timestampEpoch - b.timestampEpoch ||
    a.sourceLabel.localeCompare(b.sourceLabel) ||
    a.channel.localeCompare(b.channel) ||
    (aId < bId ? -1 : aId > bId ? 1 : 0) ||
    a.eventId - b.eventId
  );
}
function recordKey(record: EvtxRecord): string {
  const textId = record.eventRecordIdText?.trim();
  const recordId =
    textId && !/^0+$/.test(textId)
      ? `text:${record.eventRecordIdText}`
      : record.eventRecordId !== 0
        ? `number:${String(record.eventRecordId)}`
        : `missing:${record.rawXml || [
            record.provider,
            record.eventId,
            record.timestampEpoch,
            record.computer,
            record.message,
          ].join("\u0000")}`;
  return `${record.sourceLabel}\u0000${record.channel}\u0000${recordId}`;
}
function appendUniqueRecords(existing: EvtxRecord[], incoming: EvtxRecord[]): EvtxRecord[] {
  const keys = new Set(existing.map(recordKey));
  const unique = incoming.filter((record) => {
    const key = recordKey(record);
    if (keys.has(key)) return false;
    keys.add(key);
    return true;
  });
  return [...existing, ...unique];
}
let preservedSelectedRecordKey: string | null = null;

const tailSequences = new Map<string, Set<number>>();

function tailSequenceKey(requestId: string, channel: string): string {
  return `${requestId}\u0000${channel}`;
}

function aggregateTailMode(modes: EvtxLiveMode[]): EvtxLiveMode {
  const unique = new Set(modes);
  if (unique.size === 0) return "unsupported";
  if (unique.size > 1) return "mixed";
  return modes[0];
}


let requestGeneration = 0;
let activeRequestId = "initial";
let tailGeneration = 0;
let activeTailRequestId: string | null = null;
let activeTailSourceRequestId: string | null = null;
let activeTailChannels = new Set<string>();

function beginRequest(): string {
  const staleTailRequestId = activeTailRequestId;
  const staleTailChannels = activeTailChannels;
  activeTailRequestId = null;
  activeTailSourceRequestId = null;
  activeTailChannels = new Set<string>();
  if (staleTailRequestId) {
    for (const channel of staleTailChannels) {
      void invoke("evtx_stop_tail", {
        requestId: staleTailRequestId,
        channel,
      }).catch(() => undefined);
    }
  }
  activeRequestId = `event-log-${++requestGeneration}`;
  pendingBatches.clear();
  tailSequences.clear();
  return activeRequestId;
}

function isCurrentRequest(requestId: string): boolean {
  return requestId === activeRequestId;
}

function invokeEventQuery<T>(
  requestId: string,
  remoteMachine: string | null,
  channels: string[],
  maxEvents: number | null,
  filter: EventQueryFilterSubset
): Promise<T> {
  if (remoteMachine) {
    return invoke<T>("evtx_query_remote_channels", {
      machine: remoteMachine,
      channels,
      maxEvents,
      filter,
      requestId,
    });
  }
  return invoke<T>("evtx_query_channels", { channels, maxEvents, filter, requestId });
}
function mergeRecordsPreservingSelection(
  existing: EvtxRecord[],
  selectedRecordId: number | null,
  incoming: EvtxRecord[],
  selectedKey = preservedSelectedRecordKey
): { records: EvtxRecord[]; selectedRecordId: number | null } {
  const selected =
    selectedKey === null
      ? selectedRecordId === null
        ? null
        : existing.find((record) => record.id === selectedRecordId) ?? null
      : existing.find((record) => recordKey(record) === selectedKey) ??
        incoming.find((record) => recordKey(record) === selectedKey) ??
        null;
  const records = appendUniqueRecords(existing, incoming);
  records.sort(compareStoredRecords);
  for (let index = 0; index < records.length; index++) records[index].id = index;
  const remappedSelectedRecordId =
    selected === null
      ? null
      : records.findIndex((record) => recordKey(record) === recordKey(selected));
  if (selected !== null || selectedKey === null) preservedSelectedRecordKey = null;
  return { records, selectedRecordId: remappedSelectedRecordId };
}
function captureSelectedRecord(records: EvtxRecord[], selectedRecordId: number | null): void {
  const selected =
    selectedRecordId === null
      ? null
      : records.find((record) => record.id === selectedRecordId) ?? null;
  preservedSelectedRecordKey = selected === null ? null : recordKey(selected);
}
/** Builds the backend-owned merged timeline for the records currently shown in this workspace. */
export function buildUnifiedTimeline(
  records: EvtxRecord[],
  entries: LogEntry[] = []
): Promise<UnifiedTimeline> {
  if (
    records.some(
      (record) =>
        record.eventRecordId !== 0 &&
        !record.eventRecordIdText &&
        !Number.isSafeInteger(record.eventRecordId)
    )
  ) {
    return Promise.reject(new Error("EventRecordID exceeds JavaScript safe integer precision"));
  }
  const transportRecords = records.map((record) => ({
    ...record,
    eventRecordId: record.eventRecordIdText ?? String(record.eventRecordId),
  }));
  return invoke<UnifiedTimeline>("evtx_build_unified_timeline", {
    entries,
    records: transportRecords,
  });
}
export type EvtxSourceMode = "files" | "live" | null;
export type EvtxSortField = "time" | "eventId" | "level" | "provider" | "channel";
export type EvtxSortDirection = "asc" | "desc";


/**
 * Builds the filter handed to the backend, which compiles it to XPath.
 *
 * Only criteria with an exact XPath equivalent are pushed down. Text, case sensitivity, visible
 * column scope and hide mode stay local; sending an approximation would silently broaden or narrow
 * the query compared with the rows the operator sees.
 */
function buildServerFilter(
  timeWindow: EvtxTimeWindow,
  filterEventIds: string,
  filterLevels: Set<EvtxLevel>
): ServerFilter {
  const filter: ServerFilter =
    timeWindow === "all"
      ? {}
      : { time: { kind: "last", milliseconds: EVTX_TIME_WINDOW_MS[timeWindow] } };

  const parsedIds = parseEventIdSelectors(filterEventIds);
  if (parsedIds.selectors.length > 0 && !parsedIds.invalid) {
    filter.eventIds = parsedIds.selectors;
    filter.eventIdMode = "include";
  }

  // Information includes an unbounded provider-specific raw-level domain (6..254). The parser
  // intentionally caps XPath OR expressions, so leave level selection local whenever Information
  // is selected rather than issuing an over-budget or incomplete server predicate.
  if (
    filterLevels.size > 0 &&
    filterLevels.size < ALL_LEVELS.length &&
    !filterLevels.has("Information")
  ) {
    filter.levels = [...filterLevels].map((level) => ALL_LEVELS.indexOf(level) + 1);
  }
  return filter;
}
function hasInvalidEventIdFilter(raw: string): boolean {
  const trimmed = raw.trim();
  return trimmed.length > 0 && parseEventIdSelectors(trimmed).invalid;
}

const ALL_LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];

interface EvtxState {
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  sourceMode: EvtxSourceMode;
  /** Paths currently represented by `records`; used to protect export destinations. */
  sourcePaths: string[];
  /** Remote target used for live queries; credentials stay in the Windows session only. */
  remoteMachine: string | null;
  isLoading: boolean;
  loadingChannel: string | null;
  loadingProgress: number | null;
  loadStartTime: number | null;
  loadElapsedMs: number | null;
  loadError: string | null;
  coverageGaps: string[];
  sourceManifest: EventLogSourceManifest | null;
  selectedChannels: Set<string>;
  loadedChannels: Set<string>;
  /**
   * Structured parser locations behind `coverageGaps`. The legacy strings remain for live
   * streaming diagnostics, while file recovery gaps retain chunk/record identity here.
   */
  coverageDetails: EvtxCoverageGap[];
  filterLevels: Set<EvtxLevel>;
  filterEventIds: string;
  filterSearch: string;
  /** The on-load and after-load quick criteria are retained across every refetch. */
  quickFilter: EvtxQuickFilter;
  timeWindow: EvtxTimeWindow;
  /** Which clock event times are shown in. */
  timeZoneMode: EvtxTimeZoneMode;
  columnConfig: EvtxColumnConfig;
  groupBy: EvtxGroupField[];
  collapsedGroups: Set<string>;
  sortField: EvtxSortField;
  sortDirection: EvtxSortDirection;
  selectedRecordId: number | null;
loadGeneration: number;
  tailMode: EvtxLiveMode | null;
  tailRequestId: string | null;
  tailChannels: Set<string>;
  tailCoverageGaps: string[];
  parseFiles: (paths: string[]) => Promise<void>;
  parseManifest: (manifest: EventLogSourceManifest) => Promise<void>;
  enumerateChannels: () => Promise<void>;
  enumerateLocalChannels: () => Promise<void>;
  enumerateRemoteChannels: (machine: string) => Promise<void>;
  queryChannels: (channels: string[], maxEvents?: number) => Promise<void>;
  loadSelectedChannels: () => Promise<void>;
  refreshLoadedChannels: () => Promise<void>;
  startLiveTail: () => Promise<EvtxTailStatus[]>;
  stopLiveTail: () => Promise<void>;
  clearChannel: (channel: string, confirmed: boolean) => Promise<EvtxClearResult>;
  setTimeZoneMode: (mode: EvtxTimeZoneMode) => void;
  setSelectedChannels: (channels: Set<string>) => void;
  toggleChannel: (channel: string) => void;
  selectAllChannels: () => void;
  deselectAllChannels: () => void;
  setFilterLevels: (levels: Set<EvtxLevel>) => void;
  toggleFilterLevel: (level: EvtxLevel) => void;
  setFilterEventIds: (eventIds: string) => void;
  setBeforeLoadCriteria: (criteria: EvtxBeforeLoadCriteria) => void;
  setFilterSearch: (search: string) => void;
  setQuickFilter: (filter: EvtxQuickFilter) => void;
  setTimeWindow: (window: EvtxTimeWindow) => void;
  setGroupBy: (fields: EvtxGroupField[]) => void;
  toggleColumnVisible: (id: EvtxColumnId) => void;
  moveColumnBy: (id: EvtxColumnId, direction: -1 | 1) => void;
  resetColumns: () => void;
  toggleGroup: (key: string) => void;
  setSortField: (field: EvtxSortField) => void;
  setSortDirection: (direction: EvtxSortDirection) => void;
  setSelectedRecordId: (id: number | null) => void;
  reset: () => void;
}

function applyParseResult(
  result: EvtxParseResult,
  sourceMode: EvtxSourceMode,
  sourceCoverage: readonly EventLogSourceCoverage[] = [],
): Partial<EvtxState> {
  const channelNames = new Set(result.channels.map((c) => c.name));
  const coverageMessages = [
    ...sourceCoverageMessages(sourceCoverage),
    ...sourceCoverageMessages(result.coverage ?? []),
  ];
  return {
    records: result.records,
    channels: result.channels,
    sourceMode,
    isLoading: false,
    loadError: null,
    coverageGaps: [
      ...new Set([
        ...result.errorMessages,
        ...coverageMessages,
        ...(result.coverageGaps ?? []).map(formatCoverageGap),
      ]),
    ],
    coverageDetails: result.coverageGaps ?? [],
    selectedChannels: channelNames,
    selectedRecordId: null,
    tailMode: null,
    tailRequestId: null,
    tailChannels: new Set<string>(),
    tailCoverageGaps: [],
  };
}

export const useEvtxStore = create<EvtxState>()((set, get) => {
  let refreshScheduled = false;
  let refreshRequested = false;
  const refreshBeforeLoad = () => {
    refreshRequested = true;
    if (refreshScheduled) return;
    refreshScheduled = true;
    queueMicrotask(() => {
      refreshScheduled = false;
      const state = get();
      if (state.isLoading) return;
      if (state.sourceMode === "live" && state.loadedChannels.size > 0) {
        refreshRequested = false;
        void state.refreshLoadedChannels();
      } else if (!state.isLoading) {
        refreshRequested = false;
      }
    });
  };

  return ({
  records: [],
  remoteMachine: null,
  channels: [],
  sourceMode: null,
  sourcePaths: [],
  isLoading: false,
  loadError: null,
  loadingChannel: null,
  loadingProgress: null,
  loadStartTime: null,
  loadElapsedMs: null,
  loadGeneration: 0,
  coverageGaps: [],
  coverageDetails: [],
  sourceManifest: null,
  selectedChannels: new Set<string>(),
  loadedChannels: new Set<string>(),
  filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
  filterEventIds: "",
  filterSearch: "",
  quickFilter: { ...DEFAULT_QUICK_FILTER },
  timeZoneMode: "local" as EvtxTimeZoneMode,
  timeWindow: "24h",
  columnConfig: defaultColumnConfig(),
  groupBy: [],
  collapsedGroups: new Set<string>(),
  sortField: "time",
  sortDirection: "asc",
  selectedRecordId: null,
  tailMode: null,
  tailRequestId: null,
  tailChannels: new Set<string>(),
  tailCoverageGaps: [],
  parseFiles: async (paths) => {
    const previousTimeWindow = get().timeWindow;
    const generation = get().loadGeneration + 1;
    const requestId = beginRequest();
preservedSelectedRecordKey = null;
    invalidateAllStreamedRecords(requestId);
    refreshRequested = false;
    set({
      loadGeneration: generation,
      records: [],
      channels: [],
      sourceMode: null,
      remoteMachine: null,
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      coverageGaps: [],
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      tailCoverageGaps: [],
      timeWindow: "all",
      isLoading: true,
      loadError: null,
    });
    try {
      const result = await invoke<EvtxParseResult>("evtx_parse_files", { paths });
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const checked = assertParseResultShape(result);
      set({
        ...applyParseResult(
          {
            ...result,
            errorMessages: checked.errorMessages,
            coverageGaps: checked.coverageGaps,
            coverage: checked.coverage,
          },
          "files",
        ),
        sourcePaths: [...paths],
        loadGeneration: generation,
      });
    } catch (error) {
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message, timeWindow: previousTimeWindow });
    }
  },

  parseManifest: async (manifest) => {
    set({ isLoading: true, loadError: null, sourceManifest: manifest });
    try {
      const result = await invoke<EvtxParseResult>("evtx_parse_manifest", { manifest });
      const checked = assertParseResultShape(result);
      set({
        ...applyParseResult(
          {
            ...result,
            errorMessages: checked.errorMessages,
            coverageGaps: checked.coverageGaps,
            coverage: checked.coverage,
          },
          "files",
          manifest.coverage,
        ),
        sourceManifest: manifest,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message, sourceManifest: manifest });
    }
  },

  enumerateChannels: async () => {
    const generation = get().loadGeneration + 1;
    const requestId = beginRequest();
    captureSelectedRecord(get().records, get().selectedRecordId);
    invalidateAllStreamedRecords(requestId);
    set({
      loadGeneration: generation,
      isLoading: true,
      loadError: null,
      timeWindow:
        get().sourceMode === null && get().timeWindow === "all" ? "24h" : get().timeWindow,
    });
    try {
      const remoteMachine = get().remoteMachine;
      const channels = remoteMachine
        ? await invoke<EvtxChannelInfo[]>("evtx_enumerate_remote_channels", {
            machine: remoteMachine,
          })
        : await invoke<EvtxChannelInfo[]>("evtx_enumerate_channels");
      if (!isCurrentRequest(requestId)) return;

      // Step 2: Auto-query the core Windows Logs channels immediately
      const coreChannels = ["Application", "System", "Security", "Setup"];
      const availableCore = coreChannels.filter((c) =>
        channels.some((ch) => ch.name === c)
      );
      let updatedChannels = channels;
      let loadError: string | null = null;
      const emptyRemoteGaps =
        remoteMachine && channels.length === 0
          ? [`${remoteMachine}: remote source is empty (no channels available)`]
          : [];

      // Show channels immediately, then load events in parallel
      const selectedNames = new Set(availableCore);
      const startTime = performance.now();
      captureSelectedRecord(get().records, get().selectedRecordId);
      set({
        channels: updatedChannels,
        sourceMode: "live",
        sourcePaths: [],
        isLoading: true,
        loadError: null,
        coverageGaps: emptyRemoteGaps,
        loadStartTime: startTime,
        coverageDetails: [],
        loadElapsedMs: null,
        selectedChannels: selectedNames,
        loadedChannels: new Set<string>(),
        records: [],
        selectedRecordId: null,
      });
      // Live query records arrive through the batch event. This path invokes the backend directly
      // rather than through queryChannels, so it must drain the same stream before merging.
      const mergeResult = (
        ch: string,
        result: EvtxParseResult,
        gaps: string[],
        structuredGaps: readonly EvtxCoverageGap[]
      ) => {
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        const state = get();
        const merged = mergeRecordsPreservingSelection(
          state.records,
          state.selectedRecordId,
          result.records
        );

        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const newChannels = state.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const newLoaded = new Set(state.loadedChannels);
        const hasHardFailure = result.parseErrors > 0 && result.records.length === 0;
        const channelHasUsableData =
          !hasHardFailure &&
          (gaps.length === 0 ||
            result.records.length > 0 ||
            (result.channels.find((c) => c.name === ch)?.eventCount ?? 0) > 0);
        if (channelHasUsableData) newLoaded.add(ch);

        set({
          ...merged,
          channels: newChannels,
          loadedChannels: newLoaded,
          loadElapsedMs: performance.now() - startTime,
          // Channels load one at a time and each may report its own gaps, so they accumulate
          // rather than replace. Deduplicated because re-querying a channel would otherwise
          // repeat the same line.
          coverageGaps: mergeCoverageGaps(state.coverageGaps, gaps),
          coverageDetails: mergeStructuredCoverageGaps(state.coverageDetails, structuredGaps),
        });
      };
      const promises = availableCore.map(async (ch) => {
        const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
        resetStreamedRecords([ch], requestId);
        try {
          const result = await invokeEventQuery<EvtxParseResult>(
            requestId,
            remoteMachine,
            [ch],
            hasInvalidEventIdFilter(get().filterEventIds) ? 0 : null,
            buildServerFilter(
              get().timeWindow,
              get().filterEventIds,
              get().filterLevels
            )
          );
          observeStreamReply(ch, requestId, { kind: "success" });
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          await waitForStreamReconciliation(ch, requestId);
          const checked = assertParseResultShape(result);
          const streamed = drainStreamedRecords(ch, requestId);
          const arrived = [...streamed.records, ...result.records];
          const streamedGaps =
            streamed.missingSequences.length > 0
              ? [`${context}: ${streamed.missingSequences.length} batches of events were not received`]
              : [];
          const shortfallGaps =
            typeof checked.totalRecords === "number" && arrived.length < checked.totalRecords
              ? [
                  `${context}: ${checked.totalRecords - arrived.length} of ${checked.totalRecords} events did not reach the view`,
                ]
              : [];
          mergeResult(
            ch,
            { ...result, records: arrived },
            [...checked.errorMessages, ...streamedGaps, ...shortfallGaps],
            checked.coverageGaps
          );
          acknowledgeStreamedRecords(ch, requestId);
        } catch (e) {
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          const msg = e instanceof Error ? e.message : String(e);
          observeStreamReply(ch, requestId, { kind: "error", message: msg });
          console.warn(`[evtx] Failed to query ${context}: ${msg}`);
          if (!loadError) loadError = `${context}: ${msg}`;
          drainStreamedRecords(ch, requestId);
          acknowledgeStreamedRecords(ch, requestId);
          set((s) => ({
            coverageGaps: mergeCoverageGaps(s.coverageGaps, [
              `${context}: not read (${msg})`,
            ]),
          }));
        }
      });
      await Promise.all(promises);
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const finalState = get();
      const remoteQueryFailed =
        remoteMachine !== null &&
        (availableCore.length === 0
          ? channels.length === 0
          : finalState.loadedChannels.size === 0 && finalState.coverageGaps.length > 0);
      set({
        sourceMode: remoteQueryFailed ? null : "live",
        isLoading: false,
        loadingChannel: null,
        loadingProgress: null,
        loadElapsedMs: performance.now() - startTime,
        loadError,
      });
    if (refreshRequested) refreshBeforeLoad();
  } catch (error) {
    if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const message = error instanceof Error ? error.message : String(error);
      const remoteMachine = get().remoteMachine;
      const remoteGap = remoteMachine
        ? message.startsWith(`${remoteMachine}:`)
          ? message
          : message.includes("access denied") || message.includes("credentials rejected")
            ? `${remoteMachine}: remote source access denied (${message})`
            : message.includes("unavailable")
              ? `${remoteMachine}: remote source unavailable (${message})`
              : `${remoteMachine}: remote source query failed (${message})`
        : null;
      set((state) => ({
        isLoading: false,
        loadError: message,
        coverageGaps: remoteGap
          ? mergeCoverageGaps(state.coverageGaps, [remoteGap])
          : state.coverageGaps,
      }));
    }
  },

  enumerateLocalChannels: async () => {
    set({
      remoteMachine: null,
      channels: [],
      records: [],
      sourceMode: null,
      coverageGaps: [],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
    });
    await get().enumerateChannels();
  },
  enumerateRemoteChannels: async (machine) => {
    beginRequest();
    set({
      remoteMachine: null,
      channels: [],
      records: [],
      sourceMode: null,
      coverageGaps: [],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      isLoading: false,
      loadError: null,
    });
    const normalized = machine.trim().replace(/^[/\\]+/, "");
    if (!normalized || /[\u0000-\u001f\u007f]/.test(normalized)) {
      set({
        isLoading: false,
        loadError: "Enter a valid remote computer name.",
      });
      return;
    }
    set({
      remoteMachine: normalized,
      channels: [],
      records: [],
      sourceMode: null,
      coverageGaps: [],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      loadError: null,
    });
    await get().enumerateChannels();
  },

  queryChannels: async (channels, maxEvents) => {
    const generation = get().loadGeneration + 1;
    const requestId = beginRequest();
    captureSelectedRecord(get().records, get().selectedRecordId);
    set({
      isLoading: true,
      loadError: null,
      selectedRecordId: null,
loadGeneration: generation,
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      tailCoverageGaps: [],
    });
    const remoteMachine = get().remoteMachine;
    // One request per channel rather than one request for all of them. The backend collects a
    // whole request's records into a single vector before replying, so asking for forty channels
    // at once held every event of every channel in memory twice, once per channel and once in the
    // combined vector, before anything reached the screen.
    //
    // It also isolates failure. A single request fails as a whole, so one unreadable channel threw
    // away the results of every channel queried alongside it and left the view empty.
    let loadError: string | null = null;

    // Anything left over from an earlier attempt at these channels is dropped, so a retry cannot
    // count a previous run's batches towards this one.
    invalidateAllStreamedRecords(requestId);
    for (const channel of channels) resetStreamedRecords([channel], requestId);

    const results = await Promise.all(
      channels.map(async (ch) => {
        try {
          const result = await invokeEventQuery<EvtxParseResult>(
            requestId,
            remoteMachine,
            [ch],
            hasInvalidEventIdFilter(get().filterEventIds) ? 0 : maxEvents ?? null,
            buildServerFilter(
              get().timeWindow,
              get().filterEventIds,
              get().filterLevels
            )
          );
          observeStreamReply(ch, requestId, { kind: "success" });
          return { channel: ch, result, error: null as string | null };
        } catch (e) {
          const message = e instanceof Error ? e.message : String(e);
          observeStreamReply(ch, requestId, { kind: "error", message });
          const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
          console.warn(`[evtx] Failed to query ${context}: ${message}`);
          if (!loadError) loadError = `${context}: ${message}`;
          return { channel: ch, result: null, error: message };
        }
      })
    );
    if (!isCurrentRequest(requestId)) return;
    for (const { channel, result, error } of results) {
      if (get().loadGeneration !== generation) return;
      const context = remoteMachine ? `${remoteMachine}/${channel}` : channel;
      try {
        if (!result) {
          await waitForStreamReconciliation(channel, requestId);
          drainStreamedRecords(channel, requestId);
          acknowledgeStreamedRecords(channel, requestId);
          // A channel that could not be read is recorded as a gap, not merely as an error banner
          // that the next successful load replaces. The events it would have contributed are absent
          // from the view for as long as the view is on screen.
          set((s) => ({
            coverageGaps: mergeCoverageGaps(s.coverageGaps, [
              `${context}: not read (${error ?? "unknown error"})`,
            ]),
          }));
          continue;
        }

        // Both the invoke reply and stream terminal are required before coverage is measured. The
        // terminal may arrive on either side of the reply.
        await waitForStreamReconciliation(channel, requestId);
        const checked = assertParseResultShape(result);
        const streamed = drainStreamedRecords(channel, requestId);
        const arrived = [...streamed.records, ...result.records];

        const gapsFound: string[] = [];
        if (streamed.missingSequences.length > 0) {
          gapsFound.push(
            `${context}: ${streamed.missingSequences.length} batches of events were not received`
          );
        }
        const expected = checked.totalRecords;
        if (typeof expected === "number" && arrived.length < expected) {
          gapsFound.push(
            `${context}: ${expected - arrived.length} of ${expected} events did not reach the view`
          );
        }

        const state = get();
        const merged = mergeRecordsPreservingSelection(
          state.records,
          state.selectedRecordId,
          arrived
        );
        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const updatedChannels = state.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));

        const reportedGaps = [...checked.errorMessages, ...gapsFound];
        const newLoaded = new Set(state.loadedChannels);
        const channelHasUsableData =
          reportedGaps.length === 0 ||
          arrived.length > 0 ||
          (result.channels.find((c) => c.name === channel)?.eventCount ?? 0) > 0;
        if (channelHasUsableData) newLoaded.add(channel);

        const channelGaps = `${context}:`;
        const priorGaps = state.coverageGaps.filter((gap) => !gap.startsWith(channelGaps));
        set({
          ...merged,
          channels: updatedChannels,
          loadedChannels: newLoaded,
          // Replace this channel's prior coverage with the current attempt while retaining gaps for
          // unrelated channels.
          coverageGaps: mergeCoverageGaps(priorGaps, reportedGaps),
          coverageDetails: mergeStructuredCoverageGaps(
            state.coverageDetails,
            checked.coverageGaps
          ),
        });
        acknowledgeStreamedRecords(channel, requestId);
      } catch (processingError) {
        drainStreamedRecords(channel, requestId);
        acknowledgeStreamedRecords(channel, requestId);
        // assertParseResultShape throws by design on a reply this build cannot read, and a malformed
        // reply is not a reason to leave the workspace stuck on a spinner with no message.
        const message =
          processingError instanceof Error ? processingError.message : String(processingError);
        console.warn(`[evtx] Failed to process ${context}: ${message}`);
        if (!loadError) loadError = `${context}: ${message}`;
        set((s) => ({
          coverageGaps: mergeCoverageGaps(s.coverageGaps, [`${context}: not read (${message})`]),
        }));
      }
    }

    set({ isLoading: false, loadError });
    if (refreshRequested && get().sourceMode === "live") {
      refreshRequested = false;
      const refreshChannels = [...new Set([...channels, ...get().loadedChannels])];
      set((s) => ({
        records: s.records.filter((record) => !refreshChannels.includes(record.channel)),
        loadedChannels: new Set(
          [...s.loadedChannels].filter((channel) => !refreshChannels.includes(channel))
        ),
        coverageGaps: s.coverageGaps.filter(
          (gap) => !refreshChannels.some((channel) => gap.startsWith(`${channel}:`))
        ),
      }));
      void get().queryChannels(refreshChannels, maxEvents);
    } else {
      refreshRequested = false;
    }
  },
  loadSelectedChannels: async () => {
    const state = get();
    const unloaded = [...state.selectedChannels].filter(
      (channel) => !state.loadedChannels.has(channel)
    );
    if (unloaded.length === 0) return;
    await get().queryChannels(unloaded);
  },
  refreshLoadedChannels: async () => {
    const state = get();
    const loaded = [...state.loadedChannels];
    if (loaded.length === 0) return;
    const requestId = beginRequest();
    const generation = state.loadGeneration + 1;
    const remoteMachine = state.remoteMachine;
    const startTime = performance.now();
    captureSelectedRecord(get().records, get().selectedRecordId);
    invalidateAllStreamedRecords(requestId);
    set({
      records: [],
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      loadGeneration: generation,
      isLoading: true,
      loadError: null,
      loadStartTime: startTime,
      loadElapsedMs: null,
      coverageGaps: [],
      coverageDetails: [],
    });
    for (const channel of loaded) resetStreamedRecords([channel], requestId);
    // Refresh invokes the streaming command directly, so drain its batch before merging the
    // command reply (which intentionally carries only records not emitted in batches).
    const promises = loaded.map(async (ch) => {
      const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
      try {
        resetStreamedRecords([ch], requestId);
        const result = await invokeEventQuery<EvtxParseResult>(
          requestId,
          remoteMachine,
          [ch],
          hasInvalidEventIdFilter(get().filterEventIds) ? 0 : null,
          buildServerFilter(
            get().timeWindow,
            get().filterEventIds,
            get().filterLevels
          )
        );
        observeStreamReply(ch, requestId, { kind: "success" });
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        await waitForStreamReconciliation(ch, requestId);
        const checked = assertParseResultShape(result);
        const streamed = drainStreamedRecords(ch, requestId);
        const arrived = [...streamed.records, ...result.records];
        const streamedGaps =
          streamed.missingSequences.length > 0
            ? [`${context}: ${streamed.missingSequences.length} batches of events were not received`]
            : [];
        const shortfallGaps =
          typeof checked.totalRecords === "number" && arrived.length < checked.totalRecords
            ? [
                `${context}: ${checked.totalRecords - arrived.length} of ${checked.totalRecords} events did not reach the view`,
              ]
            : [];

        const s = get();
        const merged = mergeRecordsPreservingSelection(
          s.records,
          s.selectedRecordId,
          arrived
        );
        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const newChannels = s.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const reportedGaps = [...checked.errorMessages, ...streamedGaps, ...shortfallGaps];
        const newLoaded = new Set(s.loadedChannels);
        const channelHasUsableData =
          reportedGaps.length === 0 ||
          arrived.length > 0 ||
          (result.channels.find((c) => c.name === ch)?.eventCount ?? 0) > 0;
        if (channelHasUsableData) newLoaded.add(ch);

        set({
          ...merged,
          channels: newChannels,
          loadedChannels: newLoaded,
          loadElapsedMs: performance.now() - startTime,
          coverageGaps: mergeCoverageGaps(s.coverageGaps, reportedGaps),
          coverageDetails: mergeStructuredCoverageGaps(s.coverageDetails, checked.coverageGaps),
        });
        acknowledgeStreamedRecords(ch, requestId);
      } catch (e) {
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        observeStreamReply(
          ch,
          requestId,
          { kind: "error", message: e instanceof Error ? e.message : String(e) }
        );
        drainStreamedRecords(ch, requestId);
        acknowledgeStreamedRecords(ch, requestId);
        const message = e instanceof Error ? e.message : String(e);
        const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
        console.warn(`[evtx] Refresh failed for ${context}: ${message}`);
        // Recorded, not only logged. The refresh cleared the previous gaps, so a silent failure
        // here presents a view that is missing a whole channel as complete.
        if (get().loadGeneration !== generation) return;
        set((s) => ({
          coverageGaps: mergeCoverageGaps(s.coverageGaps, [
            `${context}: not read (${message})`,
          ]),
          loadError: s.loadError ?? `${context}: ${message}`,
        }));
      }
    });
    await Promise.all(promises);
    if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
    const finalState = get();
    const remoteRefreshFailed =
      remoteMachine !== null &&
      finalState.loadedChannels.size === 0 &&
      finalState.coverageGaps.length > 0;
    set({
      sourceMode: remoteRefreshFailed ? null : finalState.sourceMode,
      isLoading: false,
      loadingChannel: null,
      loadingProgress: null,
      loadElapsedMs: performance.now() - startTime,
    });
    if (refreshRequested) refreshBeforeLoad();
  },
  startLiveTail: async () => {
    const state = get();
    if (state.sourceMode !== "live") return [];
    const channels = [...state.loadedChannels];
    if (channels.length === 0) return [];
    const sourceRequestId = activeRequestId;
    const requestId = `event-log-tail-${++tailGeneration}`;
    const remoteMachine = state.remoteMachine;
    activeTailRequestId = requestId;
    activeTailSourceRequestId = sourceRequestId;
    activeTailChannels = new Set(channels);
    const statuses = await Promise.all(
      channels.map(async (channel) => {
        try {
          return await invoke<EvtxTailStatus>("evtx_start_tail", {
            channel,
            requestId,
            filter: buildServerFilter(get().timeWindow, get().filterEventIds, get().filterLevels),
            remoteMachine,
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          return {
            requestId,
            channel,
            mode: "unsupported" as const,
            active: false,
            nextSequence: 0,
            coverageGaps: [`${channel}: live tail unavailable (${message})`],
          };
        }
      })
    );
    if (!isCurrentRequest(sourceRequestId) || activeTailRequestId !== requestId) return [];
    const modes = statuses.map((status) => status.mode);
    const gaps = statuses.flatMap((status) => status.coverageGaps);
    activeTailChannels = new Set(
      statuses.filter((status) => status.active).map((status) => status.channel)
    );
    set({
      tailMode: aggregateTailMode(modes),
      tailRequestId: requestId,
      tailChannels: activeTailChannels,
      tailCoverageGaps: mergeCoverageGaps([], gaps),
    });
    return statuses;
  },
  stopLiveTail: async () => {
    const state = get();
    const requestId = state.tailRequestId;
    if (!requestId) return;
    const channels = [...state.tailChannels];
    const sequenceSnapshots = new Map(
      channels.map((channel) => [
        channel,
        new Set(tailSequences.get(tailSequenceKey(requestId, channel)) ?? []),
      ])
    );
    activeTailSourceRequestId = null;
    activeTailChannels = new Set<string>();
    tailSequences.clear();
    set({
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
    });
    const statuses = await Promise.all(
      channels.map((channel) =>
        invoke<EvtxTailStatus>("evtx_stop_tail", {
          requestId,
          channel,
        }).catch(() => undefined)
      )
    );
    const finalGaps = statuses.flatMap((status, index) => {
      if (!status) return [];
      const received = sequenceSnapshots.get(channels[index]) ?? new Set<number>();
      return Array.from({ length: status.nextSequence }, (_, sequence) =>
        received.has(sequence)
          ? null
          : `${status.channel}: live tail batch ${sequence} was not received`
      ).filter((gap): gap is string => gap !== null);
    });
    if (finalGaps.length > 0) {
      set((current) => ({
        tailCoverageGaps: mergeCoverageGaps(current.tailCoverageGaps, finalGaps),
      }));
    }
    tailSequences.clear();
  },

  clearChannel: async (channel, confirmed) => {
    const state = get();
    const requestId = state.tailRequestId;
    const wasTailing = requestId !== null && state.tailChannels.has(channel);
    if (wasTailing) {
      await invoke("evtx_stop_tail", { requestId, channel }).catch(() => undefined);
      activeTailChannels.delete(channel);
      tailSequences.delete(tailSequenceKey(requestId, channel));
    }
    const response = await invoke<{ channel: string; result: EvtxClearResult }>(
      "evtx_clear_channel",
      { channel, confirmed, remoteMachine: state.remoteMachine }
    );
    const result = response.result;
    if (result.status === "cleared") {
      set((current) => ({
        records: current.records.filter((record) => record.channel !== channel),
        loadedChannels: new Set([...current.loadedChannels].filter((name) => name !== channel)),
        channels: current.channels.map((info) =>
          info.name === channel ? { ...info, eventCount: 0 } : info
        ),
        coverageGaps: current.coverageGaps.filter((gap) => !gap.startsWith(`${channel}:`)),
        tailChannels: new Set([...current.tailChannels].filter((name) => name !== channel)),
      }));
    } else if (wasTailing && get().tailRequestId === requestId) {
      // A denied, unavailable, or cancelled clear must leave the live view in the state the
      // operator was using before confirmation.
      await get().startLiveTail();
    }
    return result;
  },


  setTimeZoneMode: (mode) => set({ timeZoneMode: mode }),

  setSelectedChannels: (channels) => set({ selectedChannels: channels }),

  toggleChannel: (channel) => {
    const current = get().selectedChannels;
    const next = new Set(current);
    if (next.has(channel)) {
      next.delete(channel);
    } else {
      next.add(channel);
    }
    set({ selectedChannels: next });
  },

  selectAllChannels: () => {
    const channelNames = new Set(get().channels.map((c) => c.name));
    set({ selectedChannels: channelNames });
  },

  deselectAllChannels: () => {
    set({ selectedChannels: new Set<string>() });
  },

  setFilterLevels: (levels) => {
    set({ filterLevels: levels });
    refreshBeforeLoad();
  },

  toggleFilterLevel: (level) => {
    const current = get().filterLevels;
    const next = new Set(current);
    if (next.has(level)) next.delete(level);
    else next.add(level);
    if (next.size === 0) ALL_LEVELS.forEach((known) => next.add(known));
    set({ filterLevels: next });
    refreshBeforeLoad();
  },

  setFilterEventIds: (eventIds) => {
    set({ filterEventIds: eventIds });
    refreshBeforeLoad();
  },
  setBeforeLoadCriteria: (criteria) => {
    set({
      filterLevels: new Set(criteria.levels),
      filterEventIds: criteria.eventIds,
      timeWindow: criteria.timeWindow,
      ...(criteria.selectedChannels
        ? { selectedChannels: new Set(criteria.selectedChannels) }
        : {}),
    });
    refreshBeforeLoad();
  },
  setFilterSearch: (search) => set({ filterSearch: search }),
  setQuickFilter: (filter) => set({ quickFilter: { ...filter } }),
  setTimeWindow: (window) => {
    set({ timeWindow: window });
    refreshBeforeLoad();
  },
  // Changing the grouping invalidates every collapse key, so the old set is discarded rather than
  // left to collapse unrelated groups that happen to share a key.
  setGroupBy: (fields) => set({ groupBy: fields, collapsedGroups: new Set<string>() }),
  toggleColumnVisible: (id) =>
    set({ columnConfig: sanitizeColumnConfig(toggleColumn(get().columnConfig, id)) }),
  moveColumnBy: (id, direction) =>
    set({ columnConfig: sanitizeColumnConfig(moveColumn(get().columnConfig, id, direction)) }),
  resetColumns: () => set({ columnConfig: defaultColumnConfig() }),
  toggleGroup: (key) => {
    const next = new Set(get().collapsedGroups);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    set({ collapsedGroups: next });
  },
  setSortField: (field) => set({ sortField: field }),
  setSortDirection: (direction) => set({ sortDirection: direction }),
  setSelectedRecordId: (id) => set({ selectedRecordId: id }),

  reset: () => {
    const loadGeneration = get().loadGeneration + 1;
    preservedSelectedRecordKey = null;
    const requestId = beginRequest();
    invalidateAllStreamedRecords(requestId);
    set({
      records: [],
      channels: [],
      sourceMode: null,
      sourcePaths: [],
      remoteMachine: null,
      isLoading: false,
      loadError: null,
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      loadingChannel: null,
      loadingProgress: null,
      loadStartTime: null,
      loadElapsedMs: null,
      loadGeneration,
      filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
      filterEventIds: "",
      filterSearch: "",
      timeZoneMode: "local",
      quickFilter: { ...DEFAULT_QUICK_FILTER },
      timeWindow: "24h",
      // Reset with everything else. Gaps describe records that are gone, so surviving a reset
      // would report a hole in a set no longer on screen, and a zone left over from a previous
      // session would silently reinterpret the next one's timestamps.
      coverageGaps: [],
      coverageDetails: [],
      sourceManifest: null,
      columnConfig: defaultColumnConfig(),
      groupBy: [],
      collapsedGroups: new Set<string>(),
      sortField: "time",
      sortDirection: "asc",
      selectedRecordId: null,
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      tailCoverageGaps: [],
    });
  },
});
});

// Listen for progress events from the Rust backend
listen<{ requestId: string; channel: string; fetched: number }>(
  "evtx-query-progress",
  (event) => {
    if (!isCurrentRequest(event.payload.requestId)) return;
    useEvtxStore.setState({
      loadingChannel: event.payload.channel,
      loadingProgress: event.payload.fetched,
    });
  }
);
type StreamReply =
  | { kind: "success" }
  | { kind: "error"; message: string };

interface PendingStream {
  channel: string;
  requestId: string;
  records: EvtxRecord[];
  sequences: Set<number>;
  terminal?: { sequenceCount: number; totalRecords: number };
  terminalSynthetic: boolean;
  reply?: StreamReply;
  consumerAcknowledged: boolean;
  settled: boolean;
  settling: boolean;
  terminalGraceTimer?: ReturnType<typeof setTimeout>;
  waiters: Array<() => void>;
}

/**
 * A request may query more than one channel, so channel alone is not a stream identity. Keeping
 * the request in the key also lets a late event from an older query be rejected after a refresh.
 */
const pendingBatches = new Map<string, PendingStream>();
const activeRequestIds = new Map<string, string>();

function streamKey(channel: string, requestId: string): string {
  return `${requestId}\u0000${channel}`;
}

function createPendingStream(channel: string, requestId: string): PendingStream {
  const pending: PendingStream = {
    channel,
    requestId,
    records: [],
    sequences: new Set<number>(),
    terminalSynthetic: false,
    consumerAcknowledged: false,
    settled: false,
    settling: false,
    waiters: [],
  };
  pendingBatches.set(streamKey(channel, requestId), pending);
  return pending;
}

function pendingFor(channel: string, requestId: string): PendingStream | undefined {
  return pendingBatches.get(streamKey(channel, requestId));
}

function sequenceNumbers(pending: PendingStream): number[] {
  if (!pending.terminal) return [];
  const missing: number[] = [];
  for (let sequence = 0; sequence < pending.terminal.sequenceCount; sequence++) {
    if (!pending.sequences.has(sequence)) missing.push(sequence);
  }
  return missing;
}

const TERMINAL_BATCH_GRACE_MS = 25;

function settlePendingStream(pending: PendingStream, allowMissing = false): void {
  if (pending.settled || pending.settling || !pending.reply || !pending.terminal) return;
  if (!allowMissing && sequenceNumbers(pending).length > 0) {
    if (pending.terminalGraceTimer === undefined) {
      pending.terminalGraceTimer = setTimeout(() => {
        pending.terminalGraceTimer = undefined;
        settlePendingStream(pending, true);
      }, TERMINAL_BATCH_GRACE_MS);
    }
    return;
  }
  if (pending.terminalGraceTimer !== undefined) {
    clearTimeout(pending.terminalGraceTimer);
    pending.terminalGraceTimer = undefined;
  }
  pending.settling = true;
  queueMicrotask(() => {
    pending.settling = false;
    if (pending.settled || !pending.reply || !pending.terminal) return;
    pending.settled = true;
    const waiters = pending.waiters.splice(0);
    for (const resolve of waiters) resolve();
  });
}

function observeStreamReply(channel: string, requestId: string, reply: StreamReply): void {
  const pending = pendingFor(channel, requestId);
  if (!pending || pending.requestId !== requestId || pending.consumerAcknowledged) return;
  pending.reply = reply;
  if (reply.kind === "error") {
    // A rejected invoke is terminal from the consumer's point of view. It must not leave a waiter
    // behind for an event the backend could not deliver.
    let highest = -1;
    for (const sequence of pending.sequences) highest = Math.max(highest, sequence);
    pending.terminal = { sequenceCount: highest + 1, totalRecords: 0 };
    pending.terminalSynthetic = true;
    settlePendingStream(pending);
    return;
  }
  if (pending.terminal) settlePendingStream(pending);
}

function waitForStreamReconciliation(channel: string, requestId: string): Promise<void> {
  const pending = pendingFor(channel, requestId);
  if (!pending || pending.requestId !== requestId || pending.settled) return Promise.resolve();
  return new Promise<void>((resolve) => pending.waiters.push(resolve));
}

function invalidateAllStreamedRecords(requestId: string): void {
  const channels = new Set([
    ...[...pendingBatches.values()].map((pending) => pending.channel),
    ...activeRequestIds.keys(),
  ]);
  for (const channel of channels) resetStreamedRecords([channel], requestId);
}

listen<{ channel: string; requestId: string; sequence: number; records: EvtxRecord[] }>(
  "evtx-record-batch",
  (event) => {
    const { channel, requestId, sequence, records } = event.payload;
    if (!isCurrentRequest(requestId) || activeRequestIds.get(channel) !== requestId) return;
    const pending = pendingFor(channel, requestId) ?? createPendingStream(channel, requestId);
    if (pending.consumerAcknowledged || pending.sequences.has(sequence)) return;

    pending.sequences.add(sequence);
    pending.records = appendUniqueRecords(pending.records, records);

    // Batches are visible while a request is running. Use the same identity-preserving merge as all
    // reply/refresh paths so a late, out-of-order batch cannot move the operator's selection.
    const state = useEvtxStore.getState();
    const merged = mergeRecordsPreservingSelection(
      state.records,
      state.selectedRecordId,
      records
    );
    useEvtxStore.setState(merged);

    // A terminal can race the final batch. Keep the pending state until the consumer acknowledges
    // the drain; the records above remain available even after reconciliation has resolved.
    settlePendingStream(pending);
  }
);

listen<{ channel: string; requestId: string; sequenceCount: number; totalRecords: number }>(
  "evtx-record-stream-complete",
  (event) => {
    const { channel, requestId, sequenceCount, totalRecords } = event.payload;
    if (!isCurrentRequest(requestId) || activeRequestIds.get(channel) !== requestId) return;
    const pending = pendingFor(channel, requestId) ?? createPendingStream(channel, requestId);
    if (pending.consumerAcknowledged) return;
    pending.terminal = { sequenceCount, totalRecords };
    pending.terminalSynthetic = false;
    settlePendingStream(pending);
  }
);

listen<EvtxTailBatch>("evtx-tail-batch", (event) => {
  const payload = event.payload;
  if (
    activeTailSourceRequestId === null ||
    !isCurrentRequest(activeTailSourceRequestId) ||
    activeTailRequestId !== payload.requestId ||
    !activeTailChannels.has(payload.channel)
  ) {
    return;
  }
  const key = tailSequenceKey(payload.requestId, payload.channel);
  let sequences = tailSequences.get(key);
  if (!sequences) {
    sequences = new Set<number>();
    tailSequences.set(key, sequences);
  }
  if (sequences.has(payload.sequence)) return;

  const missing: string[] = [];
  let highest = -1;
  for (const sequence of sequences) highest = Math.max(highest, sequence);
  for (let sequence = highest + 1; sequence < payload.sequence; sequence++) {
    if (!sequences.has(sequence)) {
      missing.push(`${payload.channel}: live tail batch ${sequence} was not received`);
    }
  }
  sequences.add(payload.sequence);
  if (payload.coverageGaps.length > 0) missing.push(...payload.coverageGaps);

  useEvtxStore.setState((state) => {
    const merged = mergeRecordsPreservingSelection(
      state.records,
      state.selectedRecordId,
      payload.records
    );
    const existingMode = state.tailMode;
    const mode =
      existingMode === null || existingMode === payload.mode
        ? payload.mode
        : existingMode === "unsupported"
          ? payload.mode
          : "mixed";
    return {
      ...merged,
      tailMode: mode,
      tailRequestId: payload.requestId,
      tailChannels: new Set([...state.tailChannels, payload.channel]),
      tailCoverageGaps: mergeCoverageGaps(state.tailCoverageGaps, missing),
    };
  });
});

/** Takes everything received for `channel`, and reports whether it is contiguous. */
export function drainStreamedRecords(channel: string, requestId: string): {
  records: EvtxRecord[];
  missingSequences: number[];
} {
  const pending = pendingFor(channel, requestId);
  if (!pending || pending.requestId !== requestId) {
    return { records: [], missingSequences: [] };
  }
  return { records: pending.records, missingSequences: sequenceNumbers(pending) };
}

/**
 * A load path calls this only after merging the drained snapshot. Until then events may still
 * arrive after the terminal marker and must remain available for exactly-once draining.
 */
export function acknowledgeStreamedRecords(channel: string, requestId: string): void {
  const pending = pendingFor(channel, requestId);
  if (!pending) return;
  pending.consumerAcknowledged = true;
  clearTimeout(pending.terminalGraceTimer);
  pending.terminalGraceTimer = undefined;
  pending.waiters.length = 0;
  pendingBatches.delete(streamKey(channel, requestId));
  if (activeRequestIds.get(channel) === requestId) activeRequestIds.delete(channel);
}

/** Discards anything buffered for channels a query is about to start, and registers the request. */
export function resetStreamedRecords(channels: string[], requestId: string): void {
  for (const channel of channels) {
    const activeRequestId = activeRequestIds.get(channel);
    if (activeRequestId !== undefined) {
      pendingBatches.delete(streamKey(channel, activeRequestId));
    }
    activeRequestIds.set(channel, requestId);
    createPendingStream(channel, requestId);
  }
}
