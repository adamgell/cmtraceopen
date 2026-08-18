import { create } from "zustand";
import { assertParseResultShape, mergeCoverageGaps } from "./evtx-coverage";
import type { EvtxTimeZoneMode } from "./evtx-time";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  EvtxRecord,
  EvtxChannelInfo,
  EvtxLevel,
  EvtxParseResult,
  EvtxTimeWindow,
  EventQueryFilterSubset,
} from "./types";
import { EVTX_TIME_WINDOW_MS } from "./types";

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
  return (
    a.timestampEpoch - b.timestampEpoch ||
    a.sourceLabel.localeCompare(b.sourceLabel) ||
    a.channel.localeCompare(b.channel) ||
    a.eventRecordId - b.eventRecordId ||
    a.eventId - b.eventId
  );
}
function recordKey(record: EvtxRecord): string {
  return `${record.channel}\u0000${record.eventRecordId}\u0000${record.eventId}\u0000${record.timestampEpoch}`;
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
function clearChannelReadGaps(gaps: string[], channel: string): string[] {
  return gaps.filter((gap) => !gap.startsWith(`${channel}: not read`));
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
  isLoading: boolean;
  loadingChannel: string | null;
  loadingProgress: number | null;
  loadStartTime: number | null;
  loadElapsedMs: number | null;
  loadError: string | null;
  /**
   * What is missing from the loaded set, and why.
   *
   * Separate from loadError because these are not failures: the events that did load are real and
   * usable. They are gaps, and a gap that only reaches the console reads to an operator as a
   * complete picture, which is how absent events get mistaken for evidence that nothing happened.
   */
  coverageGaps: string[];
  selectedChannels: Set<string>;
  loadedChannels: Set<string>;
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

  parseFiles: (paths: string[]) => Promise<void>;
  enumerateChannels: () => Promise<void>;
  queryChannels: (channels: string[], maxEvents?: number) => Promise<void>;
  loadSelectedChannels: () => Promise<void>;
  refreshLoadedChannels: () => Promise<void>;
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
  sourceMode: EvtxSourceMode
): Partial<EvtxState> {
  const channelNames = new Set(result.channels.map((c) => c.name));
  return {
    records: result.records,
    channels: result.channels,
    sourceMode,
    isLoading: false,
    loadError: null,
    coverageGaps: result.errorMessages,
    selectedChannels: channelNames,
    selectedRecordId: null,
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
  channels: [],
  sourceMode: null,
  isLoading: false,
  loadingChannel: null,
  loadingProgress: null,
  loadStartTime: null,
  loadElapsedMs: null,
  loadError: null,
  coverageGaps: [],
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
  loadGeneration: 0,

  parseFiles: async (paths) => {
    const previousTimeWindow = get().timeWindow;
    const generation = get().loadGeneration + 1;
    preservedSelectedRecordKey = null;
    invalidateAllStreamedRecords(generation);
    refreshRequested = false;
    set({
      loadGeneration: generation,
      sourceMode: null,
      records: [],
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      coverageGaps: [],
      timeWindow: "all",
      isLoading: true,
      loadError: null,
    });
    try {
      const result = await invoke<EvtxParseResult>("evtx_parse_files", { paths });
      if (get().loadGeneration !== generation) return;
      const checked = assertParseResultShape(result);
      set({ ...applyParseResult({ ...result, errorMessages: checked.errorMessages }, "files"), loadGeneration: generation });
    } catch (error) {
      if (get().loadGeneration !== generation) return;
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message, timeWindow: previousTimeWindow });
    }
  },
  enumerateChannels: async () => {
    const generation = get().loadGeneration + 1;
    captureSelectedRecord(get().records, get().selectedRecordId);
    invalidateAllStreamedRecords(generation);
    set({
      loadGeneration: generation,
      isLoading: true,
      loadError: null,
      timeWindow: get().sourceMode === null && get().timeWindow === "all" ? "24h" : get().timeWindow,
    });
    try {
      const channels = await invoke<EvtxChannelInfo[]>("evtx_enumerate_channels");
      if (get().loadGeneration !== generation) return;

      // Step 2: Auto-query the core Windows Logs channels immediately
      const coreChannels = ["Application", "System", "Security", "Setup"];
      const availableCore = coreChannels.filter((c) =>
        channels.some((ch) => ch.name === c)
      );

      let updatedChannels = channels;
      let loadError: string | null = null;

      // Show channels immediately, then load events in parallel
      const selectedNames = new Set(availableCore);
      const startTime = performance.now();
      captureSelectedRecord(get().records, get().selectedRecordId);
      set({
        channels: updatedChannels,
        sourceMode: "live",
        isLoading: true,
        loadError: null,
        coverageGaps: [],
        loadStartTime: startTime,
        loadElapsedMs: null,
        selectedChannels: selectedNames,
        loadedChannels: new Set<string>(),
        records: [],
        selectedRecordId: null,
      });
      // Live query records arrive through the batch event. This path invokes the backend directly
      // rather than through queryChannels, so it must drain the same stream before merging.
      const mergeResult = (ch: string, result: EvtxParseResult, gaps: string[]) => {
        if (get().loadGeneration !== generation) return;
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
        newLoaded.add(ch);

        set({
          ...merged,
          channels: newChannels,
          loadedChannels: newLoaded,
          loadElapsedMs: performance.now() - startTime,
          // Channels load one at a time and each may report its own gaps, so they accumulate
          // rather than replace. Deduplicated because re-querying a channel would otherwise
          // repeat the same line.
          coverageGaps: mergeCoverageGaps(state.coverageGaps, gaps),
        });
      };
      const promises = availableCore.map(async (ch) => {
        resetStreamedRecords([ch], generation);
        try {
          const result = await invoke<EvtxParseResult>("evtx_query_channels", {
            channels: [ch],
            maxEvents: hasInvalidEventIdFilter(get().filterEventIds) ? 0 : null,
            requestId: generation,
            filter: buildServerFilter(
              get().timeWindow,
              get().filterEventIds,
              get().filterLevels
            ),
          });
          observeStreamReply(ch, generation, { kind: "success" });
          if (get().loadGeneration !== generation) return;
          await waitForStreamReconciliation(ch, generation);
          const checked = assertParseResultShape(result);
          const streamed = drainStreamedRecords(ch, generation);
          const arrived = [...streamed.records, ...result.records];
          const streamedGaps =
            streamed.missingSequences.length > 0
              ? [`${ch}: ${streamed.missingSequences.length} batches of events were not received`]
              : [];
          const shortfallGaps =
            typeof checked.totalRecords === "number" && arrived.length < checked.totalRecords
              ? [
                  `${ch}: ${checked.totalRecords - arrived.length} of ${checked.totalRecords} events did not reach the view`,
                ]
              : [];
          mergeResult(
            ch,
            { ...result, records: arrived },
            [...checked.errorMessages, ...streamedGaps, ...shortfallGaps]
          );
          acknowledgeStreamedRecords(ch, generation);
        } catch (e) {
          if (get().loadGeneration !== generation) return;
          const msg = e instanceof Error ? e.message : String(e);
          observeStreamReply(ch, generation, { kind: "error", message: msg });
          console.warn(`[evtx] Failed to query ${ch}: ${msg}`);
          drainStreamedRecords(ch, generation);
          acknowledgeStreamedRecords(ch, generation);
          set((s) => ({
            coverageGaps: mergeCoverageGaps(s.coverageGaps, [`${ch}: not read (${msg})`]),
          }));
        }
      });

      await Promise.all(promises);
      if (get().loadGeneration !== generation) return;

      set({
        isLoading: false,
        loadingChannel: null,
        loadingProgress: null,
        loadElapsedMs: performance.now() - startTime,
        loadError,
      });
      if (refreshRequested) refreshBeforeLoad();
    } catch (error) {
      if (get().loadGeneration !== generation) return;
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message });
    }
  },

  queryChannels: async (channels, maxEvents) => {
    const generation = get().loadGeneration + 1;
    set({
      isLoading: true,
      loadError: null,
      loadGeneration: generation,
    });

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
    invalidateAllStreamedRecords(generation);
    for (const channel of channels) resetStreamedRecords([channel], generation);

    const results = await Promise.all(
      channels.map(async (ch) => {
        try {
          const result = await invoke<EvtxParseResult>("evtx_query_channels", {
            channels: [ch],
            requestId: generation,
            maxEvents: hasInvalidEventIdFilter(get().filterEventIds) ? 0 : maxEvents ?? null,
            filter: buildServerFilter(
              get().timeWindow,
              get().filterEventIds,
              get().filterLevels
            ),
          });
          observeStreamReply(ch, generation, { kind: "success" });
          return { channel: ch, result, error: null as string | null };
        } catch (e) {
          const message = e instanceof Error ? e.message : String(e);
          observeStreamReply(ch, generation, { kind: "error", message });
          console.warn(`[evtx] Failed to query ${ch}: ${message}`);
          if (!loadError) loadError = `${ch}: ${message}`;
          return { channel: ch, result: null, error: message };
        }
      })
    );
    for (const { channel, result, error } of results) {
      if (get().loadGeneration !== generation) return;
      try {
        if (!result) {
          await waitForStreamReconciliation(channel, generation);
          drainStreamedRecords(channel, generation);
          acknowledgeStreamedRecords(channel, generation);
          // A channel that could not be read is recorded as a gap, not merely as an error banner
          // that the next successful load replaces. The events it would have contributed are absent
          // from the view for as long as the view is on screen.
          set((s) => ({
            coverageGaps: mergeCoverageGaps(s.coverageGaps, [
              `${channel}: not read (${error ?? "unknown error"})`,
            ]),
          }));
          continue;
        }

        // Both the invoke reply and stream terminal are required before coverage is measured. The
        // terminal may arrive on either side of the reply.
        await waitForStreamReconciliation(channel, generation);
        const checked = assertParseResultShape(result);
        const streamed = drainStreamedRecords(channel, generation);
        const arrived = [...streamed.records, ...result.records];

        const gapsFound: string[] = [];
        if (streamed.missingSequences.length > 0) {
          gapsFound.push(
            `${channel}: ${streamed.missingSequences.length} batches of events were not received`
          );
        }
        const expected = checked.totalRecords;
        if (typeof expected === "number" && arrived.length < expected) {
          gapsFound.push(
            `${channel}: ${expected - arrived.length} of ${expected} events did not reach the view`
          );
        }

        const state = get();
        const merged = mergeRecordsPreservingSelection(
          state.records,
          state.selectedRecordId,
          result.records
        );
        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const updatedChannels = state.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const newLoaded = new Set(state.loadedChannels);
        newLoaded.add(channel);

        set({
          ...merged,
          channels: updatedChannels,
          loadedChannels: newLoaded,
          // Accumulated, not dropped. This path loads channels incrementally, so discarding what the
          // backend reported here would show a complete view of a partly unreadable set.
          coverageGaps: mergeCoverageGaps(clearChannelReadGaps(state.coverageGaps, channel), [
            ...checked.errorMessages,
            ...gapsFound,
          ]),
        });
        acknowledgeStreamedRecords(channel, generation);
      } catch (processingError) {
        drainStreamedRecords(channel, generation);
        acknowledgeStreamedRecords(channel, generation);
        // assertParseResultShape throws by design on a reply this build cannot read, and a malformed
        // reply is not a reason to leave the workspace stuck on a spinner with no message.
        const message =
          processingError instanceof Error ? processingError.message : String(processingError);
        console.warn(`[evtx] Failed to process ${channel}: ${message}`);
        if (!loadError) loadError = `${channel}: ${message}`;
        set((s) => ({
          coverageGaps: mergeCoverageGaps(s.coverageGaps, [`${channel}: not read (${message})`]),
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
    const generation = state.loadGeneration + 1;
    const startTime = performance.now();
    captureSelectedRecord(get().records, get().selectedRecordId);
    invalidateAllStreamedRecords(generation);
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
    });
    for (const channel of loaded) resetStreamedRecords([channel], generation);

    // Refresh invokes the streaming command directly, so drain its batch before merging the
    // command reply (which intentionally carries only records not emitted in batches).
    const promises = loaded.map(async (ch) => {
      try {
        const result = await invoke<EvtxParseResult>("evtx_query_channels", {
          channels: [ch],
          maxEvents: hasInvalidEventIdFilter(get().filterEventIds) ? 0 : null,
          requestId: generation,
          // The window is a server-side predicate and a refetch is the only thing that applies it.
          filter: buildServerFilter(
            get().timeWindow,
            get().filterEventIds,
            get().filterLevels
          ),
        });
        observeStreamReply(ch, generation, { kind: "success" });
        if (get().loadGeneration !== generation) return;
        await waitForStreamReconciliation(ch, generation);
        const checked = assertParseResultShape(result);
        const streamed = drainStreamedRecords(ch, generation);
        const arrived = [...streamed.records, ...result.records];
        const streamedGaps =
          streamed.missingSequences.length > 0
            ? [`${ch}: ${streamed.missingSequences.length} batches of events were not received`]
            : [];
        const shortfallGaps =
          typeof checked.totalRecords === "number" && arrived.length < checked.totalRecords
            ? [
                `${ch}: ${checked.totalRecords - arrived.length} of ${checked.totalRecords} events did not reach the view`,
              ]
            : [];

        const s = get();
        const merged = mergeRecordsPreservingSelection(
          s.records,
          s.selectedRecordId,
          result.records
        );
        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const newChannels = s.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const newLoaded = new Set(s.loadedChannels);
        newLoaded.add(ch);

        set({
          ...merged,
          channels: newChannels,
          loadedChannels: newLoaded,
          loadElapsedMs: performance.now() - startTime,
          coverageGaps: mergeCoverageGaps(clearChannelReadGaps(s.coverageGaps, ch), [
            ...checked.errorMessages,
            ...streamedGaps,
            ...shortfallGaps,
          ]),
        });
        acknowledgeStreamedRecords(ch, generation);
      } catch (e) {
        observeStreamReply(
          ch,
          generation,
          { kind: "error", message: e instanceof Error ? e.message : String(e) }
        );
        drainStreamedRecords(ch, generation);
        acknowledgeStreamedRecords(ch, generation);
        const message = e instanceof Error ? e.message : String(e);
        console.warn(`[evtx] Refresh failed for ${ch}: ${message}`);
        // Recorded, not only logged. The refresh cleared the previous gaps, so a silent failure
        // here presents a view that is missing a whole channel as complete.
        if (get().loadGeneration !== generation) return;
        set((s) => ({
          coverageGaps: mergeCoverageGaps(s.coverageGaps, [`${ch}: not read (${message})`]),
          loadError: s.loadError ?? `${ch}: ${message}`,
        }));
      }
    });
    await Promise.all(promises);
    if (get().loadGeneration !== generation) return;
    set({
      isLoading: false,
      loadingChannel: null,
      loadingProgress: null,
      loadElapsedMs: performance.now() - startTime,
    });
    if (refreshRequested) refreshBeforeLoad();
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
    invalidateAllStreamedRecords(loadGeneration);
    set({
      records: [],
      channels: [],
      sourceMode: null,
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
      quickFilter: { ...DEFAULT_QUICK_FILTER },
      timeWindow: "24h",
      coverageGaps: [],
      timeZoneMode: "local",
      columnConfig: defaultColumnConfig(),
      groupBy: [],
      collapsedGroups: new Set<string>(),
      sortField: "time",
      sortDirection: "asc",
      selectedRecordId: null,
    });
  },
});
});

// Listen for progress events from the Rust backend
listen<{ channel: string; requestId: number; fetched: number }>("evtx-query-progress", (event) => {
  const state = useEvtxStore.getState();
  if (event.payload.requestId !== state.loadGeneration) return;
  useEvtxStore.setState({
    loadingChannel: event.payload.channel,
    loadingProgress: event.payload.fetched,
  });
});
type StreamReply =
  | { kind: "success" }
  | { kind: "error"; message: string };

interface PendingStream {
  channel: string;
  requestId?: number;
  records: EvtxRecord[];
  sequences: Set<number>;
  terminal?: { sequenceCount: number; totalRecords: number };
  terminalSynthetic: boolean;
  reply?: StreamReply;
  consumerAcknowledged: boolean;
  settled: boolean;
  settling: boolean;
  terminalGraceTimer?: number;
  waiters: Array<() => void>;
}

/**
 * A request may query more than one channel, so channel alone is not a stream identity. Keeping
 * the request in the key also lets a late event from an older query be rejected after a refresh.
 */
const pendingBatches = new Map<string, PendingStream>();
const activeRequestIds = new Map<string, number>();

function streamKey(channel: string, requestId?: number): string {
  return `${requestId === undefined ? "legacy" : requestId}\u0000${channel}`;
}

function createPendingStream(channel: string, requestId?: number): PendingStream {
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

function pendingFor(channel: string, requestId?: number): PendingStream | undefined {
  if (requestId !== undefined) return pendingBatches.get(streamKey(channel, requestId));
  const activeRequestId = activeRequestIds.get(channel);
  if (activeRequestId === undefined) return pendingBatches.get(streamKey(channel));
  return pendingBatches.get(streamKey(channel, activeRequestId));
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

function observeStreamReply(channel: string, requestId: number, reply: StreamReply): void {
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

function waitForStreamReconciliation(channel: string, requestId: number): Promise<void> {
  const pending = pendingFor(channel, requestId);
  if (!pending || pending.requestId !== requestId || pending.settled) return Promise.resolve();
  return new Promise<void>((resolve) => pending.waiters.push(resolve));
}

function invalidateAllStreamedRecords(requestId: number): void {
  const channels = new Set([
    ...[...pendingBatches.values()].map((pending) => pending.channel),
    ...activeRequestIds.keys(),
  ]);
  for (const channel of channels) resetStreamedRecords([channel], requestId);
}

listen<{ channel: string; requestId?: number; sequence: number; records: EvtxRecord[] }>(
  "evtx-record-batch",
  (event) => {
    const { channel, requestId, sequence, records } = event.payload;
    const activeRequestId = activeRequestIds.get(channel);
    if (
      requestId !== undefined &&
      (activeRequestId === undefined || requestId !== activeRequestId)
    ) {
      return;
    }
    const pending =
      pendingFor(channel, requestId) ??
      (requestId === undefined ? createPendingStream(channel) : undefined);
    if (!pending || pending.consumerAcknowledged || pending.sequences.has(sequence)) return;

    pending.sequences.add(sequence);
    pending.records = appendUniqueRecords(pending.records, records);

    if (
      requestId !== undefined &&
      useEvtxStore.getState().loadGeneration !== requestId
    ) {
      return;
    }

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

listen<{ channel: string; requestId?: number; sequenceCount: number; totalRecords: number }>(
  "evtx-record-stream-complete",
  (event) => {
    const { channel, requestId, sequenceCount, totalRecords } = event.payload;
    const activeRequestId = activeRequestIds.get(channel);
    if (
      requestId !== undefined &&
      (activeRequestId === undefined || activeRequestId !== requestId)
    ) {
      return;
    }
    const pending = pendingFor(channel, requestId) ?? createPendingStream(channel, requestId);
    if (pending.consumerAcknowledged) return;
    pending.terminal = { sequenceCount, totalRecords };
    pending.terminalSynthetic = false;
    settlePendingStream(pending);
  }
);

/** Takes everything received for `channel` so far, and reports whether it is contiguous. */
export function drainStreamedRecords(channel: string, requestId?: number): {
  records: EvtxRecord[];
  missingSequences: number[];
} {
  const pending = pendingFor(channel, requestId);
  if (
    !pending ||
    (requestId !== undefined && pending.requestId !== undefined && pending.requestId !== requestId)
  ) {
    return { records: [], missingSequences: [] };
  }
  return { records: pending.records, missingSequences: sequenceNumbers(pending) };
}

/**
 * A load path calls this only after merging the drained snapshot. Until then events may still
 * arrive after the terminal marker and must remain available for exactly-once draining.
 */
export function acknowledgeStreamedRecords(channel: string, requestId?: number): void {
  const pending = pendingFor(channel, requestId);
  if (!pending) return;
  pending.consumerAcknowledged = true;
  clearTimeout(pending.terminalGraceTimer);
  pending.terminalGraceTimer = undefined;
  pending.waiters.length = 0;
  pendingBatches.delete(streamKey(channel, pending.requestId));
  if (pending.requestId !== undefined && activeRequestIds.get(channel) === pending.requestId) {
    activeRequestIds.delete(channel);
  }
}

/** Discards anything buffered for channels a query is about to start, and registers the request. */
export function resetStreamedRecords(channels: string[], requestId?: number): void {
  for (const channel of channels) {
    const activeRequestId = activeRequestIds.get(channel);
    if (activeRequestId !== undefined) pendingBatches.delete(streamKey(channel, activeRequestId));
    const legacy = pendingBatches.get(streamKey(channel));
    pendingBatches.delete(streamKey(channel, requestId));
    if (requestId !== undefined) {
      activeRequestIds.set(channel, requestId);
      if (legacy) {
        pendingBatches.delete(streamKey(channel));
        legacy.requestId = requestId;
        pendingBatches.set(streamKey(channel, requestId), legacy);
      } else {
        createPendingStream(channel, requestId);
      }
    } else {
      activeRequestIds.delete(channel);
      createPendingStream(channel);
    }
  }
}
