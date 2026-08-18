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
        const merged = appendUniqueRecords(state.records, result.records);
        merged.sort(compareStoredRecords);
        for (let i = 0; i < merged.length; i++) merged[i].id = i;

        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const newChannels = state.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const newLoaded = new Set(state.loadedChannels);
        newLoaded.add(ch);

        set({
          records: merged,
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
        if (get().loadGeneration !== generation) return;
        try {
          resetStreamedRecords([ch], generation);
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
          if (get().loadGeneration !== generation) return;
          const checked = assertParseResultShape(result);
          const streamed = drainStreamedRecords(ch, generation);
          const arrived = [...streamed.records, ...result.records];
          const streamedGaps =
            streamed.missingSequences.length > 0
              ? [`${ch}: ${streamed.missingSequences.length} batches of events were not received`]
              : [];
          const shortfallGaps =
            typeof checked.totalRecords === "number" &&
            arrived.length < checked.totalRecords
              ? [
                  `${ch}: ${checked.totalRecords - arrived.length} of ${checked.totalRecords} events did not reach the view`,
                ]
              : [];
          mergeResult(
            ch,
            { ...result, records: arrived },
            [...checked.errorMessages, ...streamedGaps, ...shortfallGaps]
          );
        } catch (e) {
          if (get().loadGeneration !== generation) return;
          const msg = e instanceof Error ? e.message : String(e);
          console.warn(`[evtx] Failed to query ${ch}: ${msg}`);
          drainStreamedRecords(ch, generation);
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
      selectedRecordId: null,
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
    resetStreamedRecords(channels, generation);

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
          return { channel: ch, result, error: null as string | null };
        } catch (e) {
          const message = e instanceof Error ? e.message : String(e);
          console.warn(`[evtx] Failed to query ${ch}: ${message}`);
          if (!loadError) loadError = `${ch}: ${message}`;
          return { channel: ch, result: null, error: message };
        }
      })
    );
    if (get().loadGeneration !== generation) return;

    for (const { channel, result, error } of results) {
      if (get().loadGeneration !== generation) return;
      try {
        if (!result) {
          drainStreamedRecords(channel, generation);
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

        const checked = assertParseResultShape(result);

        // The records travel as batches while the query runs; the reply carries only whatever the
        // backend did not stream. Both are taken, so this works whether or not streaming happened.
        const streamed = drainStreamedRecords(channel, generation);
        const arrived = [...streamed.records, ...result.records];

        // The reply says how many records were sent. Silence is not agreement: if fewer arrived, or a
        // batch number is missing from the run, those events are absent from the view and must be
        // said so rather than left to look like events that never happened.
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
        // Streamed records are already published; the reply carries only its unstreamed tail.
        // Merge the reply directly so a channel with both sources does not lose that tail.
        const merged = appendUniqueRecords(state.records, result.records);
        merged.sort(compareStoredRecords);
        // Reassign IDs
        for (let i = 0; i < merged.length; i++) merged[i].id = i;

        // Update channel event counts
        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const updatedChannels = state.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));

        const newLoaded = new Set(state.loadedChannels);
        newLoaded.add(channel);

        set({
          records: merged,
          channels: updatedChannels,
          loadedChannels: newLoaded,
          // Accumulated, not dropped. This path loads channels incrementally, so discarding what the
          // backend reported here would show a complete view of a partly unreadable set.
          coverageGaps: mergeCoverageGaps(state.coverageGaps, [
            ...checked.errorMessages,
            ...gapsFound,
          ]),
        });
      } catch (processingError) {
        drainStreamedRecords(channel, generation);
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

    // Refresh invokes the streaming command directly, so drain its batch before merging the
    // command reply (which intentionally carries only records not emitted in batches).
    const promises = loaded.map(async (ch) => {
      try {
        resetStreamedRecords([ch], generation);
        const result = await invoke<EvtxParseResult>("evtx_query_channels", {
          channels: [ch],
          maxEvents: hasInvalidEventIdFilter(get().filterEventIds) ? 0 : null,
          requestId: generation,
          // The window is a server-side predicate and a refetch is the only thing that applies it.
          // Omitting it here made the time-window control a no-op: selecting 1h triggered this
          // refresh, which then fetched the channel unbounded and replaced the view with events
          // outside the window the toolbar was still showing as selected.
          filter: buildServerFilter(
            get().timeWindow,
            get().filterEventIds,
            get().filterLevels
          ),
        });
        if (get().loadGeneration !== generation) return;
        const checked = assertParseResultShape(result);
        const streamed = drainStreamedRecords(ch, generation);
        const arrived = [...streamed.records, ...result.records];
        const streamedGaps =
          streamed.missingSequences.length > 0
            ? [`${ch}: ${streamed.missingSequences.length} batches of events were not received`]
            : [];
        const shortfallGaps =
          typeof checked.totalRecords === "number" &&
          arrived.length < checked.totalRecords
            ? [
                `${ch}: ${checked.totalRecords - arrived.length} of ${checked.totalRecords} events did not reach the view`,
              ]
            : [];

        const s = get();
        const merged = appendUniqueRecords(s.records, arrived);
        merged.sort(compareStoredRecords);
        for (let i = 0; i < merged.length; i++) merged[i].id = i;

        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const newChannels = s.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const newLoaded = new Set(s.loadedChannels);
        newLoaded.add(ch);

        set({
          records: merged,
          channels: newChannels,
          loadedChannels: newLoaded,
          loadElapsedMs: performance.now() - startTime,
          coverageGaps: mergeCoverageGaps(s.coverageGaps, [
            ...checked.errorMessages,
            ...streamedGaps,
            ...shortfallGaps,
          ]),
        });
      } catch (e) {
        drainStreamedRecords(ch, generation);
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

/**
 * Records arriving in batches while a query is still running.
 *
 * A channel can be most of a scan on its own: Security measured 286,401 of 404,769 events and 191.8
 * seconds of 267, so waiting for the reply meant three minutes of empty list. Batches are collected
 * here as they arrive and drained by the query that asked for them.
 *
 * Keyed by channel, and the sequence numbers are kept rather than discarded. An event channel makes
 * no delivery promise, so the query checks both the count and the sequence run before treating a
 * channel as complete. A batch that never arrived would otherwise be indistinguishable from events
 * that do not exist, which is the failure this workspace exists to avoid.
 */
const pendingBatches = new Map<
  string,
  { requestId?: number; records: EvtxRecord[]; sequences: Set<number> }
>();
const activeRequestIds = new Map<string, number>();
function invalidateAllStreamedRecords(requestId: number): void {
  const channels = new Set([...pendingBatches.keys(), ...activeRequestIds.keys()]);
  resetStreamedRecords([...channels], requestId);
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
    let pending = pendingBatches.get(channel);
    if (!pending || pending.requestId !== requestId) {
      pending = { requestId, records: [], sequences: new Set<number>() };
      pendingBatches.set(channel, pending);
    }
    if (pending.sequences.has(sequence)) return;
    useEvtxStore.setState((state) => {
      if (requestId !== undefined && state.loadGeneration !== requestId) return state;
      const merged = appendUniqueRecords(state.records, records);
      merged.sort(compareStoredRecords);
      for (let i = 0; i < merged.length; i++) merged[i].id = i;
      return { records: merged };
    });
    pending.sequences.add(sequence);
    pending.records.push(...records);
  }
);

/** Takes everything received for `channel` so far, and reports whether it is contiguous. */
export function drainStreamedRecords(channel: string, requestId?: number): {
  records: EvtxRecord[];
  missingSequences: number[];
} {
  const pending = pendingBatches.get(channel);
  if (
    !pending ||
    (requestId !== undefined && pending.requestId !== undefined && pending.requestId !== requestId)
  ) {
    return { records: [], missingSequences: [] };
  }
  pendingBatches.delete(channel);
  if (requestId !== undefined && activeRequestIds.get(channel) === requestId) {
    activeRequestIds.delete(channel);
  }
  let highest = 0;
  for (const sequence of pending.sequences) {
    if (sequence > highest) highest = sequence;
  }
  const missingSequences: number[] = [];
  for (let i = 0; i < highest; i++) {
    if (!pending.sequences.has(i)) missingSequences.push(i);
  }
  return { records: pending.records, missingSequences };
}

/** Discards anything buffered for channels a query is about to start. */
export function resetStreamedRecords(channels: string[], requestId?: number) {
  for (const channel of channels) {
    pendingBatches.delete(channel);
    if (requestId !== undefined) activeRequestIds.set(channel, requestId);
  }
}
