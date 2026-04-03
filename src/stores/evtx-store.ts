import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  EvtxRecord,
  EvtxChannelInfo,
  EvtxLevel,
  EvtxParseResult,
} from "../types/event-log-workspace";

export type EvtxSourceMode = "files" | "live" | null;
export type EvtxSortField = "time" | "eventId" | "level" | "provider" | "channel";
export type EvtxSortDirection = "asc" | "desc";

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
  selectedChannels: Set<string>;
  loadedChannels: Set<string>;
  filterLevels: Set<EvtxLevel>;
  filterEventIds: string;
  filterSearch: string;
  sortField: EvtxSortField;
  sortDirection: EvtxSortDirection;
  selectedRecordId: number | null;

  parseFiles: (paths: string[]) => Promise<void>;
  enumerateChannels: () => Promise<void>;
  queryChannels: (channels: string[], maxEvents?: number) => Promise<void>;
  loadSelectedChannels: () => Promise<void>;
  refreshLoadedChannels: () => Promise<void>;
  setSelectedChannels: (channels: Set<string>) => void;
  toggleChannel: (channel: string) => void;
  selectAllChannels: () => void;
  deselectAllChannels: () => void;
  setFilterLevels: (levels: Set<EvtxLevel>) => void;
  toggleFilterLevel: (level: EvtxLevel) => void;
  setFilterEventIds: (eventIds: string) => void;
  setFilterSearch: (search: string) => void;
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
    selectedChannels: channelNames,
    selectedRecordId: null,
  };
}

export const useEvtxStore = create<EvtxState>()((set, get) => ({
  records: [],
  channels: [],
  sourceMode: null,
  isLoading: false,
  loadingChannel: null,
  loadingProgress: null,
  loadStartTime: null,
  loadElapsedMs: null,
  loadError: null,
  selectedChannels: new Set<string>(),
  loadedChannels: new Set<string>(),
  filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
  filterEventIds: "",
  filterSearch: "",
  sortField: "time",
  sortDirection: "asc",
  selectedRecordId: null,

  parseFiles: async (paths) => {
    set({ isLoading: true, loadError: null });
    try {
      const result = await invoke<EvtxParseResult>("evtx_parse_files", { paths });
      set(applyParseResult(result, "files"));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message });
    }
  },

  enumerateChannels: async () => {
    set({ isLoading: true, loadError: null });
    try {
      // Step 1: Enumerate all channels
      const channels = await invoke<EvtxChannelInfo[]>("evtx_enumerate_channels");

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
        loadStartTime: startTime,
        loadElapsedMs: null,
        selectedChannels: selectedNames,
        loadedChannels: new Set<string>(),
        records: [],
        selectedRecordId: null,
      });

      // Query all core channels in parallel (bypass queryChannels to avoid isLoading conflicts)
      const mergeResult = (ch: string, result: EvtxParseResult) => {
        console.log(`[evtx] ${ch}: got ${result.records.length} records, ${result.parseErrors} errors`, result.errorMessages);
        const state = get();
        const merged = [...state.records, ...result.records];
        merged.sort((a, b) => a.timestampEpoch - b.timestampEpoch);
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
        });
      };

      const promises = availableCore.map(async (ch) => {
        try {
          const result = await invoke<EvtxParseResult>("evtx_query_channels", {
            channels: [ch],
            maxEvents: null,
          });
          mergeResult(ch, result);
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          console.warn(`[evtx] Failed to query ${ch}: ${msg}`);
          if (!loadError) loadError = `${ch}: ${msg}`;
        }
      });

      await Promise.all(promises);

      set({
        isLoading: false,
        loadingChannel: null,
        loadingProgress: null,
        loadElapsedMs: performance.now() - startTime,
        loadError,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message });
    }
  },

  queryChannels: async (channels, maxEvents) => {
    set({ isLoading: true, loadError: null });
    try {
      const result = await invoke<EvtxParseResult>("evtx_query_channels", {
        channels,
        maxEvents: maxEvents ?? null,
      });

      // Merge new records with existing ones (for incremental channel loading)
      const state = get();
      const existingChannelNames = new Set(state.records.map((r) => r.channel));
      // Only add records from channels we don't already have
      const newRecords = result.records.filter((r) => !existingChannelNames.has(r.channel));
      const merged = [...state.records, ...newRecords];
      merged.sort((a, b) => a.timestampEpoch - b.timestampEpoch);
      // Reassign IDs
      for (let i = 0; i < merged.length; i++) merged[i].id = i;

      // Update channel event counts
      const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
      const updatedChannels = state.channels.map((c) => ({
        ...c,
        eventCount: countMap.get(c.name) ?? c.eventCount,
      }));

      const newLoaded = new Set(state.loadedChannels);
      for (const ch of channels) newLoaded.add(ch);

      set({
        records: merged,
        channels: updatedChannels,
        loadedChannels: newLoaded,
        isLoading: false,
        loadError: null,
        selectedRecordId: null,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message });
    }
  },

  loadSelectedChannels: async () => {
    const state = get();
    const unloaded = [...state.selectedChannels].filter(
      (ch) => !state.loadedChannels.has(ch)
    );
    if (unloaded.length === 0) return;
    await get().queryChannels(unloaded);
  },

  refreshLoadedChannels: async () => {
    const state = get();
    const loaded = [...state.loadedChannels];
    if (loaded.length === 0) return;
    const startTime = performance.now();
    set({
      records: [],
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      isLoading: true,
      loadStartTime: startTime,
      loadElapsedMs: null,
    });

    const promises = loaded.map(async (ch) => {
      try {
        const result = await invoke<EvtxParseResult>("evtx_query_channels", {
          channels: [ch],
          maxEvents: null,
        });

        const s = get();
        const merged = [...s.records, ...result.records];
        merged.sort((a, b) => a.timestampEpoch - b.timestampEpoch);
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
        });
      } catch (e) {
        console.warn(`[evtx] Refresh failed for ${ch}:`, e);
      }
    });

    await Promise.all(promises);
    set({
      isLoading: false,
      loadingChannel: null,
      loadingProgress: null,
      loadElapsedMs: performance.now() - startTime,
    });
  },

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

  setFilterLevels: (levels) => set({ filterLevels: levels }),

  toggleFilterLevel: (level) => {
    const current = get().filterLevels;
    const next = new Set(current);
    if (next.has(level)) {
      next.delete(level);
    } else {
      next.add(level);
    }
    set({ filterLevels: next });
  },

  setFilterEventIds: (eventIds) => set({ filterEventIds: eventIds }),
  setFilterSearch: (search) => set({ filterSearch: search }),
  setSortField: (field) => set({ sortField: field }),
  setSortDirection: (direction) => set({ sortDirection: direction }),
  setSelectedRecordId: (id) => set({ selectedRecordId: id }),

  reset: () =>
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
      filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
      filterEventIds: "",
      filterSearch: "",
      sortField: "time",
      sortDirection: "asc",
      selectedRecordId: null,
    }),
}));

// Listen for progress events from the Rust backend
listen<{ channel: string; fetched: number }>("evtx-query-progress", (event) => {
  useEvtxStore.setState({
    loadingChannel: event.payload.channel,
    loadingProgress: event.payload.fetched,
  });
});
