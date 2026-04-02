import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
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
  loadError: string | null;
  selectedChannels: Set<string>;
  filterLevels: Set<EvtxLevel>;
  filterEventIds: string;
  filterSearch: string;
  sortField: EvtxSortField;
  sortDirection: EvtxSortDirection;
  selectedRecordId: number | null;

  parseFiles: (paths: string[]) => Promise<void>;
  enumerateChannels: () => Promise<void>;
  queryChannels: (channels: string[], maxEvents?: number) => Promise<void>;
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
  loadError: null,
  selectedChannels: new Set<string>(),
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
      const channels = await invoke<EvtxChannelInfo[]>("evtx_enumerate_channels");
      const channelNames = new Set(channels.map((c) => c.name));
      set({
        channels,
        sourceMode: "live",
        isLoading: false,
        loadError: null,
        selectedChannels: channelNames,
        records: [],
        selectedRecordId: null,
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
      set(applyParseResult(result, "live"));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      set({ isLoading: false, loadError: message });
    }
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
      filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
      filterEventIds: "",
      filterSearch: "",
      sortField: "time",
      sortDirection: "asc",
      selectedRecordId: null,
    }),
}));
