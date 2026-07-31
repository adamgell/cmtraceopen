import { create } from "zustand";

import type {
  JamfConnectEvent,
  JamfEnvironment,
  JamfLogScanResult,
  JamfPolicyLogResult,
  JamfProfilesResult,
  JamfSelfServiceEvent,
  MacosJamfTabId,
} from "./types";

export type SliceStatus = "idle" | "loading" | "ok" | "error" | "notInstalled";

export interface Slice<T> {
  status: SliceStatus;
  data: T | null;
  error: string | null;
  lastLoadedAt: number | null;
}

const idleSlice = <T,>(): Slice<T> => ({
  status: "idle",
  data: null,
  error: null,
  lastLoadedAt: null,
});

interface JamfStoreState {
  activeTab: MacosJamfTabId;
  environment: Slice<JamfEnvironment>;
  policies: Slice<JamfPolicyLogResult>;
  profiles: Slice<JamfProfilesResult>;
  selfService: Slice<JamfSelfServiceEvent[]>;
  connect: Slice<JamfConnectEvent[]>;
  logs: Slice<JamfLogScanResult>;
}

interface JamfStoreActions {
  setActiveTab: (tab: MacosJamfTabId) => void;
  beginLoad: (slice: keyof Omit<JamfStoreState, "activeTab">) => void;
  finishLoad: <K extends keyof Omit<JamfStoreState, "activeTab">>(
    slice: K,
    data: NonNullable<JamfStoreState[K]["data"]>,
  ) => void;
  failLoad: (
    slice: keyof Omit<JamfStoreState, "activeTab">,
    error: string,
  ) => void;
  markNotInstalled: (slice: keyof Omit<JamfStoreState, "activeTab">) => void;
  reset: () => void;
}

const initialState: JamfStoreState = {
  activeTab: "overview",
  environment: idleSlice(),
  policies: idleSlice(),
  profiles: idleSlice(),
  selfService: idleSlice(),
  connect: idleSlice(),
  logs: idleSlice(),
};

export const useJamfStore = create<JamfStoreState & JamfStoreActions>((set) => ({
  ...initialState,
  setActiveTab: (activeTab) => set({ activeTab }),
  beginLoad: (slice) =>
    set((s) => ({
      [slice]: {
        ...(s[slice] as Slice<unknown>),
        status: "loading",
        error: null,
      },
    } as Partial<JamfStoreState>)),
  finishLoad: (slice, data) =>
    set(() => ({
      [slice]: {
        status: "ok",
        data,
        error: null,
        lastLoadedAt: Date.now(),
      },
    } as Partial<JamfStoreState>)),
  failLoad: (slice, error) =>
    set((s) => ({
      [slice]: {
        ...(s[slice] as Slice<unknown>),
        status: "error",
        error,
      },
    } as Partial<JamfStoreState>)),
  markNotInstalled: (slice) =>
    set(() => ({
      [slice]: {
        status: "notInstalled",
        data: null,
        error: null,
        lastLoadedAt: Date.now(),
      },
    } as Partial<JamfStoreState>)),
  reset: () => set(initialState),
}));
