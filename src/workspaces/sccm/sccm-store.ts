import { create } from "zustand";
import type {
  SccmAdvancedCaptureCapability,
  SccmCaptureResult,
  SccmEnvironmentDiscovery,
} from "./types";

export type SccmWorkspacePhase =
  | "idle"
  | "discovering"
  | "ready"
  | "capturing"
  | "authorizing"
  | "capturingAdvanced";

interface SccmState {
  phase: SccmWorkspacePhase;
  discovery: SccmEnvironmentDiscovery | null;
  capture: SccmCaptureResult | null;
  error: string | null;
  advancedCapability: SccmAdvancedCaptureCapability | null;
  beginDiscovery: () => void;
  completeDiscovery: (discovery: SccmEnvironmentDiscovery) => void;
  beginCapture: () => void;
  completeCapture: (capture: SccmCaptureResult) => void;
  beginAdvancedAuthorization: () => void;
  completeAdvancedAuthorization: (
    capability: SccmAdvancedCaptureCapability,
  ) => void;
  beginAdvancedCapture: () => void;
  clearAdvancedCapability: () => void;
  fail: (message: string) => void;
  reset: () => void;
}

const INITIAL_STATE = {
  phase: "idle" as const,
  discovery: null,
  capture: null,
  error: null,
  advancedCapability: null,
};

export const useSccmStore = create<SccmState>((set) => ({
  ...INITIAL_STATE,
  beginDiscovery: () => set({ phase: "discovering", error: null }),
  completeDiscovery: (discovery) =>
    set({ phase: "ready", discovery, capture: null, error: null }),
  beginCapture: () =>
    set((state) =>
      state.discovery?.supported && state.discovery.roles.length > 0
        ? { phase: "capturing", error: null }
        : state,
    ),
  completeCapture: (capture) =>
    set({
      phase: "ready",
      capture,
      error: null,
      advancedCapability: null,
    }),
  beginAdvancedAuthorization: () =>
    set((state) =>
      state.discovery?.supported
        ? { phase: "authorizing", error: null, advancedCapability: null }
        : state,
    ),
  completeAdvancedAuthorization: (advancedCapability) =>
    set({ phase: "ready", advancedCapability, error: null }),
  beginAdvancedCapture: () =>
    set((state) =>
      state.advancedCapability
        ? { phase: "capturingAdvanced", error: null }
        : state,
    ),
  clearAdvancedCapability: () =>
    set((state) => ({
      phase: state.discovery ? "ready" : "idle",
      advancedCapability: null,
    })),
  fail: (message) =>
    set((state) => ({
      phase: state.discovery ? "ready" : "idle",
      error: message,
      advancedCapability: null,
    })),
  reset: () => set(INITIAL_STATE),
}));
