import { create } from "zustand";
import type { SccmCaptureResult, SccmEnvironmentDiscovery } from "./types";

export type SccmWorkspacePhase =
  | "idle"
  | "discovering"
  | "ready"
  | "capturing";

interface SccmState {
  phase: SccmWorkspacePhase;
  discovery: SccmEnvironmentDiscovery | null;
  capture: SccmCaptureResult | null;
  error: string | null;
  beginDiscovery: () => void;
  completeDiscovery: (discovery: SccmEnvironmentDiscovery) => void;
  beginCapture: () => void;
  completeCapture: (capture: SccmCaptureResult) => void;
  fail: (message: string) => void;
  reset: () => void;
}

const INITIAL_STATE = {
  phase: "idle" as const,
  discovery: null,
  capture: null,
  error: null,
};

export const useSccmStore = create<SccmState>((set) => ({
  ...INITIAL_STATE,
  beginDiscovery: () => set({ phase: "discovering", error: null }),
  completeDiscovery: (discovery) =>
    set({ phase: "ready", discovery, capture: null, error: null }),
  beginCapture: () => set({ phase: "capturing", error: null }),
  completeCapture: (capture) => set({ phase: "ready", capture, error: null }),
  fail: (message) =>
    set((state) => ({
      phase: state.discovery ? "ready" : "idle",
      error: message,
    })),
  reset: () => set(INITIAL_STATE),
}));
