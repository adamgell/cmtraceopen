import { create } from "zustand";
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspSessionUpdate,
} from "./types";

export type EspWorkspacePhase =
  | "idle"
  | "analyzing"
  | "starting"
  | "live"
  | "stopping"
  | "ready"
  | "error";

export type EspEvidenceViewMode = "collapsed" | "docked" | "full";
export type EspGraphPhase =
  | "disabled"
  | "unavailable"
  | "idle"
  | "loading"
  | "ready"
  | "partial"
  | "error"
  | "cancelled";
export type EspGraphUnavailableReason =
  | "graphDisabled"
  | "graphNotConnected"
  | "unsupportedPlatform";

export const ESP_EVIDENCE_DOCK_MIN_HEIGHT = 180;
export const ESP_EVIDENCE_DOCK_MAX_HEIGHT = 720;
export const ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT = 280;

export interface EspDiagnosticsStore {
  phase: EspWorkspacePhase;
  requestId: string | null;
  sessionId: string | null;
  sequence: number;
  snapshot: EspDiagnosticsSnapshot | null;
  error: string | null;
  graphRequestId: string | null;
  graphPhase: EspGraphPhase;
  graphUnavailableReason: EspGraphUnavailableReason | null;
  graphError: string | null;
  evidenceViewMode: EspEvidenceViewMode;
  evidenceDockHeight: number;
  unreadEvidenceCount: number;
  beginAnalysis(requestId: string): void;
  beginLiveStart(requestId: string): void;
  beginStop(sessionId: string): void;
  applyAnalysis(requestId: string, snapshot: EspDiagnosticsSnapshot): void;
  applySessionUpdate(update: EspSessionUpdate): void;
  fail(requestId: string, error: string): void;
  beginGraph(requestId: string): void;
  applyGraphOverlay(requestId: string, overlay: EspGraphOverlay): void;
  failGraph(requestId: string, error: string): void;
  setGraphUnavailable(reason: EspGraphUnavailableReason): void;
  cancelGraph(requestId: string): void;
  clearGraphOverlay(): void;
  setEvidenceViewMode(mode: EspEvidenceViewMode): void;
  setEvidenceDockHeight(height: number): void;
  markEvidenceRead(): void;
  clearStoppedSession(sessionId: string): void;
}

function normalizeIdentityValue(value: string | null): string {
  return value?.trim().toLocaleLowerCase("en-US") ?? "";
}

export function getEspIdentityFingerprint(
  snapshot: EspDiagnosticsSnapshot,
): string {
  const identity = snapshot.identity;
  return JSON.stringify([
    normalizeIdentityValue(identity.deviceName),
    normalizeIdentityValue(identity.managedDeviceId),
    normalizeIdentityValue(identity.entraDeviceId),
    normalizeIdentityValue(identity.entdmId?.value ?? null),
    normalizeIdentityValue(identity.tenantId?.value ?? null),
    normalizeIdentityValue(identity.tenantDomain?.value ?? null),
    normalizeIdentityValue(identity.userPrincipalName?.value ?? null),
    normalizeIdentityValue(identity.serialNumber?.value ?? null),
  ]);
}

function withPreservedGraph(
  current: EspDiagnosticsSnapshot | null,
  incoming: EspDiagnosticsSnapshot,
): EspDiagnosticsSnapshot {
  if (
    !current ||
    getEspIdentityFingerprint(current) !== getEspIdentityFingerprint(incoming)
  ) {
    return incoming;
  }

  return {
    ...incoming,
    graph: incoming.graph ?? current.graph,
  };
}

function graphOverlayIsPartial(overlay: EspGraphOverlay): boolean {
  return [
    overlay.deviceMatch,
    overlay.autopilotIdentity,
    overlay.deploymentProfile,
    overlay.intendedDeploymentProfile,
    overlay.profileAssignments,
    overlay.autopilotEvents,
    overlay.enrollmentConfiguration,
    overlay.apps,
    overlay.policies,
    overlay.scripts,
  ].some((section) =>
    ["permissionDenied", "failed", "cancelled"].includes(section.status),
  );
}

function unreadEvidenceDelta(
  current: EspDiagnosticsSnapshot | null,
  incoming: EspDiagnosticsSnapshot,
  mode: EspEvidenceViewMode,
): number {
  if (mode !== "collapsed") {
    return 0;
  }

  return Math.max(
    0,
    incoming.rawEvidence.length - (current?.rawEvidence.length ?? 0),
  );
}

function phaseForSessionUpdate(update: EspSessionUpdate): EspWorkspacePhase {
  switch (update.state) {
    case "starting":
      return "starting";
    case "live":
      return "live";
    case "stopping":
      return "stopping";
    case "stopped":
    case "completed":
    case "expired":
      return "ready";
    case "error":
      return "error";
  }
}

export const useEspDiagnosticsStore = create<EspDiagnosticsStore>((set) => ({
  phase: "idle",
  requestId: null,
  sessionId: null,
  sequence: 0,
  snapshot: null,
  error: null,
  graphRequestId: null,
  graphPhase: "disabled",
  graphUnavailableReason: "graphDisabled",
  graphError: null,
  evidenceViewMode: "collapsed",
  evidenceDockHeight: ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT,
  unreadEvidenceCount: 0,

  beginAnalysis: (requestId) =>
    set({
      phase: "analyzing",
      requestId,
      sessionId: null,
      sequence: 0,
      snapshot: null,
      error: null,
      graphRequestId: null,
      graphPhase: "idle",
      graphUnavailableReason: null,
      graphError: null,
      unreadEvidenceCount: 0,
    }),

  beginLiveStart: (requestId) =>
    set({
      phase: "starting",
      requestId,
      sessionId: null,
      sequence: 0,
      snapshot: null,
      error: null,
      graphRequestId: null,
      graphPhase: "idle",
      graphUnavailableReason: null,
      graphError: null,
      unreadEvidenceCount: 0,
    }),

  beginStop: (sessionId) =>
    set((state) =>
      state.sessionId === sessionId ? { phase: "stopping" } : state,
    ),

  applyAnalysis: (requestId, snapshot) =>
    set((state) => {
      if (state.phase !== "analyzing" || state.requestId !== requestId) {
        return state;
      }

      return {
        phase: "ready",
        requestId: null,
        snapshot: withPreservedGraph(state.snapshot, snapshot),
        error: null,
        unreadEvidenceCount:
          state.unreadEvidenceCount +
          unreadEvidenceDelta(state.snapshot, snapshot, state.evidenceViewMode),
      };
    }),

  applySessionUpdate: (update) =>
    set((state) => {
      const isInitialUpdate =
        state.phase === "starting" &&
        state.sessionId === null &&
        state.requestId === update.requestId;
      if (!isInitialUpdate && state.sessionId !== update.sessionId) {
        return state;
      }
      if (
        update.sequence < state.sequence ||
        (!isInitialUpdate && update.sequence === state.sequence)
      ) {
        return state;
      }

      const snapshot = withPreservedGraph(state.snapshot, update.snapshot);
      return {
        phase: phaseForSessionUpdate(update),
        requestId: update.requestId,
        sessionId:
          update.state === "stopped" ||
          update.state === "completed" ||
          update.state === "expired"
            ? null
            : update.sessionId,
        sequence: update.sequence,
        snapshot,
        error:
          update.state === "error" ? "The live ESP session failed." : null,
        unreadEvidenceCount:
          state.unreadEvidenceCount +
          unreadEvidenceDelta(
            state.snapshot,
            update.snapshot,
            state.evidenceViewMode,
          ),
      };
    }),

  fail: (requestId, error) =>
    set((state) => {
      if (state.requestId !== requestId) {
        return state;
      }
      return {
        phase: "error",
        requestId: null,
        error,
      };
    }),

  beginGraph: (requestId) =>
    set({
      graphRequestId: requestId,
      graphPhase: "loading",
      graphUnavailableReason: null,
      graphError: null,
    }),

  applyGraphOverlay: (requestId, overlay) =>
    set((state) => {
      if (state.graphRequestId !== requestId || !state.snapshot) {
        return state;
      }
      return {
        graphRequestId: null,
        graphPhase: graphOverlayIsPartial(overlay) ? "partial" : "ready",
        graphUnavailableReason: null,
        graphError: null,
        snapshot: {
          ...state.snapshot,
          graph: overlay,
        },
      };
    }),

  failGraph: (requestId, error) =>
    set((state) =>
      state.graphRequestId === requestId
        ? {
            graphRequestId: null,
            graphPhase: "error",
            graphError: error,
          }
        : state,
    ),

  setGraphUnavailable: (reason) =>
    set({
      graphRequestId: null,
      graphPhase: reason === "graphDisabled" ? "disabled" : "unavailable",
      graphUnavailableReason: reason,
      graphError: null,
    }),

  cancelGraph: (requestId) =>
    set((state) =>
      state.graphRequestId === requestId
        ? {
            graphRequestId: null,
            graphPhase: "cancelled",
            graphError: null,
          }
        : state,
    ),

  clearGraphOverlay: () =>
    set((state) => {
      if (!state.snapshot?.graph) {
        return state;
      }
      return {
        snapshot: {
          ...state.snapshot,
          graph: null,
        },
      };
    }),

  setEvidenceViewMode: (evidenceViewMode) => set({ evidenceViewMode }),

  setEvidenceDockHeight: (height) =>
    set({
      evidenceDockHeight: Math.max(
        ESP_EVIDENCE_DOCK_MIN_HEIGHT,
        Math.min(ESP_EVIDENCE_DOCK_MAX_HEIGHT, Math.round(height)),
      ),
    }),

  markEvidenceRead: () => set({ unreadEvidenceCount: 0 }),

  clearStoppedSession: (sessionId) =>
    set((state) => {
      if (state.sessionId !== sessionId) {
        return state;
      }
      return {
        phase: state.snapshot ? "ready" : "idle",
        requestId: null,
        sessionId: null,
        sequence: 0,
        error: null,
      };
    }),
}));
