import { create } from "zustand";
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspRawEvidenceRecord,
  EspSessionUpdate,
} from "./types";

export type EspWorkspacePhase =
  "idle" | "analyzing" | "starting" | "live" | "stopping" | "ready" | "error";

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
  "graphDisabled" | "graphNotConnected" | "unsupportedPlatform";

export const ESP_EVIDENCE_DOCK_MIN_HEIGHT = 180;
export const ESP_EVIDENCE_DOCK_MAX_HEIGHT = 720;
export const ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT = 280;
export const ESP_EVIDENCE_DOCK_MAX_WORKSPACE_RATIO = 0.7;
export const ESP_EVIDENCE_BOUNDARY_MARKER_LIMIT = 64;
export const ESP_EVIDENCE_BOUNDARY_DELTA_LIMIT = 32;

export interface EspEvidenceBoundarySource {
  sourceArtifactId: string;
  filePath: string | null;
}

export type EspEvidenceBoundaryDeltaKind = "removed" | "added" | "changed";

export interface EspEvidenceBoundaryDelta {
  kind: EspEvidenceBoundaryDeltaKind;
  recordId: string;
  previous: EspEvidenceBoundarySource | null;
  incoming: EspEvidenceBoundarySource | null;
}

export interface EspEvidenceBoundaryMarker {
  markerId: string;
  kind: "sourceReset";
  emittedAtUtc: string;
  order: number;
  attribution: "unknown";
  observedDeltas: EspEvidenceBoundaryDelta[];
  omittedDeltaCount: number;
}

export interface EspEvidenceRecordRow {
  rowId: string;
  order: number;
}

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
  evidenceBoundaryMarkers: EspEvidenceBoundaryMarker[];
  evidenceRecordRows: Map<string, EspEvidenceRecordRow>;
  nextEvidenceOrder: number;
  beginAnalysis(requestId: string): void;
  rejectAnalysisInput(error: string): void;
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
  setEvidenceDockHeight(height: number, workspaceHeight?: number): void;
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

function identityChanged(
  current: EspDiagnosticsSnapshot | null,
  incoming: EspDiagnosticsSnapshot,
): boolean {
  return (
    current !== null &&
    getEspIdentityFingerprint(current) !== getEspIdentityFingerprint(incoming)
  );
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

function graphStateForFreshLocalRun(
  state: Pick<EspDiagnosticsStore, "graphPhase" | "graphUnavailableReason">,
): Pick<EspDiagnosticsStore, "graphPhase" | "graphUnavailableReason"> {
  if (state.graphPhase === "disabled" || state.graphPhase === "unavailable") {
    return {
      graphPhase: state.graphPhase,
      graphUnavailableReason: state.graphUnavailableReason,
    };
  }

  return {
    graphPhase: "idle",
    graphUnavailableReason: null,
  };
}

function recordsMatch(
  current: EspRawEvidenceRecord,
  incoming: EspRawEvidenceRecord,
): boolean {
  return JSON.stringify(current) === JSON.stringify(incoming);
}

function unreadEvidenceDelta(
  current: EspDiagnosticsSnapshot | null,
  incoming: EspDiagnosticsSnapshot,
  mode: EspEvidenceViewMode,
): number {
  if (mode !== "collapsed") {
    return 0;
  }

  const currentById = new Map(
    current?.rawEvidence.map((record) => [record.recordId, record]) ?? [],
  );
  let unread = 0;
  for (const incomingRecord of incoming.rawEvidence) {
    const currentRecord = currentById.get(incomingRecord.recordId);
    if (!currentRecord || !recordsMatch(currentRecord, incomingRecord)) {
      unread += 1;
    }
  }
  return unread;
}

function boundarySource(
  record: EspRawEvidenceRecord,
): EspEvidenceBoundarySource {
  return {
    sourceArtifactId: record.provenance.sourceArtifactId,
    filePath: record.provenance.filePath,
  };
}

function observedEvidenceDeltas(
  current: EspDiagnosticsSnapshot | null,
  incoming: EspDiagnosticsSnapshot,
): Pick<EspEvidenceBoundaryMarker, "observedDeltas" | "omittedDeltaCount"> {
  const currentById = new Map(
    current?.rawEvidence.map((record) => [record.recordId, record]) ?? [],
  );
  const incomingById = new Map(
    incoming.rawEvidence.map((record) => [record.recordId, record]),
  );
  const observedDeltas: EspEvidenceBoundaryDelta[] = [];
  let deltaCount = 0;
  const observe = (delta: EspEvidenceBoundaryDelta) => {
    deltaCount += 1;
    if (observedDeltas.length < ESP_EVIDENCE_BOUNDARY_DELTA_LIMIT) {
      observedDeltas.push(delta);
    }
  };

  for (const previous of current?.rawEvidence ?? []) {
    const replacement = incomingById.get(previous.recordId);
    if (!replacement) {
      observe({
        kind: "removed",
        recordId: previous.recordId,
        previous: boundarySource(previous),
        incoming: null,
      });
    } else if (!recordsMatch(previous, replacement)) {
      observe({
        kind: "changed",
        recordId: previous.recordId,
        previous: boundarySource(previous),
        incoming: boundarySource(replacement),
      });
    }
  }

  for (const added of incoming.rawEvidence) {
    if (!currentById.has(added.recordId)) {
      observe({
        kind: "added",
        recordId: added.recordId,
        previous: null,
        incoming: boundarySource(added),
      });
    }
  }

  return {
    observedDeltas,
    omittedDeltaCount: deltaCount - observedDeltas.length,
  };
}

function reconcileEvidenceRecordRows(
  current: EspDiagnosticsSnapshot | null,
  incoming: EspDiagnosticsSnapshot,
  currentRows: Map<string, EspEvidenceRecordRow>,
  firstAvailableOrder: number,
): {
  evidenceRecordRows: Map<string, EspEvidenceRecordRow>;
  nextEvidenceOrder: number;
} {
  const currentById = new Map(
    current?.rawEvidence.map((record) => [record.recordId, record]) ?? [],
  );
  const evidenceRecordRows = new Map<string, EspEvidenceRecordRow>();
  let nextEvidenceOrder = firstAvailableOrder;

  for (const incomingRecord of incoming.rawEvidence) {
    const currentRecord = currentById.get(incomingRecord.recordId);
    const currentRow = currentRows.get(incomingRecord.recordId);
    if (
      currentRecord &&
      currentRow &&
      recordsMatch(currentRecord, incomingRecord)
    ) {
      evidenceRecordRows.set(incomingRecord.recordId, currentRow);
      continue;
    }

    evidenceRecordRows.set(incomingRecord.recordId, {
      rowId: `evidence:${nextEvidenceOrder}:${incomingRecord.recordId}`,
      order: nextEvidenceOrder,
    });
    nextEvidenceOrder += 1;
  }

  return { evidenceRecordRows, nextEvidenceOrder };
}

function appendBoundaryMarker(
  markers: EspEvidenceBoundaryMarker[],
  current: EspDiagnosticsSnapshot | null,
  update: EspSessionUpdate,
  order: number,
): EspEvidenceBoundaryMarker[] {
  const marker: EspEvidenceBoundaryMarker = {
    markerId: `source-reset:${update.sessionId}:${update.sequence}`,
    kind: "sourceReset",
    emittedAtUtc: update.emittedAtUtc,
    order,
    attribution: "unknown",
    ...observedEvidenceDeltas(current, update.snapshot),
  };
  return [...markers, marker].slice(-ESP_EVIDENCE_BOUNDARY_MARKER_LIMIT);
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

export function getEspEvidenceDockMaxHeight(workspaceHeight?: number): number {
  if (workspaceHeight === undefined || !Number.isFinite(workspaceHeight)) {
    return ESP_EVIDENCE_DOCK_MAX_HEIGHT;
  }
  return Math.max(
    ESP_EVIDENCE_DOCK_MIN_HEIGHT,
    Math.min(
      ESP_EVIDENCE_DOCK_MAX_HEIGHT,
      Math.floor(
        Math.max(0, workspaceHeight) * ESP_EVIDENCE_DOCK_MAX_WORKSPACE_RATIO,
      ),
    ),
  );
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
  evidenceBoundaryMarkers: [],
  evidenceRecordRows: new Map(),
  nextEvidenceOrder: 0,

  beginAnalysis: (requestId) =>
    set((state) => ({
      phase: "analyzing",
      requestId,
      sessionId: null,
      sequence: 0,
      snapshot: null,
      error: null,
      graphRequestId: null,
      ...graphStateForFreshLocalRun(state),
      graphError: null,
      unreadEvidenceCount: 0,
      evidenceBoundaryMarkers: [],
      evidenceRecordRows: new Map(),
      nextEvidenceOrder: 0,
    })),

  rejectAnalysisInput: (error) =>
    set((state) => ({
      phase: state.snapshot ? "ready" : "error",
      error,
    })),

  beginLiveStart: (requestId) =>
    set((state) => ({
      phase: "starting",
      requestId,
      sessionId: null,
      sequence: 0,
      snapshot: null,
      error: null,
      graphRequestId: null,
      ...graphStateForFreshLocalRun(state),
      graphError: null,
      unreadEvidenceCount: 0,
      evidenceBoundaryMarkers: [],
      evidenceRecordRows: new Map(),
      nextEvidenceOrder: 0,
    })),

  beginStop: (sessionId) =>
    set((state) =>
      state.sessionId === sessionId ? { phase: "stopping" } : state,
    ),

  applyAnalysis: (requestId, snapshot) =>
    set((state) => {
      if (state.phase !== "analyzing" || state.requestId !== requestId) {
        return state;
      }

      const evidenceRows = reconcileEvidenceRecordRows(
        state.snapshot,
        snapshot,
        state.evidenceRecordRows,
        state.nextEvidenceOrder,
      );
      const graphIdentityState = identityChanged(state.snapshot, snapshot)
        ? {
            graphRequestId: null,
            ...graphStateForFreshLocalRun(state),
            graphError: null,
          }
        : {};

      return {
        phase: "ready",
        requestId: null,
        snapshot: withPreservedGraph(state.snapshot, snapshot),
        error: null,
        unreadEvidenceCount:
          state.unreadEvidenceCount +
          unreadEvidenceDelta(state.snapshot, snapshot, state.evidenceViewMode),
        ...graphIdentityState,
        ...evidenceRows,
      };
    }),

  applySessionUpdate: (update) =>
    set((state) => {
      const isInitialUpdate =
        state.phase === "starting" &&
        state.sessionId === null &&
        state.requestId === update.requestId;
      if (
        !isInitialUpdate &&
        (state.sessionId !== update.sessionId ||
          state.requestId !== update.requestId)
      ) {
        return state;
      }
      if (
        update.sequence < state.sequence ||
        (!isInitialUpdate && update.sequence === state.sequence)
      ) {
        return state;
      }

      const snapshot = withPreservedGraph(state.snapshot, update.snapshot);
      const graphIdentityState = identityChanged(
        state.snapshot,
        update.snapshot,
      )
        ? {
            graphRequestId: null,
            ...graphStateForFreshLocalRun(state),
            graphError: null,
          }
        : {};
      const isSourceReset = update.reason === "sourceReset";
      const boundaryOrder = state.nextEvidenceOrder;
      const evidenceRows = reconcileEvidenceRecordRows(
        state.snapshot,
        update.snapshot,
        state.evidenceRecordRows,
        isSourceReset ? boundaryOrder + 1 : boundaryOrder,
      );
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
        error: update.state === "error" ? "The live ESP session failed." : null,
        unreadEvidenceCount:
          state.unreadEvidenceCount +
          unreadEvidenceDelta(
            state.snapshot,
            update.snapshot,
            state.evidenceViewMode,
          ),
        ...graphIdentityState,
        ...evidenceRows,
        evidenceBoundaryMarkers: isSourceReset
          ? appendBoundaryMarker(
              state.evidenceBoundaryMarkers,
              state.snapshot,
              update,
              boundaryOrder,
            )
          : state.evidenceBoundaryMarkers,
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

  setEvidenceDockHeight: (height, workspaceHeight) =>
    set((state) => {
      if (!Number.isFinite(height)) {
        return state;
      }
      const evidenceDockHeight = Math.max(
        ESP_EVIDENCE_DOCK_MIN_HEIGHT,
        Math.min(
          getEspEvidenceDockMaxHeight(workspaceHeight),
          Math.round(height),
        ),
      );
      return evidenceDockHeight === state.evidenceDockHeight
        ? state
        : { evidenceDockHeight };
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
