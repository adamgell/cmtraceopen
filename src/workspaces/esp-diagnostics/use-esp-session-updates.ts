import { useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  graphCancelEspDiagnostics,
  graphFetchEspDiagnostics,
} from "../../lib/commands";
import { useUiStore } from "../../stores/ui-store";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspGraphRequest,
  EspSessionState,
  EspSessionUpdate,
  EspUpdateReason,
} from "./types";

export const ESP_SESSION_UPDATE_EVENT = "esp-diagnostics-session-update";

const SESSION_STATES = new Set<EspSessionState>([
  "starting",
  "live",
  "stopping",
  "stopped",
  "completed",
  "expired",
  "error",
]);
const UPDATE_REASONS = new Set<EspUpdateReason>([
  "initialSnapshot",
  "evidenceChanged",
  "sourceAttached",
  "sourceReset",
  "stopped",
  "expired",
  "error",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function isEspSessionUpdate(value: unknown): value is EspSessionUpdate {
  if (
    !isRecord(value) ||
    !isRecord(value.snapshot) ||
    !isRecord(value.snapshot.identity)
  ) {
    return false;
  }

  return (
    typeof value.sessionId === "string" &&
    value.sessionId.length > 0 &&
    typeof value.requestId === "string" &&
    value.requestId.length > 0 &&
    typeof value.sequence === "number" &&
    Number.isSafeInteger(value.sequence) &&
    value.sequence >= 0 &&
    typeof value.state === "string" &&
    SESSION_STATES.has(value.state as EspSessionState) &&
    typeof value.reason === "string" &&
    UPDATE_REASONS.has(value.reason as EspUpdateReason) &&
    typeof value.emittedAtUtc === "string" &&
    typeof value.snapshot.schemaVersion === "number" &&
    typeof value.snapshot.generatedAtUtc === "string" &&
    Array.isArray(value.snapshot.workloads) &&
    Array.isArray(value.snapshot.rawEvidence)
  );
}

function normalizeIdentityValue(value: string | null): string {
  return value?.trim().toLocaleLowerCase("en-US") ?? "";
}

export function getEspIdentityFingerprint(
  snapshot: EspDiagnosticsSnapshot,
): string {
  const identity = snapshot.identity;
  return JSON.stringify([
    normalizeIdentityValue(identity.managedDeviceId),
    normalizeIdentityValue(identity.entraDeviceId),
    normalizeIdentityValue(identity.serialNumber),
    normalizeIdentityValue(identity.hostName),
    normalizeIdentityValue(identity.tenantId),
    normalizeIdentityValue(identity.userPrincipalName),
  ]);
}

function createGraphRequest(
  snapshot: EspDiagnosticsSnapshot,
  requestId: string,
): EspGraphRequest {
  return {
    requestId,
    identity: snapshot.identity,
    workloadIds: Array.from(
      new Set(
        snapshot.workloads
          .map((workload) => workload.rawId ?? workload.id)
          .filter((id) => id.length > 0),
      ),
    ),
    selectedManagedDeviceId: null,
  };
}

function createRequestId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `esp-graph-${crypto.randomUUID()}`;
  }
  return `esp-graph-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export interface EspGraphCoordinatorDependencies {
  fetchGraph(request: EspGraphRequest): Promise<EspGraphOverlay>;
  cancelGraph(requestId: string): Promise<void>;
  createRequestId(): string;
}

export interface EspGraphCoordinator {
  reconcile(): Promise<void>;
  refresh(): Promise<void>;
  start(): void;
  dispose(): void;
}

export function createEspGraphCoordinator(
  dependencies: Partial<EspGraphCoordinatorDependencies> = {},
): EspGraphCoordinator {
  const fetchGraph = dependencies.fetchGraph ?? graphFetchEspDiagnostics;
  const cancelGraph = dependencies.cancelGraph ?? graphCancelEspDiagnostics;
  const nextRequestId = dependencies.createRequestId ?? createRequestId;
  let disposed = false;
  let started = false;
  let lastRequestedFingerprint: string | null = null;
  let blockedFingerprint: string | null = null;
  let unsubscribeEsp: (() => void) | null = null;
  let unsubscribeUi: (() => void) | null = null;

  const cancelCurrentRequest = (): Promise<void> | null => {
    const requestId = useEspDiagnosticsStore.getState().graphRequestId;
    if (!requestId) {
      return null;
    }

    return cancelGraph(requestId)
      .catch(() => {
        console.warn("[esp-diagnostics] native Graph cancellation failed", {
          requestId,
        });
      })
      .finally(() => {
        useEspDiagnosticsStore.getState().cancelGraph(requestId);
      });
  };

  const run = async (force: boolean) => {
    if (disposed) {
      return;
    }

    const snapshot = useEspDiagnosticsStore.getState().snapshot;
    if (!snapshot) {
      return;
    }

    const fingerprint = getEspIdentityFingerprint(snapshot);
    const { graphApiEnabled, graphApiStatus } = useUiStore.getState();

    if (!graphApiEnabled) {
      const cancellation = cancelCurrentRequest();
      if (cancellation) {
        await cancellation;
      }
      useEspDiagnosticsStore.getState().clearGraphOverlay();
      useEspDiagnosticsStore.getState().setGraphUnavailable("graphDisabled");
      blockedFingerprint = null;
      lastRequestedFingerprint = null;
      return;
    }

    if (graphApiStatus !== "connected") {
      const cancellation = cancelCurrentRequest();
      if (cancellation) {
        await cancellation;
      }
      useEspDiagnosticsStore.getState().clearGraphOverlay();
      useEspDiagnosticsStore.getState().setGraphUnavailable("graphNotConnected");
      blockedFingerprint = fingerprint;
      return;
    }

    if (!force) {
      if (
        blockedFingerprint === fingerprint ||
        lastRequestedFingerprint === fingerprint
      ) {
        return;
      }
    }

    const cancellation = cancelCurrentRequest();
    if (cancellation) {
      await cancellation;
    }
    if (disposed) {
      return;
    }

    blockedFingerprint = null;
    lastRequestedFingerprint = fingerprint;
    const requestId = nextRequestId();
    const request = createGraphRequest(snapshot, requestId);
    useEspDiagnosticsStore.getState().beginGraph(requestId);

    try {
      const overlay = await fetchGraph(request);
      if (!disposed) {
        useEspDiagnosticsStore
          .getState()
          .applyGraphOverlay(requestId, overlay);
      }
    } catch (error) {
      if (!disposed) {
        useEspDiagnosticsStore
          .getState()
          .failGraph(requestId, errorMessage(error));
      }
    }
  };

  return {
    reconcile: () => run(false),
    refresh: () => run(true),
    start: () => {
      if (started || disposed) {
        return;
      }
      started = true;
      unsubscribeEsp = useEspDiagnosticsStore.subscribe((state, previous) => {
        if (state.snapshot !== previous.snapshot) {
          void run(false);
        }
      });
      unsubscribeUi = useUiStore.subscribe((state, previous) => {
        if (
          state.graphApiEnabled !== previous.graphApiEnabled ||
          state.graphApiStatus !== previous.graphApiStatus
        ) {
          void run(false);
        }
      });
      void run(false);
    },
    dispose: () => {
      disposed = true;
      unsubscribeEsp?.();
      unsubscribeUi?.();
      unsubscribeEsp = null;
      unsubscribeUi = null;
    },
  };
}

let globalGraphCoordinator: EspGraphCoordinator | null = null;

export async function refreshEspGraphData(): Promise<void> {
  await globalGraphCoordinator?.refresh();
}

export function useEspSessionUpdates(): void {
  useEffect(() => {
    let disposed = false;
    let unlisten: UnlistenFn | null = null;
    let stopWaitingForHydration: (() => void) | null = null;

    const attach = () => {
      if (disposed || unlisten) {
        return;
      }

      globalGraphCoordinator = createEspGraphCoordinator();
      globalGraphCoordinator.start();

      void listen<unknown>(ESP_SESSION_UPDATE_EVENT, (event) => {
        if (isEspSessionUpdate(event.payload)) {
          useEspDiagnosticsStore.getState().applySessionUpdate(event.payload);
        }
      }).then((disposeListener) => {
        if (disposed) {
          disposeListener();
        } else {
          unlisten = disposeListener;
        }
      });
    };

    if (useUiStore.persist.hasHydrated()) {
      attach();
    } else {
      stopWaitingForHydration = useUiStore.persist.onFinishHydration(attach);
    }

    return () => {
      disposed = true;
      stopWaitingForHydration?.();
      unlisten?.();
      globalGraphCoordinator?.dispose();
      globalGraphCoordinator = null;
    };
  }, []);
}
