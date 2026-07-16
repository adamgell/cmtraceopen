import { useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  graphCancelEspDiagnostics,
  graphFetchEspDiagnostics,
} from "../../lib/commands";
import { useUiStore } from "../../stores/ui-store";
import {
  getEspIdentityFingerprint,
  useEspDiagnosticsStore,
} from "./esp-diagnostics-store";
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspGraphRequest,
  EspSessionState,
  EspSessionUpdate,
  EspUpdateReason,
} from "./types";

export const ESP_SESSION_UPDATE_EVENT = "esp-diagnostics-session-update";
export { getEspIdentityFingerprint } from "./esp-diagnostics-store";

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

function isSessionWorkload(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.workloadId === "string" &&
    typeof value.rawIdentifier === "string"
  );
}

function isSessionRawEvidence(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.recordId === "string" &&
    isRecord(value.provenance) &&
    typeof value.provenance.sourceArtifactId === "string"
  );
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
    value.snapshot.workloads.every(isSessionWorkload) &&
    Array.isArray(value.snapshot.rawEvidence) &&
    value.snapshot.rawEvidence.every(isSessionRawEvidence)
  );
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
          .map((workload) => workload.rawIdentifier || workload.workloadId)
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
  let pendingOrphanCancellation: Promise<void> | null = null;
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

  const cancelOrphanedRequest = (requestId: string): void => {
    const cancellation = cancelGraph(requestId).catch(() => {
      console.warn("[esp-diagnostics] orphan Graph cancel failed", {
        requestId,
      });
    });
    pendingOrphanCancellation = cancellation;
    void cancellation.then(() => {
      if (pendingOrphanCancellation === cancellation) {
        pendingOrphanCancellation = null;
      }
    });
  };

  const run = async (force: boolean) => {
    if (disposed) {
      return;
    }

    const orphanCancellation = pendingOrphanCancellation;
    if (orphanCancellation) {
      await orphanCancellation;
    }
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

    // Claim the fingerprint before any await so concurrent invocations see
    // it immediately and cannot slip through the deduplication guard above.
    lastRequestedFingerprint = fingerprint;
    blockedFingerprint = null;

    const cancellation = cancelCurrentRequest();
    if (cancellation) {
      await cancellation;
    }
    if (disposed) {
      return;
    }

    // Re-read the snapshot after the cancellation await: the store snapshot
    // may have changed identity while we yielded (e.g. a new analysis for a
    // different device fired and a concurrent run claimed a new fingerprint).
    // If the identity has changed, the stale fingerprint-A claim would pass
    // the dedup guard (lastRequestedFingerprint is now fingerprint-B) and
    // could cancel the concurrent run's correct fetch and dispatch a fetch for
    // the wrong device whose overlay would then be applied to the new snapshot.
    // Release the stale claim, reschedule a run for the current snapshot, and
    // bail out.
    const currentSnapshot = useEspDiagnosticsStore.getState().snapshot;
    if (
      !currentSnapshot ||
      getEspIdentityFingerprint(currentSnapshot) !== fingerprint
    ) {
      lastRequestedFingerprint = null;
      void run(false);
      return;
    }

    const requestId = nextRequestId();
    const request = createGraphRequest(currentSnapshot, requestId);
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
          if (!state.snapshot) {
            // A replacement analysis is a new enrichment lifecycle even when
            // it describes the same device. Release both fingerprint guards
            // before its snapshot arrives, and preserve the old request ID
            // long enough to finish native cancellation first.
            lastRequestedFingerprint = null;
            blockedFingerprint = null;
            if (
              previous.graphRequestId !== null &&
              state.graphRequestId === null
            ) {
              cancelOrphanedRequest(previous.graphRequestId);
            }
            return;
          }
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
      if (disposed) {
        return;
      }
      disposed = true;
      const cancellation = cancelCurrentRequest();
      if (cancellation) {
        void cancellation;
      }
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
