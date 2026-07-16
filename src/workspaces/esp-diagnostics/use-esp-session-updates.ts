import { useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  getSafeErrorMessage,
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
  EspGraphPolicyKind,
  EspGraphRequest,
  EspGraphScriptKind,
  EspSessionState,
  EspSessionUpdate,
  EspUpdateReason,
} from "./types";
import { isEspDiagnosticsSnapshot } from "./esp-wire-validation";

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
  if (!isRecord(value) || !isEspDiagnosticsSnapshot(value.snapshot)) {
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

const GRAPH_GUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function normalizeGraphGuid(value: string | null | undefined): string | null {
  const normalized = value?.trim().toLowerCase() ?? "";
  return GRAPH_GUID_PATTERN.test(normalized) ? normalized : null;
}

type GraphReferenceKinds<K extends string> = Map<string, Set<K>>;

function addReference<K extends string>(
  references: GraphReferenceKinds<K>,
  id: string,
  kind: K,
): void {
  const kinds = references.get(id) ?? new Set<K>();
  kinds.add(kind);
  references.set(id, kinds);
}

function sortedReferences<K extends string>(
  references: GraphReferenceKinds<K>,
): Array<{ id: string; kind: K }> {
  return Array.from(references)
    .flatMap(([id, kinds]) => Array.from(kinds, (kind) => ({ id, kind })))
    .sort(
      (left, right) =>
        left.id.localeCompare(right.id) || left.kind.localeCompare(right.kind),
    );
}

function createGraphRequest(
  snapshot: EspDiagnosticsSnapshot,
  requestId: string,
  selectedManagedDeviceId: string | null = null,
): EspGraphRequest {
  const evidenceWindow = getEvidenceWindow(snapshot);
  const appIds = new Set<string>();
  const policyReferences: GraphReferenceKinds<EspGraphPolicyKind> = new Map();
  const scriptReferences: GraphReferenceKinds<EspGraphScriptKind> = new Map();
  for (const workload of snapshot.workloads) {
    const id = normalizeGraphGuid(workload.rawIdentifier);
    if (!id) {
      continue;
    }
    switch (workload.kind) {
      case "modernApp":
      case "win32App":
      case "devicePreparationWorkload":
        appIds.add(id);
        break;
      case "policy":
        addReference(policyReferences, id, "deviceConfiguration");
        break;
      case "scepCertificate":
        addReference(policyReferences, id, "scepCertificate");
        break;
      case "platformScript":
        addReference(scriptReferences, id, "platformScript");
        break;
    }
  }
  for (const value of snapshot.profile?.devicePreparation?.scriptIds ?? []) {
    const id = normalizeGraphGuid(value);
    if (id) {
      addReference(scriptReferences, id, "platformScript");
    }
  }
  const enrollmentConfigurationIds = new Set<string>();
  const graph = snapshot.graph;
  if (graph) {
    for (const section of [
      graph.deploymentProfile,
      graph.intendedDeploymentProfile,
    ]) {
      for (const value of section.data?.selectedMobileAppIds ?? []) {
        const id = normalizeGraphGuid(value);
        if (id) {
          appIds.add(id);
        }
      }
    }
    for (const value of graph.enrollmentConfiguration.data
      ?.selectedMobileAppIds ?? []) {
      const id = normalizeGraphGuid(value);
      if (id) {
        appIds.add(id);
      }
    }
    for (const record of graph.apps.data ?? []) {
      const id = normalizeGraphGuid(record.appId);
      if (id) {
        appIds.add(id);
      }
    }
    const configurationId = normalizeGraphGuid(
      graph.enrollmentConfiguration.data?.configurationId,
    );
    if (configurationId) {
      enrollmentConfigurationIds.add(configurationId);
    }
    for (const event of graph.autopilotEvents.data ?? []) {
      const id = normalizeGraphGuid(event.enrollmentConfigurationId);
      if (id) {
        enrollmentConfigurationIds.add(id);
      }
    }
    const graphPolicyReferences: GraphReferenceKinds<EspGraphPolicyKind> =
      new Map();
    for (const record of graph.policies.data ?? []) {
      const id = normalizeGraphGuid(record.policyId);
      if (id) {
        addReference(graphPolicyReferences, id, record.kind);
      }
    }
    const graphScriptReferences: GraphReferenceKinds<EspGraphScriptKind> =
      new Map();
    for (const record of graph.scripts.data ?? []) {
      const id = normalizeGraphGuid(record.scriptId);
      if (id) {
        addReference(graphScriptReferences, id, record.kind);
      }
    }
    // Graph object IDs are collection-scoped, so preserve unique (id, kind)
    // pairs. A prior Graph overlay is authoritative for IDs whose collection
    // was already resolved and replaces locally inferred generic kinds.
    for (const [id, kinds] of graphPolicyReferences) {
      policyReferences.set(id, kinds);
    }
    for (const [id, kinds] of graphScriptReferences) {
      scriptReferences.set(id, kinds);
    }
  }
  const sortedAppIds = Array.from(appIds).sort();
  return {
    requestId,
    identity: snapshot.identity,
    workloadIds: sortedAppIds,
    selectedManagedDeviceId,
    evidenceWindowStartUtc: evidenceWindow?.start ?? null,
    evidenceWindowEndUtc: evidenceWindow?.end ?? null,
    enrollmentConfigurationIds: Array.from(enrollmentConfigurationIds).sort(),
    appIds: sortedAppIds,
    policyReferences: sortedReferences(policyReferences),
    scriptReferences: sortedReferences(scriptReferences),
  };
}

const RFC3339_OFFSET_TIMESTAMP_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/i;

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    return isLeapYear(year) ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function timestampInstant(value: string | null | undefined): number | null {
  if (!value) {
    return null;
  }
  const match = RFC3339_OFFSET_TIMESTAMP_PATTERN.exec(value);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[8] == null ? 0 : Number(match[8]);
  const offsetMinute = match[9] == null ? 0 : Number(match[9]);
  if (
    match[7].toLowerCase() === "-00:00" ||
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    return null;
  }
  const instant = Date.parse(value);
  return Number.isFinite(instant) ? instant : null;
}

function timestampUtc(
  timestamp: { normalizedUtc: string | null; rawText: string } | null,
): string | null {
  const rawMatch = timestamp
    ? RFC3339_OFFSET_TIMESTAMP_PATTERN.exec(timestamp.rawText)
    : null;
  if (rawMatch?.[7].toLowerCase() === "-00:00") {
    // RFC 3339 uses -00:00 to say the local offset is unknown. A derived
    // normalized value cannot turn that source evidence into an exact instant.
    return null;
  }
  for (const value of [timestamp?.normalizedUtc, timestamp?.rawText]) {
    const instant = timestampInstant(value);
    if (instant != null) {
      return new Date(instant).toISOString();
    }
  }
  return null;
}

function getEvidenceWindow(
  snapshot: EspDiagnosticsSnapshot,
): { start: string; end: string } | null {
  const latestSessions = snapshot.sessions
    .filter((session) => session.isLatest)
    .map((session) => ({
      session,
      start: timestampUtc(session.startedAt),
    }))
    .filter(
      (candidate): candidate is typeof candidate & { start: string } =>
        candidate.start !== null,
    )
    .sort(
      (left, right) =>
        (timestampInstant(right.start) ?? 0) -
          (timestampInstant(left.start) ?? 0) ||
        left.session.sessionId.localeCompare(right.session.sessionId),
    );
  const latest = latestSessions[0];
  if (latest) {
    const end = timestampUtc(latest.session.endedAt) ?? snapshot.generatedAtUtc;
    const startInstant = timestampInstant(latest.start);
    const endInstant = timestampInstant(end);
    if (
      startInstant != null &&
      endInstant != null &&
      startInstant <= endInstant
    ) {
      return { start: latest.start, end: new Date(endInstant).toISOString() };
    }
  }

  const activityInstants = snapshot.activity
    .map((entry) => timestampUtc(entry.timestamp))
    .filter((value): value is string => value !== null)
    .map((value) => ({ value, instant: timestampInstant(value) }))
    .filter(
      (candidate): candidate is { value: string; instant: number } =>
        candidate.instant !== null,
    )
    .sort((left, right) => left.instant - right.instant);
  if (activityInstants.length === 0) {
    return null;
  }
  return {
    start: activityInstants[0].value,
    end: activityInstants[activityInstants.length - 1].value,
  };
}

function createRequestId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `esp-graph-${crypto.randomUUID()}`;
  }
  return `esp-graph-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export interface EspGraphCoordinatorDependencies {
  fetchGraph(request: EspGraphRequest): Promise<EspGraphOverlay>;
  cancelGraph(requestId: string): Promise<void>;
  createRequestId(): string;
}

export interface EspGraphCoordinator {
  reconcile(): Promise<void>;
  refresh(selectedManagedDeviceId?: string | null): Promise<void>;
  cancel(): Promise<void>;
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
  let operationGeneration = 0;
  let lastRequestedFingerprint: string | null = null;
  let blockedFingerprint: string | null = null;
  let selectedManagedDeviceId: string | null = null;
  let selectedManagedDeviceFingerprint: string | null = null;
  let pendingOrphanCancellation: Promise<void> | null = null;
  let ownedRequestId: string | null = null;
  let unsubscribeEsp: (() => void) | null = null;
  let unsubscribeUi: (() => void) | null = null;

  const clearSelectedManagedDevice = () => {
    selectedManagedDeviceId = null;
    selectedManagedDeviceFingerprint = null;
  };

  const resolveSelectedManagedDeviceId = (
    snapshot: EspDiagnosticsSnapshot,
    fingerprint: string,
    requestedManagedDeviceId: string | null | undefined,
  ): string | null => {
    if (
      selectedManagedDeviceFingerprint !== null &&
      selectedManagedDeviceFingerprint !== fingerprint
    ) {
      clearSelectedManagedDevice();
    }

    if (requestedManagedDeviceId !== undefined) {
      if (requestedManagedDeviceId === null) {
        clearSelectedManagedDevice();
        return null;
      }
      selectedManagedDeviceId = requestedManagedDeviceId;
      selectedManagedDeviceFingerprint = fingerprint;
      return requestedManagedDeviceId;
    }

    if (selectedManagedDeviceFingerprint === fingerprint) {
      return selectedManagedDeviceId;
    }

    const overlaySelection =
      snapshot.graph?.deviceMatch.data?.selected?.managedDeviceId ?? null;
    if (overlaySelection) {
      selectedManagedDeviceId = overlaySelection;
      selectedManagedDeviceFingerprint = fingerprint;
    }
    return overlaySelection;
  };

  const cancelCurrentRequest = (): Promise<void> | null => {
    const requestId =
      ownedRequestId ?? useEspDiagnosticsStore.getState().graphRequestId;
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
        if (ownedRequestId === requestId) {
          ownedRequestId = null;
        }
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
      if (ownedRequestId === requestId) {
        ownedRequestId = null;
      }
      useEspDiagnosticsStore.getState().cancelGraph(requestId);
      if (pendingOrphanCancellation === cancellation) {
        pendingOrphanCancellation = null;
      }
    });
  };

  const run = async (
    force: boolean,
    requestedManagedDeviceId?: string | null,
  ) => {
    if (disposed) {
      return;
    }

    if (
      !useEspDiagnosticsStore.getState().snapshot ||
      !useUiStore.getState().graphApiEnabled
    ) {
      clearSelectedManagedDevice();
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
      const generation = ++operationGeneration;
      clearSelectedManagedDevice();
      blockedFingerprint = null;
      lastRequestedFingerprint = null;
      const cancellation = cancelCurrentRequest();
      if (cancellation) {
        await cancellation;
      }
      if (disposed || generation !== operationGeneration) {
        return;
      }
      return;
    }

    const fingerprint = getEspIdentityFingerprint(snapshot);
    if (
      selectedManagedDeviceFingerprint !== null &&
      selectedManagedDeviceFingerprint !== fingerprint
    ) {
      clearSelectedManagedDevice();
    }
    const { graphApiEnabled, graphApiStatus } = useUiStore.getState();

    if (!graphApiEnabled) {
      const generation = ++operationGeneration;
      clearSelectedManagedDevice();
      const cancellation = cancelCurrentRequest();
      if (cancellation) {
        await cancellation;
      }
      if (disposed || generation !== operationGeneration) {
        return;
      }
      if (useUiStore.getState().graphApiEnabled) {
        blockedFingerprint = null;
        lastRequestedFingerprint = null;
        return run(false);
      }
      useEspDiagnosticsStore.getState().clearGraphOverlay();
      useEspDiagnosticsStore.getState().setGraphUnavailable("graphDisabled");
      blockedFingerprint = null;
      lastRequestedFingerprint = null;
      return;
    }

    if (graphApiStatus !== "connected") {
      const generation = ++operationGeneration;
      const cancellation = cancelCurrentRequest();
      if (cancellation) {
        await cancellation;
      }
      if (disposed || generation !== operationGeneration) {
        return;
      }
      const currentUi = useUiStore.getState();
      const currentSnapshot = useEspDiagnosticsStore.getState().snapshot;
      if (
        !currentUi.graphApiEnabled ||
        currentUi.graphApiStatus === "connected" ||
        !currentSnapshot ||
        getEspIdentityFingerprint(currentSnapshot) !== fingerprint
      ) {
        return run(false);
      }
      useEspDiagnosticsStore.getState().clearGraphOverlay();
      useEspDiagnosticsStore
        .getState()
        .setGraphUnavailable("graphNotConnected");
      blockedFingerprint = fingerprint;
      return;
    }

    const requestSelectedManagedDeviceId = resolveSelectedManagedDeviceId(
      snapshot,
      fingerprint,
      requestedManagedDeviceId,
    );

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
    const generation = ++operationGeneration;
    const cancellation = cancelCurrentRequest();
    if (cancellation) {
      await cancellation;
    }
    if (disposed || generation !== operationGeneration) {
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
    const currentGraphState = useUiStore.getState();
    if (
      !currentSnapshot ||
      getEspIdentityFingerprint(currentSnapshot) !== fingerprint ||
      !currentGraphState.graphApiEnabled ||
      currentGraphState.graphApiStatus !== "connected"
    ) {
      if (lastRequestedFingerprint === fingerprint) {
        lastRequestedFingerprint = null;
      }
      void run(false);
      return;
    }

    const currentFingerprint = getEspIdentityFingerprint(currentSnapshot);
    blockedFingerprint = null;
    lastRequestedFingerprint = fingerprint;
    const requestId = nextRequestId();
    const request = createGraphRequest(
      currentSnapshot,
      requestId,
      requestSelectedManagedDeviceId,
    );
    ownedRequestId = requestId;
    useEspDiagnosticsStore.getState().beginGraph(requestId, currentFingerprint);

    try {
      const overlay = await fetchGraph(request);
      const latestSnapshot = useEspDiagnosticsStore.getState().snapshot;
      const latestUi = useUiStore.getState();
      if (
        !disposed &&
        generation === operationGeneration &&
        latestUi.graphApiEnabled &&
        latestUi.graphApiStatus === "connected" &&
        latestSnapshot &&
        getEspIdentityFingerprint(latestSnapshot) === currentFingerprint
      ) {
        if (overlay.requestId !== requestId) {
          useEspDiagnosticsStore
            .getState()
            .failGraph(
              requestId,
              "Microsoft Graph returned data for a different request. Refresh Graph data to try again.",
            );
        } else {
          useEspDiagnosticsStore
            .getState()
            .applyGraphOverlay(requestId, overlay);
        }
      }
    } catch (error) {
      if (!disposed && generation === operationGeneration) {
        useEspDiagnosticsStore
          .getState()
          .failGraph(
            requestId,
            getSafeErrorMessage(error, "Microsoft Graph enrichment failed."),
          );
      }
    } finally {
      if (ownedRequestId === requestId) {
        ownedRequestId = null;
      }
    }
  };

  return {
    reconcile: () => run(false),
    refresh: (selectedManagedDeviceId) => run(true, selectedManagedDeviceId),
    cancel: async () => {
      operationGeneration += 1;
      const cancellation = cancelCurrentRequest();
      if (cancellation) {
        await cancellation;
      }
    },
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
            clearSelectedManagedDevice();
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
          if (!state.graphApiEnabled) {
            clearSelectedManagedDevice();
          }
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
      operationGeneration += 1;
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

export async function refreshEspGraphData(
  selectedManagedDeviceId?: string | null,
): Promise<void> {
  await globalGraphCoordinator?.refresh(selectedManagedDeviceId);
}

export async function cancelEspGraphData(): Promise<void> {
  await globalGraphCoordinator?.cancel();
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
