import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import {
  analyzeEspEvidence,
  getEspDiagnosticsSession,
  graphCancelEspDiagnostics,
  graphFetchEspDiagnostics,
  restartEspAsAdministrator,
  startEspDiagnosticsSession,
  stopEspDiagnosticsSession,
} from "../../lib/commands";
import { useUiStore } from "../../stores/ui-store";
import {
  ESP_EVIDENCE_DOCK_MAX_HEIGHT,
  ESP_EVIDENCE_DOCK_MIN_HEIGHT,
  useEspDiagnosticsStore,
} from "./esp-diagnostics-store";
import {
  createEspGraphCoordinator,
  getEspIdentityFingerprint,
  isEspSessionUpdate,
} from "./use-esp-session-updates";
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspGraphRequest,
  EspSessionUpdate,
} from "./types";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

function makeSnapshot(
  evidenceIds: string[] = [],
  identitySeed = "device-a",
): EspDiagnosticsSnapshot {
  return {
    schemaVersion: 1,
    scenario: "autopilotV1",
    phase: "deviceSetup",
    generatedAtUtc: "2026-07-15T20:00:00Z",
    elevation: {
      isElevated: false,
      restartSupported: true,
      restrictedSources: [],
    },
    identity: {
      deviceName: `host-${identitySeed}`,
      managedDeviceId: null,
      entraDeviceId: `entra-${identitySeed}`,
      entdmId: { value: "entdm-a", sensitivity: "sensitive" },
      tenantId: { value: "tenant-a", sensitivity: "sensitive" },
      tenantDomain: { value: "contoso.example", sensitivity: "public" },
      userPrincipalName: {
        value: "user@contoso.example",
        sensitivity: "restricted",
      },
      serialNumber: {
        value: `serial-${identitySeed}`,
        sensitivity: "sensitive",
      },
      evidence: [],
    },
    profile: null,
    enrollments: [],
    sessions: [],
    workloads: [],
    installerCorrelations: [],
    nodeCache: [],
    registrationEvents: [],
    deliveryOptimization: null,
    hardware: null,
    activity: [],
    findings: [],
    coverage: [],
    rawEvidence: evidenceIds.map((id, index) => ({
      recordId: id,
      provenance: {
        sourceKind: "imeLog",
        sourceArtifactId: "ime-app-workload",
        filePath: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
        lineNumber: index + 1,
        recordNumber: null,
        registry: null,
        event: null,
      },
      sourceTimestamp: null,
      observedAtUtc: `2026-07-15T20:00:0${index}Z`,
      rawValue: { text: `raw-${id}` },
      sensitivity: "public",
      parseState: "parsed",
      accessState: "available",
      evidence: [],
    })),
    graph: null,
  };
}

function makeOverlay(requestId: string): EspGraphOverlay {
  const skipped = {
    status: "skipped" as const,
    requiredScope: null,
    apiVersion: "v1.0" as const,
    data: null,
    error: null,
  };

  return {
    requestId,
    requestedAtUtc: "2026-07-15T20:01:00Z",
    deviceMatch: {
      status: "available",
      requiredScope: "DeviceManagementManagedDevices.Read.All",
      apiVersion: "v1.0",
      data: {
        selected: {
          managedDeviceId: "managed-a",
          entraDeviceId: "entra-device-a",
          serialNumber: { value: "serial-device-a", sensitivity: "sensitive" },
          deviceName: "host-device-a",
          userId: "user-a",
          userPrincipalName: {
            value: "user@contoso.example",
            sensitivity: "restricted",
          },
          tenantId: { value: "tenant-a", sensitivity: "sensitive" },
          evidence: [],
        },
        candidates: [],
        matchBasis: "entraDeviceId",
        confidence: "exact",
        evidence: [],
      },
      error: null,
    },
    autopilotIdentity: skipped,
    deploymentProfile: skipped,
    intendedDeploymentProfile: skipped,
    profileAssignments: skipped,
    autopilotEvents: skipped,
    enrollmentConfiguration: skipped,
    apps: skipped,
    policies: skipped,
    scripts: skipped,
  };
}

function makeSessionUpdate(
  sequence: number,
  snapshot: EspDiagnosticsSnapshot,
  sessionId = "session-a",
): EspSessionUpdate {
  return {
    sessionId,
    requestId: "live-a",
    sequence,
    state: "live",
    reason: "evidenceChanged",
    emittedAtUtc: "2026-07-15T20:00:00Z",
    snapshot,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

beforeEach(() => {
  vi.mocked(invoke).mockReset();
  useEspDiagnosticsStore.setState(useEspDiagnosticsStore.getInitialState(), true);
  useUiStore.setState({
    graphApiEnabled: false,
    graphApiStatus: "idle",
  });
});

describe("ESP typed command wrappers", () => {
  it("routes local session, relaunch, and Graph calls through normalized IPC", async () => {
    const snapshot = makeSnapshot(["local-a"]);
    const envelope = {
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 1,
      state: "live" as const,
      snapshot,
    };
    const overlay = makeOverlay("graph-a");
    vi.mocked(invoke)
      .mockResolvedValueOnce(snapshot)
      .mockResolvedValueOnce(envelope)
      .mockResolvedValueOnce(envelope)
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ launched: true, reason: "launched" })
      .mockResolvedValueOnce(overlay)
      .mockResolvedValueOnce(undefined);

    await expect(analyzeEspEvidence("/bundle", "analysis-a")).resolves.toBe(
      snapshot,
    );
    await expect(startEspDiagnosticsSession("live-a")).resolves.toBe(envelope);
    await expect(getEspDiagnosticsSession("session-a")).resolves.toBe(envelope);
    await expect(stopEspDiagnosticsSession("session-a")).resolves.toBeUndefined();
    await expect(restartEspAsAdministrator()).resolves.toEqual({
      launched: true,
      reason: "launched",
    });
    const request: EspGraphRequest = {
      requestId: "graph-a",
      identity: snapshot.identity,
      workloadIds: [],
      selectedManagedDeviceId: null,
    };
    await expect(graphFetchEspDiagnostics(request)).resolves.toBe(overlay);
    await expect(graphCancelEspDiagnostics("graph-a")).resolves.toBeUndefined();

    expect(vi.mocked(invoke).mock.calls).toEqual([
      ["analyze_esp_evidence", { path: "/bundle", requestId: "analysis-a" }],
      ["start_esp_diagnostics_session", { requestId: "live-a" }],
      ["get_esp_diagnostics_session", { sessionId: "session-a" }],
      ["stop_esp_diagnostics_session", { sessionId: "session-a" }],
      ["restart_esp_as_administrator", undefined],
      ["graph_fetch_esp_diagnostics", { request }],
      ["graph_cancel_esp_diagnostics", { requestId: "graph-a" }],
    ]);
  });

  it("normalizes missing ESP backend command errors", async () => {
    vi.mocked(invoke).mockRejectedValueOnce(
      "command analyze_esp_evidence not found",
    );

    await expect(
      analyzeEspEvidence("/bundle", "analysis-a"),
    ).rejects.toThrow("Restart CMTrace Open");
  });
});

describe("ESP local session state", () => {
  it("moves idle to analyzing to ready and ignores stale analysis responses", () => {
    const initial = useEspDiagnosticsStore.getState();
    expect(initial.phase).toBe("idle");
    expect(initial.snapshot).toBeNull();

    initial.beginAnalysis("analysis-a");
    expect(useEspDiagnosticsStore.getState().phase).toBe("analyzing");

    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-stale", makeSnapshot(["stale"]));
    expect(useEspDiagnosticsStore.getState().snapshot).toBeNull();

    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));
    expect(useEspDiagnosticsStore.getState().phase).toBe("ready");
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId).toBe(
      "local-a",
    );
  });

  it("moves starting to live to stopping to ready and rejects wrong or old updates", () => {
    useEspDiagnosticsStore.getState().beginLiveStart("live-a");
    expect(useEspDiagnosticsStore.getState().phase).toBe("starting");

    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(1, makeSnapshot(["first"])));
    expect(useEspDiagnosticsStore.getState().phase).toBe("live");
    expect(useEspDiagnosticsStore.getState().sessionId).toBe("session-a");
    expect(useEspDiagnosticsStore.getState().sequence).toBe(1);

    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(
        makeSessionUpdate(2, makeSnapshot(["wrong"]), "session-wrong"),
      );
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(1, makeSnapshot(["duplicate"])));
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(0, makeSnapshot(["old"])));
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId).toBe(
      "first",
    );

    useEspDiagnosticsStore.getState().beginStop("session-a");
    expect(useEspDiagnosticsStore.getState().phase).toBe("stopping");
    useEspDiagnosticsStore.getState().clearStoppedSession("session-wrong");
    expect(useEspDiagnosticsStore.getState().phase).toBe("stopping");
    useEspDiagnosticsStore.getState().clearStoppedSession("session-a");
    expect(useEspDiagnosticsStore.getState().phase).toBe("ready");
    expect(useEspDiagnosticsStore.getState().sessionId).toBeNull();
  });

  it("clears the native session identity when live collection expires", () => {
    useEspDiagnosticsStore.getState().beginLiveStart("live-a");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(1, makeSnapshot(["first"])));

    useEspDiagnosticsStore.getState().applySessionUpdate({
      ...makeSessionUpdate(2, makeSnapshot(["first", "final"])),
      state: "expired",
      reason: "expired",
    });

    expect(useEspDiagnosticsStore.getState().phase).toBe("ready");
    expect(useEspDiagnosticsStore.getState().sessionId).toBeNull();
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence).toHaveLength(2);
  });

  it("recovers from local errors on the next request", () => {
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore.getState().fail("analysis-a", "Unreadable bundle");
    expect(useEspDiagnosticsStore.getState().phase).toBe("error");
    expect(useEspDiagnosticsStore.getState().error).toBe("Unreadable bundle");

    useEspDiagnosticsStore.getState().beginLiveStart("live-b");
    expect(useEspDiagnosticsStore.getState().phase).toBe("starting");
    expect(useEspDiagnosticsStore.getState().error).toBeNull();
  });

  it("clamps evidence height and counts unread evidence only while collapsed", () => {
    const state = useEspDiagnosticsStore.getState();
    expect(state.evidenceViewMode).toBe("collapsed");

    state.setEvidenceDockHeight(10);
    expect(useEspDiagnosticsStore.getState().evidenceDockHeight).toBe(
      ESP_EVIDENCE_DOCK_MIN_HEIGHT,
    );
    state.setEvidenceDockHeight(10_000);
    expect(useEspDiagnosticsStore.getState().evidenceDockHeight).toBe(
      ESP_EVIDENCE_DOCK_MAX_HEIGHT,
    );

    state.beginLiveStart("live-a");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(1, makeSnapshot(["one", "two"])));
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(2);

    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(2, makeSnapshot(["one", "two", "three"])));
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(2);
    useEspDiagnosticsStore.getState().markEvidenceRead();
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(0);
  });

  it("validates the complete session envelope before applying native events", () => {
    const update = makeSessionUpdate(1, makeSnapshot(["local-a"]));
    expect(isEspSessionUpdate(update)).toBe(true);
    expect(isEspSessionUpdate({ ...update, sequence: -1 })).toBe(false);
    expect(
      isEspSessionUpdate({
        ...update,
        snapshot: { ...update.snapshot, identity: null },
      }),
    ).toBe(false);
  });
});

describe("ESP Graph overlay state", () => {
  it("preserves raw unknown Graph status and API-version wire values", () => {
    const overlay = makeOverlay("graph-unknown-wire-values");
    overlay.scripts = {
      status: "retrying",
      requiredScope: "DeviceManagementScripts.Read.All",
      apiVersion: "vNext",
      data: null,
      error: null,
    };

    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));
    useEspDiagnosticsStore
      .getState()
      .beginGraph("graph-unknown-wire-values");
    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-unknown-wire-values", overlay);

    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.scripts).toEqual(
      overlay.scripts,
    );
  });

  it("classifies the exact Rust Graph sections without reading absent frontend-only keys", () => {
    const local = makeSnapshot(["local-a"]);
    const overlay = makeOverlay("graph-a");
    overlay.profileAssignments = {
      status: "permissionDenied",
      requiredScope: "DeviceManagementServiceConfig.Read.All",
      apiVersion: "beta",
      data: null,
      error: {
        code: "Authorization_RequestDenied",
        message: "Insufficient privileges",
        requestId: "graph-a",
        blockedBy: "consent",
        retryAfterSeconds: null,
      },
    };

    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore.getState().applyAnalysis("analysis-a", local);
    useEspDiagnosticsStore.getState().beginGraph("graph-a");

    expect(() =>
      useEspDiagnosticsStore.getState().applyGraphOverlay("graph-a", overlay),
    ).not.toThrow();
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("partial");
  });

  it("rejects stale Graph responses and preserves the raw local snapshot after failure", () => {
    const local = makeSnapshot(["local-a"]);
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore.getState().applyAnalysis("analysis-a", local);

    useEspDiagnosticsStore.getState().beginGraph("graph-a");
    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-stale", makeOverlay("graph-stale"));
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();

    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-a", makeOverlay("graph-a"));
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("ready");
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-a",
    );

    useEspDiagnosticsStore.getState().beginGraph("graph-b");
    useEspDiagnosticsStore.getState().failGraph("graph-b", "Graph unavailable");
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("error");
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId).toBe(
      "local-a",
    );
  });

  it("does not rewrite a local snapshot when no Graph overlay exists", () => {
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));
    const localSnapshot = useEspDiagnosticsStore.getState().snapshot;

    useEspDiagnosticsStore.getState().clearGraphOverlay();

    expect(useEspDiagnosticsStore.getState().snapshot).toBe(localSnapshot);
  });

  it("preserves Graph when local identity changes only by case or whitespace", () => {
    const current = {
      ...makeSnapshot(["local-a"], "same-device"),
      graph: makeOverlay("graph-a"),
    };
    const incoming = makeSnapshot(["local-a", "local-b"], "same-device");
    incoming.identity = {
      ...incoming.identity,
      deviceName: `  ${incoming.identity.deviceName!.toUpperCase()}  `,
      entraDeviceId: ` ${incoming.identity.entraDeviceId?.toUpperCase()} `,
      entdmId: {
        ...incoming.identity.entdmId!,
        value: ` ${incoming.identity.entdmId!.value.toUpperCase()} `,
      },
      tenantId: {
        ...incoming.identity.tenantId!,
        value: ` ${incoming.identity.tenantId!.value.toUpperCase()} `,
      },
      tenantDomain: {
        ...incoming.identity.tenantDomain!,
        value: ` ${incoming.identity.tenantDomain!.value.toUpperCase()} `,
      },
      userPrincipalName: {
        ...incoming.identity.userPrincipalName!,
        value: ` ${incoming.identity.userPrincipalName!.value.toUpperCase()} `,
      },
      serialNumber: {
        ...incoming.identity.serialNumber!,
        value: ` ${incoming.identity.serialNumber!.value.toUpperCase()} `,
      },
    };
    useEspDiagnosticsStore.setState({
      phase: "live",
      requestId: "live-a",
      sessionId: "session-a",
      sequence: 1,
      snapshot: current,
    });

    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(2, incoming));

    expect(getEspIdentityFingerprint(incoming)).toBe(
      getEspIdentityFingerprint(current),
    );
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-a",
    );
  });
});

describe("ESP Graph scheduling", () => {
  it("keeps Graph disabled without fetching and removes only the remote overlay", async () => {
    const fetchGraph = vi.fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>();
    const cancelGraph = vi.fn<(requestId: string) => Promise<void>>();
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", {
        ...makeSnapshot(["local-a"]),
        graph: makeOverlay("old-overlay"),
      });

    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => "graph-a",
    });
    await coordinator.reconcile();

    expect(fetchGraph).not.toHaveBeenCalled();
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("disabled");
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId).toBe(
      "local-a",
    );
    coordinator.dispose();
  });

  it.each(["idle", "connecting", "error"] as const)(
    "requires explicit refresh after Graph is %s and never queues behind WAM",
    async (graphApiStatus) => {
      const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
        makeOverlay(request.requestId),
      );
      const cancelGraph = vi.fn(async () => undefined);
      useUiStore.setState({ graphApiEnabled: true, graphApiStatus });
      useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
      useEspDiagnosticsStore
        .getState()
        .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));
      const coordinator = createEspGraphCoordinator({
        fetchGraph,
        cancelGraph,
        createRequestId: () => "graph-refresh",
      });

      await coordinator.reconcile();
      expect(fetchGraph).not.toHaveBeenCalled();
      expect(useEspDiagnosticsStore.getState().graphUnavailableReason).toBe(
        "graphNotConnected",
      );

      useUiStore.setState({ graphApiStatus: "connected" });
      await coordinator.reconcile();
      expect(fetchGraph).not.toHaveBeenCalled();

      await coordinator.refresh();
      expect(fetchGraph).toHaveBeenCalledTimes(1);
      expect(useEspDiagnosticsStore.getState().graphPhase).toBe("ready");
      coordinator.dispose();
    },
  );

  it("fetches once per stable local identity for imported and live snapshots", async () => {
    let requestNumber = 0;
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => `graph-${++requestNumber}`,
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });

    const imported = makeSnapshot(["imported"], "same-device");
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore.getState().applyAnalysis("analysis-a", imported);
    await coordinator.reconcile();
    expect(fetchGraph).toHaveBeenCalledTimes(1);

    useEspDiagnosticsStore.getState().beginLiveStart("live-a");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(
        makeSessionUpdate(1, makeSnapshot(["live-one"], "same-device")),
      );
    await coordinator.reconcile();
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(
        makeSessionUpdate(2, makeSnapshot(["live-one", "live-two"], "same-device")),
      );
    await coordinator.reconcile();

    expect(fetchGraph).toHaveBeenCalledTimes(1);
    expect(getEspIdentityFingerprint(imported)).toBe(
      getEspIdentityFingerprint(makeSnapshot([], "same-device")),
    );
    coordinator.dispose();
  });

  it("fingerprints classified identity values safely without treating sensitivity as identity", () => {
    const snapshot = makeSnapshot([], "same-device");
    const reclassified: EspDiagnosticsSnapshot = {
      ...snapshot,
      identity: {
        ...snapshot.identity,
        tenantId: { value: "tenant-a", sensitivity: "restricted" },
        serialNumber: {
          value: "serial-same-device",
          sensitivity: "restricted",
        },
      },
    };
    const unclassified: EspDiagnosticsSnapshot = {
      ...snapshot,
      identity: {
        ...snapshot.identity,
        entdmId: null,
        tenantId: null,
        tenantDomain: null,
        userPrincipalName: null,
        serialNumber: null,
      },
    };

    expect(getEspIdentityFingerprint(reclassified)).toBe(
      getEspIdentityFingerprint(snapshot),
    );
    expect(() => getEspIdentityFingerprint(unclassified)).not.toThrow();
  });

  it("rejects late refresh results and cancels without sign-out when disabled", async () => {
    const first = deferred<EspGraphOverlay>();
    const second = deferred<EspGraphOverlay>();
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const cancelGraph = vi.fn(async () => undefined);
    const ids = ["graph-a", "graph-b"];
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => ids.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));

    const initialQuery = coordinator.reconcile();
    const refreshQuery = coordinator.refresh();
    expect(cancelGraph).toHaveBeenCalledWith("graph-a");
    second.resolve(makeOverlay("graph-b"));
    await refreshQuery;
    first.resolve(makeOverlay("graph-a"));
    await initialQuery;
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-b",
    );

    const third = deferred<EspGraphOverlay>();
    fetchGraph.mockImplementationOnce(() => third.promise);
    const activeRefresh = coordinator.refresh();
    useUiStore.setState({ graphApiEnabled: false });
    await coordinator.reconcile();
    expect(cancelGraph).toHaveBeenCalledWith("graph-extra");
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId).toBe(
      "local-a",
    );
    third.resolve(makeOverlay("graph-extra"));
    await activeRefresh;
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    coordinator.dispose();
  });

  it("clears remote data when native Graph cancellation fails", async () => {
    const snapshot = makeSnapshot(["local-a"]);
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: {
        ...snapshot,
        graph: makeOverlay("graph-complete"),
      },
      graphRequestId: "graph-active",
      graphPhase: "loading",
    });
    useUiStore.setState({ graphApiEnabled: false, graphApiStatus: "connected" });
    const cancelGraph = vi.fn(async () => {
      throw new Error("Native cancellation unavailable");
    });
    const coordinator = createEspGraphCoordinator({ cancelGraph });

    await expect(coordinator.reconcile()).resolves.toBeUndefined();

    expect(cancelGraph).toHaveBeenCalledWith("graph-active");
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("disabled");
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId).toBe(
      "local-a",
    );
    coordinator.dispose();
  });

  it("cancels an in-flight native Graph request when disposed", async () => {
    const pending = deferred<EspGraphOverlay>();
    const fetchGraph = vi.fn(() => pending.promise);
    const cancelGraph = vi.fn(async () => undefined);
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => "graph-dispose",
    });

    const activeQuery = coordinator.reconcile();
    expect(fetchGraph).toHaveBeenCalledTimes(1);
    expect(useEspDiagnosticsStore.getState().graphRequestId).toBe(
      "graph-dispose",
    );

    coordinator.dispose();

    expect(cancelGraph).toHaveBeenCalledWith("graph-dispose");
    pending.resolve(makeOverlay("graph-dispose"));
    await activeQuery;
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
  });
});
