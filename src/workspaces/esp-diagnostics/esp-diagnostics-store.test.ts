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
  ESP_EVIDENCE_BOUNDARY_MARKER_LIMIT,
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
  GraphSection,
} from "./types";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const GRAPH_MANAGED_DEVICE_DEFAULT =
  "10101010-1010-4010-8010-101010101010";
const GRAPH_MANAGED_DEVICE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

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
        filePath:
          "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
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

function makeWorkload(
  kind: EspDiagnosticsSnapshot["workloads"][number]["kind"],
  rawIdentifier: string,
  workloadId = `local-${kind}-${rawIdentifier}`,
): EspDiagnosticsSnapshot["workloads"][number] {
  return {
    workloadId,
    sessionId: "session-a",
    kind,
    scope: "device",
    rawIdentifier,
    displayName: null,
    status: {
      raw: "pending",
      normalized: "pending",
      display: "Pending",
      detail: null,
    },
    timestamps: {
      firstObserved: {
        rawText: "2026-07-15T18:00:00Z",
        originalOffset: "Z",
        normalizedUtc: "2026-07-15T18:00:00Z",
        kind: "utc",
      },
      started: null,
      ended: null,
      lastUpdated: null,
    },
    exitCode: null,
    enforcementErrorCode: null,
    blocking: null,
    evidence: [],
  };
}

function makeOverlay(requestId: string): EspGraphOverlay {
  const skipped = {
    status: "skipped" as const,
    requiredScope: null,
    apiVersion: "notRequested" as const,
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
          managedDeviceId: GRAPH_MANAGED_DEVICE_DEFAULT,
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

function availableGraphSection<T>(
  data: T,
  apiVersion: "v1.0" | "beta" = "beta",
): GraphSection<T> {
  return {
    status: "available",
    requiredScope: null,
    apiVersion,
    data,
    error: null,
  };
}

function makeOverlayWithSelectedDevice(
  requestId: string,
  managedDeviceId: string,
): EspGraphOverlay {
  const overlay = makeOverlay(requestId);
  const selected = overlay.deviceMatch.data?.selected;
  if (!selected) {
    throw new Error("Expected the Graph overlay fixture to select a device");
  }
  selected.managedDeviceId = managedDeviceId;
  return overlay;
}

function makeSessionUpdate(
  sequence: number,
  snapshot: EspDiagnosticsSnapshot,
  sessionId = "session-a",
  overrides: Partial<EspSessionUpdate> = {},
): EspSessionUpdate {
  return {
    sessionId,
    requestId: "live-a",
    sequence,
    state: "live",
    reason: "evidenceChanged",
    emittedAtUtc: "2026-07-15T20:00:00Z",
    snapshot,
    ...overrides,
  };
}

function evidenceBoundaryMarkers() {
  return useEspDiagnosticsStore.getState().evidenceBoundaryMarkers;
}

function evidenceRecordRows() {
  return useEspDiagnosticsStore.getState().evidenceRecordRows;
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
  useEspDiagnosticsStore.setState(
    useEspDiagnosticsStore.getInitialState(),
    true,
  );
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
    await expect(
      stopEspDiagnosticsSession("session-a"),
    ).resolves.toBeUndefined();
    await expect(restartEspAsAdministrator()).resolves.toEqual({
      launched: true,
      reason: "launched",
    });
    const request: EspGraphRequest = {
      requestId: "graph-a",
      identity: snapshot.identity,
      workloadIds: [],
      selectedManagedDeviceId: null,
      evidenceWindowStartUtc: null,
      evidenceWindowEndUtc: null,
      enrollmentConfigurationIds: [],
      appIds: [],
      policyReferences: [],
      scriptReferences: [],
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

    await expect(analyzeEspEvidence("/bundle", "analysis-a")).rejects.toThrow(
      "Restart CMTrace Open",
    );
  });

  it("preserves only the safe message from structured command errors", async () => {
    const snapshot = makeSnapshot(["structured-command-error"]);
    const request: EspGraphRequest = {
      requestId: "graph-structured-error",
      identity: snapshot.identity,
      workloadIds: [],
      selectedManagedDeviceId: null,
      evidenceWindowStartUtc: null,
      evidenceWindowEndUtc: null,
      enrollmentConfigurationIds: [],
      appIds: [],
      policyReferences: [],
      scriptReferences: [],
    };
    vi.mocked(invoke).mockRejectedValueOnce({
      message: "Microsoft Graph transport is unavailable.",
      body: "Bearer body-secret",
      token: "token-secret",
    });

    const error = await graphFetchEspDiagnostics(request).catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe(
      "Microsoft Graph transport is unavailable.",
    );
    expect((error as Error).message).not.toContain("body-secret");
    expect((error as Error).message).not.toContain("token-secret");
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
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("local-a");
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
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("first");

    useEspDiagnosticsStore.getState().beginStop("session-a");
    expect(useEspDiagnosticsStore.getState().phase).toBe("stopping");
    useEspDiagnosticsStore.getState().clearStoppedSession("session-wrong");
    expect(useEspDiagnosticsStore.getState().phase).toBe("stopping");
    useEspDiagnosticsStore.getState().clearStoppedSession("session-a");
    expect(useEspDiagnosticsStore.getState().phase).toBe("ready");
    expect(useEspDiagnosticsStore.getState().sessionId).toBeNull();
  });

  it("accepts sequence zero exactly once as the initial live update", () => {
    useEspDiagnosticsStore.getState().beginLiveStart("live-a");

    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(0, makeSnapshot(["initial-zero"])));

    expect(useEspDiagnosticsStore.getState().phase).toBe("live");
    expect(useEspDiagnosticsStore.getState().sessionId).toBe("session-a");
    expect(useEspDiagnosticsStore.getState().sequence).toBe(0);
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("initial-zero");

    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(
        makeSessionUpdate(0, makeSnapshot(["duplicate-zero"])),
      );

    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("initial-zero");
  });

  it("rejects a same-session update from a different live request", () => {
    useEspDiagnosticsStore.getState().beginLiveStart("live-a");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(1, makeSnapshot(["accepted"])));

    useEspDiagnosticsStore.getState().applySessionUpdate(
      makeSessionUpdate(2, makeSnapshot(["wrong-request"]), "session-a", {
        requestId: "live-b",
      }),
    );

    const state = useEspDiagnosticsStore.getState();
    expect(state.requestId).toBe("live-a");
    expect(state.sequence).toBe(1);
    expect(state.snapshot?.rawEvidence[0].recordId).toBe("accepted");
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
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence,
    ).toHaveLength(2);
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
    state.setEvidenceDockHeight(10_000, 600);
    expect(useEspDiagnosticsStore.getState().evidenceDockHeight).toBe(420);

    state.beginLiveStart("live-a");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(1, makeSnapshot(["one", "two"])));
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(2);

    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(
        makeSessionUpdate(2, makeSnapshot(["one", "two", "three"])),
      );
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(2);
    useEspDiagnosticsStore.getState().markEvidenceRead();
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(0);
  });

  it("ignores non-finite evidence dock heights", () => {
    const state = useEspDiagnosticsStore.getState();
    state.setEvidenceDockHeight(420);

    for (const height of [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
    ]) {
      useEspDiagnosticsStore.getState().setEvidenceDockHeight(height, 800);
      expect(useEspDiagnosticsStore.getState().evidenceDockHeight).toBe(420);
    }
  });

  it("counts replacement evidence as unread when rotation keeps the record count constant", () => {
    const initial = makeSnapshot(["old-a", "old-b"]);
    const rotated = makeSnapshot(["old-b", "new-c"]);
    rotated.rawEvidence[0] = structuredClone(initial.rawEvidence[1]);
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(1, initial));
    useEspDiagnosticsStore.getState().markEvidenceRead();

    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(2, rotated));

    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(1);
  });

  it("persists a typed source-reset boundary outside native evidence through later updates", () => {
    const initial = makeSnapshot(["old-a"]);
    initial.rawEvidence[0].provenance.filePath =
      "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload.log";
    const replacement = makeSnapshot(["new-b"]);
    replacement.rawEvidence[0].provenance.filePath =
      "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload-20260715.log";
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate(
      makeSessionUpdate(1, initial, "session-a", {
        reason: "initialSnapshot",
      }),
    );
    useEspDiagnosticsStore.getState().markEvidenceRead();

    useEspDiagnosticsStore.getState().applySessionUpdate(
      makeSessionUpdate(2, replacement, "session-a", {
        reason: "sourceReset",
        emittedAtUtc: "2026-07-15T20:00:42Z",
      }),
    );

    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(1);
    expect(evidenceBoundaryMarkers()).toEqual([
      {
        markerId: "source-reset:session-a:2",
        kind: "sourceReset",
        emittedAtUtc: "2026-07-15T20:00:42Z",
        order: 1,
        attribution: "unknown",
        observedDeltas: [
          {
            kind: "removed",
            recordId: "old-a",
            previous: {
              sourceArtifactId: "ime-app-workload",
              filePath:
                "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload.log",
            },
            incoming: null,
          },
          {
            kind: "added",
            recordId: "new-b",
            previous: null,
            incoming: {
              sourceArtifactId: "ime-app-workload",
              filePath:
                "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload-20260715.log",
            },
          },
        ],
        omittedDeltaCount: 0,
      },
    ]);
    expect(useEspDiagnosticsStore.getState().snapshot?.rawEvidence).toEqual(
      replacement.rawEvidence,
    );
    expect(
      useEspDiagnosticsStore
        .getState()
        .snapshot?.rawEvidence.some((record) =>
          record.recordId.includes("reset"),
        ),
    ).toBe(false);

    const later = makeSnapshot(["new-b", "new-c"]);
    later.rawEvidence[0] = structuredClone(replacement.rawEvidence[0]);
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(makeSessionUpdate(3, later));
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(2);
    expect(evidenceBoundaryMarkers()).toHaveLength(1);
    expect(evidenceBoundaryMarkers()[0].markerId).toBe(
      "source-reset:session-a:2",
    );
    expect(evidenceBoundaryMarkers()[0].order).toBe(1);
    expect(evidenceRecordRows().get("new-b")).toEqual({
      rowId: "evidence:2:new-b",
      order: 2,
    });
    expect(evidenceRecordRows().get("new-c")).toEqual({
      rowId: "evidence:3:new-c",
      order: 3,
    });
  });

  it("counts a changed same-ID reset record as unread and assigns a fresh row generation", () => {
    const initial = makeSnapshot(["same-id"]);
    const replacement = makeSnapshot(["same-id"]);
    replacement.rawEvidence[0].rawValue = { text: "replacement generation" };
    replacement.rawEvidence[0].provenance.filePath =
      "C:\\Windows\\Temp\\replacement.log";
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate(
      makeSessionUpdate(1, initial, "session-a", {
        reason: "initialSnapshot",
      }),
    );
    const initialRow = evidenceRecordRows().get("same-id");
    expect(initialRow).toEqual({
      rowId: "evidence:0:same-id",
      order: 0,
    });
    useEspDiagnosticsStore.getState().markEvidenceRead();

    useEspDiagnosticsStore.getState().applySessionUpdate(
      makeSessionUpdate(2, replacement, "session-a", {
        reason: "sourceReset",
      }),
    );

    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(1);
    expect(evidenceRecordRows().get("same-id")).toEqual({
      rowId: "evidence:2:same-id",
      order: 2,
    });
    expect(evidenceRecordRows().get("same-id")?.rowId).not.toBe(
      initialRow?.rowId,
    );
    expect(evidenceBoundaryMarkers()[0].observedDeltas).toEqual([
      {
        kind: "changed",
        recordId: "same-id",
        previous: {
          sourceArtifactId: "ime-app-workload",
          filePath:
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
        },
        incoming: {
          sourceArtifactId: "ime-app-workload",
          filePath: "C:\\Windows\\Temp\\replacement.log",
        },
      },
    ]);
  });

  it("records an unattributed zero-delta reset without inventing source provenance", () => {
    const unchanged = makeSnapshot(["same-id"]);
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate(
      makeSessionUpdate(1, unchanged, "session-a", {
        reason: "initialSnapshot",
      }),
    );
    useEspDiagnosticsStore.getState().markEvidenceRead();

    useEspDiagnosticsStore.getState().applySessionUpdate(
      makeSessionUpdate(2, structuredClone(unchanged), "session-a", {
        reason: "sourceReset",
      }),
    );

    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(0);
    expect(evidenceBoundaryMarkers()).toEqual([
      {
        markerId: "source-reset:session-a:2",
        kind: "sourceReset",
        emittedAtUtc: "2026-07-15T20:00:00Z",
        order: 1,
        attribution: "unknown",
        observedDeltas: [],
        omittedDeltaCount: 0,
      },
    ]);
    expect(evidenceRecordRows().get("same-id")).toEqual({
      rowId: "evidence:0:same-id",
      order: 0,
    });
  });

  it("bounds observed reset deltas and reports the omitted count", () => {
    const initial = makeSnapshot(
      Array.from({ length: 40 }, (_, index) => `old-${index}`),
    );
    const replacement = makeSnapshot(
      Array.from({ length: 40 }, (_, index) => `new-${index}`),
    );
    initial.rawEvidence.forEach((record, index) => {
      record.provenance.sourceArtifactId = `old-source-${index}`;
    });
    replacement.rawEvidence.forEach((record, index) => {
      record.provenance.sourceArtifactId = `new-source-${index}`;
    });
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate(
      makeSessionUpdate(1, initial, "session-a", {
        reason: "initialSnapshot",
      }),
    );

    useEspDiagnosticsStore.getState().applySessionUpdate(
      makeSessionUpdate(2, replacement, "session-a", {
        reason: "sourceReset",
      }),
    );

    const marker = evidenceBoundaryMarkers()[0];
    expect(marker.observedDeltas).toHaveLength(32);
    expect(marker.omittedDeltaCount).toBe(48);
    expect(marker.observedDeltas[0]).toMatchObject({
      kind: "removed",
      recordId: "old-0",
      previous: { sourceArtifactId: "old-source-0" },
      incoming: null,
    });
  });

  it("bounds reset-marker history and clears it for every new local run", () => {
    const markerLimit = ESP_EVIDENCE_BOUNDARY_MARKER_LIMIT;
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate(
      makeSessionUpdate(1, makeSnapshot(["record-1"]), "session-a", {
        reason: "initialSnapshot",
      }),
    );

    for (let sequence = 2; sequence <= markerLimit + 7; sequence += 1) {
      useEspDiagnosticsStore
        .getState()
        .applySessionUpdate(
          makeSessionUpdate(
            sequence,
            makeSnapshot([`record-${sequence}`]),
            "session-a",
            { reason: "sourceReset" },
          ),
        );
    }

    expect(evidenceBoundaryMarkers()).toHaveLength(markerLimit);
    expect(evidenceBoundaryMarkers()[0].markerId).toBe(
      "source-reset:session-a:8",
    );
    const retainedMarkers = evidenceBoundaryMarkers();
    expect(retainedMarkers[retainedMarkers.length - 1]?.markerId).toBe(
      "source-reset:session-a:71",
    );

    useEspDiagnosticsStore.getState().beginLiveStart("live-b");
    expect(evidenceBoundaryMarkers()).toEqual([]);
    expect(evidenceRecordRows()).toEqual(new Map());
    expect(useEspDiagnosticsStore.getState().nextEvidenceOrder).toBe(0);
    useEspDiagnosticsStore.getState().applySessionUpdate(
      makeSessionUpdate(1, makeSnapshot(["session-b"]), "session-b", {
        requestId: "live-b",
        reason: "sourceReset",
      }),
    );
    expect(evidenceBoundaryMarkers()).toHaveLength(1);

    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    expect(evidenceBoundaryMarkers()).toEqual([]);
    expect(evidenceRecordRows()).toEqual(new Map());
    expect(useEspDiagnosticsStore.getState().nextEvidenceOrder).toBe(0);
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

    expect(
      isEspSessionUpdate({
        ...update,
        snapshot: { ...update.snapshot, workloads: [null] },
      }),
    ).toBe(false);
    expect(
      isEspSessionUpdate({
        ...update,
        snapshot: {
          ...update.snapshot,
          workloads: [{ workloadId: "workload-a", rawIdentifier: 42 }],
        },
      }),
    ).toBe(false);
    expect(
      isEspSessionUpdate({
        ...update,
        snapshot: {
          ...update.snapshot,
          rawEvidence: ["not-an-evidence-record"],
        },
      }),
    ).toBe(false);
    expect(
      isEspSessionUpdate({
        ...update,
        snapshot: {
          ...update.snapshot,
          rawEvidence: [{ provenance: { sourceArtifactId: null } }],
        },
      }),
    ).toBe(false);

    const invalidSnapshots: unknown[] = [
      { ...update.snapshot, schemaVersion: 2 },
      { ...update.snapshot, identity: {} },
      { ...update.snapshot, coverage: undefined },
      {
        ...update.snapshot,
        workloads: [{ workloadId: "missing-required-workload-fields" }],
      },
      {
        ...update.snapshot,
        rawEvidence: [{ recordId: "missing-required-evidence-fields" }],
      },
      {
        ...update.snapshot,
        rawEvidence: [
          {
            ...update.snapshot.rawEvidence[0],
            rawValue: { integer: 1.5 },
          },
        ],
      },
      {
        ...update.snapshot,
        rawEvidence: [
          {
            ...update.snapshot.rawEvidence[0],
            rawValue: { unsigned: -1 },
          },
        ],
      },
      {
        ...update.snapshot,
        rawEvidence: [
          {
            ...update.snapshot.rawEvidence[0],
            provenance: {
              ...update.snapshot.rawEvidence[0].provenance,
              lineNumber: 2.5,
            },
          },
        ],
      },
      {
        ...update.snapshot,
        graph: {
          ...makeOverlay("graph-malformed"),
          deviceMatch: {
            ...makeOverlay("graph-malformed").deviceMatch,
            data: { selected: {}, candidates: [] },
          },
        },
      },
    ];

    for (const snapshot of invalidSnapshots) {
      expect(
        isEspSessionUpdate({ ...update, snapshot }),
        JSON.stringify(snapshot),
      ).toBe(false);
    }
  });
});

describe("ESP Graph overlay state", () => {
  it("invalidates a pending Graph request when live identity changes", () => {
    useEspDiagnosticsStore.getState().beginLiveStart("live-a");
    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(
        makeSessionUpdate(1, makeSnapshot(["device-a"], "device-a")),
      );
    useEspDiagnosticsStore.getState().beginGraph("graph-device-a");

    useEspDiagnosticsStore
      .getState()
      .applySessionUpdate(
        makeSessionUpdate(2, makeSnapshot(["device-b"], "device-b")),
      );

    expect(useEspDiagnosticsStore.getState().graphRequestId).toBeNull();
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("idle");
    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-device-a", makeOverlay("graph-device-a"));
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    expect(
      useEspDiagnosticsStore.getState().snapshot?.identity.deviceName,
    ).toBe("host-device-b");
  });

  it("preserves disabled Graph availability when analysis fails before producing a snapshot", () => {
    useEspDiagnosticsStore.getState().setGraphUnavailable("graphDisabled");

    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");

    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("disabled");
    expect(useEspDiagnosticsStore.getState().graphUnavailableReason).toBe(
      "graphDisabled",
    );

    useEspDiagnosticsStore.getState().fail("analysis-a", "Import failed");

    expect(useEspDiagnosticsStore.getState().snapshot).toBeNull();
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("disabled");
    expect(useEspDiagnosticsStore.getState().graphUnavailableReason).toBe(
      "graphDisabled",
    );
  });

  it("preserves not-connected Graph availability when live start fails before its first snapshot", () => {
    useEspDiagnosticsStore.getState().setGraphUnavailable("graphNotConnected");

    useEspDiagnosticsStore.getState().beginLiveStart("live-a");

    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("unavailable");
    expect(useEspDiagnosticsStore.getState().graphUnavailableReason).toBe(
      "graphNotConnected",
    );

    useEspDiagnosticsStore.getState().fail("live-a", "Live start failed");

    expect(useEspDiagnosticsStore.getState().snapshot).toBeNull();
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("unavailable");
    expect(useEspDiagnosticsStore.getState().graphUnavailableReason).toBe(
      "graphNotConnected",
    );
  });

  it("reports a failed optional app-intent cross-check as partial without losing primary apps", () => {
    const overlay = makeOverlay("graph-app-intent-partial");
    overlay.apps = {
      status: "available",
      requiredScope: "DeviceManagementApps.Read.All",
      apiVersion: "v1.0",
      data: [
        {
          appId: "app-a",
          displayName: "Primary App",
          trackedOnEnrollmentStatus: true,
          status: null,
          intentState: {
            status: "permissionDenied",
            requiredScope: "DeviceManagementConfiguration.Read.All",
            apiVersion: "beta",
            data: null,
            error: {
              code: "PermissionDenied",
              message: "Microsoft Graph could not provide this section.",
              requestId: "graph-request-error",
              blockedBy: null,
              retryAfterSeconds: null,
            },
          },
          assignments: [],
          evidence: [],
        },
      ],
      error: null,
    };
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-app-intent");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-app-intent", makeSnapshot(["local-app"]));
    useEspDiagnosticsStore.getState().beginGraph("graph-app-intent-partial");

    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-app-intent-partial", overlay);

    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("partial");
    expect(
      useEspDiagnosticsStore.getState().snapshot?.graph?.apps.data?.[0]
        .displayName,
    ).toBe("Primary App");
  });

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
    useEspDiagnosticsStore.getState().beginGraph("graph-unknown-wire-values");
    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-unknown-wire-values", overlay);

    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.scripts).toEqual(
      overlay.scripts,
    );
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("partial");
  });

  it("rejects a native Graph overlay whose embedded request ID is mismatched", () => {
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));
    useEspDiagnosticsStore.getState().beginGraph("graph-active");

    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-active", makeOverlay("graph-other"));

    expect(useEspDiagnosticsStore.getState().graphRequestId).toBe(
      "graph-active",
    );
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("loading");
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
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
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("local-a");
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
  it("sends only typed canonical Graph identifiers from local evidence to the provider", async () => {
    const appA = "11111111-1111-4111-8111-111111111111";
    const appB = "22222222-2222-4222-8222-222222222222";
    const msiProductCode = "33333333-3333-4333-8333-333333333333";
    const officeProduct = "44444444-4444-4444-8444-444444444444";
    const policy = "55555555-5555-4555-8555-555555555555";
    const certificate = "66666666-6666-4666-8666-666666666666";
    const script = "77777777-7777-4777-8777-777777777777";
    const profileScript = "88888888-8888-4888-8888-888888888888";
    const deploymentProfile = "99999999-9999-4999-8999-999999999999";
    const correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const localEnrollment = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-local-contract",
    });
    const snapshot = makeSnapshot(["local-contract"]);
    snapshot.workloads = [
      makeWorkload("win32App", `  ${appA.toUpperCase()}  `),
      makeWorkload("modernApp", appA),
      makeWorkload("devicePreparationWorkload", appB),
      makeWorkload("msi", msiProductCode),
      makeWorkload("office", officeProduct),
      makeWorkload("policy", policy),
      makeWorkload("scepCertificate", certificate),
      makeWorkload("platformScript", script),
      makeWorkload("win32App", "not-a-guid"),
      makeWorkload("policy", "   ", "internal-policy-workload"),
    ];
    snapshot.profile = {
      profileName: "Local profile",
      deploymentProfileId: deploymentProfile,
      correlationId: correlation,
      tenantDomain: null,
      tenantId: null,
      oobeConfig: null,
      profileDownloadTime: null,
      joinMode: null,
      odjApplied: null,
      skipDomainConnectivityCheck: null,
      devicePreparation: {
        agentDownloadTimeoutSeconds: null,
        pageTimeoutSeconds: null,
        allowSkipOnFailure: null,
        allowDiagnostics: null,
        scriptIds: [profileScript, ` ${profileScript.toUpperCase()} `, "bad"],
        evidence: [],
      },
      evidence: [],
    };
    snapshot.enrollments = [
      {
        enrollmentId: localEnrollment,
        providerId: deploymentProfile,
        tenantId: null,
        userPrincipalName: null,
        entdmId: null,
        settings: {
          deviceEspEnabled: null,
          userEspEnabled: null,
          timeoutSeconds: null,
          blocking: null,
          allowReset: null,
          allowRetry: null,
          continueAnyway: null,
        },
        evidence: [],
      },
    ];
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-local-contract");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-local-contract", snapshot);

    await coordinator.reconcile();

    expect(fetchGraph).toHaveBeenCalledWith({
      requestId: "graph-local-contract",
      identity: snapshot.identity,
      workloadIds: [appA, appB],
      selectedManagedDeviceId: null,
      evidenceWindowStartUtc: null,
      evidenceWindowEndUtc: null,
      enrollmentConfigurationIds: [],
      appIds: [appA, appB],
      policyReferences: [
        { id: policy, kind: "deviceConfiguration" },
        { id: certificate, kind: "scepCertificate" },
      ],
      scriptReferences: [
        { id: script, kind: "platformScript" },
        { id: profileScript, kind: "platformScript" },
      ],
    });
    const request = fetchGraph.mock.calls[0][0] as unknown as Record<
      string,
      unknown
    >;
    expect(JSON.stringify(request)).not.toContain(msiProductCode);
    expect(JSON.stringify(request)).not.toContain(officeProduct);
    expect(JSON.stringify(request)).not.toContain(deploymentProfile);
    expect(JSON.stringify(request)).not.toContain(correlation);
    expect(JSON.stringify(request)).not.toContain(localEnrollment);
    expect(JSON.stringify(request)).not.toContain("internal-policy-workload");
    coordinator.dispose();
  });

  it.each([
    ["policy", "scepCertificate"],
    ["scepCertificate", "policy"],
  ] as const)(
    "preserves conflicting policy kinds for one canonical ID in %s-first evidence",
    async (firstKind, secondKind) => {
      const sharedId = "abababab-abab-4bab-8bab-abababababab";
      const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
        makeOverlay(request.requestId),
      );
      const coordinator = createEspGraphCoordinator({
        fetchGraph,
        cancelGraph: vi.fn(async () => undefined),
        createRequestId: () => `graph-${firstKind}-first`,
      });
      const snapshot = makeSnapshot([`local-${firstKind}-first`]);
      snapshot.workloads = [
        makeWorkload(firstKind, sharedId, `workload-${firstKind}`),
        makeWorkload(secondKind, sharedId, `workload-${secondKind}`),
      ];
      useUiStore.setState({
        graphApiEnabled: true,
        graphApiStatus: "connected",
      });
      useEspDiagnosticsStore
        .getState()
        .beginAnalysis(`analysis-${firstKind}-first`);
      useEspDiagnosticsStore
        .getState()
        .applyAnalysis(`analysis-${firstKind}-first`, snapshot);

      await coordinator.reconcile();

      expect(fetchGraph).toHaveBeenCalledWith(
        expect.objectContaining({
          policyReferences: [
            { id: sharedId, kind: "deviceConfiguration" },
            { id: sharedId, kind: "scepCertificate" },
          ],
        }),
      );
      coordinator.dispose();
    },
  );

  it("refines typed references from prior Graph enrollment and profile evidence", async () => {
    const selectedManagedDevice = "10101010-1010-4010-8010-101010101010";
    const localApp = "11111111-1111-4111-8111-111111111111";
    const profileApp = "12121212-1212-4212-8212-121212121212";
    const intendedProfileApp = "13131313-1313-4313-8313-131313131313";
    const enrollmentApp = "14141414-1414-4414-8414-141414141414";
    const remoteApp = "15151515-1515-4515-8515-151515151515";
    const enrollmentA = "20202020-2020-4020-8020-202020202020";
    const enrollmentB = "21212121-2121-4121-8121-212121212121";
    const deviceConfiguration = "30303030-3030-4030-8030-303030303030";
    const compliance = "31313131-3131-4131-8131-313131313131";
    const configurationPolicy = "32323232-3232-4232-8232-323232323232";
    const certificate = "33333333-3333-4333-8333-333333333333";
    const platformScript = "40404040-4040-4040-8040-404040404040";
    const remediation = "41414141-4141-4141-8141-414141414141";
    const localDeploymentProfile = "50505050-5050-4050-8050-505050505050";
    const localCorrelation = "51515151-5151-4151-8151-515151515151";
    const overlay = makeOverlay("prior-overlay");
    overlay.deviceMatch.data!.selected!.managedDeviceId = ` ${selectedManagedDevice.toUpperCase()} `;
    overlay.deploymentProfile = availableGraphSection({
      profileId: "60606060-6060-4060-8060-606060606060",
      displayName: "Assigned profile",
      joinMode: "entra",
      selectedMobileAppIds: [profileApp, "not-an-app-id"],
      evidence: [],
    });
    overlay.intendedDeploymentProfile = availableGraphSection({
      profileId: "61616161-6161-4161-8161-616161616161",
      displayName: "Intended profile",
      joinMode: "entra",
      selectedMobileAppIds: [intendedProfileApp, profileApp.toUpperCase()],
      evidence: [],
    });
    overlay.autopilotEvents = availableGraphSection([
      {
        eventId: "event-a",
        managedDeviceId: selectedManagedDevice,
        enrollmentConfigurationId: enrollmentA,
        eventTime: null,
        deploymentState: {
          raw: "success",
          normalized: "succeeded",
          display: "success",
          detail: null,
        },
        policyStatusDetails: [],
        evidence: [],
      },
      {
        eventId: "event-b",
        managedDeviceId: selectedManagedDevice,
        enrollmentConfigurationId: enrollmentB.toUpperCase(),
        eventTime: null,
        deploymentState: {
          raw: "success",
          normalized: "succeeded",
          display: "success",
          detail: null,
        },
        policyStatusDetails: [],
        evidence: [],
      },
      {
        eventId: "event-invalid",
        managedDeviceId: selectedManagedDevice,
        enrollmentConfigurationId: "not-a-configuration-id",
        eventTime: null,
        deploymentState: {
          raw: "unknown",
          normalized: "unknown",
          display: "unknown",
          detail: null,
        },
        policyStatusDetails: [],
        evidence: [],
      },
    ]);
    overlay.enrollmentConfiguration = availableGraphSection({
      configurationId: enrollmentA.toUpperCase(),
      displayName: "ESP",
      showInstallationProgress: true,
      deviceEspEnabled: null,
      userEspEnabled: null,
      disableUserStatusTrackingAfterFirstUser: false,
      timeoutMinutes: 60,
      selectedMobileAppIds: [enrollmentApp, profileApp],
      assignments: [],
      evidence: [],
    });
    overlay.apps = availableGraphSection(
      [remoteApp, "invalid-app"].map((appId) => ({
        appId,
        displayName: null,
        trackedOnEnrollmentStatus: null,
        status: null,
        intentState: {
          status: "notFound" as const,
          requiredScope: null,
          apiVersion: "beta" as const,
          data: null,
          error: null,
        },
        assignments: [],
        evidence: [],
      })),
      "v1.0",
    );
    overlay.policies = availableGraphSection([
      {
        policyId: deviceConfiguration,
        displayName: null,
        kind: "deviceConfiguration",
        status: null,
        assignments: [],
        evidence: [],
      },
      {
        policyId: compliance,
        displayName: null,
        kind: "compliance",
        status: null,
        assignments: [],
        evidence: [],
      },
      {
        policyId: configurationPolicy,
        displayName: null,
        kind: "configurationPolicy",
        status: null,
        assignments: [],
        evidence: [],
      },
      {
        policyId: certificate,
        displayName: null,
        kind: "scepCertificate",
        status: null,
        assignments: [],
        evidence: [],
      },
      {
        policyId: "invalid-policy",
        displayName: null,
        kind: "compliance",
        status: null,
        assignments: [],
        evidence: [],
      },
    ]);
    overlay.scripts = availableGraphSection([
      {
        scriptId: platformScript,
        displayName: null,
        kind: "platformScript",
        status: null,
        assignments: [],
        evidence: [],
      },
      {
        scriptId: remediation,
        displayName: null,
        kind: "remediation",
        status: null,
        assignments: [],
        evidence: [],
      },
      {
        scriptId: "invalid-script",
        displayName: null,
        kind: "remediation",
        status: null,
        assignments: [],
        evidence: [],
      },
    ]);
    const snapshot = makeSnapshot(["overlay-contract"]);
    snapshot.workloads = [
      makeWorkload("win32App", localApp),
      makeWorkload("policy", compliance),
      makeWorkload("platformScript", remediation),
    ];
    snapshot.profile = {
      profileName: "Local profile",
      deploymentProfileId: localDeploymentProfile,
      correlationId: localCorrelation,
      tenantDomain: null,
      tenantId: null,
      oobeConfig: null,
      profileDownloadTime: null,
      joinMode: null,
      odjApplied: null,
      skipDomainConnectivityCheck: null,
      devicePreparation: null,
      evidence: [],
    };
    snapshot.graph = overlay;
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-overlay-contract",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore
      .getState()
      .beginAnalysis("analysis-overlay-contract");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-overlay-contract", snapshot);

    await coordinator.reconcile();

    expect(fetchGraph).toHaveBeenCalledWith({
      requestId: "graph-overlay-contract",
      identity: snapshot.identity,
      workloadIds: [
        localApp,
        profileApp,
        intendedProfileApp,
        enrollmentApp,
        remoteApp,
      ].sort(),
      selectedManagedDeviceId: selectedManagedDevice,
      evidenceWindowStartUtc: null,
      evidenceWindowEndUtc: null,
      enrollmentConfigurationIds: [enrollmentA, enrollmentB],
      appIds: [
        localApp,
        profileApp,
        intendedProfileApp,
        enrollmentApp,
        remoteApp,
      ].sort(),
      policyReferences: [
        { id: deviceConfiguration, kind: "deviceConfiguration" },
        { id: compliance, kind: "compliance" },
        { id: configurationPolicy, kind: "configurationPolicy" },
        { id: certificate, kind: "scepCertificate" },
      ],
      scriptReferences: [
        { id: platformScript, kind: "platformScript" },
        { id: remediation, kind: "remediation" },
      ],
    });
    const serialized = JSON.stringify(fetchGraph.mock.calls[0][0]);
    expect(serialized).not.toContain(localDeploymentProfile);
    expect(serialized).not.toContain(localCorrelation);
    expect(serialized).not.toContain("invalid-");
    coordinator.dispose();
  });

  it("sends the latest local ESP session window with Graph event requests", async () => {
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-window",
    });
    const snapshot = makeSnapshot(["local-window"]);
    snapshot.sessions = [
      {
        sessionId: "older",
        kind: "classic",
        scope: "device",
        userSid: null,
        startedAt: {
          rawText: "2026-07-14T08:00:00-04:00",
          originalOffset: "-04:00",
          normalizedUtc: "2026-07-14T12:00:00Z",
          kind: "offset",
        },
        endedAt: null,
        phase: "completed",
        isLatest: false,
        workloadIds: [],
        evidence: [],
      },
      {
        sessionId: "latest",
        kind: "classic",
        scope: "device",
        userSid: null,
        startedAt: {
          rawText: "2026-07-15T14:00:00",
          originalOffset: null,
          normalizedUtc: "2026-07-15T18:00:00Z",
          kind: "unspecified",
        },
        endedAt: {
          rawText: "2026-07-15T15:00:00",
          originalOffset: null,
          normalizedUtc: "2026-07-15T19:00:00Z",
          kind: "unspecified",
        },
        phase: "failed",
        isLatest: true,
        workloadIds: [],
        evidence: [],
      },
    ];
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-window");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-window", snapshot);

    await coordinator.reconcile();

    expect(fetchGraph).toHaveBeenCalledWith(
      expect.objectContaining({
        evidenceWindowStartUtc: "2026-07-15T18:00:00.000Z",
        evidenceWindowEndUtc: "2026-07-15T19:00:00.000Z",
      }),
    );
    coordinator.dispose();
  });

  it("never interprets offset-free raw evidence timestamps in the analyst timezone", async () => {
    vi.stubEnv("TZ", "Pacific/Kiritimati");
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-offset-free-window",
    });
    try {
      const snapshot = makeSnapshot(["local-offset-free-window"]);
      snapshot.sessions = [
        {
          sessionId: "offset-free",
          kind: "classic",
          scope: "device",
          userSid: null,
          startedAt: {
            rawText: "2026-07-15T14:00:00",
            originalOffset: null,
            normalizedUtc: null,
            kind: "unspecified",
          },
          endedAt: {
            rawText: "2026-07-15T15:00:00",
            originalOffset: null,
            normalizedUtc: null,
            kind: "unspecified",
          },
          phase: "failed",
          isLatest: true,
          workloadIds: [],
          evidence: [],
        },
      ];
      useUiStore.setState({
        graphApiEnabled: true,
        graphApiStatus: "connected",
      });
      useEspDiagnosticsStore
        .getState()
        .beginAnalysis("analysis-offset-free-window");
      useEspDiagnosticsStore
        .getState()
        .applyAnalysis("analysis-offset-free-window", snapshot);

      await coordinator.reconcile();

      expect(fetchGraph).toHaveBeenCalledWith(
        expect.objectContaining({
          evidenceWindowStartUtc: null,
          evidenceWindowEndUtc: null,
        }),
      );
    } finally {
      coordinator.dispose();
      vi.unstubAllEnvs();
    }
  });

  it("normalizes strict raw RFC3339 offsets independently of the analyst timezone", async () => {
    vi.stubEnv("TZ", "America/Los_Angeles");
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-explicit-offset-window",
    });
    try {
      const snapshot = makeSnapshot(["local-explicit-offset-window"]);
      snapshot.sessions = [
        {
          sessionId: "explicit-offset",
          kind: "classic",
          scope: "device",
          userSid: null,
          startedAt: {
            rawText: "2026-07-15T14:00:00+05:30",
            originalOffset: "+05:30",
            normalizedUtc: "2026-07-15T14:00:00",
            kind: "offset",
          },
          endedAt: {
            rawText: "2026-07-15T15:00:00+05:30",
            originalOffset: "+05:30",
            normalizedUtc: "2026-07-15T15:00:00",
            kind: "offset",
          },
          phase: "failed",
          isLatest: true,
          workloadIds: [],
          evidence: [],
        },
      ];
      useUiStore.setState({
        graphApiEnabled: true,
        graphApiStatus: "connected",
      });
      useEspDiagnosticsStore
        .getState()
        .beginAnalysis("analysis-explicit-offset-window");
      useEspDiagnosticsStore
        .getState()
        .applyAnalysis("analysis-explicit-offset-window", snapshot);

      await coordinator.reconcile();

      expect(fetchGraph).toHaveBeenCalledWith(
        expect.objectContaining({
          evidenceWindowStartUtc: "2026-07-15T08:30:00.000Z",
          evidenceWindowEndUtc: "2026-07-15T09:30:00.000Z",
        }),
      );
    } finally {
      coordinator.dispose();
      vi.unstubAllEnvs();
    }
  });

  it.each([
    "0000-07-15T14:00:00Z",
    "2026-00-15T14:00:00Z",
    "2026-13-15T14:00:00Z",
    "2026-04-31T14:00:00Z",
    "2025-02-29T14:00:00Z",
    "2026-07-15T24:00:00Z",
    "2026-07-15T14:60:00Z",
    "2026-07-15T14:00:60Z",
    "2026-07-15T14:00:00+24:00",
    "2026-07-15T14:00:00+05:60",
    "2026-07-15T14:00:00-00:00",
  ])(
    "rejects semantically invalid normalized RFC3339 %s and falls back to valid raw evidence",
    async (invalidNormalizedUtc) => {
      const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
        makeOverlay(request.requestId),
      );
      const coordinator = createEspGraphCoordinator({
        fetchGraph,
        cancelGraph: vi.fn(async () => undefined),
        createRequestId: () => "graph-invalid-normalized-window",
      });
      const snapshot = makeSnapshot(["local-invalid-normalized-window"]);
      snapshot.sessions = [
        {
          sessionId: "invalid-normalized",
          kind: "classic",
          scope: "device",
          userSid: null,
          startedAt: {
            rawText: "2026-07-15T14:00:00+05:30",
            originalOffset: "+05:30",
            normalizedUtc: invalidNormalizedUtc,
            kind: "offset",
          },
          endedAt: {
            rawText: "2026-07-15T15:00:00+05:30",
            originalOffset: "+05:30",
            normalizedUtc: invalidNormalizedUtc,
            kind: "offset",
          },
          phase: "failed",
          isLatest: true,
          workloadIds: [],
          evidence: [],
        },
      ];
      useUiStore.setState({
        graphApiEnabled: true,
        graphApiStatus: "connected",
      });
      useEspDiagnosticsStore
        .getState()
        .beginAnalysis("analysis-invalid-normalized-window");
      useEspDiagnosticsStore
        .getState()
        .applyAnalysis("analysis-invalid-normalized-window", snapshot);

      await coordinator.reconcile();

      expect(fetchGraph).toHaveBeenCalledWith(
        expect.objectContaining({
          evidenceWindowStartUtc: "2026-07-15T08:30:00.000Z",
          evidenceWindowEndUtc: "2026-07-15T09:30:00.000Z",
        }),
      );
      coordinator.dispose();
    },
  );

  it("omits an evidence window whose only claimed offset is RFC3339 unknown local offset", async () => {
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-unknown-offset-window",
    });
    const snapshot = makeSnapshot(["local-unknown-offset-window"]);
    snapshot.sessions = [
      {
        sessionId: "unknown-offset",
        kind: "classic",
        scope: "device",
        userSid: null,
        startedAt: {
          rawText: "2026-07-15T14:00:00-00:00",
          originalOffset: "-00:00",
          normalizedUtc: "2026-07-15T14:00:00Z",
          kind: "offset",
        },
        endedAt: null,
        phase: "failed",
        isLatest: true,
        workloadIds: [],
        evidence: [],
      },
    ];
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore
      .getState()
      .beginAnalysis("analysis-unknown-offset-window");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-unknown-offset-window", snapshot);

    await coordinator.reconcile();

    expect(fetchGraph).toHaveBeenCalledWith(
      expect.objectContaining({
        evidenceWindowStartUtc: null,
        evidenceWindowEndUtc: null,
      }),
    );
    coordinator.dispose();
  });

  it("omits the evidence window when normalized and raw RFC3339 dates are impossible", async () => {
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-impossible-window",
    });
    const snapshot = makeSnapshot(["local-impossible-window"]);
    snapshot.sessions = [
      {
        sessionId: "impossible",
        kind: "classic",
        scope: "device",
        userSid: null,
        startedAt: {
          rawText: "2026-02-30T14:00:00+05:30",
          originalOffset: "+05:30",
          normalizedUtc: "2026-02-30T08:30:00Z",
          kind: "offset",
        },
        endedAt: null,
        phase: "failed",
        isLatest: true,
        workloadIds: [],
        evidence: [],
      },
    ];
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore
      .getState()
      .beginAnalysis("analysis-impossible-window");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-impossible-window", snapshot);

    await coordinator.reconcile();

    expect(fetchGraph).toHaveBeenCalledWith(
      expect.objectContaining({
        evidenceWindowStartUtc: null,
        evidenceWindowEndUtc: null,
      }),
    );
    coordinator.dispose();
  });

  it("keeps Graph disabled without fetching and removes only the remote overlay", async () => {
    const fetchGraph =
      vi.fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>();
    const cancelGraph = vi.fn<(requestId: string) => Promise<void>>();
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore.getState().applyAnalysis("analysis-a", {
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
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("local-a");
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

  it("reuses an explicit managed-device selection on later generic refreshes", async () => {
    const requestIds = ["graph-selected", "graph-refreshed"];
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlayWithSelectedDevice(
        request.requestId,
        request.selectedManagedDeviceId ?? "managed-default",
      ),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: makeSnapshot(["local-a"]),
    });

    await coordinator.refresh(GRAPH_MANAGED_DEVICE_B);
    await coordinator.refresh();

    expect(
      fetchGraph.mock.calls.map(([request]) => request.selectedManagedDeviceId),
    ).toEqual([GRAPH_MANAGED_DEVICE_B, GRAPH_MANAGED_DEVICE_B]);
    coordinator.dispose();
  });

  it("reuses the current overlay selection when reconciling the same identity", async () => {
    const snapshot = makeSnapshot(["local-a"]);
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlayWithSelectedDevice(
        request.requestId,
        request.selectedManagedDeviceId ?? "managed-default",
      ),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-reconciled",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: {
        ...snapshot,
        graph: makeOverlayWithSelectedDevice(
          "graph-existing",
          GRAPH_MANAGED_DEVICE_B,
        ),
      },
    });

    await coordinator.reconcile();

    expect(fetchGraph).toHaveBeenCalledWith(
      expect.objectContaining({
        selectedManagedDeviceId: GRAPH_MANAGED_DEVICE_B,
      }),
    );
    coordinator.dispose();
  });

  it("clears an explicit selection when the local identity changes", async () => {
    const requestIds = ["graph-device-a", "graph-device-b"];
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlayWithSelectedDevice(
        request.requestId,
        request.selectedManagedDeviceId ?? "managed-default",
      ),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: makeSnapshot(["local-a"], "device-a"),
    });

    await coordinator.refresh(GRAPH_MANAGED_DEVICE_B);
    useEspDiagnosticsStore.setState({
      snapshot: makeSnapshot(["local-b"], "device-b"),
    });
    await coordinator.refresh();

    expect(
      fetchGraph.mock.calls.map(([request]) => request.selectedManagedDeviceId),
    ).toEqual([GRAPH_MANAGED_DEVICE_B, null]);
    coordinator.dispose();
  });

  it("clears an explicit selection for a replacement analysis of the same identity", async () => {
    const requestIds = ["graph-first-analysis", "graph-second-analysis"];
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlayWithSelectedDevice(
        request.requestId,
        request.selectedManagedDeviceId ?? "managed-default",
      ),
    );
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-first");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-first",
        makeSnapshot(["local-first"], "same-device"),
      );

    await coordinator.refresh(GRAPH_MANAGED_DEVICE_B);
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-second");
    await coordinator.reconcile();
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-second",
        makeSnapshot(["local-second"], "same-device"),
      );
    await coordinator.refresh();

    expect(
      fetchGraph.mock.calls.map(([request]) => request.selectedManagedDeviceId),
    ).toEqual([GRAPH_MANAGED_DEVICE_B, null]);
    coordinator.dispose();
  });

  it("preserves an explicit selection across manual cancellation while rejecting the late result", async () => {
    const lateOverlay = deferred<EspGraphOverlay>();
    const requestIds = ["graph-cancelled", "graph-after-cancel"];
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(() => lateOverlay.promise)
      .mockImplementationOnce(async (request) =>
        makeOverlayWithSelectedDevice(
          request.requestId,
          request.selectedManagedDeviceId ?? "managed-default",
        ),
      );
    const cancelGraph = vi.fn(async () => undefined);
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: makeSnapshot(["local-a"]),
    });

    const cancelled = coordinator.refresh(GRAPH_MANAGED_DEVICE_B);
    expect(fetchGraph).toHaveBeenCalledTimes(1);
    await coordinator.cancel();
    await coordinator.refresh();
    lateOverlay.resolve(
      makeOverlayWithSelectedDevice("graph-cancelled", GRAPH_MANAGED_DEVICE_B),
    );
    await cancelled;

    expect(cancelGraph).toHaveBeenCalledWith("graph-cancelled");
    expect(
      fetchGraph.mock.calls.map(([request]) => request.selectedManagedDeviceId),
    ).toEqual([GRAPH_MANAGED_DEVICE_B, GRAPH_MANAGED_DEVICE_B]);
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-after-cancel",
    );
    coordinator.dispose();
  });

  it("clears selection on disable and keeps a late pre-disable result stale after re-enable", async () => {
    const lateOverlay = deferred<EspGraphOverlay>();
    const requestIds = ["graph-before-disable", "graph-after-enable"];
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(() => lateOverlay.promise)
      .mockImplementationOnce(async (request) =>
        makeOverlayWithSelectedDevice(
          request.requestId,
          request.selectedManagedDeviceId ?? "managed-default",
        ),
      );
    const cancelGraph = vi.fn(async () => undefined);
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: makeSnapshot(["local-a"]),
    });

    const stale = coordinator.refresh(GRAPH_MANAGED_DEVICE_B);
    expect(fetchGraph).toHaveBeenCalledTimes(1);
    useUiStore.setState({ graphApiEnabled: false });
    await coordinator.reconcile();
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    await coordinator.refresh();
    lateOverlay.resolve(
      makeOverlayWithSelectedDevice(
        "graph-before-disable",
        GRAPH_MANAGED_DEVICE_B,
      ),
    );
    await stale;

    expect(cancelGraph).toHaveBeenCalledWith("graph-before-disable");
    expect(fetchGraph.mock.calls[1]?.[0].selectedManagedDeviceId).toBeNull();
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-after-enable",
    );
    coordinator.dispose();
  });

  it("does not restore a selected overlay when Graph is re-enabled during deferred cancellation", async () => {
    const activeOverlay = deferred<EspGraphOverlay>();
    const disableCancellation = deferred<void>();
    const requestIds = [
      "graph-selected",
      "graph-before-disable",
      "graph-after-enable",
    ];
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(async (request) =>
        makeOverlayWithSelectedDevice(
          request.requestId,
          request.selectedManagedDeviceId ?? "managed-default",
        ),
      )
      .mockImplementationOnce(() => activeOverlay.promise)
      .mockImplementationOnce(async (request) =>
        makeOverlayWithSelectedDevice(
          request.requestId,
          request.selectedManagedDeviceId ?? "managed-default",
        ),
      );
    const cancelGraph = vi.fn(() => disableCancellation.promise);
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: makeSnapshot(["local-a"]),
    });

    await coordinator.refresh(GRAPH_MANAGED_DEVICE_B);
    coordinator.start();
    const stale = coordinator.refresh();
    await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(2));

    useUiStore.setState({ graphApiEnabled: false });
    await vi.waitFor(() =>
      expect(cancelGraph).toHaveBeenCalledWith("graph-before-disable"),
    );
    useUiStore.setState({
      graphApiEnabled: true,
      graphApiStatus: "connected",
    });

    disableCancellation.resolve();
    await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(3));
    activeOverlay.resolve(
      makeOverlayWithSelectedDevice(
        "graph-before-disable",
        GRAPH_MANAGED_DEVICE_B,
      ),
    );
    await stale;
    const selectedManagedDeviceId =
      fetchGraph.mock.calls[2]?.[0].selectedManagedDeviceId;
    const appliedRequestId =
      useEspDiagnosticsStore.getState().snapshot?.graph?.requestId;
    coordinator.dispose();

    expect(selectedManagedDeviceId).toBeNull();
    expect(appliedRequestId).toBe("graph-after-enable");
  });

  it("invalidates a captured selection when a same-identity analysis begins during cancellation", async () => {
    const activeCancellation = deferred<void>();
    const orphanCancellation = deferred<void>();
    const requestIds = ["graph-selected", "graph-replacement"];
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlayWithSelectedDevice(
        request.requestId,
        request.selectedManagedDeviceId ?? "managed-default",
      ),
    );
    const cancelGraph = vi
      .fn<(requestId: string) => Promise<void>>()
      .mockImplementationOnce(() => activeCancellation.promise)
      .mockImplementationOnce(() => orphanCancellation.promise);
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: makeSnapshot(["local-first"], "same-device"),
    });

    await coordinator.refresh(GRAPH_MANAGED_DEVICE_B);
    coordinator.start();
    useEspDiagnosticsStore.setState({
      graphRequestId: "graph-active",
      graphPhase: "loading",
    });

    const staleRefresh = coordinator.refresh();
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-second");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-second",
        makeSnapshot(["local-second"], "same-device"),
      );
    expect(cancelGraph.mock.calls).toEqual([
      ["graph-active"],
      ["graph-active"],
    ]);

    activeCancellation.resolve();
    await staleRefresh;
    const fetchCountBeforeOrphanCancellation = fetchGraph.mock.calls.length;

    orphanCancellation.resolve();
    await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(2));
    const replacementRequest = fetchGraph.mock.calls[1]?.[0];
    const appliedRequestId =
      useEspDiagnosticsStore.getState().snapshot?.graph?.requestId;
    coordinator.dispose();

    expect(fetchCountBeforeOrphanCancellation).toBe(1);
    expect(replacementRequest).toEqual(
      expect.objectContaining({
        requestId: "graph-replacement",
        selectedManagedDeviceId: null,
      }),
    );
    expect(appliedRequestId).toBe("graph-replacement");
  });

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
        makeSessionUpdate(
          2,
          makeSnapshot(["live-one", "live-two"], "same-device"),
        ),
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

  it("keeps the newest identity in control when cancellation promises settle out of order", async () => {
    const olderCancellation = deferred<void>();
    const newerCancellation = deferred<void>();
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    const cancelGraph = vi
      .fn<(requestId: string) => Promise<void>>()
      .mockImplementationOnce(() => olderCancellation.promise)
      .mockImplementationOnce(() => newerCancellation.promise);
    const ids = ["graph-newest", "graph-stale"];
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => ids.shift() ?? "graph-unexpected",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.setState({
      phase: "ready",
      snapshot: makeSnapshot(["local-y"], "device-y"),
      graphRequestId: "graph-active",
      graphPhase: "loading",
    });

    const olderRun = coordinator.reconcile();
    useEspDiagnosticsStore.setState({
      snapshot: makeSnapshot(["local-z"], "device-z"),
    });
    const newerRun = coordinator.reconcile();

    newerCancellation.resolve();
    await newerRun;
    olderCancellation.resolve();
    await olderRun;

    expect(fetchGraph).toHaveBeenCalledTimes(1);
    expect(fetchGraph.mock.calls[0][0].identity.deviceName).toBe(
      "host-device-z",
    );
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-newest",
    );
    coordinator.dispose();
  });

  it("settles an owned request when the provider returns a different embedded request ID", async () => {
    const fetchGraph = vi.fn(async () => makeOverlay("graph-foreign-owner"));
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-expected-owner",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-owner-mismatch");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-owner-mismatch",
        makeSnapshot(["local-owner-mismatch"]),
      );

    await coordinator.reconcile();

    expect(useEspDiagnosticsStore.getState()).toMatchObject({
      graphRequestId: null,
      graphPhase: "error",
      graphError:
        "Microsoft Graph returned data for a different request. Refresh Graph data to try again.",
    });
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    coordinator.dispose();
  });

  it("does not let a stale wrong-owner response settle its replacement request", async () => {
    const stale = deferred<EspGraphOverlay>();
    const replacement = deferred<EspGraphOverlay>();
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(() => stale.promise)
      .mockImplementationOnce(() => replacement.promise);
    const ids = ["graph-stale-owner", "graph-current-owner"];
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => ids.shift() ?? "graph-unexpected",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-owner-race");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-owner-race", makeSnapshot(["local-owner-race"]));

    const staleRun = coordinator.reconcile();
    const replacementRun = coordinator.refresh();
    await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(2));
    await vi.waitFor(() =>
      expect(useEspDiagnosticsStore.getState().graphRequestId).toBe(
        "graph-current-owner",
      ),
    );
    stale.resolve(makeOverlay("graph-foreign-owner"));
    await staleRun;

    expect(useEspDiagnosticsStore.getState()).toMatchObject({
      graphRequestId: "graph-current-owner",
      graphPhase: "loading",
      graphError: null,
    });

    replacement.resolve(makeOverlay("graph-current-owner"));
    await replacementRun;
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-current-owner",
    );
    coordinator.dispose();
  });

  it("ignores a late wrong-owner response after Graph is disabled", async () => {
    const pending = deferred<EspGraphOverlay>();
    const coordinator = createEspGraphCoordinator({
      fetchGraph: vi.fn(() => pending.promise),
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-disabled-owner",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-disabled-owner");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-disabled-owner",
        makeSnapshot(["local-disabled-owner"]),
      );

    const active = coordinator.reconcile();
    useUiStore.setState({ graphApiEnabled: false });
    await coordinator.reconcile();
    pending.resolve(makeOverlay("graph-foreign-owner"));
    await active;

    expect(useEspDiagnosticsStore.getState()).toMatchObject({
      graphRequestId: null,
      graphPhase: "disabled",
      graphError: null,
    });
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    coordinator.dispose();
  });

  it("preserves only the safe message from structured coordinator errors", async () => {
    const coordinator = createEspGraphCoordinator({
      fetchGraph: vi.fn(async () => {
        throw {
          message: "Microsoft Graph consent is required.",
          body: "Bearer coordinator-body-secret",
          token: "coordinator-token-secret",
        };
      }),
      cancelGraph: vi.fn(async () => undefined),
      createRequestId: () => "graph-structured-coordinator-error",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore
      .getState()
      .beginAnalysis("analysis-structured-coordinator-error");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-structured-coordinator-error",
        makeSnapshot(["local-structured-coordinator-error"]),
      );

    await coordinator.reconcile();

    expect(useEspDiagnosticsStore.getState()).toMatchObject({
      graphRequestId: null,
      graphPhase: "error",
      graphError: "Microsoft Graph consent is required.",
    });
    expect(useEspDiagnosticsStore.getState().graphError).not.toContain(
      "coordinator-body-secret",
    );
    expect(useEspDiagnosticsStore.getState().graphError).not.toContain(
      "coordinator-token-secret",
    );
    coordinator.dispose();
  });

  it("refetches Graph after a completed same-identity analysis is reset", async () => {
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
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-first");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-first",
        makeSnapshot(["local-first"], "same-device"),
      );

    coordinator.start();
    try {
      await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(1));
      await vi.waitFor(() =>
        expect(
          useEspDiagnosticsStore.getState().snapshot?.graph?.requestId,
        ).toBe("graph-1"),
      );

      useEspDiagnosticsStore.getState().beginAnalysis("analysis-second");
      useEspDiagnosticsStore
        .getState()
        .applyAnalysis(
          "analysis-second",
          makeSnapshot(["local-second"], "same-device"),
        );

      await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(2));
      expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
        "graph-2",
      );
    } finally {
      coordinator.dispose();
    }
  });

  it("cancels coordinator-owned work across a reset before replacing it", async () => {
    const staleOverlay = deferred<EspGraphOverlay>();
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(() => staleOverlay.promise)
      .mockImplementationOnce(async (request) =>
        makeOverlay(request.requestId),
      );
    const cancelGraph = vi.fn(async () => undefined);
    const ids = ["graph-stale", "graph-replacement"];
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => ids.shift() ?? "graph-unexpected",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-first");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis(
        "analysis-first",
        makeSnapshot(["local-first"], "same-device"),
      );

    coordinator.start();
    try {
      await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(1));
      expect(useEspDiagnosticsStore.getState().graphRequestId).toBe(
        "graph-stale",
      );

      useEspDiagnosticsStore.getState().beginAnalysis("analysis-second");
      await vi.waitFor(() =>
        expect(cancelGraph).toHaveBeenCalledWith("graph-stale"),
      );
      useEspDiagnosticsStore
        .getState()
        .applyAnalysis(
          "analysis-second",
          makeSnapshot(["local-second"], "same-device"),
        );

      await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(2));
      await vi.waitFor(() =>
        expect(
          useEspDiagnosticsStore.getState().snapshot?.graph?.requestId,
        ).toBe("graph-replacement"),
      );

      staleOverlay.resolve(makeOverlay("graph-stale"));
      await Promise.resolve();
      expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
        "graph-replacement",
      );
    } finally {
      coordinator.dispose();
    }
  });

  it("does not attach an overlay to a different identity than its request", () => {
    const requested = makeSnapshot(["local-y"], "device-y");
    useEspDiagnosticsStore.setState({ phase: "ready", snapshot: requested });
    useEspDiagnosticsStore
      .getState()
      .beginGraph("graph-y", getEspIdentityFingerprint(requested));

    useEspDiagnosticsStore.setState({
      snapshot: makeSnapshot(["local-z"], "device-z"),
    });
    useEspDiagnosticsStore
      .getState()
      .applyGraphOverlay("graph-y", makeOverlay("graph-y"));

    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
  });

  it.each(["refreshFirst", "disableFirst"] as const)(
    "never launches stale Graph work after opt-out when %s cancellation settles first",
    async (settlesFirst) => {
      const refreshCancellation = deferred<void>();
      const disableCancellation = deferred<void>();
      const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
        makeOverlay(request.requestId),
      );
      const cancelGraph = vi
        .fn<(requestId: string) => Promise<void>>()
        .mockImplementationOnce(() => refreshCancellation.promise)
        .mockImplementationOnce(() => disableCancellation.promise);
      const coordinator = createEspGraphCoordinator({
        fetchGraph,
        cancelGraph,
        createRequestId: () => "graph-after-opt-out",
      });
      useUiStore.setState({
        graphApiEnabled: true,
        graphApiStatus: "connected",
      });
      useEspDiagnosticsStore.setState({
        phase: "ready",
        snapshot: makeSnapshot(["local-a"]),
        graphRequestId: "graph-active",
        graphPhase: "loading",
      });

      const refresh = coordinator.refresh();
      useUiStore.setState({ graphApiEnabled: false });
      const disable = coordinator.reconcile();

      if (settlesFirst === "refreshFirst") {
        refreshCancellation.resolve();
        await refresh;
        disableCancellation.resolve();
        await disable;
      } else {
        disableCancellation.resolve();
        await disable;
        refreshCancellation.resolve();
        await refresh;
      }

      expect(fetchGraph).not.toHaveBeenCalled();
      expect(useEspDiagnosticsStore.getState().graphPhase).toBe("disabled");
      expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
      coordinator.dispose();
    },
  );

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
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("local-a");
    third.resolve(makeOverlay("graph-extra"));
    await activeRefresh;
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    coordinator.dispose();
  });

  it("deduplicates concurrent reconcile calls with an in-flight cancellation", async () => {
    const cancellation = deferred<void>();
    const result = deferred<EspGraphOverlay>();
    const cancelGraph = vi.fn(() => cancellation.promise);
    const fetchGraph = vi.fn(() => result.promise);
    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => "graph-new",
    });
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));

    // Simulate a pre-existing in-flight request so cancelCurrentRequest() yields.
    useEspDiagnosticsStore.setState({
      graphRequestId: "graph-old",
      graphPhase: "loading",
    });

    // Two concurrent reconcile() calls. r1 yields inside cancelCurrentRequest()
    // (awaiting cancellation.promise). Without the fingerprint claim before the
    // yield, r2 would also pass the dedup guard and dispatch a second fetch.
    const r1 = coordinator.reconcile();
    const r2 = coordinator.reconcile();

    // With the fix, r1 claims the fingerprint synchronously and r2 returns early
    // without calling cancelCurrentRequest() a second time.
    expect(cancelGraph).toHaveBeenCalledTimes(1);

    cancellation.resolve();
    result.resolve(makeOverlay("graph-new"));
    await Promise.all([r1, r2]);

    // Exactly one fetch should have been dispatched despite two concurrent calls.
    expect(fetchGraph).toHaveBeenCalledTimes(1);
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
    useUiStore.setState({
      graphApiEnabled: false,
      graphApiStatus: "connected",
    });
    const cancelGraph = vi.fn(async () => {
      throw new Error("Native cancellation unavailable");
    });
    const coordinator = createEspGraphCoordinator({ cancelGraph });

    await expect(coordinator.reconcile()).resolves.toBeUndefined();

    expect(cancelGraph).toHaveBeenCalledWith("graph-active");
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("disabled");
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).toBeNull();
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("local-a");
    coordinator.dispose();
  });

  it("reconciles a Graph re-enable that occurs while cancellation is pending", async () => {
    const firstOverlay = deferred<EspGraphOverlay>();
    const cancel = deferred<void>();
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(() => firstOverlay.promise)
      .mockImplementationOnce(async (request) =>
        makeOverlay(request.requestId),
      );
    const cancelGraph = vi.fn(() => cancel.promise);
    const ids = ["graph-first", "graph-reenabled"];
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

    const initial = coordinator.reconcile();
    await vi.waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(1));

    useUiStore.setState({ graphApiEnabled: false });
    const disabling = coordinator.reconcile();
    await vi.waitFor(() =>
      expect(cancelGraph).toHaveBeenCalledWith("graph-first"),
    );
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    await coordinator.reconcile();

    cancel.resolve();
    await disabling;
    expect(fetchGraph).toHaveBeenCalledTimes(2);
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("ready");
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-reenabled",
    );

    firstOverlay.resolve(makeOverlay("graph-first"));
    await initial;
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-reenabled",
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

  it("cancels an in-flight native Graph request when beginAnalysis fires (orphan cancel)", async () => {
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
      createRequestId: () => "graph-in-flight",
    });
    coordinator.start();

    // Wait for the initial reconcile to dispatch the fetch
    await Promise.resolve();
    expect(fetchGraph).toHaveBeenCalledTimes(1);
    expect(useEspDiagnosticsStore.getState().graphRequestId).toBe(
      "graph-in-flight",
    );

    // A new analysis begins while the Graph fetch is still pending.
    // beginAnalysis atomically sets graphRequestId: null, so cancelCurrentRequest()
    // cannot read the old requestId. The coordinator must detect this via
    // previous.graphRequestId in the subscription callback.
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-b");

    // Flush the subscription callback
    await Promise.resolve();

    expect(cancelGraph).toHaveBeenCalledWith("graph-in-flight");

    // The late result is still silently dropped.
    pending.resolve(makeOverlay("graph-in-flight"));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    // snapshot was cleared by beginAnalysis("analysis-b")
    expect(useEspDiagnosticsStore.getState().snapshot).toBeNull();

    coordinator.dispose();
  });

  it("re-enriches a replacement analysis with the same identity after cancelling the orphaned request", async () => {
    const first = deferred<EspGraphOverlay>();
    const second = deferred<EspGraphOverlay>();
    const orphanCancellation = deferred<void>();
    const fetchGraph = vi
      .fn<(request: EspGraphRequest) => Promise<EspGraphOverlay>>()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const cancelGraph = vi.fn(() => orphanCancellation.promise);
    const requestIds = ["graph-first", "graph-second"];
    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"], "same-device"));

    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => requestIds.shift() ?? "graph-extra",
    });
    coordinator.start();
    await Promise.resolve();
    expect(fetchGraph).toHaveBeenCalledTimes(1);

    useEspDiagnosticsStore.getState().beginAnalysis("analysis-b");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-b", makeSnapshot(["local-b"], "same-device"));
    await Promise.resolve();

    expect(cancelGraph).toHaveBeenCalledWith("graph-first");
    expect(fetchGraph).toHaveBeenCalledTimes(1);

    orphanCancellation.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(fetchGraph).toHaveBeenCalledTimes(2);
    expect(fetchGraph.mock.calls[1]?.[0].requestId).toBe("graph-second");

    first.resolve(makeOverlay("graph-first"));
    second.resolve(makeOverlay("graph-second"));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(useEspDiagnosticsStore.getState().snapshot?.graph?.requestId).toBe(
      "graph-second",
    );
    coordinator.dispose();
  });

  it("does not dispatch a stale-device fetch when snapshot identity changes during a cancellation await", async () => {
    // This test reproduces a race where:
    //   1. An old run claims fingerprint-A and awaits cancelCurrentRequest()
    //      for a prior in-flight request.
    //   2. While awaiting, a new analysis for device-B fires. The subscription
    //      resets lastRequestedFingerprint → null, and a new run (r2) starts
    //      for device-B, claiming fingerprint-B.
    //   3. The old run resumes with a stale snapshot (device-A). Because
    //      lastRequestedFingerprint is now fingerprint-B, the stale fingerprint-A
    //      passes the dedup guard. Without the re-validation fix the old run
    //      would cancel r2's correct fetch and dispatch a device-A fetch whose
    //      overlay would be applied to the current device-B snapshot.
    const snapshotA = makeSnapshot(["local-a"], "device-a");
    const snapshotB = makeSnapshot(["local-b"], "device-b");

    const cancellation = deferred<void>();
    // Every cancelGraph call returns the same deferred so both the
    // cancelCurrentRequest() in the old run and the orphan cancel from the
    // subscription resolve together when cancellation.resolve() fires.
    const cancelGraph = vi.fn(() => cancellation.promise);
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );
    let idSeq = 0;

    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore.getState().applyAnalysis("analysis-a", snapshotA);

    // Inject a prior in-flight request so cancelCurrentRequest() will yield.
    useEspDiagnosticsStore.setState({
      graphRequestId: "graph-prior",
      graphPhase: "loading",
    });

    const coordinator = createEspGraphCoordinator({
      fetchGraph,
      cancelGraph,
      createRequestId: () => `graph-${++idSeq}`,
    });

    // Old run starts. It claims fingerprint-A and blocks in cancelCurrentRequest().
    const r1 = coordinator.reconcile();

    // Switch to a different device while r1 is blocked.
    // beginAnalysis clears graphRequestId → null; applyAnalysis sets snapshotB.
    // The subscription resets lastRequestedFingerprint → null, detects the
    // orphan, and triggers a new run (r2) for snapshotB that awaits the same
    // cancellation deferred via pendingOrphanCancellation.
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-b");
    useEspDiagnosticsStore.getState().applyAnalysis("analysis-b", snapshotB);

    // Flush subscription callbacks so r2 is scheduled and awaiting the orphan.
    await Promise.resolve();

    // Resolve the shared cancellation deferred. Both r1 (awaiting the prior
    // request cancel) and r2 (awaiting the orphan cancel) unblock together.
    cancellation.resolve();
    await r1;

    // Flush r2 and the rescheduled run spawned by the re-validation fix.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

    // The fix ensures the old run detects the identity mismatch after the
    // cancellation await and returns without dispatching a device-A fetch.
    // Every fetch that was dispatched should be for device-B.
    for (const [request] of fetchGraph.mock.calls) {
      expect(request.identity.deviceName).toBe(snapshotB.identity.deviceName);
    }
    expect(fetchGraph).toHaveBeenCalledTimes(1);

    // Device-B's overlay is ultimately applied to the current snapshot.
    expect(useEspDiagnosticsStore.getState().snapshot?.graph).not.toBeNull();
    expect(
      useEspDiagnosticsStore.getState().snapshot?.rawEvidence[0].recordId,
    ).toBe("local-b");

    coordinator.dispose();
  });

  it("does not dispatch a Graph fetch when the option is disabled during a cancellation await", async () => {
    const cancellation = deferred<void>();
    const cancelGraph = vi.fn(() => cancellation.promise);
    const fetchGraph = vi.fn(async (request: EspGraphRequest) =>
      makeOverlay(request.requestId),
    );

    useUiStore.setState({ graphApiEnabled: true, graphApiStatus: "connected" });
    useEspDiagnosticsStore.getState().beginAnalysis("analysis-a");
    useEspDiagnosticsStore
      .getState()
      .applyAnalysis("analysis-a", makeSnapshot(["local-a"]));
    useEspDiagnosticsStore.setState({
      graphRequestId: "graph-prior",
      graphPhase: "loading",
    });

    const coordinator = createEspGraphCoordinator({ fetchGraph, cancelGraph });
    const reconcile = coordinator.reconcile();
    useUiStore.setState({ graphApiEnabled: false });
    cancellation.resolve();
    await reconcile;
    await Promise.resolve();

    expect(fetchGraph).not.toHaveBeenCalled();
    expect(useEspDiagnosticsStore.getState().graphPhase).toBe("disabled");
    coordinator.dispose();
  });
});
