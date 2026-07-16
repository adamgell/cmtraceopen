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
