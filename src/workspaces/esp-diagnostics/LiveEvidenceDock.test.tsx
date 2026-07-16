import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT,
  useEspDiagnosticsStore,
} from "./esp-diagnostics-store";
import { LiveEvidenceDock } from "./LiveEvidenceDock";
import type {
  EspDiagnosticsSnapshot,
  EspRawEvidenceRecord,
  EspTimelineEntry,
} from "./types";

const virtualizer = vi.hoisted(() => ({
  scrollToIndex: vi.fn(),
  itemKeys: [] as Array<string | number>,
  startIndex: 0,
}));

class ResizeObserverDouble {
  readonly observe = vi.fn();
  readonly unobserve = vi.fn();
  readonly disconnect = vi.fn();

  constructor(readonly callback: ResizeObserverCallback) {
    resizeObservers.push(this);
  }
}

let resizeObservers: ResizeObserverDouble[] = [];

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({
    count,
    getItemKey,
  }: {
    count: number;
    getItemKey: (index: number) => string | number;
  }) => {
    virtualizer.itemKeys = Array.from({ length: count }, (_, index) =>
      getItemKey(index),
    );
    return {
      getVirtualItems: () =>
        Array.from(
          {
            length: Math.min(Math.max(count - virtualizer.startIndex, 0), 3),
          },
          (_, offset) => {
            const index = virtualizer.startIndex + offset;
            return {
              index,
              key: getItemKey(index),
              start: index * 32,
              size: 32,
            };
          },
        ),
      getTotalSize: () => count * 32,
      measureElement: vi.fn(),
      scrollToIndex: virtualizer.scrollToIndex,
    };
  },
}));

function record(
  id: string,
  message: string,
  overrides: Partial<EspRawEvidenceRecord> = {},
): EspRawEvidenceRecord {
  return {
    recordId: id,
    provenance: {
      sourceKind: "imeLog",
      sourceArtifactId: "ime-app-workload",
      filePath:
        "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload.log",
      lineNumber: Number(id.replace(/\D/g, "")) || 1,
      recordNumber: null,
      registry: null,
      event: null,
    },
    sourceTimestamp: {
      rawText: "2026-07-15T20:00:00.000Z",
      originalOffset: "+00:00",
      normalizedUtc: "2026-07-15T20:00:00.000Z",
      kind: "utc",
    },
    observedAtUtc: "2026-07-15T20:00:00.000Z",
    rawValue: { text: message },
    sensitivity: "public",
    parseState: "parsed",
    accessState: "available",
    evidence: [],
    ...overrides,
  };
}

function snapshot(records: EspRawEvidenceRecord[]): EspDiagnosticsSnapshot {
  return {
    schemaVersion: 1,
    scenario: "autopilotV1",
    phase: "deviceSetup",
    generatedAtUtc: "2026-07-15T20:00:30.000Z",
    elevation: {
      isElevated: true,
      restartSupported: true,
      restrictedSources: [],
    },
    identity: {
      deviceName: "ESP-LAB-042",
      managedDeviceId: null,
      entraDeviceId: null,
      entdmId: null,
      tenantId: null,
      tenantDomain: null,
      userPrincipalName: null,
      serialNumber: null,
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
    rawEvidence: records,
    graph: null,
  };
}

function mockWorkspaceHeight(initialHeight: number) {
  let height = initialHeight;
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(
    () =>
      ({
        x: 0,
        y: 0,
        width: 1_200,
        height,
        top: 0,
        right: 1_200,
        bottom: height,
        left: 0,
        toJSON: () => ({}),
      }) as DOMRect,
  );
  return {
    setHeight(nextHeight: number) {
      height = nextHeight;
    },
    notify() {
      const observer = resizeObservers[resizeObservers.length - 1];
      if (!observer) throw new Error("Expected a ResizeObserver instance");
      act(() => observer.callback([], observer as unknown as ResizeObserver));
    },
  };
}

const baseRecords = [
  record("record-1", "Installation failed with error 0x80070005"),
  record("record-2", "Warning: retrying content download", {
    provenance: {
      sourceKind: "deploymentLog",
      sourceArtifactId: "configmgr-cas",
      filePath: "C:\\Windows\\CCM\\Logs\\CAS.log",
      lineNumber: 22,
      recordNumber: null,
      registry: null,
      event: null,
    },
  }),
  record("record-3", "Policy evaluation completed"),
  record("record-4", "Content download completed"),
  record("record-5", "MSI transaction started"),
];

beforeEach(() => {
  useEspDiagnosticsStore.setState(
    useEspDiagnosticsStore.getInitialState(),
    true,
  );
  virtualizer.scrollToIndex.mockReset();
  virtualizer.itemKeys = [];
  virtualizer.startIndex = 0;
  Object.defineProperty(window, "innerHeight", {
    configurable: true,
    value: 600,
  });
  resizeObservers = [];
  vi.stubGlobal("ResizeObserver", ResizeObserverDouble);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("LiveEvidenceDock", () => {
  it("starts collapsed, resizes accessibly, expands, restores, and collapses", () => {
    render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    expect(
      screen.queryByRole("region", { name: "Live evidence and logs" }),
    ).not.toBeInTheDocument();

    act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode("docked"));
    const dock = screen.getByRole("region", { name: "Live evidence and logs" });
    expect(dock).toHaveAttribute("data-view-mode", "docked");
    expect(dock).toHaveStyle({
      height: `${ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT}px`,
    });
    expect(dock).toHaveStyle({
      gridTemplateRows: "auto minmax(0, 1fr)",
    });

    const separator = screen.getByRole("separator", {
      name: "Resize live evidence and logs",
    });
    fireEvent.keyDown(separator, { key: "ArrowUp" });
    expect(dock).toHaveStyle({ height: "304px" });
    fireEvent.keyDown(separator, { key: "End" });
    expect(dock).toHaveStyle({ height: "420px" });

    fireEvent.click(screen.getByRole("button", { name: "Expand live logs" }));
    expect(dock).toHaveAttribute("data-view-mode", "full");
    expect(dock).toHaveStyle({ height: "100%" });
    fireEvent.click(
      screen.getByRole("button", { name: "Restore docked live logs" }),
    );
    expect(dock).toHaveStyle({ height: "420px" });

    fireEvent.click(screen.getByRole("button", { name: "Expand live logs" }));
    fireEvent.click(screen.getByRole("button", { name: "Close live logs" }));
    expect(
      screen.queryByRole("region", { name: "Live evidence and logs" }),
    ).not.toBeInTheDocument();
    expect(useEspDiagnosticsStore.getState().evidenceDockHeight).toBe(420);

    act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode("docked"));
    fireEvent.click(screen.getByRole("button", { name: "Close live logs" }));
    expect(
      screen.queryByRole("region", { name: "Live evidence and logs" }),
    ).not.toBeInTheDocument();
  });

  it("reclamps a retained dock height when the workspace shrinks and preserves it across remounts", () => {
    Object.defineProperty(window, "innerHeight", {
      configurable: true,
      value: 1_000,
    });
    useEspDiagnosticsStore.getState().setEvidenceDockHeight(720);
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");

    const view = render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    expect(
      screen.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveStyle({
      height: "700px",
    });

    Object.defineProperty(window, "innerHeight", {
      configurable: true,
      value: 600,
    });
    fireEvent(window, new Event("resize"));
    expect(
      screen.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveStyle({
      height: "420px",
    });

    view.unmount();
    render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    expect(
      screen.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveStyle({
      height: "420px",
    });
  });

  it("supports pointer resizing within seventy percent of the workspace", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    const separator = screen.getByRole("separator", {
      name: "Resize live evidence and logs",
    });

    fireEvent.pointerDown(separator, { clientY: 500, pointerId: 1 });
    fireEvent.pointerMove(window, { clientY: 100, pointerId: 1 });
    fireEvent.pointerUp(window, { pointerId: 1 });

    expect(
      screen.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveStyle({
      height: "420px",
    });
  });

  it("uses the current workspace height when it shrinks during pointer resize", () => {
    const workspace = mockWorkspaceHeight(1_000);
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    render(
      <div data-testid="esp-workspace">
        <LiveEvidenceDock snapshot={snapshot(baseRecords)} />
      </div>,
    );
    const separator = screen.getByRole("separator", {
      name: "Resize live evidence and logs",
    });

    fireEvent.pointerDown(separator, { clientY: 500, pointerId: 1 });
    workspace.setHeight(400);
    workspace.notify();
    fireEvent.pointerMove(window, { clientY: 100, pointerId: 1 });
    fireEvent.pointerUp(window, { pointerId: 1 });

    expect(
      screen.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveStyle({ height: "280px" });
  });

  it.each(["full", "collapsed"] as const)(
    "stops an active pointer resize when switching to %s mode",
    (mode) => {
      useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
      render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
      const separator = screen.getByRole("separator", {
        name: "Resize live evidence and logs",
      });

      fireEvent.pointerDown(separator, { clientY: 500, pointerId: 1 });
      act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode(mode));
      fireEvent.pointerMove(window, { clientY: 100, pointerId: 1 });

      expect(useEspDiagnosticsStore.getState().evidenceDockHeight).toBe(
        ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT,
      );
    },
  );

  it("tracks the parent resize range in ARIA state and disconnects its observer", () => {
    Object.defineProperty(window, "innerHeight", {
      configurable: true,
      value: 1_000,
    });
    const workspace = mockWorkspaceHeight(500);
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const view = render(
      <div data-testid="esp-workspace">
        <LiveEvidenceDock snapshot={snapshot(baseRecords)} />
      </div>,
    );
    const observer = resizeObservers[resizeObservers.length - 1];
    expect(observer).toBeDefined();
    const separator = screen.getByRole("separator", {
      name: "Resize live evidence and logs",
    });
    expect(separator).toHaveAttribute("aria-valuemax", "350");

    workspace.setHeight(900);
    workspace.notify();
    expect(separator).toHaveAttribute("aria-valuemax", "630");

    workspace.setHeight(300);
    workspace.notify();
    expect(separator).toHaveAttribute("aria-valuemax", "210");
    expect(
      screen.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveStyle({ height: "210px" });

    view.unmount();
    expect(observer?.disconnect).toHaveBeenCalledTimes(1);
  });

  it("removes an active pointer resize listener when the dock unmounts", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const view = render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    const separator = screen.getByRole("separator", {
      name: "Resize live evidence and logs",
    });

    fireEvent.pointerDown(separator, { clientY: 500, pointerId: 1 });
    view.unmount();
    fireEvent.pointerMove(window, { clientY: 100, pointerId: 1 });

    expect(useEspDiagnosticsStore.getState().evidenceDockHeight).toBe(
      ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT,
    );
  });

  it("keeps collecting while hidden and clears unread state only after opening", () => {
    const first = snapshot(baseRecords.slice(0, 1));
    const second = snapshot(baseRecords.slice(0, 3));
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 1,
      state: "live",
      reason: "initialSnapshot",
      emittedAtUtc: first.generatedAtUtc,
      snapshot: first,
    });
    useEspDiagnosticsStore.getState().applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 2,
      state: "live",
      reason: "evidenceChanged",
      emittedAtUtc: second.generatedAtUtc,
      snapshot: second,
    });
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(3);

    render(<LiveEvidenceDock snapshot={second} />);
    act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode("docked"));
    expect(screen.getAllByTestId("live-evidence-row")).toHaveLength(3);
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(0);
  });

  it("renders a real source-reset update as a distinct stable boundary row", () => {
    const oldPath =
      "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload.log";
    const newPath =
      "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload-20260715.log";
    const initial = snapshot([
      record("old-record", "Old generation", {
        provenance: {
          sourceKind: "imeLog",
          sourceArtifactId: "ime-app-workload",
          filePath: oldPath,
          lineNumber: 41,
          recordNumber: null,
          registry: null,
          event: null,
        },
      }),
    ]);
    const replacement = snapshot([
      record("new-record", "New generation", {
        provenance: {
          sourceKind: "imeLog",
          sourceArtifactId: "ime-app-workload",
          filePath: newPath,
          lineNumber: 1,
          recordNumber: null,
          registry: null,
          event: null,
        },
      }),
    ]);
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 1,
      state: "live",
      reason: "initialSnapshot",
      emittedAtUtc: initial.generatedAtUtc,
      snapshot: initial,
    });
    useEspDiagnosticsStore.getState().markEvidenceRead();
    useEspDiagnosticsStore.getState().applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 2,
      state: "live",
      reason: "sourceReset",
      emittedAtUtc: "2026-07-15T20:00:42.000Z",
      snapshot: replacement,
    });
    expect(useEspDiagnosticsStore.getState().unreadEvidenceCount).toBe(1);

    render(<LiveEvidenceDock snapshot={replacement} />);
    act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode("docked"));
    const resetRow = screen.getByTestId("live-evidence-reset-row");
    expect(resetRow).toHaveAttribute(
      "data-record-id",
      "source-reset:session-a:2",
    );
    expect(resetRow).toHaveTextContent("2026-07-15T20:00:42.000Z");
    expect(resetRow).toHaveTextContent("Exact source unknown");
    expect(resetRow).toHaveTextContent("Source reset");
    expect(screen.getByText("New generation")).toBeVisible();

    fireEvent.click(resetRow);
    const provenance = screen.getByRole("complementary", {
      name: "Reset boundary provenance",
    });
    expect(provenance).toHaveTextContent("Exact reset source unavailable");
    expect(provenance).toHaveTextContent(
      "Observed raw-record deltas do not identify the reset source",
    );
    expect(provenance).toHaveTextContent("Removed");
    expect(provenance).toHaveTextContent("Added");
    expect(provenance).toHaveTextContent(oldPath);
    expect(provenance).toHaveTextContent(newPath);
  });

  it("renders a zero-delta reset as unknown without inventing source provenance", () => {
    const unchanged = snapshot([record("same-record", "Same generation")]);
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 1,
      state: "live",
      reason: "initialSnapshot",
      emittedAtUtc: unchanged.generatedAtUtc,
      snapshot: unchanged,
    });
    useEspDiagnosticsStore.getState().applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 2,
      state: "live",
      reason: "sourceReset",
      emittedAtUtc: "2026-07-15T20:00:42.000Z",
      snapshot: structuredClone(unchanged),
    });

    render(<LiveEvidenceDock snapshot={unchanged} />);
    act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode("docked"));
    const resetRow = screen.getByTestId("live-evidence-reset-row");
    expect(resetRow).toHaveTextContent("Exact source unknown");

    fireEvent.click(resetRow);
    const provenance = screen.getByRole("complementary", {
      name: "Reset boundary provenance",
    });
    expect(provenance).toHaveTextContent("Exact reset source unavailable");
    expect(provenance).toHaveTextContent(
      "No raw-record changes were observed in this reset update",
    );
  });

  it("filters a multi-source reset marker by every observed source without claiming exact attribution", () => {
    const oldPath = "C:\\Windows\\Temp\\old.log";
    const newPath = "C:\\Windows\\Temp\\new.log";
    const unrelatedPath = "C:\\Windows\\Temp\\unrelated.log";
    const initial = snapshot([
      record("reset-old", "Old generation", {
        provenance: {
          sourceKind: "imeLog",
          sourceArtifactId: "reset-candidate",
          filePath: oldPath,
          lineNumber: 1,
          recordNumber: null,
          registry: null,
          event: null,
        },
      }),
    ]);
    const replacement = snapshot([
      record("reset-new", "New generation", {
        provenance: {
          sourceKind: "imeLog",
          sourceArtifactId: "reset-candidate",
          filePath: newPath,
          lineNumber: 1,
          recordNumber: null,
          registry: null,
          event: null,
        },
      }),
      record("unrelated-new", "Concurrent evidence", {
        provenance: {
          sourceKind: "deploymentLog",
          sourceArtifactId: "unrelated-source",
          filePath: unrelatedPath,
          lineNumber: 1,
          recordNumber: null,
          registry: null,
          event: null,
        },
      }),
    ]);
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 1,
      state: "live",
      reason: "initialSnapshot",
      emittedAtUtc: initial.generatedAtUtc,
      snapshot: initial,
    });
    useEspDiagnosticsStore.getState().applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 2,
      state: "live",
      reason: "sourceReset",
      emittedAtUtc: "2026-07-15T20:00:42.000Z",
      snapshot: replacement,
    });

    render(<LiveEvidenceDock snapshot={replacement} />);
    act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode("docked"));
    fireEvent.change(screen.getByLabelText("Filter live evidence by source"), {
      target: { value: "unrelated-source" },
    });

    const resetRow = screen.getByTestId("live-evidence-reset-row");
    expect(resetRow).toHaveTextContent("Exact source unknown");
    expect(resetRow).not.toHaveTextContent("unrelated-source");
    fireEvent.click(resetRow);
    const provenance = screen.getByRole("complementary", {
      name: "Reset boundary provenance",
    });
    expect(provenance).toHaveTextContent("Exact reset source unavailable");
    expect(provenance).toHaveTextContent("unrelated-source");
    expect(provenance).toHaveTextContent(unrelatedPath);
  });

  it("replaces same-ID row identity, clears stale selection, and interleaves the reset boundary", () => {
    const stableRecord = record("stable-id", "Stable evidence");
    const oldRecord = record("same-id", "Old generation");
    const initial = snapshot([stableRecord, oldRecord]);
    const replacementRecord = record("same-id", "Replacement generation", {
      rawValue: { text: "Replacement generation" },
      provenance: {
        ...oldRecord.provenance,
        filePath: "C:\\Windows\\Temp\\replacement.log",
      },
    });
    const replacement = snapshot([stableRecord, replacementRecord]);
    const latest = snapshot([
      stableRecord,
      replacementRecord,
      record("later-id", "Later evidence"),
    ]);
    const state = useEspDiagnosticsStore.getState();
    state.beginLiveStart("live-a");
    state.applySessionUpdate({
      sessionId: "session-a",
      requestId: "live-a",
      sequence: 1,
      state: "live",
      reason: "initialSnapshot",
      emittedAtUtc: initial.generatedAtUtc,
      snapshot: initial,
    });

    const view = render(<LiveEvidenceDock snapshot={initial} />);
    act(() => useEspDiagnosticsStore.getState().setEvidenceViewMode("docked"));
    const oldRow = screen.getByText("Old generation").closest('[role="row"]');
    if (!oldRow) throw new Error("Expected the old evidence row");
    const oldRowId = oldRow.getAttribute("data-record-id");
    fireEvent.click(oldRow);
    expect(
      screen.getByRole("complementary", { name: "Raw evidence provenance" }),
    ).toHaveTextContent("same-id");

    act(() => {
      useEspDiagnosticsStore.getState().applySessionUpdate({
        sessionId: "session-a",
        requestId: "live-a",
        sequence: 2,
        state: "live",
        reason: "sourceReset",
        emittedAtUtc: "2026-07-15T20:00:42.000Z",
        snapshot: replacement,
      });
      useEspDiagnosticsStore.getState().applySessionUpdate({
        sessionId: "session-a",
        requestId: "live-a",
        sequence: 3,
        state: "live",
        reason: "evidenceChanged",
        emittedAtUtc: "2026-07-15T20:00:43.000Z",
        snapshot: latest,
      });
    });
    view.rerender(<LiveEvidenceDock snapshot={latest} />);

    const replacementRow = screen
      .getByText("Replacement generation")
      .closest('[role="row"]');
    if (!replacementRow) throw new Error("Expected the replacement row");
    expect(replacementRow.getAttribute("data-record-id")).not.toBe(oldRowId);
    expect(
      screen.queryByRole("complementary", { name: "Raw evidence provenance" }),
    ).not.toBeInTheDocument();
    const markerId = "source-reset:session-a:2";
    const stableKey = virtualizer.itemKeys.find((key) =>
      String(key).endsWith(":stable-id"),
    );
    const replacementKey = virtualizer.itemKeys.find((key) =>
      String(key).endsWith(":same-id"),
    );
    const laterKey = virtualizer.itemKeys.find((key) =>
      String(key).endsWith(":later-id"),
    );
    expect(stableKey).toBeDefined();
    expect(replacementKey).toBeDefined();
    expect(laterKey).toBeDefined();
    expect(virtualizer.itemKeys).toEqual([
      stableKey,
      markerId,
      replacementKey,
      laterKey,
    ]);
    expect(screen.getByTestId("live-evidence-reset-row")).toHaveAttribute(
      "data-record-id",
      markerId,
    );
  });
});

describe("LiveEvidenceTable", () => {
  it("virtualizes columns, filters sources/text/severity, and exposes provenance", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    const table = screen.getByRole("table", { name: "Live evidence records" });
    for (const column of [
      "Timestamp",
      "Source",
      "Severity",
      "Component",
      "Message",
    ]) {
      expect(
        within(table).getByRole("columnheader", { name: column }),
      ).toBeVisible();
    }
    expect(screen.getAllByTestId("live-evidence-row")).toHaveLength(3);
    expect(
      screen.queryByText("MSI transaction started"),
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Filter live evidence by source"), {
      target: { value: "configmgr-cas" },
    });
    expect(
      screen.getByText("Warning: retrying content download"),
    ).toBeVisible();
    expect(screen.queryByText(/Installation failed/)).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Search live evidence"), {
      target: { value: "content" },
    });
    expect(
      screen.getByText("Warning: retrying content download"),
    ).toBeVisible();
    fireEvent.change(screen.getByLabelText("Filter live evidence by source"), {
      target: { value: "all" },
    });
    fireEvent.change(screen.getByLabelText("Search live evidence"), {
      target: { value: "" },
    });

    fireEvent.click(
      screen.getByRole("button", { name: "Errors and warnings" }),
    );
    expect(screen.getByText(/Installation failed/)).toBeVisible();
    expect(screen.getByText(/Warning: retrying/)).toBeVisible();
    expect(
      screen.queryByText("Policy evaluation completed"),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByText(/Installation failed/));
    const details = screen.getByRole("complementary", {
      name: "Raw evidence provenance",
    });
    expect(details).toHaveTextContent("AppWorkload.log");
    expect(details).toHaveTextContent("Line 1");
    expect(details).toHaveTextContent("record-1");
  });

  it("reconciles a removed active source filter back to all sources", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const view = render(
      <LiveEvidenceDock snapshot={snapshot(baseRecords.slice(0, 2))} />,
    );
    const sourceSelect = screen.getByLabelText(
      "Filter live evidence by source",
    );
    fireEvent.change(sourceSelect, {
      target: { value: "configmgr-cas" },
    });
    expect(sourceSelect).toHaveValue("configmgr-cas");
    expect(screen.getByText("1 / 2")).toBeVisible();

    view.rerender(
      <LiveEvidenceDock snapshot={snapshot(baseRecords.slice(0, 1))} />,
    );

    expect(sourceSelect).toHaveValue("all");
    expect(screen.getByText("1 / 1")).toBeVisible();
    expect(screen.getByText(/Installation failed/)).toBeVisible();
  });

  it("reports the complete virtual row count and absolute one-based row positions", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    virtualizer.startIndex = 2;
    render(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);

    const table = screen.getByRole("table", { name: "Live evidence records" });
    expect(table).toHaveAttribute("aria-rowcount", "6");
    const renderedRows = within(table).getAllByRole("row");
    expect(renderedRows[0]).toHaveAttribute("aria-rowindex", "1");
    const evidenceRows = screen.getAllByTestId("live-evidence-row");
    expect(evidenceRows).toHaveLength(3);
    expect(evidenceRows[0]).toHaveAttribute("aria-rowindex", "4");
    expect(evidenceRows[1]).toHaveAttribute("aria-rowindex", "5");
    expect(evidenceRows[2]).toHaveAttribute("aria-rowindex", "6");
  });

  it("displays normalized UTC instead of raw local timestamp text when available", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const evidence = snapshot([
      record("record-local-time", "Timestamp normalization evidence", {
        sourceTimestamp: {
          rawText: "07/15/2026 16:00:00",
          originalOffset: "-04:00",
          normalizedUtc: "2026-07-15T20:00:00.000Z",
          kind: "local",
        },
      }),
    ]);

    render(<LiveEvidenceDock snapshot={evidence} />);

    const row = screen
      .getByText("Timestamp normalization evidence")
      .closest<HTMLElement>('[role="row"]');
    if (!row) throw new Error("Expected a live evidence row");
    expect(within(row).getByText("2026-07-15T20:00:00.000Z")).toBeVisible();
    expect(within(row).queryByText("07/15/2026 16:00:00")).toBeNull();
  });

  it("indexes timeline evidence once instead of rescanning activity for every record", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const entryCount = 40;
    let evidenceReads = 0;
    const records = Array.from({ length: entryCount }, (_, index) =>
      record(`linear-${index}`, `Linear evidence ${index}`),
    );
    const activity = records.map((item, index) => {
      const entry: EspTimelineEntry = {
        entryId: `activity-${index}`,
        timestamp: {
          rawText: "2026-07-15T20:00:00.000Z",
          originalOffset: "+00:00",
          normalizedUtc: "2026-07-15T20:00:00.000Z",
          kind: "utc",
        },
        kind: "workload",
        title: `Activity ${index}`,
        detail: null,
        status: null,
        evidence: [],
      };
      Object.defineProperty(entry, "evidence", {
        enumerable: true,
        get: () => {
          evidenceReads += 1;
          return [
            {
              evidenceId: item.recordId,
              sourceArtifactId: item.provenance.sourceArtifactId,
            },
          ];
        },
      });
      return entry;
    });
    const evidence = snapshot(records);
    evidence.activity = activity;

    render(<LiveEvidenceDock snapshot={evidence} />);

    expect(evidenceReads).toBeLessThanOrEqual(entryCount * 2);
  });

  it("keeps local raw log text verbatim when normalized timeline evidence exists", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const rawLine = "  <![LOG[Raw  MSI\tline:\nproperty VALUE=unchanged]LOG]!>";
    const evidence = snapshot([record("record-1", rawLine)]);
    evidence.activity = [
      {
        entryId: "activity-1",
        timestamp: {
          rawText: "2026-07-15T20:00:00.000Z",
          originalOffset: "+00:00",
          normalizedUtc: "2026-07-15T20:00:00.000Z",
          kind: "utc",
        },
        kind: "workload",
        title: "Normalized installer failure",
        detail: "Friendly summary",
        status: {
          raw: "failed",
          normalized: "failed",
          display: "Failed",
          detail: null,
        },
        evidence: [
          {
            evidenceId: "record-1",
            sourceArtifactId: "ime-app-workload",
          },
        ],
      },
    ];

    render(<LiveEvidenceDock snapshot={evidence} />);

    const message = screen
      .getAllByRole("cell")
      .find((cell) => cell.getAttribute("title") === rawLine);
    if (!message) throw new Error("Expected the raw evidence message cell");
    expect(message.textContent).toBe(rawLine);
    expect(message).toHaveStyle({ whiteSpace: "pre" });
    expect(
      screen.queryByText("Normalized installer failure"),
    ).not.toBeInTheDocument();
  });

  it("pauses visual follow away from the bottom without pausing collection", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const view = render(
      <LiveEvidenceDock snapshot={snapshot(baseRecords.slice(0, 3))} />,
    );
    expect(virtualizer.scrollToIndex).toHaveBeenCalled();
    virtualizer.scrollToIndex.mockClear();

    const scroller = screen.getByTestId("live-evidence-scroller");
    Object.defineProperties(scroller, {
      clientHeight: { configurable: true, value: 100 },
      scrollHeight: { configurable: true, value: 1000 },
      scrollTop: { configurable: true, value: 100, writable: true },
    });
    fireEvent.scroll(scroller);
    expect(screen.getByRole("button", { name: "Resume follow" })).toBeVisible();

    view.rerender(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    expect(screen.getByText("5 / 5")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Search live evidence"), {
      target: { value: "MSI transaction" },
    });
    expect(screen.getByText("MSI transaction started")).toBeVisible();
    expect(virtualizer.scrollToIndex).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Resume follow" }));
    expect(virtualizer.scrollToIndex).toHaveBeenCalled();
  });

  it("keeps an explicit visual pause latched while the scroller remains near the bottom", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const view = render(
      <LiveEvidenceDock snapshot={snapshot(baseRecords.slice(0, 3))} />,
    );
    const scroller = screen.getByTestId("live-evidence-scroller");
    Object.defineProperties(scroller, {
      clientHeight: { configurable: true, value: 100 },
      scrollHeight: { configurable: true, value: 100 },
      scrollTop: { configurable: true, value: 0, writable: true },
    });

    fireEvent.click(screen.getByRole("button", { name: "Pause follow" }));
    virtualizer.scrollToIndex.mockClear();
    fireEvent.scroll(scroller);
    expect(screen.getByRole("button", { name: "Resume follow" })).toBeVisible();

    view.rerender(<LiveEvidenceDock snapshot={snapshot(baseRecords)} />);
    expect(screen.getByText("5 / 5")).toBeVisible();
    expect(virtualizer.scrollToIndex).not.toHaveBeenCalled();
  });

  it("retains the selected record while new evidence arrives", () => {
    useEspDiagnosticsStore.getState().setEvidenceViewMode("docked");
    const view = render(
      <LiveEvidenceDock snapshot={snapshot(baseRecords.slice(0, 2))} />,
    );
    fireEvent.click(screen.getByText(/Installation failed/));
    expect(
      screen.getByRole("complementary", { name: "Raw evidence provenance" }),
    ).toHaveTextContent("record-1");

    view.rerender(
      <LiveEvidenceDock snapshot={snapshot(baseRecords.slice(0, 3))} />,
    );
    expect(
      screen.getByRole("complementary", { name: "Raw evidence provenance" }),
    ).toHaveTextContent("record-1");
  });
});
