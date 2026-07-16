import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT,
  useEspDiagnosticsStore,
} from "./esp-diagnostics-store";
import { LiveEvidenceDock } from "./LiveEvidenceDock";
import type { EspDiagnosticsSnapshot, EspRawEvidenceRecord } from "./types";

const virtualizer = vi.hoisted(() => ({
  scrollToIndex: vi.fn(),
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
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: Math.min(count, 3) }, (_, index) => ({
        index,
        key: index,
        start: index * 32,
        size: 32,
      })),
    getTotalSize: () => count * 32,
    measureElement: vi.fn(),
    scrollToIndex: virtualizer.scrollToIndex,
  }),
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
    expect(resetRow).toHaveTextContent("ime-app-workload");
    expect(resetRow).toHaveTextContent("Source reset");
    expect(screen.getByText("New generation")).toBeVisible();

    fireEvent.click(resetRow);
    const provenance = screen.getByRole("complementary", {
      name: "Reset boundary provenance",
    });
    expect(provenance).toHaveTextContent(oldPath);
    expect(provenance).toHaveTextContent(newPath);
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
