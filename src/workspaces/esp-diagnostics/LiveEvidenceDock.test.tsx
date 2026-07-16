import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ESP_EVIDENCE_DOCK_DEFAULT_HEIGHT,
  useEspDiagnosticsStore,
} from "./esp-diagnostics-store";
import { LiveEvidenceDock } from "./LiveEvidenceDock";
import type { EspDiagnosticsSnapshot, EspRawEvidenceRecord } from "./types";

const virtualizer = vi.hoisted(() => ({
  scrollToIndex: vi.fn(),
}));

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
  record("record-4", "Source reset after rotation"),
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
      target: { value: "Source reset" },
    });
    expect(screen.getByText("Source reset after rotation")).toBeVisible();
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
