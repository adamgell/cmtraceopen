import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { UnifiedTimelineView } from "./UnifiedTimelineView";
import type { UnifiedTimeline } from "./unified-timeline";

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: index,
        size: estimateSize(),
        start: index * estimateSize(),
      })),
    measureElement: vi.fn(),
  }),
}));

vi.mock("./evtx-store", () => ({
  useEvtxStore: (selector: (state: { timeZoneMode: "utc" }) => unknown) =>
    selector({ timeZoneMode: "utc" }),
}));

const timeline: UnifiedTimeline = {
  items: [
    {
      timestampMs: 1,
      severity: "error",
      message: "Enrollment failed",
      origin: {
        kind: "event",
        stableId: "source12:capture.evtx|channel72:Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin|record1234",
        source: "capture.evtx",
        machine: "HOST-A",
        bundle: "bundle-1",
        channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
        provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
        processId: 4321,
        activityId: "{activity}",
        eventId: 76,
        recordId: 1234,
      },
    },
  ],
  unplaced: [
    {
      origin: {
        kind: "event",
        stableId: "source12:capture.evtx|channel8:Security|record1234",
        source: "capture.evtx",
        machine: null,
        bundle: null,
        channel: "Security",
        provider: "Provider",
        processId: null,
        activityId: null,
        eventId: 4624,
        recordId: 1234,
      },
      reason: "missingTimestamp",
    },
  ],
};

describe("UnifiedTimelineView", () => {
  it("renders source and machine provenance while exposing unplaced coverage", () => {
    render(<UnifiedTimelineView timeline={timeline} />);
    expect(screen.getByText(/HOST-A · capture\.evtx/)).toBeInTheDocument();
    expect(screen.getAllByTitle(/stable source12:capture\.evtx/)).toHaveLength(2);
    expect(screen.getByText("1 event could not be placed: no timestamp")).toBeInTheDocument();
    expect(screen.getByText("Enrollment failed")).toBeInTheDocument();
  });
  it("renders actionable details when every entry is unplaced", () => {
    render(<UnifiedTimelineView timeline={{ ...timeline, items: [] }} />);
    expect(screen.getByRole("list", { name: "Unplaced timeline entries" })).toBeInTheDocument();
    expect(screen.getByText("Security (4624)")).toBeInTheDocument();
    expect(screen.getByText("machine unknown · capture.evtx")).toBeInTheDocument();
    expect(screen.getByText("No timestamp")).toBeInTheDocument();
  });
});
