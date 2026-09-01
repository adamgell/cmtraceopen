import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxRecord } from "./types";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const { EvtxDetailPane } = await import("./EvtxDetailPane");
const { useEvtxStore } = await import("./evtx-store");
const { useMarkerStore } = await import("../../stores/marker-store");

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 42,
  timestamp: "2026-08-22T12:00:00Z",
  timestampEpoch: 1,
  provider: "Example Provider",
  channel: "Application",
  eventId: 100,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "Application.evtx",
  activityId: "activity-1",
  userId: "user-42",
  userSid: "S-1-5-21-1000",
};

describe("EvtxDetailPane correlation identity", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: [RECORD],
      selectedRecordId: RECORD.id,
    });
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:Application.evtx"]),
    });
  });

  it("renders the event user identifier separately from the security identifier", () => {
    render(<EvtxDetailPane />);

    expect(screen.getByText("Correlation identity")).toBeInTheDocument();
    expect(screen.getByText("User ID")).toBeInTheDocument();
    expect(screen.getByText("user-42")).toBeInTheDocument();
    expect(screen.getAllByText(/User SID/)).toHaveLength(1);
    expect(screen.getByText("S-1-5-21-1000")).toBeInTheDocument();
  });

  it("keeps a SID-only value in metadata instead of presenting it as correlation identity", () => {
    useEvtxStore.setState({
      records: [{ ...RECORD, activityId: undefined, userId: undefined }],
    });

    render(<EvtxDetailPane />);

    expect(screen.queryByText("Correlation identity")).not.toBeInTheDocument();
    expect(screen.getAllByText(/User SID/)).toHaveLength(1);
    expect(screen.getByText("S-1-5-21-1000")).toBeInTheDocument();
  });
});
