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

describe("EvtxDetailPane error codes", () => {
  const mention = (overrides: Record<string, unknown>) => ({
    start: 0,
    end: 10,
    codeHex: "0x80070005",
    codeDecimal: "-2147024891",
    description: "",
    category: "",
    outcome: null,
    known: false,
    ...overrides,
  });

  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: [{ ...RECORD, message: "Update failed with 0x80070005" }],
      selectedRecordId: RECORD.id,
    });
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:Application.evtx"]),
    });
  });

  it("shows a code the database knows with its meaning", async () => {
    invoke.mockImplementation((command: string) =>
      command === "resolve_error_codes_in_text"
        ? Promise.resolve([
            mention({
              known: true,
              description: "Access is denied.",
              category: "Win32",
              outcome: "Failure",
            }),
          ])
        : Promise.resolve(null),
    );

    render(<EvtxDetailPane />);

    expect(
      await screen.findByText("Error codes in this event"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Access is denied\./)).toBeInTheDocument();
    expect(screen.getByText(/Win32/)).toBeInTheDocument();
  });

  it("labels a code the database cannot explain instead of staying silent", async () => {
    invoke.mockImplementation((command: string) =>
      command === "resolve_error_codes_in_text"
        ? Promise.resolve([mention({ codeHex: "0xDEADBEEF", known: false })])
        : Promise.resolve(null),
    );

    render(<EvtxDetailPane />);

    expect(
      await screen.findByText("Error codes in this event"),
    ).toBeInTheDocument();
    expect(screen.getByText("0xDEADBEEF")).toBeInTheDocument();
    expect(screen.getByText("Not in the error database")).toBeInTheDocument();
  });

  it("shows nothing extra when the command reports no codes", async () => {
    invoke.mockResolvedValue([]);

    render(<EvtxDetailPane />);

    expect(screen.getByText("Update failed with 0x80070005")).toBeInTheDocument();
    expect(screen.queryByText("Error codes in this event")).not.toBeInTheDocument();
  });
});
