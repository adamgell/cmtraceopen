import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { deferred } from "../../test-utils/deferred";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const mocks = vi.hoisted(() => ({
  buildAnalysis: vi.fn(),
  closeAnalysis: vi.fn(),
  queryTimeline: vi.fn(),
}));

vi.mock("../../lib/commands", () => ({
  closeEventLogAnalysisSession: mocks.closeAnalysis,
  queryEventLogAnalysisTimeline: mocks.queryTimeline,
}));
vi.mock("./event-analysis-session", () => ({
  buildEventLogAnalysisSession: mocks.buildAnalysis,
  EventLogAnalysisCancelled: class EventLogAnalysisCancelled extends Error {},
}));

vi.mock("./SourcePicker", () => ({ SourcePicker: () => null }));
vi.mock("./ChannelPicker", () => ({ ChannelPicker: () => null }));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxTimeline", () => ({ EvtxTimeline: () => null }));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./EventDiagnosisPanel", () => ({ EventDiagnosisPanel: () => null }));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));

import { useLogStore } from "../../stores/log-store";
import { useEvtxStore } from "./evtx-store";
import { EventLogWorkspace } from "./EventLogWorkspace";
import type { EvtxRecord } from "./types";

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: 1,
  provider: "Example Provider",
  channel: "Application",
  eventId: 42,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event message",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
};

function analysisResult(sessionId = "session-1", eventItems = 1) {
  const status = {
    sessionId,
    revision: 1,
    totalItems: eventItems,
    eventItems,
    logItems: 0,
    totalUnplaced: 0,
    totalEdges: 0,
    totalCoverageGaps: 0,
    finalized: true,
  };
  return {
    status,
    initialPage: {
      sessionId,
      revision: status.revision,
      offset: 0,
      nextOffset: null,
      serializedBytes: 1_024,
      totalItems: status.totalItems,
      eventItems: status.eventItems,
      logItems: status.logItems,
      totalUnplaced: status.totalUnplaced,
      totalEdges: status.totalEdges,
      totalCoverageGaps: status.totalCoverageGaps,
      items: [],
      unplacedPreview: [],
      edgesPreview: [],
      coverageGapsPreview: [],
    },
    diagnosis: {},
  };
}

function seed(records: EvtxRecord[], isLoading = false): void {
  useEvtxStore.setState({
    records,
    channels: [
      {
        name: "Application",
        eventCount: records.length,
        sourceType: { file: { path: "sample.evtx" } },
      },
      {
        name: "Security",
        eventCount: records.length,
        sourceType: { file: { path: "sample.evtx" } },
      },
    ],
    selectedChannels: new Set(["Application"]),
    loadedChannels: new Set(["Application", "Security"]),
    sourceMode: "files",
    timeWindow: "all",
    isLoading,
  });
}

describe("EventLogWorkspace backend-owned analysis wiring", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
    useLogStore.setState({
      entries: [],
      activeSource: null,
      sourceOpenMode: "merged",
    });
    mocks.buildAnalysis.mockReset().mockResolvedValue(analysisResult());
    mocks.closeAnalysis.mockReset().mockResolvedValue(undefined);
    mocks.queryTimeline.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("passes the currently visible snapshot to one analysis session", async () => {
    seed([RECORD]);
    render(<EventLogWorkspace />);

    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));
    expect(mocks.buildAnalysis).toHaveBeenCalledWith({
      records: [RECORD],
      entries: [],
      coverageGaps: [],
      cancelled: expect.any(Function),
    });
  });

  it("sends only filtered records to timeline and diagnosis analysis", async () => {
    const hiddenRecord: EvtxRecord = {
      ...RECORD,
      id: 2,
      eventRecordId: 102,
      channel: "Security",
      message: "Hidden event",
    };
    seed([RECORD, hiddenRecord]);
    render(<EventLogWorkspace />);

    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));
    expect(mocks.buildAnalysis).toHaveBeenCalledWith(
      expect.objectContaining({ records: [RECORD] }),
    );
  });

  it("coalesces a burst of record changes into one session build", async () => {
    const newer = { ...RECORD, id: 2, eventRecordId: 102 };
    const newest = { ...RECORD, id: 3, eventRecordId: 103 };
    seed([RECORD]);
    render(<EventLogWorkspace />);
    act(() => useEvtxStore.setState({ records: [RECORD, newer] }));
    act(() => useEvtxStore.setState({ records: [RECORD, newer, newest] }));

    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));
    expect(mocks.buildAnalysis).toHaveBeenCalledWith(
      expect.objectContaining({ records: [RECORD, newer, newest] }),
    );
  });

  it("defers analysis until a streamed load settles", async () => {
    const newer = { ...RECORD, id: 2, eventRecordId: 102 };
    seed([RECORD], true);
    render(<EventLogWorkspace />);
    act(() => useEvtxStore.setState({ records: [RECORD, newer] }));
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 150));
    });
    expect(mocks.buildAnalysis).not.toHaveBeenCalled();

    act(() => useEvtxStore.setState({ isLoading: false }));
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));
    expect(mocks.buildAnalysis).toHaveBeenCalledWith(
      expect.objectContaining({ records: [RECORD, newer] }),
    );
  });

  it("keeps a rolling-window snapshot stable until records change", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-30T12:00:00Z"));
    const boundaryRecord = {
      ...RECORD,
      timestampEpoch: Date.now() - 24 * 60 * 60 * 1_000 + 60_000,
    };
    seed([boundaryRecord]);
    useEvtxStore.setState({ timeWindow: "24h" });
    render(<EventLogWorkspace />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5 * 60_000);
    });
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1);

    const newRecord = {
      ...RECORD,
      id: 2,
      eventRecordId: 102,
      timestampEpoch: Date.now(),
    };
    act(() =>
      useEvtxStore.setState({ records: [boundaryRecord, newRecord] }),
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2);
    expect(mocks.buildAnalysis).toHaveBeenLastCalledWith(
      expect.objectContaining({ records: [newRecord] }),
    );
  });

  it("serializes more than eight rapid supersessions and builds only the newest snapshot", async () => {
    const firstBuild = deferred<ReturnType<typeof analysisResult>>();
    mocks.buildAnalysis
      .mockReset()
      .mockReturnValueOnce(firstBuild.promise)
      .mockResolvedValueOnce(analysisResult("session-latest", 11));
    seed([RECORD]);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));

    const firstOptions = mocks.buildAnalysis.mock.calls[0][0];
    let latestRecords = [RECORD];
    for (let index = 2; index <= 11; index += 1) {
      latestRecords = [
        ...latestRecords,
        { ...RECORD, id: index, eventRecordId: 100 + index },
      ];
      const records = latestRecords;
      act(() => useEvtxStore.setState({ records }));
    }
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 150));
    });

    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1);
    expect(firstOptions.cancelled()).toBe(true);

    await act(async () => {
      firstBuild.resolve(analysisResult("session-1"));
      await firstBuild.promise;
    });
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2));
    expect(mocks.buildAnalysis).toHaveBeenLastCalledWith(
      expect.objectContaining({ records: latestRecords }),
    );
    await waitFor(() =>
      expect(mocks.closeAnalysis).toHaveBeenCalledWith("session-1"),
    );
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 150));
    });
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2);
  });
});
