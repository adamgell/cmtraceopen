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
vi.mock("./EvtxViewBar", () => ({ EvtxViewBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxTimeline", () => ({ EvtxTimeline: () => null }));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./EventDiagnosisPanel", () => ({ EventDiagnosisPanel: () => null }));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));

import { loadSelectedLogFile } from "../../lib/log-source";
import { setCachedTabSnapshot, useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import type { LogEntry } from "../../types/log";
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

function textLog(filePath: string, line: number): LogEntry {
  return {
    id: line,
    lineNumber: line,
    message: `line ${line}`,
    component: null,
    timestamp: 1_000 + line,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Ccm",
    filePath,
    timezoneOffset: null,
  };
}

const LOG_A = "C:\\logs\\a.log";
const LOG_B = "C:\\logs\\b.log";

/**
 * The log store as a text-log open leaves it, in the modes that replace (the other workspace
 * tests all seed "merged", which never narrows the entries, so none of them can tell a replacing
 * open from an additive one).
 */
function openTextLog(filePath: string, lines: number): void {
  useLogStore.setState({
    activeSource: { kind: "file", path: filePath },
    sourceOpenMode: "single-file",
    entries: Array.from({ length: lines }, (_, index) => textLog(filePath, index + 1)),
  });
}

describe("EventLogWorkspace text-log wiring", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
    useUiStore.setState({ currentPlatform: "windows" });
    useLogStore.setState({
      entries: [],
      activeSource: null,
      sourceOpenMode: null,
      isLoading: false,
    });
    mocks.buildAnalysis.mockReset().mockResolvedValue(analysisResult());
    mocks.closeAnalysis.mockReset().mockResolvedValue(undefined);
    mocks.queryTimeline.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("builds a new session with the entries of a text log opened after mount", async () => {
    seed([RECORD]);
    openTextLog(LOG_A, 2);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));
    expect(mocks.buildAnalysis.mock.calls[0][0].entries.map((e: LogEntry) => e.filePath)).toEqual([
      LOG_A,
      LOG_A,
    ]);

    // The next open replaces the first in the store; the session follows the store.
    act(() => openTextLog(LOG_B, 3));

    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2));
    const entries: LogEntry[] = mocks.buildAnalysis.mock.calls[1][0].entries;
    expect(entries).toHaveLength(3);
    expect(entries.every((entry) => entry.filePath === LOG_B)).toBe(true);
  });

  it("rebuilds with a cached file's entries when it takes over from a load that held the flag", async () => {
    seed([RECORD]);
    openTextLog(LOG_A, 2);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));

    // A folder load is in flight: the flag is up, and nothing is built from its half state.
    act(() => useLogStore.setState({ isLoading: true, activeSource: { kind: "folder", path: "C:\\logs" } }));
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 150));
    });
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1);

    // The sidebar's click on a file it already parsed supersedes that load. The load's own finally
    // can no longer clear the flag, so the cache hit does, and the workspace builds again.
    setCachedTabSnapshot(LOG_B, {
      entries: Array.from({ length: 3 }, (_, index) => textLog(LOG_B, index + 1)),
      formatDetected: "Ccm",
      parserSelection: null,
      totalLines: 3,
      byteOffset: 0,
      selectedSourceFilePath: LOG_B,
      sourceOpenMode: "single-file",
      activeColumns: [],
    });
    await act(async () => {
      await loadSelectedLogFile(LOG_B, { kind: "folder", path: "C:\\logs" });
    });

    expect(useLogStore.getState().isLoading).toBe(false);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2));
    const entries: LogEntry[] = mocks.buildAnalysis.mock.calls[1][0].entries;
    expect(entries).toHaveLength(3);
    expect(entries.every((entry) => entry.filePath === LOG_B)).toBe(true);
  });

  it("holds and then rebuilds when nothing but the log store's loading flag changes", async () => {
    // Neither the entries nor the source move in this test, so the flag is the only input that can
    // make the workspace hold and build again. It is the one a dropped dependency would miss.
    seed([RECORD]);
    openTextLog(LOG_A, 2);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));
    const entriesBefore = useLogStore.getState().entries;

    act(() => useLogStore.setState({ isLoading: true }));
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 150));
    });
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1);
    // The published session is closed for the length of the load.
    expect(mocks.closeAnalysis).toHaveBeenCalledWith("session-1");

    act(() => useLogStore.setState({ isLoading: false }));
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2));
    expect(useLogStore.getState().entries).toBe(entriesBefore);
  });

  it("builds no session while the log store is loading, even after the source has moved", async () => {
    seed([RECORD]);
    openTextLog(LOG_A, 2);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1));

    // A folder load moves the source first and keeps the previous entries until the parse ends.
    // Scoped to the new folder, those entries no longer belong to it.
    act(() => useLogStore.setState({ isLoading: true }));
    act(() => useLogStore.setState({ activeSource: { kind: "folder", path: "C:\\other" } }));
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 150));
    });
    expect(mocks.buildAnalysis).toHaveBeenCalledTimes(1);

    act(() =>
      useLogStore.setState({
        sourceOpenMode: "aggregate-folder",
        entries: [textLog("C:\\other\\c.log", 1)],
        isLoading: false,
      }),
    );
    await waitFor(() => expect(mocks.buildAnalysis).toHaveBeenCalledTimes(2));
    expect(
      mocks.buildAnalysis.mock.calls[1][0].entries.map((e: LogEntry) => e.filePath),
    ).toEqual(["C:\\other\\c.log"]);
  });
});
