import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  buildAnalysis: vi.fn(),
  closeAnalysis: vi.fn(),
  queryTimeline: vi.fn(),
  selectVisibleRecords: vi.fn(),
  visibleRecords: [] as unknown[],
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
vi.mock("../../lib/commands", () => ({
  closeEventLogAnalysisSession: mocks.closeAnalysis,
  queryEventLogAnalysisTimeline: mocks.queryTimeline,
}));
vi.mock("./event-analysis-session", () => ({
  buildEventLogAnalysisSession: mocks.buildAnalysis,
  EventLogAnalysisCancelled: class EventLogAnalysisCancelled extends Error {},
}));
vi.mock("./evtx-filter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-filter")>();
  return {
    ...actual,
    selectVisibleRecords: mocks.selectVisibleRecords,
  };
});
vi.mock("./SourcePicker", () => ({ SourcePicker: () => null }));
vi.mock("./ChannelPicker", () => ({ ChannelPicker: () => null }));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxCoverageBanner", () => ({ EvtxCoverageBanner: () => null }));
vi.mock("./EvtxTimeline", () => ({ EvtxTimeline: () => null }));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./EventDiagnosisPanel", () => ({ EventDiagnosisPanel: () => null }));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));

import { useLogStore } from "../../stores/log-store";
import { EventLogWorkspace } from "./EventLogWorkspace";
import { useEvtxStore } from "./evtx-store";
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

describe("EventLogWorkspace stable analysis membership", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: [RECORD],
      selectedChannels: new Set(["Application"]),
      loadedChannels: new Set(["Application"]),
      isLoading: false,
      sourceMode: "files",
      timeWindow: "all",
    });
    useLogStore.setState({
      entries: [],
      activeSource: null,
      sourceOpenMode: "merged",
    });
    mocks.buildAnalysis.mockReset();
    mocks.closeAnalysis.mockReset().mockResolvedValue(undefined);
    mocks.queryTimeline.mockReset();
    mocks.selectVisibleRecords.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("does not scan an unchanged memoized record array on an unrelated rerender", () => {
    const memoizedRecords = [RECORD];
    const some = vi.fn(() => {
      throw new Error("the unchanged record array was rescanned");
    });
    Object.defineProperty(memoizedRecords, "some", {
      configurable: true,
      value: some,
    });
    mocks.visibleRecords = memoizedRecords;
    mocks.selectVisibleRecords.mockReturnValue(memoizedRecords);

    const view = render(<EventLogWorkspace />);
    view.rerender(<EventLogWorkspace />);

    expect(mocks.selectVisibleRecords).toHaveBeenCalledTimes(1);
    expect(some).not.toHaveBeenCalled();
  });
});
