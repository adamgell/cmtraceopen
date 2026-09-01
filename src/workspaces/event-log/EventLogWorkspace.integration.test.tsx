import type * as EvtxStoreModule from "./evtx-store";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const mocks = vi.hoisted(() => ({
  buildTimeline: vi.fn(),
  diagnose: vi.fn(),
}));

vi.mock("../../lib/commands", () => ({
  diagnoseEventRecords: mocks.diagnose,
}));
vi.mock("./evtx-store", async () => {
  const actual = await vi.importActual<typeof EvtxStoreModule>("./evtx-store");
  return { ...actual, buildUnifiedTimeline: mocks.buildTimeline };
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

const TIMELINE = {
  items: [],
  unplaced: [],
  edges: [],
  coverageGaps: [],
};

describe("EventLogWorkspace diagnosis and timeline wiring", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
    useLogStore.setState({
      entries: [],
      activeSource: null,
      sourceOpenMode: "merged",
    });
    mocks.buildTimeline.mockReset();
    mocks.diagnose.mockReset();
    mocks.buildTimeline.mockResolvedValue(TIMELINE);
    mocks.diagnose.mockResolvedValue({});
  });

  afterEach(() => {
    cleanup();
  });

  it("passes the resolved full timeline to diagnosis", async () => {
    useEvtxStore.setState({
      records: [RECORD],
      channels: [
        {
          name: "Application",
          eventCount: 1,
          sourceType: { file: { path: "sample.evtx" } },
        },
      ],
      selectedChannels: new Set(["Application"]),
      loadedChannels: new Set(["Application"]),
      sourceMode: "files",
      timeWindow: "all",
    });

    render(<EventLogWorkspace />);

    await waitFor(() => expect(mocks.buildTimeline).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mocks.diagnose).toHaveBeenCalledTimes(1));

    expect(mocks.buildTimeline).toHaveBeenCalledWith([RECORD], []);
    expect(mocks.diagnose).toHaveBeenCalledWith([RECORD], [], TIMELINE, []);
  });

  it("coalesces a burst of record changes into one timeline rebuild", async () => {
    const newer = {
      ...RECORD,
      id: 2,
      eventRecordId: 102,
      message: "Newer event",
    };
    const newest = {
      ...RECORD,
      id: 3,
      eventRecordId: 103,
      message: "Newest event",
    };
    useEvtxStore.setState({
      records: [RECORD],
      channels: [
        {
          name: "Application",
          eventCount: 3,
          sourceType: { file: { path: "sample.evtx" } },
        },
      ],
      selectedChannels: new Set(["Application"]),
      loadedChannels: new Set(["Application"]),
      sourceMode: "files",
      timeWindow: "all",
    });

    render(<EventLogWorkspace />);
    act(() => useEvtxStore.setState({ records: [RECORD, newer] }));
    act(() => useEvtxStore.setState({ records: [RECORD, newer, newest] }));

    await waitFor(() => expect(mocks.buildTimeline).toHaveBeenCalledTimes(1));
    expect(mocks.buildTimeline).toHaveBeenCalledWith(
      [RECORD, newer, newest],
      [],
    );
  });

  it("serializes timeline builds and runs only the newest queued snapshot", async () => {
    const firstBuild = deferred<typeof TIMELINE>();
    const newer = {
      ...RECORD,
      id: 2,
      eventRecordId: 102,
      message: "Newer event",
    };
    mocks.buildTimeline
      .mockReset()
      .mockReturnValueOnce(firstBuild.promise)
      .mockResolvedValue(TIMELINE);
    useEvtxStore.setState({
      records: [RECORD],
      channels: [
        {
          name: "Application",
          eventCount: 2,
          sourceType: { file: { path: "sample.evtx" } },
        },
      ],
      selectedChannels: new Set(["Application"]),
      loadedChannels: new Set(["Application"]),
      sourceMode: "files",
      timeWindow: "all",
    });

    render(<EventLogWorkspace />);
    await waitFor(() => expect(mocks.buildTimeline).toHaveBeenCalledTimes(1));

    act(() => useEvtxStore.setState({ records: [RECORD, newer] }));
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 150));
    });
    expect(mocks.buildTimeline).toHaveBeenCalledTimes(1);

    await act(async () => {
      firstBuild.resolve(TIMELINE);
      await firstBuild.promise;
    });
    await waitFor(() => expect(mocks.buildTimeline).toHaveBeenCalledTimes(2));
    expect(mocks.buildTimeline).toHaveBeenLastCalledWith([RECORD, newer], []);
  });
});
