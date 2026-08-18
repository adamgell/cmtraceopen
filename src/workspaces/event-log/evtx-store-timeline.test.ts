import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
import { buildUnifiedTimeline } from "./evtx-store";
import { selectVisibleRecords } from "./evtx-filter";
import { filterTimelineToRecords } from "./unified-timeline";
import type { EvtxRecord } from "./types";

const record: EvtxRecord = {
  id: 7,
  eventRecordId: 7,
  timestamp: "2026-01-01T00:00:00Z",
  timestampEpoch: 1,
  provider: "Visible",
  channel: "Security",
  eventId: 1,
  level: "Information",
  computer: "HOST",
  message: "visible",
  eventData: [],
  rawXml: "",
  sourceLabel: "capture.evtx",
};
const filteredRecord: EvtxRecord = { ...record, id: 8, eventId: 2, message: "filtered" };

describe("buildUnifiedTimeline", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
  });

  it("uses the loaded records and parser entries with the real timeline command", async () => {
    const timeline = { items: [], unplaced: [] };
    vi.mocked(invoke).mockResolvedValue(timeline);

    await expect(buildUnifiedTimeline([record])).resolves.toEqual(timeline);
    expect(invoke).toHaveBeenCalledWith("evtx_build_unified_timeline", {
      entries: [],
      records: [record],
    });
  });

  it("builds the unified timeline from the same visible records as the event list", async () => {
    const timeline = { items: [], unplaced: [] };
    vi.mocked(invoke).mockResolvedValue(timeline);

    const visible = selectVisibleRecords({
      records: [record, filteredRecord],
      selectedChannels: new Set(["Security"]),
      filterLevels: new Set(["Information"]),
      filterEventIds: "1",
      filterSearch: "",
    });
    await expect(buildUnifiedTimeline(visible)).resolves.toEqual(timeline);
    expect(invoke).toHaveBeenCalledWith("evtx_build_unified_timeline", {
      entries: [],
      records: [record],
    });
  });

  it("passes same-record-id events from distinct sources without collapsing them", async () => {
    const timeline = { items: [], unplaced: [] };
    vi.mocked(invoke).mockResolvedValue(timeline);
    const otherSource = {
      ...record,
      sourceLabel: "bundle-b/capture.evtx",
    };

    await expect(buildUnifiedTimeline([record, otherSource])).resolves.toEqual(timeline);
    expect(invoke).toHaveBeenCalledWith("evtx_build_unified_timeline", {
      entries: [],
      records: [record, otherSource],
    });
  });
  it("filters a large cached record set without rebuilding the backend payload", async () => {
    const timeline = { items: [], unplaced: [] };
    vi.mocked(invoke).mockResolvedValue(timeline);
    const records = Array.from({ length: 512 }, (_, index) => ({
      ...record,
      id: index,
      eventRecordId: index + 1,
    }));

    const cached = await buildUnifiedTimeline(records);
    filterTimelineToRecords(cached, records.slice(0, 1));
    filterTimelineToRecords(cached, records.slice(256, 257));

    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("fails closed instead of forwarding unsafe EventRecordIDs through JSON", async () => {
    const unsafe = { ...record, eventRecordId: Number.MAX_SAFE_INTEGER + 2 };
    await expect(buildUnifiedTimeline([unsafe])).rejects.toThrow("safe integer");
    expect(invoke).not.toHaveBeenCalled();
  });
});
