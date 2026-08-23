import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
import { buildUnifiedTimeline } from "./evtx-store";
import { selectVisibleRecords } from "./evtx-filter";
import {
  filterTimelineToRecords,
  stableRecordIdentity,
} from "./unified-timeline";
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
const filteredRecord: EvtxRecord = {
  ...record,
  id: 8,
  eventId: 2,
  message: "filtered",
};

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
      records: [{ ...record, eventRecordId: "7" }],
    });
  });
  it("accepts an event timeline origin that omits an optional process id", async () => {
    const timeline = {
      items: [
        {
          timestampMs: 1,
          severity: "info",
          message: "event",
          origin: {
            kind: "event",
            stableId: "source:Live|channel:Security|record:7",
            source: "Live",
            machine: null,
            bundle: null,
            channel: "Security",
            provider: "Provider",
            eventId: 1,
            recordId: 7,
          },
        },
      ],
      unplaced: [],
    };
    vi.mocked(invoke).mockResolvedValue(timeline);

    await expect(buildUnifiedTimeline([record])).resolves.toMatchObject({
      items: [{ origin: { processId: null } }],
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
      records: [{ ...record, eventRecordId: "7" }],
    });
  });

  it("passes same-record-id events from distinct sources without collapsing them", async () => {
    const timeline = { items: [], unplaced: [] };
    vi.mocked(invoke).mockResolvedValue(timeline);
    const otherSource = {
      ...record,
      sourceLabel: "bundle-b/capture.evtx",
    };

    await expect(buildUnifiedTimeline([record, otherSource])).resolves.toEqual(
      timeline,
    );
    expect(invoke).toHaveBeenCalledWith("evtx_build_unified_timeline", {
      entries: [],
      records: [
        { ...record, eventRecordId: "7" },
        { ...otherSource, eventRecordId: "7" },
      ],
    });
  });
  it("filters a large cached record set without rebuilding the backend payload", async () => {
    const records = Array.from({ length: 512 }, (_, index) => ({
      ...record,
      id: index,
      eventRecordId: index + 1,
    }));
    const timeline = {
      items: records.map((cachedRecord) => ({
        timestampMs: cachedRecord.timestampEpoch,
        severity: "info",
        message: cachedRecord.message,
        origin: {
          kind: "event",
          stableId: stableRecordIdentity(cachedRecord),
          source: cachedRecord.sourceLabel,
          machine: cachedRecord.computer,
          bundle: null,
          channel: cachedRecord.channel,
          provider: cachedRecord.provider,
          processId: null,
          eventId: cachedRecord.eventId,
          recordId: cachedRecord.eventRecordId,
        },
      })),
      unplaced: [],
    };
    vi.mocked(invoke).mockResolvedValue(timeline);

    const cached = await buildUnifiedTimeline(records);
    const first = filterTimelineToRecords(cached, records.slice(0, 1), records);
    const middle = filterTimelineToRecords(cached, records.slice(256, 257), records);

    expect(first.items).toHaveLength(1);
    expect(first.items[0].origin.recordId).toBe(1);
    expect(middle.items).toHaveLength(1);
    expect(middle.items[0].origin.recordId).toBe(257);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("fails closed instead of forwarding unsafe EventRecordIDs through JSON", async () => {
    const unsafe = { ...record, eventRecordId: Number.MAX_SAFE_INTEGER + 2 };
    await expect(buildUnifiedTimeline([unsafe])).rejects.toThrow(
      "safe integer",
    );
    expect(invoke).not.toHaveBeenCalled();
  });

  it("forwards an unsafe numeric ID only with its lossless decimal representation", async () => {
    const exactId = "9007199254740993";
    const lossless = {
      ...record,
      eventRecordId: Number(exactId),
      eventRecordIdText: exactId,
    };
    vi.mocked(invoke).mockResolvedValue({ items: [], unplaced: [] });

    await buildUnifiedTimeline([lossless]);

    expect(invoke).toHaveBeenCalledWith("evtx_build_unified_timeline", {
      entries: [],
      records: [{ ...lossless, eventRecordId: exactId }],
    });
  });
  it("rejects malformed timeline items before returning them to the workspace", async () => {
    vi.mocked(invoke).mockResolvedValue({
      items: [
        {
          timestampMs: 1,
          severity: "info",
          message: "bad",
          origin: { kind: "unknown" },
        },
      ],
      unplaced: [],
    });

    await expect(buildUnifiedTimeline([record])).rejects.toThrow(
      /Invalid unified timeline: items\[0\]\.origin\.kind/,
    );
  });

  it("rejects malformed correlation edge evidence", async () => {
    vi.mocked(invoke).mockResolvedValue({
      items: [],
      unplaced: [],
      edges: [
        {
          id: "edge",
          fromId: "from",
          toId: null,
          key: { kind: "activityId", value: "activity" },
          strength: "exact",
          confidence: "high",
          candidateIds: [],
          evidence: [{ originId: "from", field: "activityId", value: 42 }],
          coverage: { state: "covered" },
        },
      ],
    });

    await expect(buildUnifiedTimeline([record])).rejects.toThrow(
      /Invalid unified timeline: edges\[0\]\.evidence\[0\]\.value/,
    );
  });
  it("rejects a gap correlation edge without a coverage explanation", async () => {
    vi.mocked(invoke).mockResolvedValue({
      items: [],
      unplaced: [],
      edges: [
        {
          id: "edge",
          fromId: "from",
          toId: null,
          key: { kind: "activityId", value: "activity" },
          strength: "ambiguous",
          confidence: "unknown",
          candidateIds: [],
          evidence: [],
          coverage: { state: "gap" },
        },
      ],
    });

    await expect(buildUnifiedTimeline([record])).rejects.toThrow(
      /Invalid unified timeline: edges\[0\]\.coverage\.gap/,
    );
  });

  it("rejects a covered correlation edge that carries a coverage gap", async () => {
    vi.mocked(invoke).mockResolvedValue({
      items: [],
      unplaced: [],
      edges: [
        {
          id: "edge",
          fromId: "from",
          toId: null,
          key: { kind: "activityId", value: "activity" },
          strength: "exact",
          confidence: "high",
          candidateIds: [],
          evidence: [],
          coverage: {
            state: "covered",
            gap: { source: "from", reason: "unexpected gap" },
          },
        },
      ],
    });

    await expect(buildUnifiedTimeline([record])).rejects.toThrow(
      /Invalid unified timeline: edges\[0\]\.coverage\.gap/,
    );
  });
  it("accepts a covered correlation edge with a null coverage gap", async () => {
    vi.mocked(invoke).mockResolvedValue({
      items: [],
      unplaced: [],
      edges: [
        {
          id: "edge",
          fromId: "from",
          toId: null,
          key: { kind: "activityId", value: "activity" },
          strength: "exact",
          confidence: "high",
          candidateIds: [],
          evidence: [],
          coverage: { state: "covered", gap: null },
        },
      ],
    });

    await expect(buildUnifiedTimeline([record])).resolves.toMatchObject({
      edges: [{ coverage: { state: "covered" } }],
    });
  });

  it("accepts legacy timelines that omit optional correlation fields", async () => {
    const timeline = {
      items: [],
      unplaced: [],
      edges: [
        {
          id: "legacy-edge",
          fromId: "from",
          toId: null,
          key: { kind: "activityId", value: "activity" },
          strength: "exact",
          confidence: "high",
          coverage: { state: "covered" },
        },
      ],
    };
    vi.mocked(invoke).mockResolvedValue(timeline);

    await expect(buildUnifiedTimeline([record])).resolves.toEqual({
      ...timeline,
      edges: [
        {
          ...timeline.edges[0],
          candidateIds: [],
          evidence: [],
        },
      ],
    });
  });
});
