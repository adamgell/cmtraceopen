import { describe, expect, it } from "vitest";
import {
  buildGroupSummaries,
  classifyChannelReads,
  GROUP_RECENT_ITEMS,
  GROUP_TREND_BINS,
  groupedViewField,
  trendWindowLabel,
  type ChannelReadKind,
  type GroupSummariesInput,
} from "./evtx-group-summaries";
import { formatCoverageGap } from "./evtx-coverage";
import { buildGroupedRows } from "./evtx-filter";
import type { EvtxLevel, EvtxRecord } from "./types";

const HOUR = 60 * 60 * 1000;
/** 2026-10-06 00:00:00 UTC. */
const DAY_START = Date.UTC(2026, 9, 6);
const NOW = DAY_START + 24 * HOUR;

let nextId = 1;
function rec(partial: Partial<EvtxRecord> & { at?: number }): EvtxRecord {
  const { at, ...rest } = partial;
  const id = nextId++;
  return {
    id,
    eventRecordId: id,
    timestamp: "",
    timestampEpoch: at ?? DAY_START + HOUR,
    provider: "Service Control Manager",
    channel: "System",
    eventId: 7036,
    level: "Information",
    computer: "PC01",
    message: "The service entered the running state.",
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "System.evtx",
    ...rest,
  };
}

const complete = (): ChannelReadKind => "complete";

function input(overrides: Partial<GroupSummariesInput>): GroupSummariesInput {
  const records = overrides.records ?? [];
  return {
    records,
    loadedRecords: overrides.loadedRecords ?? records,
    field: "eventId",
    timeZoneMode: "utc",
    timeWindow: "24h",
    nowMs: NOW,
    sourceMode: "live",
    channelRead: complete,
    ...overrides,
  };
}

/** The bin a timestamp falls in on a 24 h axis ending at NOW: one bin per hour. */
const hourBin = (at: number) => Math.floor((at - DAY_START) / HOUR);

describe("groupedViewField", () => {
  it("uses the first Group by field and defaults to Event ID when Group by is None", () => {
    expect(groupedViewField([])).toBe("eventId");
    expect(groupedViewField(["provider", "level"])).toBe("provider");
  });
});

describe("trendWindowLabel", () => {
  it("names each window for the trend header", () => {
    expect(trendWindowLabel("1h")).toBe("1 h");
    expect(trendWindowLabel("24h")).toBe("24 h");
    expect(trendWindowLabel("7d")).toBe("7 d");
    expect(trendWindowLabel("30d")).toBe("30 d");
    expect(trendWindowLabel("all")).toBe("All loaded");
  });
});

describe("buildGroupSummaries: grouping, counts and sort (spec 8.8)", () => {
  it("groups by the key with the same labels the table's group headers use", () => {
    const records = [
      rec({ provider: "A" }),
      rec({ provider: "B" }),
      rec({ provider: "" }),
      rec({ provider: "A" }),
    ];
    const result = buildGroupSummaries(input({ records, field: "provider" }));
    const tableLabels = buildGroupedRows(records, ["provider"], new Set(), "utc")
      .filter((row) => row.kind === "group")
      .map((row) => (row.kind === "group" ? row.label : ""));
    expect(result.summaries.map((summary) => summary.value).sort()).toEqual(
      [...tableLabels].sort(),
    );
    expect(result.summaries.find((summary) => summary.value === "A")?.count).toBe(2);
    expect(result.summaries.find((summary) => summary.value === "(no provider)")?.count).toBe(1);
  });

  it("sorts by severity rank, then count descending, then the latest last seen", () => {
    const records = [
      // 100: three Information events.
      rec({ eventId: 100, at: DAY_START + 1 * HOUR }),
      rec({ eventId: 100, at: DAY_START + 2 * HOUR }),
      rec({ eventId: 100, at: DAY_START + 3 * HOUR }),
      // 200: one Error event, so it outranks every Information group whatever its count.
      rec({ eventId: 200, level: "Error", at: DAY_START + 1 * HOUR }),
      // 300 and 301: one Warning each; 301 was seen later, so it comes first.
      rec({ eventId: 300, level: "Warning", at: DAY_START + 1 * HOUR }),
      rec({ eventId: 301, level: "Warning", at: DAY_START + 5 * HOUR }),
      // 400: two Warning events, so it leads the Warning groups on count.
      rec({ eventId: 400, level: "Warning", at: DAY_START + 1 * HOUR }),
      rec({ eventId: 400, level: "Warning", at: DAY_START + 2 * HOUR }),
      // 500: one Critical event.
      rec({ eventId: 500, level: "Critical", at: DAY_START + 1 * HOUR }),
      // 600: one Verbose event.
      rec({ eventId: 600, level: "Verbose", at: DAY_START + 1 * HOUR }),
    ];
    const order = buildGroupSummaries(input({ records })).summaries.map((s) => s.value);
    expect(order).toEqual(["500", "200", "400", "301", "300", "100", "600"]);
  });

  it("breaks a full tie on the key, numerically for Event IDs, so the order is stable", () => {
    const at = DAY_START + HOUR;
    const records = [rec({ eventId: 20, at }), rec({ eventId: 3, at }), rec({ eventId: 100, at })];
    expect(buildGroupSummaries(input({ records })).summaries.map((s) => s.value)).toEqual([
      "3",
      "20",
      "100",
    ]);
  });

  it("ranks a group at its most severe level", () => {
    const records = [
      rec({ eventId: 1000, level: "Information" }),
      rec({ eventId: 1000, level: "Error" }),
      rec({ eventId: 1000, level: "Warning" }),
    ];
    const [summary] = buildGroupSummaries(input({ records })).summaries;
    expect(summary.level).toBe<EvtxLevel>("Error");
  });

  it("lists the distinct event IDs and providers of a group", () => {
    const records = [
      rec({ eventId: 1000, provider: "Application Error" }),
      rec({ eventId: 1000, provider: "Other Provider" }),
      rec({ eventId: 1000, provider: "Application Error" }),
    ];
    const [summary] = buildGroupSummaries(input({ records })).summaries;
    expect(summary.eventIds).toEqual([1000]);
    expect(summary.providers).toEqual(["Application Error", "Other Provider"]);
    const byProvider = buildGroupSummaries(
      input({
        records: [rec({ eventId: 2, provider: "P" }), rec({ eventId: 1, provider: "P" })],
        field: "provider",
      }),
    ).summaries[0];
    expect(byProvider.eventIds).toEqual([1, 2]);
  });

  it("returns no summaries for no records", () => {
    const result = buildGroupSummaries(input({ records: [] }));
    expect(result.summaries).toEqual([]);
  });
});

describe("buildGroupSummaries: typical message and last seen", () => {
  it("takes the most frequent message", () => {
    const records = [
      rec({ message: "rare", at: DAY_START + 9 * HOUR }),
      rec({ message: "common", at: DAY_START + 1 * HOUR }),
      rec({ message: "common", at: DAY_START + 2 * HOUR }),
    ];
    expect(buildGroupSummaries(input({ records })).summaries[0].typicalMessage).toBe("common");
  });

  it("gives a tie to the message seen latest", () => {
    const records = [
      rec({ message: "older", at: DAY_START + 1 * HOUR }),
      rec({ message: "newer", at: DAY_START + 4 * HOUR }),
      rec({ message: "older", at: DAY_START + 2 * HOUR }),
      rec({ message: "newer", at: DAY_START + 3 * HOUR }),
    ];
    expect(buildGroupSummaries(input({ records })).summaries[0].typicalMessage).toBe("newer");
  });

  it("never picks an empty message over a real one, and is empty only when every message is", () => {
    const records = [rec({ message: "" }), rec({ message: "" }), rec({ message: "real" })];
    expect(buildGroupSummaries(input({ records })).summaries[0].typicalMessage).toBe("real");
    const blank = buildGroupSummaries(input({ records: [rec({ message: "  " })] }));
    expect(blank.summaries[0].typicalMessage).toBe("");
  });

  it("reports the latest timestamp as last seen, and null when no record has one", () => {
    const records = [
      rec({ at: DAY_START + 2 * HOUR }),
      rec({ at: DAY_START + 7 * HOUR }),
      rec({ at: 0 }),
    ];
    expect(buildGroupSummaries(input({ records })).summaries[0].lastSeenMs).toBe(
      DAY_START + 7 * HOUR,
    );
    const none = buildGroupSummaries(
      input({ records: [rec({ at: 0 })], timeWindow: "all" }),
    );
    expect(none.summaries[0].lastSeenMs).toBeNull();
  });
});

describe("buildGroupSummaries: recent items", () => {
  it(`keeps the ${GROUP_RECENT_ITEMS} most recent records, newest first`, () => {
    const records = Array.from({ length: 12 }, (_, i) => rec({ at: DAY_START + i * HOUR }));
    const [summary] = buildGroupSummaries(input({ records })).summaries;
    expect(summary.count).toBe(12);
    expect(summary.recent).toHaveLength(GROUP_RECENT_ITEMS);
    expect(summary.recent.map((record) => record.timestampEpoch)).toEqual(
      Array.from({ length: GROUP_RECENT_ITEMS }, (_, i) => DAY_START + (11 - i) * HOUR),
    );
  });

  it("puts records without a timestamp after every timed one", () => {
    const untimed = rec({ at: 0 });
    const timed = rec({ at: DAY_START + HOUR });
    const [summary] = buildGroupSummaries(
      input({ records: [untimed, timed], timeWindow: "all" }),
    ).summaries;
    expect(summary.recent).toEqual([timed, untimed]);
  });
});

describe("buildGroupSummaries: the 24-bin trend", () => {
  it("spans the time window ending now, one bin per hour for 24 h", () => {
    const records = [
      rec({ at: DAY_START + 30 * 60 * 1000 }),
      rec({ at: DAY_START + 30 * 60 * 1000 + 1 }),
      rec({ at: DAY_START + 5 * HOUR + 1 }),
      // Another System event at the end of the window: System was read up to then.
      rec({ eventId: 1, at: NOW }),
    ];
    const result = buildGroupSummaries(input({ records }));
    expect(result.span).toEqual({ startMs: DAY_START, endMs: NOW });
    const { trend } = result.summaries[0];
    expect(trend).toHaveLength(GROUP_TREND_BINS);
    expect(trend[0]).toBe(2);
    expect(trend[5]).toBe(1);
    // A complete live read: every other hour was read and held none of these events.
    expect(trend.filter((bin) => bin === 0)).toHaveLength(GROUP_TREND_BINS - 2);
  });

  it("puts an event at the very end of the span in the last bin", () => {
    const [summary] = buildGroupSummaries(input({ records: [rec({ at: NOW })] })).summaries;
    expect(summary.trend[GROUP_TREND_BINS - 1]).toBe(1);
  });

  it("spans the loaded records, not only the visible ones, for All time", () => {
    const loaded = [
      rec({ eventId: 1, at: DAY_START }),
      rec({ eventId: 2, at: DAY_START + 12 * HOUR }),
    ];
    const result = buildGroupSummaries(
      input({
        records: [loaded[1]],
        loadedRecords: loaded,
        timeWindow: "all",
        sourceMode: "files",
      }),
    );
    expect(result.span).toEqual({ startMs: DAY_START, endMs: DAY_START + 12 * HOUR });
    expect(result.summaries[0].trend[GROUP_TREND_BINS - 1]).toBe(1);
  });

  it("leaves events without a timestamp out of the bins and counts them as unplaced", () => {
    const records = [rec({ at: 0 }), rec({ at: DAY_START + HOUR })];
    const [summary] = buildGroupSummaries(input({ records })).summaries;
    expect(summary.count).toBe(2);
    expect(summary.unplaced).toBe(1);
    expect(summary.trend.reduce<number>((total, bin) => total + (bin ?? 0), 0)).toBe(1);
  });

  it("has no span and an all-unknown trend when nothing loaded carries a timestamp", () => {
    const result = buildGroupSummaries(
      input({ records: [rec({ at: 0 })], timeWindow: "all", sourceMode: "files" }),
    );
    expect(result.span).toBeNull();
    expect(result.summaries[0].trend.every((bin) => bin === null)).toBe(true);
  });
});

describe("buildGroupSummaries: a trend never draws an unread span as zero (soul.md)", () => {
  it("leaves bins before a capped channel's oldest loaded event unknown, and later empty bins zero", () => {
    // The cap kept the newest events only: System was read back to 12:00 and no further.
    const records = [
      rec({ eventId: 7036, at: DAY_START + 12 * HOUR + 1 }),
      rec({ eventId: 7036, at: DAY_START + 20 * HOUR }),
      rec({ eventId: 7036, at: DAY_START + 23 * HOUR + 59 * 60 * 1000 }),
    ];
    const result = buildGroupSummaries(
      input({ records, channelRead: (channel) => (channel === "System" ? "newestOnly" : "complete") }),
    );
    const { trend } = result.summaries[0];
    for (let bin = 0; bin <= 12; bin += 1) {
      // Bin 12 holds 12:00 to 13:00, which the read covers only from 12:00:00.001: still unknown,
      // except that it holds an event, which is evidence and always counted.
      if (bin === hourBin(DAY_START + 12 * HOUR + 1)) {
        expect(trend[bin], `bin ${bin}`).toBe(1);
      } else {
        expect(trend[bin], `bin ${bin}`).toBeNull();
      }
    }
    expect(trend[13]).toBe(0);
    expect(trend[20]).toBe(1);
    expect(trend[22]).toBe(0);
    expect(trend[23]).toBe(1);
  });

  it("leaves every empty bin unknown for a channel with a gap that has no time", () => {
    const records = [rec({ at: DAY_START + 3 * HOUR })];
    const [summary] = buildGroupSummaries(
      input({ records, channelRead: () => "incomplete" }),
    ).summaries;
    expect(summary.trend[3]).toBe(1);
    expect(summary.trend.filter((bin) => bin === null)).toHaveLength(GROUP_TREND_BINS - 1);
  });

  it("knows a group only where every channel its events came from was read", () => {
    const records = [
      rec({ eventId: 1000, channel: "System", at: DAY_START + 20 * HOUR }),
      rec({ eventId: 1000, channel: "Application", at: DAY_START + 22 * HOUR }),
      // Application's oldest loaded event: its read reaches back to 18:00 only.
      rec({ eventId: 9, channel: "Application", at: DAY_START + 18 * HOUR }),
    ];
    const result = buildGroupSummaries(
      input({
        records,
        channelRead: (channel) => (channel === "Application" ? "newestOnly" : "complete"),
      }),
    );
    const mixed = result.summaries.find((summary) => summary.value === "1000");
    expect(mixed?.trend.slice(0, 18).every((bin) => bin === null)).toBe(true);
    expect(mixed?.trend[18]).toBe(0);
    expect(mixed?.trend[20]).toBe(1);
    // System's newest loaded event is at 20:00, so nothing after it is known for the group.
    expect(mixed?.trend[21]).toBeNull();
    expect(mixed?.trend[22]).toBe(1);
  });

  it("leaves a live channel's bins after its newest loaded event unknown, whatever other channels hold", () => {
    // System was read until 23:00; Application's newest event is at 09:00. Nothing the store holds
    // says Application was read after that (another channel's later load or tail batch does not).
    const records = [
      rec({ eventId: 1, channel: "System", at: DAY_START + 23 * HOUR }),
      rec({ eventId: 1000, channel: "Application", at: DAY_START + 2 * HOUR }),
      rec({ eventId: 1000, channel: "Application", at: DAY_START + 9 * HOUR }),
    ];
    const result = buildGroupSummaries(input({ records }));
    const application = result.summaries.find((summary) => summary.value === "1000");
    // A complete live read covered the window from its start.
    expect(application?.trend[0]).toBe(0);
    expect(application?.trend[2]).toBe(1);
    expect(application?.trend[8]).toBe(0);
    expect(application?.trend[9]).toBe(1);
    expect(application?.trend.slice(10).every((bin) => bin === null)).toBe(true);
  });

  it("starts a live channel at its oldest event when there is no window: the query asked for no start", () => {
    const records = [
      rec({ eventId: 1, channel: "System", at: DAY_START }),
      rec({ eventId: 1, channel: "System", at: DAY_START + 24 * HOUR }),
      rec({ eventId: 2, channel: "Application", at: DAY_START + 6 * HOUR }),
      rec({ eventId: 2, channel: "Application", at: DAY_START + 24 * HOUR }),
    ];
    const result = buildGroupSummaries(input({ records, timeWindow: "all" }));
    const application = result.summaries.find((summary) => summary.value === "2");
    expect(application?.trend.slice(0, 6).every((bin) => bin === null)).toBe(true);
    expect(application?.trend[7]).toBe(0);
  });

  it("knows a file only from its oldest to its newest event", () => {
    const loaded = [
      rec({ eventId: 1, channel: "System", at: DAY_START }),
      rec({ eventId: 1, channel: "System", at: DAY_START + 24 * HOUR }),
      rec({ eventId: 2, channel: "Application", at: DAY_START + 6 * HOUR }),
      rec({ eventId: 2, channel: "Application", at: DAY_START + 12 * HOUR }),
    ];
    const result = buildGroupSummaries(
      input({ records: loaded, timeWindow: "all", sourceMode: "files" }),
    );
    const system = result.summaries.find((summary) => summary.value === "1");
    const application = result.summaries.find((summary) => summary.value === "2");
    expect(system?.trend.filter((bin) => bin === null)).toHaveLength(0);
    expect(application?.trend.slice(0, 6).every((bin) => bin === null)).toBe(true);
    expect(application?.trend[6]).toBe(1);
    expect(application?.trend[7]).toBe(0);
    expect(application?.trend[12]).toBe(1);
    expect(application?.trend.slice(13).every((bin) => bin === null)).toBe(true);
  });
});

describe("classifyChannelReads", () => {
  const base = {
    remoteMachine: null,
    channels: [],
    coverageDetails: [],
    manifestCoverage: [],
    legacyCoverage: [],
    tailCoverage: [],
  };

  it("calls a channel with no gap complete", () => {
    expect(classifyChannelReads(base)("System")).toBe("complete");
  });

  it("recognizes the auto-load cap the store writes as a newest-only read", () => {
    const read = classifyChannelReads({
      ...base,
      legacyCoverage: ["Security: newest 2000 events shown (the channel may hold more)"],
    });
    expect(read("Security")).toBe("newestOnly");
    expect(read("System")).toBe("complete");
  });

  it("matches a remote channel's gap by machine and channel", () => {
    const read = classifyChannelReads({
      ...base,
      remoteMachine: "PC02",
      legacyCoverage: ["PC02/System: 3 batches of events were not received"],
    });
    expect(read("System")).toBe("incomplete");
  });

  it("calls a capped channel that also lost events incomplete", () => {
    const read = classifyChannelReads({
      ...base,
      legacyCoverage: [
        "System: newest 2000 events shown (the channel may hold more)",
        "System: 4 of 2000 events did not reach the view",
      ],
    });
    expect(read("System")).toBe("incomplete");
  });

  it("matches a file's structured gap by the file path the channel was read from", () => {
    const read = classifyChannelReads({
      ...base,
      channels: [
        { name: "System", eventCount: 10, sourceType: { file: { path: "C:/logs/System.evtx" } } },
      ],
      coverageDetails: [
        { source: "C:/logs/System.evtx", kind: "chunk", reason: "chunk 3 could not be parsed" },
      ],
    });
    expect(read("System")).toBe("incomplete");
  });

  it("does not count a gap string twice when it repeats a structured gap", () => {
    const provider = { source: "System", kind: "provider" as const, reason: "message unavailable" };
    const chunk = { source: "C:/logs/App.evtx", kind: "chunk" as const, reason: "bad chunk", chunkId: 3 };
    const read = classifyChannelReads({
      ...base,
      channels: [
        { name: "Application", eventCount: 1, sourceType: { file: { path: "C:/logs/App.evtx" } } },
      ],
      coverageDetails: [provider, chunk],
      legacyCoverage: [formatCoverageGap(provider), formatCoverageGap(chunk)],
    });
    // The provider gap leaves every event in place; its string twin must not undo that.
    expect(read("System")).toBe("complete");
    expect(read("Application")).toBe("incomplete");
  });

  it("ignores gaps that leave every event in place", () => {
    const read = classifyChannelReads({
      ...base,
      coverageDetails: [
        { source: "System", kind: "provider", reason: "message unavailable" },
        { source: "Setup", kind: "empty", reason: "no events" },
      ],
      tailCoverage: ["System: live tail unavailable (unsupported)"],
    });
    expect(read("System")).toBe("complete");
    expect(read("Setup")).toBe("complete");
  });

  it("calls a manifest gap on the channel's file incomplete", () => {
    const read = classifyChannelReads({
      ...base,
      channels: [
        { name: "Application", eventCount: 1, sourceType: { file: { path: "/x/Application.evtx" } } },
      ],
      manifestCoverage: [{ kind: "limitReached", path: "/x/Application.evtx", reason: "stopped" }],
    });
    expect(read("Application")).toBe("incomplete");
  });
});
