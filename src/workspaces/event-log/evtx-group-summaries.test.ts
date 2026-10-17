import { describe, expect, it } from "vitest";
import {
  buildGroupSummaries,
  classifyChannelReads,
  GROUP_RECENT_ITEMS,
  GROUP_TREND_BINS,
  groupedViewField,
  trendWindowLabel,
  type ChannelReadKind,
  type ChannelReads,
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

/** Channel reads from a table; a channel not listed is complete. */
function reads(
  kinds: Record<string, ChannelReadKind> = {},
  unattributedLoss = false,
): ChannelReads {
  return { kind: (channel) => kinds[channel] ?? "complete", unattributedLoss };
}

/**
 * Defaults: live, a 24 h window ending NOW, every channel of the loaded records in scope, read
 * whole and read through NOW.
 */
function input(overrides: Partial<GroupSummariesInput>): GroupSummariesInput {
  const records = overrides.records ?? [];
  const loadedRecords = overrides.loadedRecords ?? records;
  const channels = [...new Set(loadedRecords.map((record) => record.channel))];
  return {
    records,
    loadedRecords,
    field: "eventId",
    timeZoneMode: "utc",
    timeWindow: "24h",
    nowMs: NOW,
    sourceMode: "live",
    channelReads: reads(),
    scopeChannels: channels,
    readThrough: new Map(channels.map((channel) => [channel, NOW] as const)),
    ...overrides,
  };
}

/** Bins of `trend` from `from` to `to` inclusive. */
const bins = (trend: readonly (number | null)[], from: number, to: number) =>
  trend.slice(from, to + 1);

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
    ];
    const { trend } = buildGroupSummaries(
      input({ records, channelReads: reads({ System: "newestOnly" }) }),
    ).summaries[0];
    // Bin 12 is read only from 12:00:00.001, so it is unknown but for the event it holds.
    expect(bins(trend, 0, 11).every((bin) => bin === null)).toBe(true);
    expect(trend[hourBin(DAY_START + 12 * HOUR + 1)]).toBe(1);
    expect(trend[13]).toBe(0);
    expect(trend[20]).toBe(1);
    expect(trend[23]).toBe(0);
  });

  it("leaves every empty bin unknown for a channel with a gap that has no time", () => {
    const records = [rec({ at: DAY_START + 3 * HOUR })];
    const [summary] = buildGroupSummaries(
      input({ records, channelReads: reads({ System: "incomplete" }) }),
    ).summaries;
    expect(summary.trend[3]).toBe(1);
    expect(summary.trend.filter((bin) => bin === null)).toHaveLength(GROUP_TREND_BINS - 1);
  });

  it("leaves every empty bin unknown when a loss names no channel", () => {
    const records = [rec({ at: DAY_START + 3 * HOUR })];
    const [summary] = buildGroupSummaries(
      input({ records, channelReads: reads({}, true) }),
    ).summaries;
    expect(summary.trend[3]).toBe(1);
    expect(summary.trend.filter((bin) => bin === null)).toHaveLength(GROUP_TREND_BINS - 1);
  });
});

describe("buildGroupSummaries: every channel in the visible scope must be read", () => {
  /** System capped: its kept events run from 12:00 to 23:50 and are all Information. */
  const capped = () =>
    Array.from({ length: 24 }, (_, i) =>
      rec({ eventId: 7036, channel: "System", at: DAY_START + 12 * HOUR + i * 29 * 60 * 1000 }),
    );

  it("Group by Level: a capped System leaves the Error group's early bins unknown", () => {
    const records = [
      ...capped(),
      rec({ eventId: 1000, level: "Error", channel: "Application", at: DAY_START + 3 * HOUR }),
      rec({ eventId: 1000, level: "Error", channel: "Application", at: DAY_START + 9 * HOUR }),
      rec({ eventId: 1001, channel: "Application", at: DAY_START + 23 * HOUR }),
    ];
    const result = buildGroupSummaries(
      input({ records, field: "level", channelReads: reads({ System: "newestOnly" }) }),
    );
    const errors = result.summaries.find((summary) => summary.value === "Error")!;
    // Any System Error before 12:00 belongs to this group, and System was not read there.
    for (const bin of [0, 1, 2, 4, 5, 6, 7, 8, 10, 11]) expect(errors.trend[bin], `bin ${bin}`).toBeNull();
    expect(errors.trend[3]).toBe(1);
    expect(errors.trend[9]).toBe(1);
    expect(bins(errors.trend, 12, 23).every((bin) => bin === 0)).toBe(true);
  });

  it("Event ID 1000 seen only in Application: a capped selected System still leaves its early bins unknown", () => {
    const application = [
      rec({ eventId: 1000, channel: "Application", at: DAY_START + 5 * HOUR }),
    ];
    const records = [...capped(), ...application];
    const inScope = buildGroupSummaries(
      input({ records, channelReads: reads({ System: "newestOnly" }) }),
    ).summaries.find((summary) => summary.value === "1000")!;
    expect(inScope.trend[4]).toBeNull();
    expect(inScope.trend[13]).toBe(0);
    // The same events with System not in the visible scope: Application alone decides.
    const outOfScope = buildGroupSummaries(
      input({
        records,
        channelReads: reads({ System: "newestOnly" }),
        scopeChannels: ["Application"],
      }),
    ).summaries.find((summary) => summary.value === "1000")!;
    expect(outOfScope.trend[4]).toBe(0);
  });

  it("leaves every empty bin unknown when a channel in scope has no read time", () => {
    const records = [rec({ at: DAY_START + 3 * HOUR })];
    const [summary] = buildGroupSummaries(
      input({ records, scopeChannels: ["System", "Setup"] }),
    ).summaries;
    expect(summary.trend.filter((bin) => bin === null)).toHaveLength(GROUP_TREND_BINS - 1);
  });

  it("still consults a channel the group's events came from when it is not in the scope", () => {
    const records = [rec({ channel: "Setup", at: DAY_START + 3 * HOUR })];
    const [summary] = buildGroupSummaries(
      input({ records, scopeChannels: [], readThrough: new Map() }),
    ).summaries;
    expect(summary.trend.filter((bin) => bin === null)).toHaveLength(GROUP_TREND_BINS - 1);
  });
});

describe("buildGroupSummaries: a live read ends where the load read, not at a record", () => {
  /** System loaded whole at 09:00; 7036 at 02:00 and 08:30. */
  const loaded = () => [
    rec({ eventId: 7036, at: DAY_START + 2 * HOUR }),
    rec({ eventId: 7036, at: DAY_START + 8.5 * HOUR }),
  ];
  const readAt9 = new Map([["System", DAY_START + 9 * HOUR]]);

  it("a tail started after the load: bins between the load and the first tail event stay unknown", () => {
    const records = [...loaded(), rec({ eventId: 7040, at: DAY_START + 11 * HOUR + 5 * 60 * 1000 })];
    const result = buildGroupSummaries(input({ records, readThrough: readAt9 }));
    const service = result.summaries.find((summary) => summary.value === "7036")!;
    expect(service.trend[2]).toBe(1);
    expect(service.trend[5]).toBe(0);
    // Bin 8 ends at 09:00, where the load read through.
    expect(service.trend[8]).toBe(1);
    expect(bins(service.trend, 9, 23).every((bin) => bin === null)).toBe(true);
    const tail = result.summaries.find((summary) => summary.value === "7040")!;
    expect(tail.trend[11]).toBe(1);
    expect(tail.trend[10]).toBeNull();
    expect(tail.trend[12]).toBeNull();
  });

  it("Pause and Resume: the paused span stays unknown, the tail's events still count", () => {
    const records = [
      ...loaded(),
      rec({ eventId: 7040, at: DAY_START + 11 * HOUR + 5 * 60 * 1000 }),
      // Paused at 12:00, resumed at 14:00.
      rec({ eventId: 7040, at: DAY_START + 14.5 * HOUR }),
    ];
    const tail = buildGroupSummaries(input({ records, readThrough: readAt9 })).summaries.find(
      (summary) => summary.value === "7040",
    )!;
    expect(tail.trend[11]).toBe(1);
    expect(tail.trend[12]).toBeNull();
    expect(tail.trend[13]).toBeNull();
    expect(tail.trend[14]).toBe(1);
  });

  it("a quiet complete channel draws 0 up to its read time, after its newest event", () => {
    const records = [rec({ channel: "Application", at: DAY_START + 5 * HOUR })];
    const [summary] = buildGroupSummaries(
      input({ records, readThrough: new Map([["Application", DAY_START + 22.5 * HOUR]]) }),
    ).summaries;
    expect(bins(summary.trend, 0, 4).every((bin) => bin === 0)).toBe(true);
    expect(summary.trend[5]).toBe(1);
    expect(bins(summary.trend, 6, 21).every((bin) => bin === 0)).toBe(true);
    expect(summary.trend[23]).toBeNull();
  });

  it("leaves an empty bin the read ends inside unknown", () => {
    // System read through 20:10; the group's last event is at 14:00.
    const records = [rec({ eventId: 1000, at: DAY_START + 14 * HOUR })];
    const [summary] = buildGroupSummaries(
      input({ records, readThrough: new Map([["System", DAY_START + 20 * HOUR + 10 * 60 * 1000]]) }),
    ).summaries;
    expect(summary.trend[19]).toBe(0);
    expect(summary.trend[20]).toBeNull();
  });

  it("ends each channel at its own read time, not at another channel's", () => {
    const records = [
      rec({ eventId: 1, channel: "System", at: DAY_START + 23 * HOUR }),
      rec({ eventId: 1000, channel: "Application", at: DAY_START + 2 * HOUR }),
    ];
    const result = buildGroupSummaries(
      input({
        records,
        scopeChannels: ["Application"],
        readThrough: new Map([
          ["System", NOW],
          ["Application", DAY_START + 9 * HOUR],
        ]),
      }),
    );
    const application = result.summaries.find((summary) => summary.value === "1000")!;
    expect(application.trend[8]).toBe(0);
    expect(bins(application.trend, 9, 23).every((bin) => bin === null)).toBe(true);
  });

  it("starts a live channel at its oldest event when there is no window: the query asked for no start", () => {
    const records = [
      rec({ eventId: 1, channel: "System", at: DAY_START }),
      rec({ eventId: 1, channel: "System", at: DAY_START + 24 * HOUR }),
      rec({ eventId: 2, channel: "Application", at: DAY_START + 6 * HOUR }),
      rec({ eventId: 2, channel: "Application", at: DAY_START + 24 * HOUR }),
    ];
    const result = buildGroupSummaries(
      input({ records, timeWindow: "all", scopeChannels: ["Application"] }),
    );
    const application = result.summaries.find((summary) => summary.value === "2");
    expect(application?.trend.slice(0, 6).every((bin) => bin === null)).toBe(true);
    expect(application?.trend[7]).toBe(0);
  });
});

describe("buildGroupSummaries: a file set is read file by file", () => {
  it("knows a file only from its oldest to its newest event", () => {
    const records = [
      rec({ eventId: 2, channel: "Application", sourceLabel: "/x/Application.evtx", at: DAY_START + 6 * HOUR }),
      rec({ eventId: 2, channel: "Application", sourceLabel: "/x/Application.evtx", at: DAY_START + 12 * HOUR }),
      // System spans the whole day, so the span is 24 hourly bins.
      rec({ eventId: 1, channel: "System", at: DAY_START }),
      rec({ eventId: 1, channel: "System", at: DAY_START + 24 * HOUR }),
    ];
    const application = buildGroupSummaries(
      input({ records, timeWindow: "all", sourceMode: "files", scopeChannels: ["Application"] }),
    ).summaries.find((summary) => summary.value === "2")!;
    expect(bins(application.trend, 0, 5).every((bin) => bin === null)).toBe(true);
    expect(application.trend[6]).toBe(1);
    expect(application.trend[7]).toBe(0);
    expect(application.trend[12]).toBe(1);
    expect(bins(application.trend, 13, 23).every((bin) => bin === null)).toBe(true);
  });

  it("two System.evtx files from different weeks: the days between them stay unknown", () => {
    const day = 24 * HOUR;
    const a = "/a/System.evtx";
    const b = "/b/System.evtx";
    const records = [
      rec({ sourceLabel: a, at: DAY_START }),
      rec({ eventId: 7040, sourceLabel: a, at: DAY_START + 12 * HOUR }),
      rec({ sourceLabel: a, at: DAY_START + day }),
      rec({ sourceLabel: b, at: DAY_START + 9 * day }),
      rec({ sourceLabel: b, at: DAY_START + 10 * day }),
    ];
    const result = buildGroupSummaries(
      input({ records, timeWindow: "all", sourceMode: "files" }),
    );
    // Ten days in 24 bins of ten hours. File a covers bins 0 and 1 whole; file b bins 22 and 23.
    expect(result.span).toEqual({ startMs: DAY_START, endMs: DAY_START + 10 * day });
    const { trend } = result.summaries.find((summary) => summary.value === "7036")!;
    expect(trend[0]).toBe(1);
    expect(trend[1]).toBe(0);
    expect(trend[2]).toBe(1);
    expect(bins(trend, 3, 20).every((bin) => bin === null)).toBe(true);
    expect(trend[21]).toBe(1);
    expect(trend[22]).toBe(0);
    expect(trend[23]).toBe(1);
  });

  it("an archived and a current log with a hole between them: the hole stays unknown", () => {
    const archived = "/logs/Archive-System-2026-10-06-12-00-00.evtx";
    const current = "/logs/System.evtx";
    const records = [
      rec({ sourceLabel: archived, at: DAY_START }),
      rec({ eventId: 7040, sourceLabel: archived, at: DAY_START + 12 * HOUR }),
      rec({ eventId: 7040, sourceLabel: current, at: DAY_START + 18 * HOUR }),
      rec({ sourceLabel: current, at: DAY_START + 24 * HOUR }),
    ];
    const { trend } = buildGroupSummaries(
      input({ records, timeWindow: "all", sourceMode: "files" }),
    ).summaries.find((summary) => summary.value === "7036")!;
    expect(trend[0]).toBe(1);
    expect(bins(trend, 1, 11).every((bin) => bin === 0)).toBe(true);
    expect(bins(trend, 12, 17).every((bin) => bin === null)).toBe(true);
    expect(bins(trend, 18, 22).every((bin) => bin === 0)).toBe(true);
    expect(trend[23]).toBe(1);
  });

  it("merges files that overlap, so their shared time is read", () => {
    const records = [
      rec({ sourceLabel: "/a/System.evtx", at: DAY_START }),
      rec({ eventId: 7040, sourceLabel: "/a/System.evtx", at: DAY_START + 14 * HOUR }),
      rec({ eventId: 7040, sourceLabel: "/b/System.evtx", at: DAY_START + 10 * HOUR }),
      rec({ sourceLabel: "/b/System.evtx", at: DAY_START + 24 * HOUR }),
    ];
    const { trend } = buildGroupSummaries(
      input({ records, timeWindow: "all", sourceMode: "files" }),
    ).summaries.find((summary) => summary.value === "7036")!;
    expect(trend.filter((bin) => bin === null)).toHaveLength(0);
  });
});

describe("classifyChannelReads", () => {
  /**
   * A stand-in for the store's `isNewestOnlyGapReason`: this module takes the predicate as input,
   * so the store's wording is not repeated here. The store path is tested in EvtxGroupedView.test.
   */
  const CAP = "kept the newest events only";
  const live = (name: string) => ({ name, eventCount: 1, sourceType: "live" as const });
  const base = {
    remoteMachine: null,
    channels: ["System", "Security", "Setup", "Application"].map(live),
    coverageDetails: [],
    manifestCoverage: [],
    legacyCoverage: [],
    tailCoverage: [],
    isNewestOnlyReason: (reason: string) => reason === CAP,
  };

  it("calls a channel with no gap complete", () => {
    const read = classifyChannelReads(base);
    expect(read.kind("System")).toBe("complete");
    expect(read.unattributedLoss).toBe(false);
  });

  it("calls a channel newest-only when its gap is the bound the predicate recognizes", () => {
    const read = classifyChannelReads({ ...base, legacyCoverage: [`Security: ${CAP}`] });
    expect(read.kind("Security")).toBe("newestOnly");
    expect(read.kind("System")).toBe("complete");
  });

  it("matches a remote channel's gap by machine and channel", () => {
    const read = classifyChannelReads({
      ...base,
      remoteMachine: "PC02",
      legacyCoverage: ["PC02/System: 3 batches of events were not received"],
    });
    expect(read.kind("System")).toBe("incomplete");
    expect(read.unattributedLoss).toBe(false);
  });

  describe("a loss wins over the bound in any order", () => {
    it("a structured loss, then the bound's note (production order)", () => {
      const read = classifyChannelReads({
        ...base,
        coverageDetails: [{ source: "System", kind: "record", reason: "a record could not be read" }],
        legacyCoverage: [`System: ${CAP}`],
      });
      expect(read.kind("System")).toBe("incomplete");
    });

    it("a loss line, then the bound's note (the order the store writes them)", () => {
      const read = classifyChannelReads({
        ...base,
        legacyCoverage: ["System: 4 of 2000 events did not reach the view", `System: ${CAP}`],
      });
      expect(read.kind("System")).toBe("incomplete");
    });

    it("the bound's note, then a loss line", () => {
      const read = classifyChannelReads({
        ...base,
        legacyCoverage: [`System: ${CAP}`, "System: 3 batches of events were not received"],
      });
      expect(read.kind("System")).toBe("incomplete");
    });
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
    expect(read.kind("System")).toBe("incomplete");
  });

  it("does not count a gap string twice when it repeats a structured gap", () => {
    const provider = { source: "System", kind: "provider" as const, reason: "message unavailable" };
    const chunk = { source: "C:/logs/App.evtx", kind: "chunk" as const, reason: "bad chunk", chunkId: 3 };
    const read = classifyChannelReads({
      ...base,
      channels: [
        live("System"),
        { name: "Application", eventCount: 1, sourceType: { file: { path: "C:/logs/App.evtx" } } },
      ],
      coverageDetails: [provider, chunk],
      legacyCoverage: [formatCoverageGap(provider), formatCoverageGap(chunk)],
    });
    // The provider gap leaves every event in place; its string twin must not undo that.
    expect(read.kind("System")).toBe("complete");
    expect(read.kind("Application")).toBe("incomplete");
  });

  it("ignores structured gaps that leave every event in place", () => {
    const read = classifyChannelReads({
      ...base,
      coverageDetails: [
        { source: "System", kind: "provider", reason: "message unavailable" },
        { source: "Setup", kind: "empty", reason: "no events" },
        { source: "<coverage>", kind: "provider", reason: "messages unavailable" },
      ],
    });
    expect(read.kind("System")).toBe("complete");
    expect(read.kind("Setup")).toBe("complete");
    expect(read.unattributedLoss).toBe(false);
  });

  it.each([
    ["a tail that could not start", "System: live tail unavailable (unsupported)"],
    ["a subscription that fell back to polling", "System: EvtSubscribe unavailable; polling fallback is active (5)"],
    ["a message shown as raw data", "System: provider message unavailable; raw event data is shown instead"],
    ["a provider lookup that failed", "System: provider database lookup failed (Microsoft-Windows-X)"],
  ])("does not count %s as a loss", (_what, gap) => {
    const read = classifyChannelReads({ ...base, tailCoverage: [gap] });
    expect(read.kind("System")).toBe("complete");
  });

  it("calls a manifest gap on the channel's file incomplete", () => {
    const read = classifyChannelReads({
      ...base,
      channels: [
        { name: "Application", eventCount: 1, sourceType: { file: { path: "/x/Application.evtx" } } },
      ],
      manifestCoverage: [{ kind: "limitReached", path: "/x/Application.evtx", reason: "stopped" }],
    });
    expect(read.kind("Application")).toBe("incomplete");
  });

  describe("a loss no channel claims", () => {
    it.each([
      [
        "the parser's coalesced <coverage> gap",
        { coverageDetails: [{ source: "<coverage>", kind: "limit" as const, reason: "4,096 more gaps not listed" }] },
      ],
      ["the tail's coalesced gap", { tailCoverage: ["<live tail coverage>: 12 more gaps not listed"] }],
      ["a folder", { manifestCoverage: [{ kind: "invalidPattern" as const, path: "C:/logs/", reason: "bad" }] }],
      ["a gap string with no source", { legacyCoverage: ["events were lost"] }],
    ])("%s makes every channel's empty bins unknown", (_what, gaps) => {
      const read = classifyChannelReads({ ...base, ...gaps });
      expect(read.unattributedLoss).toBe(true);
    });

    it("but a single event log file that never opened is outside the visible scope", () => {
      const read = classifyChannelReads({
        ...base,
        manifestCoverage: [{ kind: "accessDenied", path: "C:/logs/Security.evtx", reason: "denied" }],
        legacyCoverage: ["C:/logs/Security.evtx: denied"],
      });
      expect(read.unattributedLoss).toBe(false);
    });
  });
});
