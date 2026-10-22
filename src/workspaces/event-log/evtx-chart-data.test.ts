import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildEvtxChartData,
  buildHideRuleQualifier,
  chartWindowLabel,
  countTextLogSources,
  loadedChannelCountFor,
  CHANNEL_ROW_LIMIT,
  heatStepIndex,
  hourOfDay,
  placedEpochMs,
  TOP_EVENT_ID_LIMIT,
  type EvtxChartChainSummary,
  type EvtxChartInput,
  type EvtxChartRecord,
} from "./evtx-chart-data";
import { DEFAULT_QUICK_FILTER, type EvtxQuickFilter } from "./evtx-filter";
import type { EvtxLevel } from "./types";

function at(hour: number, minute = 0): number {
  return Date.UTC(2026, 9, 8, hour, minute);
}

function record(
  overrides: Partial<EvtxChartRecord> & { hour?: number } = {},
): EvtxChartRecord {
  const { hour = 10, ...rest } = overrides;
  const epoch = at(hour);
  return {
    channel: "System",
    provider: "Service Control Manager",
    eventId: 7036,
    level: "Information" as EvtxLevel,
    timestamp: new Date(epoch).toISOString(),
    timestampEpoch: epoch,
    originKind: "event",
    sourceLabel: "live",
    ...rest,
  };
}

const NO_CHAINS: EvtxChartChainSummary = {
  counts: { exact: 0, candidate: 0, ambiguous: 0, coverageBlocked: 0 },
  edgeInputComplete: true,
};

function input(
  records: EvtxChartRecord[],
  overrides: Partial<EvtxChartInput> = {},
): EvtxChartInput {
  return {
    records,
    chains: NO_CHAINS,
    hideRules: [],
    channelOrder: [],
    timeZoneMode: "utc",
    loadedChannelCount: 2,
    textLogCount: 1,
    ...overrides,
  };
}

function kpi(data: ReturnType<typeof buildEvtxChartData>, id: string) {
  const found = data.kpis.find((k) => k.id === id);
  if (!found) throw new Error(`no KPI ${id}`);
  return found;
}

function hide(mode: EvtxQuickFilter["mode"], query: string): EvtxQuickFilter {
  return { ...DEFAULT_QUICK_FILTER, mode, query, action: "hide" };
}

describe("buildEvtxChartData: empty input", () => {
  const data = buildEvtxChartData(input([]));

  it("has zero values and no derived sublabels", () => {
    expect(data.totalEvents).toBe(0);
    expect(data.kpis.map((k) => k.value)).toEqual([0, 0, 0, 0, 0, 0]);
    expect(data.kpis.map((k) => k.sublabel)).toEqual([
      null,
      null,
      null,
      null,
      null,
      null,
    ]);
    expect(data.channels).toEqual([]);
    expect(data.topIds).toEqual([]);
    expect(data.heatMap.rows).toEqual([]);
    expect(data.heatMap.maxCount).toBe(0);
    expect(data.peak).toBeNull();
    expect(data.unplacedCount).toBe(0);
  });

  it("still has 24 hourly buckets", () => {
    expect(data.hourly).toHaveLength(24);
    expect(data.hourly.every((b) => b.errors === 0 && b.warnings === 0)).toBe(
      true,
    );
  });
});

describe("KPIs", () => {
  const records = [
    record({ level: "Error", channel: "System", eventId: 1 }),
    record({ level: "Error", channel: "System", eventId: 1 }),
    record({ level: "Warning", eventId: 10, provider: "A" }),
    record({ level: "Warning", eventId: 10, provider: "A" }),
    record({ level: "Warning", eventId: 11, provider: "B" }),
    record({ level: "Warning", eventId: 12, provider: "C" }),
    record({ level: "Critical", eventId: 41, provider: "Kernel-Power" }),
    record({ level: "Information", channel: "Application" }),
    record({
      originKind: "log",
      channel: "setup.log",
      sourceLabel: "setup.log",
      provider: "Setup",
      eventId: 0,
      level: "Warning",
    }),
    record({
      originKind: "log",
      channel: "setup.log",
      sourceLabel: "setup.log",
      provider: "Setup",
      eventId: 0,
      level: "Warning",
    }),
  ];
  const data = buildEvtxChartData(
    input(records, {
      chains: {
        counts: { exact: 2, candidate: 1, ambiguous: 5, coverageBlocked: 3 },
        edgeInputComplete: true,
      },
    }),
  );

  it("Events counts visible records with channel and text log counts", () => {
    expect(kpi(data, "events").value).toBe(10);
    expect(kpi(data, "events").sublabel).toBe("2 channels · 1 text log");
  });

  it("Errors counts Error level only", () => {
    expect(kpi(data, "errors").value).toBe(2);
    expect(kpi(data, "errors").sublabel).toBeNull();
  });

  it("Warnings sublabel is the share of the top two IDs", () => {
    // 6 warning rows on the tile, 4 of them events. The two text-log warning lines have no
    // event ID, so they are in the denominator and never a top ID: 3 of 6.
    expect(kpi(data, "warnings").value).toBe(6);
    // A/10 has 2 and B/11 has 1 (tie with C/12 broken by event ID): 3 of 4.
    expect(kpi(data, "warnings").sublabel).toBe("Top 2 IDs = 50%");
  });

  it("Warnings sublabel is omitted with fewer than two distinct IDs", () => {
    const one = buildEvtxChartData(
      input([record({ level: "Warning" }), record({ level: "Warning" })]),
    );
    expect(kpi(one, "warnings").value).toBe(2);
    expect(kpi(one, "warnings").sublabel).toBeNull();
  });

  it("Critical sublabel names the most frequent critical event", () => {
    expect(kpi(data, "critical").value).toBe(1);
    expect(kpi(data, "critical").sublabel).toBe("Kernel-Power 41");
  });

  it("Critical sublabel breaks ties by event ID then provider", () => {
    const tied = buildEvtxChartData(
      input([
        record({ level: "Critical", eventId: 50, provider: "Z" }),
        record({ level: "Critical", eventId: 41, provider: "Z" }),
        record({ level: "Critical", eventId: 41, provider: "A" }),
        record({ level: "Critical", eventId: 50, provider: "A" }),
      ]),
    );
    expect(kpi(tied, "critical").sublabel).toBe("A 41");
  });

  it("Distinct event IDs counts (provider, ID) pairs", () => {
    const pairs = buildEvtxChartData(
      input([
        record({ provider: "A", eventId: 1 }),
        record({ provider: "B", eventId: 1 }),
        record({ provider: "A", eventId: 1 }),
      ]),
    );
    expect(kpi(pairs, "distinctIds").value).toBe(2);
    expect(kpi(pairs, "distinctIds").sublabel).toBeNull();
  });

  it("Correlation chains counts Exact plus Candidate only (D7)", () => {
    expect(kpi(data, "chains").value).toBe(3);
    expect(kpi(data, "chains").sublabel).toBe("2 exact");
  });

  it("Correlation chains says when the edges are a loaded subset", () => {
    const partial = buildEvtxChartData(
      input([record()], {
        chains: {
          counts: { exact: 1, candidate: 0, ambiguous: 0, coverageBlocked: 0 },
          edgeInputComplete: false,
        },
      }),
    );
    expect(kpi(partial, "chains").sublabel).toBe("1 exact, loaded edges only");
  });

  it("Correlation chains never reads a zero from a loaded subset as definite", () => {
    const zero = buildEvtxChartData(
      input([record()], {
        chains: {
          counts: { exact: 0, candidate: 0, ambiguous: 7, coverageBlocked: 0 },
          edgeInputComplete: false,
        },
      }),
    );
    expect(kpi(zero, "chains").value).toBe(0);
    expect(kpi(zero, "chains").sublabel).toBe("0 exact, loaded edges only");
    const complete = buildEvtxChartData(input([record()]));
    expect(kpi(complete, "chains").sublabel).toBeNull();
  });

  it("Correlation chains has no value without a chain model", () => {
    const none = buildEvtxChartData(input([record()], { chains: null }));
    expect(kpi(none, "chains").value).toBeNull();
    expect(kpi(none, "chains").sublabel).toBeNull();
  });

  it("never emits a comparative sublabel", () => {
    for (const k of data.kpis) {
      expect(k.sublabel ?? "").not.toMatch(/vs |prior|new |▲|▼/);
    }
  });
});

describe("channel bars", () => {
  it("counts events, errors and warnings per channel, largest first", () => {
    const data = buildEvtxChartData(
      input([
        record({ channel: "A" }),
        record({ channel: "B", level: "Error" }),
        record({ channel: "B", level: "Warning" }),
        record({ channel: "B", level: "Critical" }),
      ], { channelOrder: ["A", "B"] }),
    );
    expect(data.channels).toEqual([
      { channel: "B", colorIndex: 1, count: 3, errors: 1, warnings: 1 },
      { channel: "A", colorIndex: 0, count: 1, errors: 0, warnings: 0 },
    ]);
  });

  it("color index follows channel display order, not rank", () => {
    const data = buildEvtxChartData(
      input([record({ channel: "A" }), record({ channel: "B" }), record({ channel: "B" })], {
        channelOrder: ["A", "Empty", "B"],
      }),
    );
    expect(data.channels.map((c) => [c.channel, c.colorIndex])).toEqual([
      ["B", 2],
      ["A", 0],
    ]);
  });

  it("puts channels missing from the display order after it", () => {
    const data = buildEvtxChartData(
      input(
        [record({ channel: "Zed" }), record({ channel: "Alpha" }), record({ channel: "Known" })],
        { channelOrder: ["Known"] },
      ),
    );
    const index = Object.fromEntries(
      data.channels.map((c) => [c.channel, c.colorIndex]),
    );
    expect(index.Known).toBe(0);
    expect(index.Alpha).toBeGreaterThanOrEqual(1);
    expect(index.Zed).toBeGreaterThanOrEqual(1);
  });

  it("breaks count ties by channel name", () => {
    const data = buildEvtxChartData(
      input([record({ channel: "b" }), record({ channel: "a" })]),
    );
    expect(data.channels.map((c) => c.channel)).toEqual(["a", "b"]);
  });

  it("caps the rows and reports what was left out", () => {
    const records = Array.from({ length: CHANNEL_ROW_LIMIT + 3 }, (_, i) =>
      record({ channel: `ch${String(i).padStart(2, "0")}` }),
    );
    const data = buildEvtxChartData(input(records));
    expect(data.channels).toHaveLength(CHANNEL_ROW_LIMIT);
    expect(data.heatMap.rows).toHaveLength(CHANNEL_ROW_LIMIT);
    expect(data.omittedChannels).toEqual({ channels: 3, events: 3 });
  });
});

describe("top event IDs", () => {
  it("returns at most nine, most frequent first, ties by ID then provider", () => {
    const records: EvtxChartRecord[] = [];
    for (let id = 1; id <= 12; id += 1) {
      for (let n = 0; n < (id === 12 ? 5 : 1); n += 1) {
        records.push(record({ eventId: id, provider: "P" }));
      }
    }
    records.push(record({ eventId: 3, provider: "A" }));
    const data = buildEvtxChartData(input(records));
    expect(data.topIds).toHaveLength(TOP_EVENT_ID_LIMIT);
    expect(data.topIds[0]).toEqual({ eventId: 12, provider: "P", count: 5 });
    // The remaining count-1 entries are ordered by ID, then provider.
    expect(data.topIds.slice(1).map((t) => `${t.eventId}/${t.provider}`)).toEqual([
      "1/P",
      "2/P",
      "3/A",
      "3/P",
      "4/P",
      "5/P",
      "6/P",
      "7/P",
    ]);
  });

  it("keeps the same ID from two providers as separate rows", () => {
    const data = buildEvtxChartData(
      input([record({ provider: "A", eventId: 1 }), record({ provider: "B", eventId: 1 })]),
    );
    expect(data.topIds).toHaveLength(2);
  });
});

describe("hide-rule qualifier", () => {
  it("is null with no rules", () => {
    expect(buildHideRuleQualifier([])).toBeNull();
  });

  it("lists IDs and ranges from Event ID hide rules in rule order", () => {
    expect(
      buildHideRuleQualifier([hide("eventIds", "7036, 16384"), hide("eventIds", "100-200")]),
    ).toBe("excluding 7036 / 16384 / 100-200");
  });

  it("is built from the rules passed in, not hard-coded", () => {
    expect(buildHideRuleQualifier([hide("eventIds", "5")])).toBe("excluding 5");
    expect(buildHideRuleQualifier([hide("eventIds", "6")])).toBe("excluding 6");
  });

  it("ignores show rules, empty rules and invalid ID lists", () => {
    expect(
      buildHideRuleQualifier([
        { ...hide("eventIds", "7036"), action: "show" },
        hide("eventIds", "   "),
        hide("eventIds", "abc"),
      ]),
    ).toBeNull();
  });

  it("lists text hide rules by their query and de-duplicates", () => {
    expect(
      buildHideRuleQualifier([
        hide("oneString", "noise"),
        hide("oneString", "noise"),
        hide("eventIds", "1"),
      ]),
    ).toBe('excluding matching "noise" / 1');
  });

  it("reaches the data result", () => {
    const data = buildEvtxChartData(
      input([record()], { hideRules: [hide("eventIds", "7036 16384")] }),
    );
    expect(data.topIdsQualifier).toBe("excluding 7036 / 16384");
  });
});

describe("hours and unplaced events", () => {
  it("places events by hour of day in the requested clock", () => {
    const epoch = Date.UTC(2026, 9, 8, 23, 30);
    const r = record({ timestampEpoch: epoch, level: "Error" });
    expect(hourOfDay(r, "utc")).toBe(23);
    // Built from local wall-clock parts, so the expectation does not reuse getHours on the epoch.
    const localNoon = new Date(2026, 9, 8, 12, 15).getTime();
    expect(hourOfDay(record({ timestampEpoch: localNoon }), "local")).toBe(12);
  });

  it("counts an event without a usable time as unplaced, never as hour 0", () => {
    const data = buildEvtxChartData(
      input([
        record({ level: "Error", hour: 5 }),
        record({ level: "Error", timestampEpoch: 0, timestamp: "" }),
        record({ level: "Error", timestampEpoch: null }),
        record({ level: "Error", timestampEpoch: Number.NaN }),
        // CBS fall-back hour: display text kept, epoch 0 (the parser could not resolve it).
        record({ level: "Error", timestampEpoch: 0, timestamp: "2026-11-01 01:30:00.000" }),
        // An EVTX TimeCreated that failed to parse.
        record({ level: "Error", timestampEpoch: 0, timestamp: "not a time" }),
        record({ level: "Error", timestampEpoch: 0, timestamp: "2026-11-01T01:30:00+0500" }),
      ]),
    );
    expect(data.unplacedCount).toBe(6);
    expect(data.hourly[0].errors).toBe(0);
    expect(data.hourly[1].errors).toBe(0);
    expect(data.hourly[5].errors).toBe(1);
    expect(data.heatMap.rows[0].counts[0]).toBe(0);
    // They still count in the totals that need no time.
    expect(kpi(data, "errors").value).toBe(7);
    expect(data.channels[0].count).toBe(7);
  });

  it("recovers a zero epoch only from the engine's two text formats", () => {
    const zero = (timestamp: string) => ({ timestamp, timestampEpoch: 0 });
    expect(hourOfDay(zero("2026-11-01T01:30:00Z"), "utc")).toBe(1);
    expect(hourOfDay(zero("2026-11-01T01:30:00.123456+02:00"), "utc")).toBe(23);
    // Zone-less ISO is read as UTC, as the backend does.
    expect(hourOfDay(zero("2026-11-01T01:30:00.250"), "utc")).toBe(1);
    expect(hourOfDay(zero("2026-11-01 01:30:00.000"), "utc")).toBeNull();
    expect(hourOfDay(zero("1970-01-01T00:00:00Z"), "utc")).toBe(0);
  });

  it("gives an off-order channel the same color index whatever else is visible", () => {
    const only = buildEvtxChartData(
      input([record({ channel: "B.evtx" })], { channelOrder: ["System"] }),
    );
    const both = buildEvtxChartData(
      input([record({ channel: "B.evtx" }), record({ channel: "A.evtx" })], {
        channelOrder: ["System"],
      }),
    );
    const index = (d: typeof only) =>
      d.channels.find((c) => c.channel === "B.evtx")!.colorIndex;
    expect(index(only)).toBe(index(both));
    expect(index(only)).toBeGreaterThanOrEqual(1);
  });

  it("builds the hour by channel matrix", () => {
    const data = buildEvtxChartData(
      input([
        record({ channel: "A", hour: 1 }),
        record({ channel: "A", hour: 1 }),
        record({ channel: "A", hour: 23 }),
        record({ channel: "B", hour: 1 }),
      ]),
    );
    const a = data.heatMap.rows.find((r) => r.channel === "A")!;
    expect(a.counts[1]).toBe(2);
    expect(a.counts[23]).toBe(1);
    expect(a.counts.reduce((x, y) => x + y, 0)).toBe(3);
    expect(data.heatMap.maxCount).toBe(2);
    expect(a.steps[1]).toBe(5);
    expect(a.steps[23]).toBe(2);
    expect(a.steps[0]).toBe(-1);
  });
});

describe("heatStepIndex", () => {
  it("marks empty cells and scales the rest across six steps", () => {
    expect(heatStepIndex(0, 10)).toBe(-1);
    expect(heatStepIndex(1, 1000)).toBe(0);
    expect(heatStepIndex(10, 10)).toBe(5);
    expect(heatStepIndex(5, 10)).toBe(2);
    expect(heatStepIndex(3, 0)).toBe(-1);
  });
});

describe("hourly errors and warnings", () => {
  it("counts Error and Warning per hour; Critical is its own KPI", () => {
    const data = buildEvtxChartData(
      input([
        record({ level: "Error", hour: 2 }),
        record({ level: "Warning", hour: 2 }),
        record({ level: "Warning", hour: 2 }),
        record({ level: "Critical", hour: 2 }),
        record({ level: "Information", hour: 2 }),
      ]),
    );
    expect(data.hourly[2]).toEqual({ hour: 2, errors: 1, warnings: 2 });
  });

  it("reports the peak hour", () => {
    const data = buildEvtxChartData(
      input([
        record({ level: "Error", hour: 3 }),
        record({ level: "Error", hour: 14 }),
        record({ level: "Warning", hour: 14 }),
      ]),
    );
    expect(data.peak).toEqual({ hour: 14, count: 2, label: "14:00" });
  });

  it("takes the earliest hour on a tied peak", () => {
    const data = buildEvtxChartData(
      input([
        record({ level: "Error", hour: 9 }),
        record({ level: "Error", hour: 4 }),
      ]),
    );
    expect(data.peak).toEqual({ hour: 4, count: 1, label: "04:00" });
  });

  it("has no peak when only informational events exist", () => {
    expect(buildEvtxChartData(input([record()])).peak).toBeNull();
  });
});

describe("text-log lines in the figures", () => {
  const logLine = (overrides: Partial<EvtxChartRecord> = {}) =>
    record({
      originKind: "log",
      channel: "agent.log",
      sourceLabel: "agent.log",
      provider: "Agent",
      eventId: 0,
      ...overrides,
    });

  it("counts them, leaves them out of the channel rows, and says how many", () => {
    const data = buildEvtxChartData(
      input([record({ channel: "System" }), logLine(), logLine({ level: "Error" })]),
    );
    expect(data.textLogLineCount).toBe(2);
    expect(data.channels.map((c) => c.channel)).toEqual(["System"]);
    expect(data.heatMap.rows.map((r) => r.channel)).toEqual(["System"]);
    expect(data.totalEvents).toBe(3);
  });

  it("with only text logs there are no channel rows, only the count", () => {
    const data = buildEvtxChartData(input([logLine(), logLine()]));
    expect(data.channels).toEqual([]);
    expect(data.heatMap.rows).toEqual([]);
    expect(data.textLogLineCount).toBe(2);
  });

  it("keeps a critical text-log line out of the Critical sublabel", () => {
    const data = buildEvtxChartData(input([logLine({ level: "Critical" })]));
    expect(kpi(data, "critical").value).toBe(1);
    expect(kpi(data, "critical").sublabel).toBeNull();
  });

  it("does not let text-log lines into the ID tallies", () => {
    const data = buildEvtxChartData(
      input([record({ eventId: 5, provider: "P" }), logLine(), logLine({ level: "Warning" })]),
    );
    expect(kpi(data, "distinctIds").value).toBe(1);
    expect(data.topIds).toEqual([{ eventId: 5, provider: "P", count: 1 }]);
  });

  it("separates unplaced events from unplaced text-log lines", () => {
    const data = buildEvtxChartData(
      input([
        record({ timestampEpoch: 0, timestamp: "" }),
        logLine({ timestampEpoch: 0, timestamp: "" }),
        logLine({ timestampEpoch: 0, timestamp: "" }),
      ]),
    );
    expect(data.unplacedCount).toBe(3);
    expect(data.unplacedEventCount).toBe(1);
    // None of them is an error or a warning.
    expect(data.unplacedErrorWarningCount).toBe(0);
  });
});

describe("unplaced error and warning rows", () => {
  it("counts Error and Warning rows from events and text-log lines, whatever the origin", () => {
    const none = { timestampEpoch: 0, timestamp: "" };
    const data = buildEvtxChartData(
      input([
        record({ level: "Error", ...none }),
        record({ level: "Warning", ...none }),
        record({ level: "Information", ...none }),
        record({ level: "Error", originKind: "log", channel: "a.log", sourceLabel: "a.log", ...none }),
        record({ level: "Critical", ...none }),
        record({ level: "Error", hour: 3 }),
      ]),
    );
    expect(data.unplacedErrorWarningCount).toBe(3);
    expect(data.unplacedCount).toBe(5);
  });
});

describe("placement under a non-UTC zone", () => {
  // The project's TS config has no Node types; Node applies a runtime TZ change to Date.
  const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } })
    .process.env;
  const previous = env.TZ;
  beforeAll(() => {
    env.TZ = "Asia/Kolkata"; // UTC+05:30, no daylight saving
  });
  afterAll(() => {
    if (previous === undefined) delete env.TZ;
    else env.TZ = previous;
  });

  it("local hour differs from UTC hour and follows the zone", () => {
    const epoch = Date.UTC(2026, 9, 8, 20, 0); // 01:30 the next day in Kolkata
    expect(hourOfDay({ timestamp: "x", timestampEpoch: epoch }, "utc")).toBe(20);
    expect(hourOfDay({ timestamp: "x", timestampEpoch: epoch }, "local")).toBe(1);
  });

  it("places the heat map and hourly figure in the local clock", () => {
    const data = buildEvtxChartData(
      input([record({ level: "Error", timestampEpoch: Date.UTC(2026, 9, 8, 20, 0) })], {
        timeZoneMode: "local",
      }),
    );
    expect(data.hourly[1].errors).toBe(1);
    expect(data.hourly[20].errors).toBe(0);
  });
});

describe("RFC 3339 text for a zero epoch", () => {
  const zero = (timestamp: string) => ({ timestamp, timestampEpoch: 0 });

  it("accepts a space between date and time, as chrono does", () => {
    expect(hourOfDay(zero("2026-11-01 01:30:00+02:00"), "utc")).toBe(23);
    expect(hourOfDay(zero("2026-11-01 01:30:00Z"), "utc")).toBe(1);
    expect(hourOfDay(zero("2026-11-01t01:30:00z"), "utc")).toBe(1);
  });

  it("accepts the U+2212 minus sign in an offset, as chrono does", () => {
    expect(hourOfDay(zero("2026-11-01T01:30:00\u221205:00"), "utc")).toBe(6);
    expect(hourOfDay(zero("2026-11-01 01:30:00\u221205:30"), "utc")).toBe(7);
  });

  it("reads U+2212 only as the offset sign, not between date parts", () => {
    expect(hourOfDay(zero("2026\u221211-01T01:30:00Z"), "utc")).toBeNull();
    expect(hourOfDay(zero("2026-11\u221201T01:30:00Z"), "utc")).toBeNull();
  });

  it("rejects a day beyond its month, leap years included", () => {
    expect(hourOfDay(zero("2026-02-30T01:30:00Z"), "utc")).toBeNull();
    expect(hourOfDay(zero("2025-02-29T00:00:00Z"), "utc")).toBeNull();
    expect(hourOfDay(zero("2026-04-31T00:00:00"), "utc")).toBeNull();
    expect(hourOfDay(zero("2024-02-29T00:00:00Z"), "utc")).toBe(0);
    expect(hourOfDay(zero("2000-02-29T05:00:00Z"), "utc")).toBe(5);
    expect(hourOfDay(zero("1900-02-29T00:00:00Z"), "utc")).toBeNull();
  });

  it("rejects hour 24 in both forms instead of rolling to the next day", () => {
    expect(hourOfDay(zero("2026-11-01T24:00:00Z"), "utc")).toBeNull();
    expect(hourOfDay(zero("2026-11-01T24:00:00"), "utc")).toBeNull();
    expect(hourOfDay(zero("2026-11-01T23:59:59Z"), "utc")).toBe(23);
  });

  it("still rejects a space without an offset, and leap seconds", () => {
    expect(hourOfDay(zero("2026-11-01 01:30:00.000"), "utc")).toBeNull();
    expect(hourOfDay(zero("2026-06-30T23:59:60Z"), "utc")).toBeNull();
  });
});

describe("timestamp fields are range-checked before Date.parse sees the text", () => {
  const zero = (timestamp: string) => ({ timestamp, timestampEpoch: 0 });
  // A parser that accepts everything makes any text that reaches it look placed (epoch 0), so
  // these cases fail on any engine that would be lenient, not only on the one the tests run in.
  let parse: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    parse = vi.spyOn(Date, "parse").mockReturnValue(0);
  });
  afterEach(() => {
    parse.mockRestore();
  });

  it.each([
    ["minute 75, RFC 3339", "2026-11-01T01:75:00Z"],
    ["second 75, RFC 3339", "2026-11-01T01:30:75Z"],
    ["second 60, RFC 3339", "2026-11-01T01:30:60Z"],
    ["minute 60, RFC 3339, space separator", "2026-11-01 01:60:00Z"],
    ["offset +24:00", "2026-11-01T01:30:00+24:00"],
    ["offset -24:00", "2026-11-01T01:30:00-24:00"],
    ["offset +05:60", "2026-11-01T01:30:00+05:60"],
    ["offset -05:60", "2026-11-01T01:30:00-05:60"],
    ["offset +99:00", "2026-11-01T01:30:00+99:00"],
    ["offset with U+2212 and hour 24", "2026-11-01T01:30:00\u221224:00"],
    ["offset with U+2212 and minute 60", "2026-11-01T01:30:00\u221205:60"],
    ["minute 75, zone-less", "2026-11-01T01:75:00"],
    ["second 75, zone-less", "2026-11-01T01:30:75"],
    ["second 60, zone-less", "2026-11-01T01:30:60"],
    ["minute 60, zone-less, fraction", "2026-11-01T01:60:00.5"],
  ])("%s is not placed and never reaches Date.parse", (_name, text) => {
    expect(placedEpochMs(zero(text))).toBeNull();
    expect(hourOfDay(zero(text), "utc")).toBeNull();
    expect(parse).not.toHaveBeenCalled();
  });

  it("does not call Date.parse for a non-zero epoch or for text that is not a timestamp", () => {
    expect(placedEpochMs({ timestamp: "2026-11-01T01:75:00Z", timestampEpoch: 5 })).toBe(5);
    expect(placedEpochMs(zero("not a time"))).toBeNull();
    expect(parse).not.toHaveBeenCalled();
  });
});

describe("the largest valid minute, second and offset still place", () => {
  const zero = (timestamp: string) => ({ timestamp, timestampEpoch: 0 });

  it("places minute 59, second 59 and offsets up to 23:59, with the real parser", () => {
    expect(hourOfDay(zero("2026-11-01T01:59:59Z"), "utc")).toBe(1);
    expect(hourOfDay(zero("2026-11-01 01:59:59Z"), "utc")).toBe(1);
    expect(hourOfDay(zero("2026-11-01T01:59:59.999"), "utc")).toBe(1);
    // 23:30 at +23:59 is 23:31 the day before.
    expect(hourOfDay(zero("2026-11-01T23:30:00+23:59"), "utc")).toBe(23);
    // 00:30 at -00:59 is 01:29 the same day.
    expect(hourOfDay(zero("2026-11-01T00:30:00-00:59"), "utc")).toBe(1);
    // 01:00 at +05:59 is 19:01 the day before.
    expect(hourOfDay(zero("2026-11-01T01:00:00+05:59"), "utc")).toBe(19);
    expect(hourOfDay(zero("2026-11-01T01:00:00\u221219:59"), "utc")).toBe(20);
    expect(hourOfDay(zero("2026-11-01T01:00:00+00:00"), "utc")).toBe(1);
  });
});

describe("edge whitespace is trimmed as the engine trims it", () => {
  const zero = (timestamp: string) => ({ timestamp, timestampEpoch: 0 });
  const range = (low: number, high: number) =>
    Array.from({ length: high - low + 1 }, (_, i) => low + i);
  // The code points Rust's `str::trim` strips (`char::is_whitespace`), enumerated over all of
  // U+0000 to U+10FFFF with rustc 1.98. JavaScript's `trim()` differs in exactly two of them:
  // it strips U+FEFF, which Rust keeps, and keeps U+0085, which Rust strips.
  const rustWhiteSpace = [
    ...range(0x09, 0x0d),
    0x20,
    0x85,
    0xa0,
    0x1680,
    ...range(0x2000, 0x200a),
    0x2028,
    0x2029,
    0x202f,
    0x205f,
    0x3000,
  ];
  const forms = ["2026-11-01T01:30:00Z", "2026-11-01 01:30:00+02:00", "2026-11-01T01:30:00.250"];

  it.each(rustWhiteSpace.map((code) => [`U+${code.toString(16).toUpperCase().padStart(4, "0")}`, String.fromCharCode(code)]))(
    "places text padded with %s on both sides",
    (_name, space) => {
      for (const form of forms) {
        expect(hourOfDay(zero(`${space}${space}${form}${space}`), "utc")).not.toBeNull();
      }
      expect(hourOfDay(zero(`${space}2026-11-01T01:30:00Z${space}`), "utc")).toBe(1);
    },
  );

  it("does not place text with a leading or trailing U+FEFF, which Rust does not trim", () => {
    for (const form of forms) {
      expect(hourOfDay(zero(`\uFEFF${form}`), "utc")).toBeNull();
      expect(hourOfDay(zero(`${form}\uFEFF`), "utc")).toBeNull();
      expect(hourOfDay(zero(` \uFEFF${form}`), "utc")).toBeNull();
    }
    expect(placedEpochMs(zero("\uFEFF2026-11-01T01:30:00Z"))).toBeNull();
  });

  it("does not trim other zero-width or separator code points that neither engine trims", () => {
    for (const code of [0x180e, 0x200b, 0x2060]) {
      const c = String.fromCharCode(code);
      expect(hourOfDay(zero(`${c}2026-11-01T01:30:00Z`), "utc")).toBeNull();
      expect(hourOfDay(zero(`2026-11-01T01:30:00Z${c}`), "utc")).toBeNull();
    }
  });
});

describe("wiring helpers", () => {
  it("labels the window for the Events tile", () => {
    expect(chartWindowLabel("1h")).toBe("1 h");
    expect(chartWindowLabel("24h")).toBe("24 h");
    expect(chartWindowLabel("7d")).toBe("7 d");
    expect(chartWindowLabel("30d")).toBe("30 d");
    expect(chartWindowLabel("all")).toBe("all loaded");
  });

  it("de-duplicates equal source strings across both inputs (a pure unit test)", () => {
    // Makes no claim about real data: log-store paths and archive labels do not normally
    // coincide. It only pins that equal strings count once and different ones count separately.
    const label = "bundle.zip::logs/agent.log";
    const entries = [
      { filePath: "C:/logs/a.log" },
      { filePath: "C:/logs/a.log" },
      { filePath: label },
    ];
    const records = [
      record({ originKind: "log", sourceLabel: label }),
      record({ originKind: "log", sourceLabel: "bundle.zip::logs/other.log" }),
      record({ originKind: "event", sourceLabel: "live" }),
    ];
    expect(countTextLogSources(entries, records)).toBe(3);
    expect(countTextLogSources([], [])).toBe(0);
  });

  it("live mode counts completed loads, not enumerated channels or records", () => {
    const loadedChannels = new Set(["A"]);
    const records = [record({ channel: "A" }), record({ channel: "B" })];
    expect(loadedChannelCountFor({ sourceMode: "live", loadedChannels, records })).toBe(1);
  });

  it("files mode counts distinct event-record channels only", () => {
    const loadedChannels = new Set<string>();
    const records = [
      // Two files sharing the channel name "System" (a rotated archive beside the live file).
      record({ channel: "System", sourceLabel: "System.evtx" }),
      record({ channel: "System", sourceLabel: "Archive-System-2026.evtx" }),
      record({ channel: "Application", sourceLabel: "Application.evtx" }),
      // An archived text log: its record's channel is its source label, and it is not a channel.
      record({
        originKind: "log",
        channel: "bundle.zip::logs/agent.log",
        sourceLabel: "bundle.zip::logs/agent.log",
      }),
    ];
    // A zero-record file adds no record, so it adds no channel.
    expect(loadedChannelCountFor({ sourceMode: "files", loadedChannels, records })).toBe(2);
    expect(loadedChannelCountFor({ sourceMode: null, loadedChannels, records })).toBe(2);
    expect(loadedChannelCountFor({ sourceMode: "files", loadedChannels, records: [] })).toBe(0);
  });
});
