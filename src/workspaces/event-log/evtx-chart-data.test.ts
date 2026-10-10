import { describe, expect, it } from "vitest";
import {
  buildEvtxChartData,
  buildHideRuleQualifier,
  CHANNEL_ROW_LIMIT,
  heatStepIndex,
  hourOfDay,
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
    }),
    record({
      originKind: "log",
      channel: "setup.log",
      sourceLabel: "setup.log",
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
    expect(kpi(data, "warnings").value).toBe(4);
    // A/10 has 2 and B/11 has 1 (tie with C/12 broken by event ID): 3 of 4.
    expect(kpi(data, "warnings").sublabel).toBe("Top 2 IDs = 75%");
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
      ]),
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

  it("puts channels missing from the display order after it, by name", () => {
    const data = buildEvtxChartData(
      input(
        [record({ channel: "Zed" }), record({ channel: "Alpha" }), record({ channel: "Known" })],
        { channelOrder: ["Known"] },
      ),
    );
    const index = Object.fromEntries(
      data.channels.map((c) => [c.channel, c.colorIndex]),
    );
    expect(index).toEqual({ Known: 0, Alpha: 1, Zed: 2 });
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
    const local = new Date(epoch).getHours();
    expect(hourOfDay(r, "local")).toBe(local);
  });

  it("counts an event without a timestamp as unplaced, never as hour 0", () => {
    const data = buildEvtxChartData(
      input([
        record({ level: "Error", hour: 5 }),
        record({ level: "Error", timestampEpoch: undefined, timestamp: "" }),
        record({ level: "Error", timestampEpoch: null }),
        record({ level: "Error", timestampEpoch: Number.NaN }),
        record({ level: "Error", timestampEpoch: 0, timestamp: "" }),
      ]),
    );
    expect(data.unplacedCount).toBe(4);
    expect(data.hourly[0].errors).toBe(0);
    expect(data.hourly[5].errors).toBe(1);
    expect(data.heatMap.rows[0].counts[0]).toBe(0);
    // They still count in the totals that need no time.
    expect(kpi(data, "errors").value).toBe(5);
    expect(data.channels[0].count).toBe(5);
  });

  it("treats a real epoch 0 with timestamp text as 1970, placed", () => {
    expect(
      hourOfDay({ timestamp: "1970-01-01T00:00:00Z", timestampEpoch: 0 }, "utc"),
    ).toBe(0);
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
