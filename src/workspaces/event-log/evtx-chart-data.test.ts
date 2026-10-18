import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildEvtxChartData,
  buildHideRuleQualifier,
  chartWindowLabel,
  countTextLogSources,
  loadedChannelCountFor,
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

  it("emits no comparative sublabel and no trend without a comparison (D15)", () => {
    for (const k of data.kpis) {
      expect(k.sublabel ?? "").not.toMatch(/vs |prior|new |▲|▼/);
      expect(k.trend).toBeNull();
    }
  });
});

describe("comparison deltas (spec 8.10, D15)", () => {
  const ids = (...keys: string[]) => new Set(keys);
  function compared(
    errors: { current: number; prior: number },
    distinct: { current: string[]; prior: string[] } = { current: [], prior: [] },
    window: "1h" | "24h" | "7d" | "30d" = "24h",
  ) {
    return buildEvtxChartData(
      input([record()], {
        comparison: {
          window,
          current: { errors: errors.current, distinctIds: ids(...distinct.current) },
          prior: { errors: errors.prior, distinctIds: ids(...distinct.prior) },
        },
      }),
    );
  }
  const errorsOf = (data: ReturnType<typeof buildEvtxChartData>) => kpi(data, "errors");

  describe("the Errors tile", () => {
    it.each([
      [6, 2, "\u25b2 3\u00d7 vs prior 24 h", "up"],
      [3, 2, "\u25b2 1.5\u00d7 vs prior 24 h", "up"],
      [10, 4, "\u25b2 2.5\u00d7 vs prior 24 h", "up"],
      [100, 7, "\u25b2 14\u00d7 vs prior 24 h", "up"],
      [21, 20, "\u25b2 1.1\u00d7 vs prior 24 h", "up"],
      [2, 5, "\u25bc 0.4\u00d7 vs prior 24 h", "down"],
      [1, 20, "\u25bc 0.1\u00d7 vs prior 24 h", "down"],
    ] as const)("%i against %i reads %s", (current, prior, text, trend) => {
      const tile = errorsOf(compared({ current, prior }));
      expect(tile.sublabel).toBe(text);
      expect(tile.trend).toBe(trend);
    });

    it("groups thousands in a large ratio", () => {
      const tile = errorsOf(compared({ current: 12_340, prior: 10 }));
      expect(tile.sublabel).toBe(`\u25b2 ${(1234).toLocaleString()}\u00d7 vs prior 24 h`);
    });

    it("names the window the comparison covered, in the words the Events tile uses", () => {
      expect(errorsOf(compared({ current: 4, prior: 2 }, undefined, "1h")).sublabel).toBe(
        "\u25b2 2\u00d7 vs prior 1 h",
      );
      expect(errorsOf(compared({ current: 4, prior: 2 }, undefined, "7d")).sublabel).toBe(
        "\u25b2 2\u00d7 vs prior 7 d",
      );
      expect(errorsOf(compared({ current: 4, prior: 2 }, undefined, "30d")).sublabel).toBe(
        "\u25b2 2\u00d7 vs prior 30 d",
      );
    });

    // A prior count of 0 has no ratio. The spec's copy is a count against 0, never an infinity.
    it("states a count against 0 when the previous period had no errors", () => {
      const tile = errorsOf(compared({ current: 5, prior: 0 }));
      expect(tile.sublabel).toBe("5 new vs 0 in prior 24 h");
      expect(tile.trend).toBeNull();
      expect(errorsOf(compared({ current: 1234, prior: 0 }, undefined, "7d")).sublabel).toBe(
        `${(1234).toLocaleString()} new vs 0 in prior 7 d`,
      );
    });

    it.each([
      [0, 0, "0 vs 0 in prior 24 h"],
      [0, 4, "0 vs 4 in prior 24 h"],
      [3, 3, "3 vs 3 in prior 24 h"],
    ] as const)("states the counts when %i is set against %i, with no arrow", (current, prior, text) => {
      const tile = errorsOf(compared({ current, prior }));
      expect(tile.sublabel).toBe(text);
      expect(tile.trend).toBeNull();
    });

    // A ratio that rounds to 1 or to 0 would put an arrow beside a number that says nothing moved,
    // or that says everything vanished, so the counts are given instead.
    it.each([
      [201, 200],
      [99, 100],
      [1, 100],
      [1000, 1001],
    ] as const)("falls back to the counts when %i against %i rounds to 1 or to 0", (current, prior) => {
      const tile = errorsOf(compared({ current, prior }));
      expect(tile.sublabel).toBe(
        `${current.toLocaleString()} vs ${prior.toLocaleString()} in prior 24 h`,
      );
      expect(tile.trend).toBeNull();
    });

    it("never produces an infinity, a NaN or an undefined for any pair of counts", () => {
      for (let current = 0; current <= 40; current += 1) {
        for (let prior = 0; prior <= 40; prior += 1) {
          const tile = errorsOf(compared({ current, prior }));
          expect(tile.sublabel).not.toBeNull();
          expect(tile.sublabel).not.toMatch(/\u221e|Infinity|NaN|undefined|null|-/);
          // The arrow, the trend and the numbers always agree.
          if (tile.trend === "up") {
            expect(tile.sublabel!.startsWith("\u25b2 ")).toBe(true);
            expect(current).toBeGreaterThan(prior);
          } else if (tile.trend === "down") {
            expect(tile.sublabel!.startsWith("\u25bc ")).toBe(true);
            expect(current).toBeLessThan(prior);
          } else {
            expect(tile.sublabel).not.toMatch(/\u25b2|\u25bc/);
          }
        }
      }
    });
  });

  describe("the Distinct event IDs tile", () => {
    it("counts the IDs of the current period that the previous one did not have", () => {
      const tile = kpi(
        compared({ current: 1, prior: 1 }, { current: ["a", "b", "c"], prior: ["a"] }),
        "distinctIds",
      );
      expect(tile.sublabel).toBe("2 new vs prior 24 h");
      expect(tile.trend).toBeNull();
    });

    it("is a set difference, not a difference of sizes", () => {
      // Two IDs came and one went: sizes are equal, and one ID is new.
      const tile = kpi(
        compared({ current: 1, prior: 1 }, { current: ["a", "b"], prior: ["b", "c"] }),
        "distinctIds",
      );
      expect(tile.sublabel).toBe("1 new vs prior 24 h");
    });

    it("says 0 new rather than saying nothing when every ID was seen before", () => {
      const tile = kpi(
        compared({ current: 1, prior: 1 }, { current: ["a"], prior: ["a", "b"] }),
        "distinctIds",
      );
      expect(tile.sublabel).toBe("0 new vs prior 24 h");
    });

    it("counts every ID as new against a previous period that had none, and 0 when neither has any", () => {
      expect(
        kpi(compared({ current: 1, prior: 0 }, { current: ["a", "b"], prior: [] }), "distinctIds")
          .sublabel,
      ).toBe("2 new vs prior 24 h");
      expect(
        kpi(compared({ current: 0, prior: 0 }, { current: [], prior: [] }), "distinctIds").sublabel,
      ).toBe("0 new vs prior 24 h");
    });

    it("names the window", () => {
      expect(
        kpi(compared({ current: 1, prior: 1 }, { current: ["a"], prior: [] }, "7d"), "distinctIds")
          .sublabel,
      ).toBe("1 new vs prior 7 d");
    });
  });

  it("reads the delta from the comparison's own current period and leaves the tile's value alone", () => {
    // The tile counts the rows on the grid; the delta compares the period the comparison measured.
    const data = buildEvtxChartData(
      input([record({ level: "Error" }), record({ level: "Error" }), record({ level: "Error" })], {
        comparison: {
          window: "24h",
          current: { errors: 10, distinctIds: ids("a") },
          prior: { errors: 5, distinctIds: ids("a") },
        },
      }),
    );
    expect(errorsOf(data).value).toBe(3);
    expect(errorsOf(data).sublabel).toBe("\u25b2 2\u00d7 vs prior 24 h");
  });

  it("marks a sublabel as comparative exactly when it is a delta, so the view can colour it for contrast", () => {
    const without = buildEvtxChartData(input([record({ level: "Error" })]));
    expect(without.kpis.map((k) => k.comparative)).toEqual([false, false, false, false, false, false]);
    const withComparison = buildEvtxChartData(
      input([record({ level: "Error" })], {
        comparison: {
          window: "24h",
          current: { errors: 4, distinctIds: ids("a") },
          prior: { errors: 2, distinctIds: ids() },
        },
      }),
    );
    expect(withComparison.kpis.filter((k) => k.comparative).map((k) => k.id)).toEqual([
      "errors",
      "distinctIds",
    ]);
    // Never a flag without the text it describes, and the counts form is comparative too.
    for (const k of withComparison.kpis) if (k.comparative) expect(k.sublabel).not.toBeNull();
    const counts = buildEvtxChartData(
      input([record({ level: "Error" })], {
        comparison: {
          window: "24h",
          current: { errors: 4, distinctIds: ids("a") },
          prior: { errors: 0, distinctIds: ids("a") },
        },
      }),
    );
    expect(kpi(counts, "errors").trend).toBeNull();
    expect(kpi(counts, "errors").comparative).toBe(true);
  });

  it("changes no other tile", () => {
    const records = [record({ level: "Warning" }), record({ level: "Critical", eventId: 41 })];
    const without = buildEvtxChartData(input(records));
    const withComparison = buildEvtxChartData(
      input(records, {
        comparison: {
          window: "24h",
          current: { errors: 4, distinctIds: ids("a", "b") },
          prior: { errors: 2, distinctIds: ids("a") },
        },
      }),
    );
    for (const id of ["events", "warnings", "critical", "chains"]) {
      expect(kpi(withComparison, id)).toEqual(kpi(without, id));
    }
  });

  it("does not move a figure: only the two tiles' sublabels differ", () => {
    const records = [record({ level: "Error" }), record({ level: "Warning", eventId: 5 })];
    const without = buildEvtxChartData(input(records));
    const withComparison = buildEvtxChartData(
      input(records, {
        comparison: {
          window: "24h",
          current: { errors: 4, distinctIds: ids("a") },
          prior: { errors: 2, distinctIds: ids() },
        },
      }),
    );
    expect({ ...withComparison, kpis: [] }).toEqual({ ...without, kpis: [] });
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
