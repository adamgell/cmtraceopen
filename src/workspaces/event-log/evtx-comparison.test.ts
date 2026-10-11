import { describe, expect, it } from "vitest";
import {
  checkFilesCoverage,
  compareLoadedFiles,
  computePriorWindow,
  createAggregator,
  eventIdentityKey,
  type ComparisonVisibility,
  type PriorWindow,
} from "./evtx-comparison";
import { DEFAULT_QUICK_FILTER, isWithinTimeWindow } from "./evtx-filter";
import { EVTX_TIME_WINDOW_MS, type EvtxLevel, type EvtxRecord } from "./types";

const ALL_LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];

/** A fixed, round anchor so every expected bound can be read off by hand. */
const ANCHOR = Date.parse("2026-08-10T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

let nextRecordId = 1;
function record(overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  const id = nextRecordId++;
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-09T06:00:00.000Z",
    timestampEpoch: ANCHOR - DAY - 6 * HOUR,
    provider: "Microsoft-Windows-Kernel-General",
    channel: "System",
    eventId: 12,
    level: "Information",
    computer: "HOST",
    message: "m",
    eventData: [],
    rawXml: "<Event/>",
    sourceLabel: "System.evtx",
    ...overrides,
  };
}

function visibility(overrides: Partial<ComparisonVisibility> = {}): ComparisonVisibility {
  return {
    selectedChannels: new Set(["System", "Application"]),
    filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
    filterEventIds: "",
    filterSearch: "",
    quickFilter: DEFAULT_QUICK_FILTER,
    ...overrides,
  };
}

function priorFor(window: "1h" | "24h" | "7d" | "30d" = "24h"): PriorWindow {
  const result = computePriorWindow(window, ANCHOR);
  if (result.status !== "available") throw new Error("expected an available prior window");
  return result.prior;
}

describe("computePriorWindow", () => {
  it.each(["1h", "24h", "7d", "30d"] as const)(
    "puts the previous %s immediately before the current one with the same length",
    (window) => {
      const length = EVTX_TIME_WINDOW_MS[window];
      const result = computePriorWindow(window, ANCHOR);
      expect(result.status).toBe("available");
      if (result.status !== "available") return;
      const { prior } = result;

      // The current window owns [anchor - length, ...]. Both service bounds are inclusive, so the
      // previous period must end one millisecond earlier or its last instant is counted twice.
      expect(prior.fromMs).toBe(ANCHOR - 2 * length);
      expect(prior.toMs).toBe(ANCHOR - length - 1);
      expect(prior.toMs - prior.fromMs + 1).toBe(length);
      expect(prior.lengthMs).toBe(length);
      expect(prior.window).toBe(window);
    }
  );

  it("renders both bounds as ISO 8601 UTC with milliseconds, the form the service accepts", () => {
    const prior = priorFor("24h");
    expect(prior.from).toBe("2026-08-08T12:00:00.000Z");
    expect(prior.to).toBe("2026-08-09T11:59:59.999Z");
  });

  it("agrees with the app's own current-window test at the boundary, so no instant is in both or neither", () => {
    for (const window of ["1h", "24h", "7d", "30d"] as const) {
      const prior = priorFor(window);
      const firstOfCurrent = prior.toMs + 1;
      expect(isWithinTimeWindow(firstOfCurrent, window, ANCHOR)).toBe(true);
      expect(isWithinTimeWindow(prior.toMs, window, ANCHOR)).toBe(false);
    }
  });

  it("has no previous period for All time and says so rather than inventing one", () => {
    const result = computePriorWindow("all", ANCHOR);
    expect(result).toEqual({
      status: "unavailable",
      reason: "allTime",
      detail: "All time has no previous period.",
    });
  });

  it("refuses an anchor that is not a whole, finite epoch", () => {
    for (const anchor of [Number.NaN, Number.POSITIVE_INFINITY, ANCHOR + 0.5]) {
      const result = computePriorWindow("24h", anchor);
      expect(result.status).toBe("unavailable");
      if (result.status === "unavailable") expect(result.reason).toBe("invalidAnchor");
    }
  });

  it("refuses an anchor whose previous period falls outside the representable dates", () => {
    const result = computePriorWindow("30d", -8.64e15);
    expect(result.status).toBe("unavailable");
    if (result.status === "unavailable") expect(result.reason).toBe("invalidAnchor");
  });

  it("refuses a window kind it does not know instead of computing from undefined", () => {
    const result = computePriorWindow("90d" as never, ANCHOR);
    expect(result.status).toBe("unavailable");
    if (result.status === "unavailable") expect(result.reason).toBe("unsupportedWindow");
  });
});

describe("createAggregator", () => {
  it("counts levels, channels and the distinct (provider, event id) set across batches", () => {
    const prior = priorFor();
    const aggregator = createAggregator(prior, visibility());
    const at = prior.fromMs + HOUR;

    aggregator.add([
      record({ timestampEpoch: at, level: "Error", eventId: 7, provider: "A", channel: "System" }),
      record({ timestampEpoch: at, level: "Error", eventId: 7, provider: "A", channel: "System" }),
      record({ timestampEpoch: at, level: "Warning", eventId: 7, provider: "B", channel: "Application" }),
    ]);
    aggregator.add([
      record({ timestampEpoch: at, level: "Critical", eventId: 8, provider: "A", channel: "Application" }),
    ]);

    const { counts, unplacedRecords, outsideWindowRecords } = aggregator.finish();
    expect(counts.total).toBe(4);
    expect(counts.levels).toEqual({
      Critical: 1,
      Error: 2,
      Warning: 1,
      Information: 0,
      Verbose: 0,
    });
    expect(Object.fromEntries(counts.channels)).toEqual({ System: 2, Application: 2 });
    // Same id from two providers is two events; the same pair twice is one.
    expect([...counts.distinctEvents].sort()).toEqual(
      [eventIdentityKey("A", 7), eventIdentityKey("B", 7), eventIdentityKey("A", 8)].sort()
    );
    expect(unplacedRecords).toBe(0);
    expect(outsideWindowRecords).toBe(0);
  });

  it("counts both inclusive bounds and nothing one millisecond beyond either", () => {
    const prior = priorFor();
    const aggregator = createAggregator(prior, visibility());
    aggregator.add([
      record({ timestampEpoch: prior.fromMs - 1 }),
      record({ timestampEpoch: prior.fromMs }),
      record({ timestampEpoch: prior.toMs }),
      record({ timestampEpoch: prior.toMs + 1 }),
    ]);
    const tally = aggregator.finish();
    expect(tally.counts.total).toBe(2);
    expect(tally.outsideWindowRecords).toBe(2);
  });

  it("does not place a record with no usable timestamp, and says how many it could not place", () => {
    const prior = priorFor();
    const aggregator = createAggregator(prior, visibility());
    aggregator.add([
      record({ timestampEpoch: 0 }),
      record({ timestampEpoch: Number.NaN }),
      record({ timestampEpoch: prior.fromMs }),
    ]);
    const tally = aggregator.finish();
    expect(tally.counts.total).toBe(1);
    expect(tally.unplacedRecords).toBe(2);
  });

  it("applies the same visibility rules the grid applies, minus the time window", () => {
    const prior = priorFor();
    const at = prior.fromMs + HOUR;
    const aggregator = createAggregator(
      prior,
      visibility({
        selectedChannels: new Set(["System"]),
        filterLevels: new Set<EvtxLevel>(["Error"]),
        filterSearch: "needle",
      })
    );
    aggregator.add([
      record({ timestampEpoch: at, level: "Error", message: "a needle here" }),
      record({ timestampEpoch: at, level: "Warning", message: "a needle here" }),
      record({ timestampEpoch: at, level: "Error", message: "nothing" }),
      record({ timestampEpoch: at, level: "Error", message: "a needle", channel: "Application" }),
    ]);
    expect(aggregator.finish().counts.total).toBe(1);
  });

  it("keeps counters and keys, never the records it was given", () => {
    const prior = priorFor();
    const given = record({ timestampEpoch: prior.fromMs + HOUR });
    const aggregator = createAggregator(prior, visibility());
    aggregator.add([given]);
    const tally = aggregator.finish();

    const seen = new Set<unknown>();
    const visit = (value: unknown): void => {
      if (typeof value !== "object" || value === null || seen.has(value)) return;
      seen.add(value);
      if (value instanceof Map) {
        for (const [key, entry] of value) {
          visit(key);
          visit(entry);
        }
      } else if (value instanceof Set) {
        for (const entry of value) visit(entry);
      } else {
        for (const entry of Object.values(value)) visit(entry);
      }
    };
    visit(tally);
    expect(seen.has(given)).toBe(false);
    expect([...seen].some((value) => (value as { rawXml?: string }).rawXml !== undefined)).toBe(
      false
    );
  });
});

describe("checkFilesCoverage", () => {
  const selected = new Set(["System", "Application"]);

  function spanning(prior: PriorWindow, overrides: Partial<EvtxRecord> = {}): EvtxRecord[] {
    return [
      record({ ...overrides, timestampEpoch: prior.fromMs }),
      record({ ...overrides, timestampEpoch: prior.toMs }),
    ];
  }

  it("is covered when the capture starts exactly at the previous period's start and reaches its end", () => {
    const prior = priorFor();
    expect(checkFilesCoverage(spanning(prior), selected, prior)).toEqual({ covered: true });
  });

  it("is not covered when the earliest event is one millisecond after the period starts", () => {
    const prior = priorFor();
    const records = [
      record({ timestampEpoch: prior.fromMs + 1 }),
      record({ timestampEpoch: prior.toMs }),
    ];
    const coverage = checkFilesCoverage(records, selected, prior);
    expect(coverage).toMatchObject({ covered: false, reason: "priorPeriodNotSpanned" });
  });

  it("is not covered when the latest event is one millisecond before the period ends", () => {
    const prior = priorFor();
    const records = [
      record({ timestampEpoch: prior.fromMs }),
      record({ timestampEpoch: prior.toMs - 1 }),
    ];
    const coverage = checkFilesCoverage(records, selected, prior);
    expect(coverage).toMatchObject({ covered: false, reason: "priorPeriodNotSpanned" });
  });

  it("reads the lower bound per source and channel, so one deep capture cannot vouch for a shallow one", () => {
    const prior = priorFor();
    const deep = spanning(prior, { channel: "Application", sourceLabel: "Application.evtx" });
    const shallow = [
      record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: prior.toMs + 5 }),
      record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: ANCHOR }),
    ];
    // Pooled, the earliest event predates the period and the latest postdates it. Per capture,
    // System.evtx starts after the period began and cannot say what happened before.
    expect(checkFilesCoverage([...deep, ...shallow], selected, prior)).toMatchObject({
      covered: false,
      reason: "priorPeriodNotSpanned",
    });
  });

  it("treats the same channel name from two files as two captures", () => {
    const prior = priorFor();
    const first = spanning(prior, { sourceLabel: "host-a/System.evtx" });
    const second = [
      record({ sourceLabel: "host-b/System.evtx", timestampEpoch: ANCHOR - HOUR }),
    ];
    expect(checkFilesCoverage([...first, ...second], selected, prior)).toMatchObject({
      covered: false,
    });
  });

  it("does not let a record stamped epoch 0 vouch for the start of the period", () => {
    // The native parser writes 0 for a timestamp it could not read, so a 1970 record would
    // otherwise satisfy "earliest event <= period start" for any capture.
    const prior = priorFor();
    const records = [
      record({ timestampEpoch: 0 }),
      record({ timestampEpoch: prior.toMs + 1 }),
      record({ timestampEpoch: ANCHOR }),
    ];
    expect(checkFilesCoverage(records, selected, prior)).toMatchObject({
      covered: false,
      reason: "priorPeriodNotSpanned",
    });
  });

  it("is not covered, for its own reason, when no selected event has a usable timestamp", () => {
    const prior = priorFor();
    const records = [record({ timestampEpoch: 0 }), record({ timestampEpoch: Number.NaN })];
    expect(checkFilesCoverage(records, selected, prior)).toMatchObject({
      covered: false,
      reason: "noTimedRecords",
    });
  });

  it("is not covered when nothing is loaded for the selected channels", () => {
    const prior = priorFor();
    const records = [record({ channel: "Security", timestampEpoch: prior.fromMs })];
    expect(checkFilesCoverage(records, selected, prior)).toMatchObject({
      covered: false,
      reason: "noTimedRecords",
    });
    expect(checkFilesCoverage([], selected, prior)).toMatchObject({ covered: false });
  });

  it("ignores captures of channels that are not selected", () => {
    const prior = priorFor();
    const records = [
      ...spanning(prior, { channel: "System" }),
      record({ channel: "Security", sourceLabel: "Security.evtx", timestampEpoch: ANCHOR }),
    ];
    expect(checkFilesCoverage(records, selected, prior)).toEqual({ covered: true });
  });
});

describe("compareLoadedFiles", () => {
  function input(records: EvtxRecord[], overrides: Record<string, unknown> = {}) {
    return {
      records,
      window: "24h" as const,
      anchorEpoch: ANCHOR,
      visibility: visibility(),
      ...overrides,
    };
  }

  function coveringRecords(prior: PriorWindow): EvtxRecord[] {
    return [
      record({ timestampEpoch: prior.fromMs, level: "Error", eventId: 1, provider: "A" }),
      record({ timestampEpoch: prior.fromMs + HOUR, level: "Warning", eventId: 2, provider: "A" }),
      record({ timestampEpoch: prior.toMs, level: "Error", eventId: 1, provider: "A" }),
    ];
  }

  it("aggregates only the previous period and reports it complete", () => {
    const prior = priorFor();
    const inCurrent = record({ timestampEpoch: prior.toMs + 1, level: "Critical" });
    const beforePrior = record({ timestampEpoch: prior.fromMs - 1, level: "Verbose" });
    const outcome = compareLoadedFiles(
      input([beforePrior, ...coveringRecords(prior), inCurrent])
    );

    // The events on either side bracket the capture, which is what makes the period covered, and
    // lie outside the period, which is why they are not counted.
    expect(outcome.status).toBe("complete");
    if (outcome.status !== "complete") return;
    expect(outcome.result.mode).toBe("files");
    expect(outcome.result.window).toBe("24h");
    expect(outcome.result.prior).toEqual(prior);
    expect(outcome.result.gaps).toEqual([]);
    expect(outcome.result.unreadChannels).toEqual([]);
    expect(outcome.result.counts.total).toBe(3);
    expect(outcome.result.counts.levels.Error).toBe(2);
    expect(outcome.result.counts.levels.Warning).toBe(1);
    expect(outcome.result.counts.levels.Critical).toBe(0);
    expect(outcome.result.counts.distinctEvents.size).toBe(2);
  });

  it("reports unavailable, never zero, when the loaded files do not cover the previous period", () => {
    const prior = priorFor();
    const outcome = compareLoadedFiles(
      input([record({ timestampEpoch: prior.toMs + HOUR }), record({ timestampEpoch: ANCHOR })])
    );
    expect(outcome).toEqual({
      status: "unavailable",
      reason: "priorPeriodNotSpanned",
      detail: "The loaded files do not cover the previous period.",
    });
  });

  it("reports All time as having no previous period, distinct from not being covered", () => {
    const outcome = compareLoadedFiles(input([], { window: "all" }));
    expect(outcome).toMatchObject({ status: "unavailable", reason: "allTime" });
  });

  it("is partial, and says so, when visible events have no usable timestamp", () => {
    const prior = priorFor();
    const outcome = compareLoadedFiles(
      input([...coveringRecords(prior), record({ timestampEpoch: 0 })])
    );
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.unplacedRecords).toBe(1);
    expect(outcome.result.counts.total).toBe(3);
    expect(outcome.result.gaps).toEqual([
      "1 loaded event has no usable timestamp and could not be placed in either period.",
    ]);
  });

  it("uses the visibility rules of the current view for the previous period", () => {
    const prior = priorFor();
    const outcome = compareLoadedFiles(
      input(coveringRecords(prior), {
        visibility: visibility({ filterLevels: new Set<EvtxLevel>(["Error"]) }),
      })
    );
    expect(outcome.status).toBe("complete");
    if (outcome.status !== "complete") return;
    expect(outcome.result.counts.total).toBe(2);
    expect(outcome.result.counts.levels.Warning).toBe(0);
  });
});
