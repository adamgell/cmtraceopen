import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginLiveComparison,
  cancelComparison,
  channelStartGap,
  checkFilesCoverage,
  compareLoadedFiles,
  computePriorWindow,
  countCurrentPeriod,
  createAggregator,
  eventIdentityKey,
  getComparisonState,
  isComparisonRequestId,
  markTailAppended,
  messageTextCriterionActive,
  observeComparisonBatch,
  observeComparisonComplete,
  observeComparisonProgress,
  publishFilesComparison,
  useComparisonStore,
  type ComparisonVisibility,
  type LiveComparisonSession,
  type PriorWindow,
} from "./evtx-comparison";
import { DEFAULT_QUICK_FILTER, isWithinTimeWindow } from "./evtx-filter";
import {
  EVTX_TIME_WINDOW_MS,
  type EventLogSourceCoverage,
  type EvtxCoverageGap,
  type EvtxLevel,
  type EvtxParseResult,
  type EvtxRecord,
} from "./types";

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
      // The anchor is recoverable from the period, so a consumer can tell whether its own current
      // window still meets this one.
      expect(prior.anchorEpoch).toBe(ANCHOR);
      expect(prior.toMs + 1 + prior.lengthMs).toBe(prior.anchorEpoch);
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

  it("sends the previous period's end at millisecond precision, a known sub-millisecond hole", () => {
    // The service compares at a finer resolution than a whole millisecond, so an event stamped in
    // the last fraction of a millisecond before the current window can fall in neither period on a
    // live source. A record's epoch is whole milliseconds, so the model cannot represent such an
    // event in a test; what can be pinned is the bound that leaves the hole. Closing it means a
    // seven-digit bound, to be adopted once the Windows lab confirms the service accepts one.
    const prior = priorFor("24h");
    expect(prior.to).toMatch(/T\d{2}:\d{2}:\d{2}\.999Z$/);
    expect(prior.to).toHaveLength("2026-08-09T11:59:59.999Z".length);
    expect(Date.parse(prior.to)).toBe(prior.toMs);
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
    // Zero is what an anchor reads before any load has set one.
    for (const anchor of [Number.NaN, Number.POSITIVE_INFINITY, ANCHOR + 0.5, 0, -1]) {
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

/** The parts of a comparison result the current side is counted from. */
function basisOf(prior: PriorWindow, comparedChannels: string[] = [], channelsWithGaps: string[] = []) {
  return { prior, comparedChannels, channelsWithGaps };
}

describe("countCurrentPeriod", () => {
  it("counts [anchor - length, anchor] and meets the previous period without overlap or gap", () => {
    const prior = priorFor("24h");
    const lengthMs = EVTX_TIME_WINDOW_MS["24h"];
    const records = [
      record({ timestampEpoch: ANCHOR - lengthMs - 1 }),
      record({ timestampEpoch: ANCHOR - lengthMs }),
      record({ timestampEpoch: ANCHOR - 1, level: "Error" }),
      record({ timestampEpoch: ANCHOR, level: "Error" }),
      record({ timestampEpoch: ANCHOR + 1 }),
    ];

    const current = countCurrentPeriod(records, basisOf(prior), visibility());
    expect(current.counts.total).toBe(3);
    expect(current.counts.levels.Error).toBe(2);
    expect(current.outsideWindowRecords).toBe(2);

    // Every record lands in exactly one of the two periods, or in neither beyond their outer ends.
    const aggregator = createAggregator(prior, visibility());
    aggregator.add(records);
    expect(aggregator.finish().counts.total + current.counts.total).toBe(4);
  });

  it("follows the comparison's anchor and not the clock the grid measures from", () => {
    // A load three hours before `now`: the current period ends there, so events after it are not
    // counted and the previous period still meets it.
    const loadAnchor = ANCHOR - 3 * HOUR;
    const result = computePriorWindow("24h", loadAnchor);
    if (result.status !== "available") throw new Error("expected an available prior window");
    const records = [
      record({ timestampEpoch: loadAnchor - HOUR }),
      record({ timestampEpoch: loadAnchor + HOUR }),
    ];
    expect(countCurrentPeriod(records, basisOf(result.prior), visibility()).counts.total).toBe(1);
  });

  it("uses the same visibility rules as the previous period", () => {
    const prior = priorFor("24h");
    const records = [
      record({ timestampEpoch: ANCHOR - HOUR, level: "Error" }),
      record({ timestampEpoch: ANCHOR - HOUR, level: "Warning" }),
    ];
    const current = countCurrentPeriod(
      records,
      basisOf(prior),
      visibility({ filterLevels: new Set<EvtxLevel>(["Error"]) })
    );
    expect(current.counts.total).toBe(1);
  });

  it("never counts a record the live tail appended, whatever its timestamp says", () => {
    const prior = priorFor("24h");
    const loaded = record({ timestampEpoch: ANCHOR - HOUR });
    const lateArrival = record({ timestampEpoch: ANCHOR - HOUR });
    markTailAppended([lateArrival]);

    const current = countCurrentPeriod([loaded, lateArrival], basisOf(prior), visibility());

    expect(current.counts.total).toBe(1);
  });

  describe("channels with no events", () => {
    const prior = () => priorFor("24h");
    const inCurrent = (channel: string, overrides: Partial<EvtxRecord> = {}) =>
      record({ channel, timestampEpoch: ANCHOR - HOUR, ...overrides });

    it("records a compared channel read without a hole as 0, and leaves an uncompared one absent", () => {
      const current = countCurrentPeriod(
        [inCurrent("System")],
        basisOf(prior(), ["System", "Setup"]),
        visibility({ selectedChannels: new Set(["System", "Setup", "Security"]) })
      );
      expect(current.counts.channels.get("System")).toBe(1);
      expect(current.counts.channels.get("Setup")).toBe(0);
      expect(current.counts.channels.has("Security")).toBe(false);
    });

    it("leaves a channel with a hole absent, however few events it showed", () => {
      const current = countCurrentPeriod(
        [inCurrent("System")],
        basisOf(prior(), ["System", "Setup"], ["Setup"]),
        visibility({ selectedChannels: new Set(["System", "Setup"]) })
      );
      expect(current.counts.channels.has("Setup")).toBe(false);
      expect(current.counts.channels.get("System")).toBe(1);
    });

    it("leaves a channel absent when one of its visible events could not be placed in time", () => {
      const current = countCurrentPeriod(
        [inCurrent("Setup", { timestampEpoch: 0 })],
        basisOf(prior(), ["Setup"]),
        visibility({ selectedChannels: new Set(["Setup"]) })
      );
      expect(current.counts.channels.has("Setup")).toBe(false);
    });

    it("zero-fills from the result the comparison published, in both modes", () => {
      const p = prior();
      // Files: Setup reaches the anchor, holds nothing in the current period, and is clean.
      const files = compareLoadedFiles({
        records: [
          record({ channel: "Setup", sourceLabel: "Setup.evtx", timestampEpoch: p.fromMs - HOUR }),
          record({ channel: "Setup", sourceLabel: "Setup.evtx", timestampEpoch: ANCHOR + 1 }),
        ],
        window: "24h",
        anchorEpoch: ANCHOR,
        visibility: visibility({ selectedChannels: new Set(["Setup"]) }),
        coverageDetails: [],
        sourceCoverage: [],
      });
      expect(files.status).toBe("complete");
      if (files.status === "complete") {
        expect(files.result.comparedChannels).toEqual(["Setup"]);
        expect(files.result.channelsWithGaps).toEqual([]);
        const current = countCurrentPeriod([], files.result, visibility());
        expect(current.counts.channels.get("Setup")).toBe(0);
      }
    });
  });
});

describe("channelStartGap", () => {
  const LENGTH = EVTX_TIME_WINDOW_MS["24h"];
  const ONE_PERCENT = LENGTH / 100;
  const iso = (epoch: number) => new Date(epoch).toISOString();

  it("is silent for a channel read at the anchor, and up to one percent of the window after it", () => {
    expect(channelStartGap("System", ANCHOR, ANCHOR, LENGTH)).toBeNull();
    expect(channelStartGap("System", ANCHOR + ONE_PERCENT, ANCHOR, LENGTH)).toBeNull();
  });

  it("states the missing start as soon as it exceeds one percent of the window", () => {
    expect(channelStartGap("System", ANCHOR + ONE_PERCENT + 1, ANCHOR, LENGTH)).toBe(
      `System was read at ${iso(ANCHOR + ONE_PERCENT + 1)}, 14 min after the comparison anchor ${iso(ANCHOR)}, so the first 14 min of its current period is not covered.`
    );
  });

  it("reports at most the whole window as missing", () => {
    const gapText = channelStartGap("System", ANCHOR + 10 * HOUR, ANCHOR, HOUR);
    expect(gapText).toContain("10 h after the comparison anchor");
    expect(gapText).toContain("so the first 1 h of its current period is not covered");
  });

  it("scales the tolerance with the window", () => {
    // One percent of an hour is 36 seconds; of 30 days, 7.2 hours.
    expect(channelStartGap("System", ANCHOR + 40_000, ANCHOR, HOUR)).not.toBeNull();
    expect(channelStartGap("System", ANCHOR + 30_000, ANCHOR, HOUR)).toBeNull();
    expect(channelStartGap("System", ANCHOR + 7 * HOUR, ANCHOR, EVTX_TIME_WINDOW_MS["30d"])).toBeNull();
    expect(channelStartGap("System", ANCHOR + 8 * HOUR, ANCHOR, EVTX_TIME_WINDOW_MS["30d"])).not.toBeNull();
  });
});

describe("messageTextCriterionActive", () => {
  const quick = (overrides: Partial<typeof DEFAULT_QUICK_FILTER>) => ({
    ...DEFAULT_QUICK_FILTER,
    ...overrides,
  });

  it("is off when nothing reads message text", () => {
    expect(messageTextCriterionActive(visibility())).toBe(false);
    expect(messageTextCriterionActive(visibility({ filterSearch: "   " }))).toBe(false);
    expect(messageTextCriterionActive(visibility({ quickFilter: quick({ query: "  " }) }))).toBe(
      false
    );
  });

  it("is on for a search, and for a quick filter that reads the message column", () => {
    expect(messageTextCriterionActive(visibility({ filterSearch: "timeout" }))).toBe(true);
    expect(messageTextCriterionActive(visibility({ quickFilter: quick({ query: "x" }) }))).toBe(
      true
    );
    expect(
      messageTextCriterionActive(
        visibility({
          quickFilter: quick({ query: "x", scope: "visibleColumns" }),
          visibleColumns: ["timestamp", "message"],
        })
      )
    ).toBe(true);
  });

  it("is off for a quick filter that cannot read the message", () => {
    expect(
      messageTextCriterionActive(
        visibility({ quickFilter: quick({ query: "4624", mode: "eventIds" }) })
      )
    ).toBe(false);
    expect(
      messageTextCriterionActive(
        visibility({
          quickFilter: quick({ query: "x", scope: "visibleColumns" }),
          visibleColumns: ["timestamp", "level"],
        })
      )
    ).toBe(false);
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
    const coverage = checkFilesCoverage(spanning(prior), selected, prior);
    expect(coverage).toMatchObject({ covered: true });
    expect(coverage.covered && coverage.captures).toEqual([
      {
        source: "System.evtx",
        channel: "System",
        earliestMs: prior.fromMs,
        latestMs: prior.toMs,
      },
    ]);
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
    expect(checkFilesCoverage(records, selected, prior)).toMatchObject({ covered: true });
  });

  it("reads coverage per channel as well as per source, so one export's deep channel cannot vouch for its shallow one", () => {
    // One container, such as an archive, holds several channels under a single source label.
    const prior = priorFor();
    const records = [
      ...spanning(prior, { sourceLabel: "export.zip", channel: "System" }),
      record({ sourceLabel: "export.zip", channel: "Application", timestampEpoch: ANCHOR }),
    ];
    expect(checkFilesCoverage(records, selected, prior)).toMatchObject({
      covered: false,
      reason: "priorPeriodNotSpanned",
    });
  });

  it("reads coverage per source as well as per channel when two sources share a channel", () => {
    const prior = priorFor();
    const records = [
      ...spanning(prior, { sourceLabel: "a.evtx", channel: "System" }),
      ...spanning(prior, { sourceLabel: "b.evtx", channel: "System" }),
    ];
    const coverage = checkFilesCoverage(records, selected, prior);
    expect(coverage.covered && coverage.captures.map((c) => c.source).sort()).toEqual([
      "a.evtx",
      "b.evtx",
    ]);
  });
});

describe("compareLoadedFiles", () => {
  function input(records: EvtxRecord[], overrides: Record<string, unknown> = {}) {
    return {
      records,
      window: "24h" as const,
      anchorEpoch: ANCHOR,
      visibility: visibility(),
      coverageDetails: [] as EvtxCoverageGap[],
      sourceCoverage: [] as EventLogSourceCoverage[],
      ...overrides,
    };
  }

  /** Spans the previous period and reaches the anchor, so nothing about it is short. */
  function coveringRecords(prior: PriorWindow): EvtxRecord[] {
    return [
      record({ timestampEpoch: prior.fromMs, level: "Error", eventId: 1, provider: "A" }),
      record({ timestampEpoch: prior.fromMs + HOUR, level: "Warning", eventId: 2, provider: "A" }),
      record({ timestampEpoch: prior.toMs, level: "Error", eventId: 1, provider: "A" }),
      record({ timestampEpoch: ANCHOR }),
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

  describe("the current period", () => {
    /** Spans the previous period, then stops `endsBefore` ms short of the anchor. */
    function captureEndingBefore(prior: PriorWindow, endsBefore: number, overrides = {}) {
      return [
        record({ timestampEpoch: prior.fromMs, ...overrides }),
        record({ timestampEpoch: prior.toMs, ...overrides }),
        record({ timestampEpoch: ANCHOR - endsBefore, ...overrides }),
      ];
    }

    it("is partial, stating the span it lacks, for an export captured 20 hours before the anchor", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(input(captureEndingBefore(prior, 20 * HOUR)));

      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      // The previous period is whole, so a decline against it would be a capture artifact.
      expect(outcome.result.counts.total).toBe(2);
      expect(outcome.result.gaps).toEqual([
        `System.evtx (System) has no events after ${new Date(ANCHOR - 20 * HOUR).toISOString()}, so the last 20 h of the current period is not covered.`,
      ]);
      expect(outcome.result.anchorBasis).toBe("clock");
      expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR);
    });

    it("is complete only when every capture reaches the anchor, to the millisecond", () => {
      const prior = priorFor();
      expect(compareLoadedFiles(input(captureEndingBefore(prior, 0))).status).toBe("complete");

      const oneShort = compareLoadedFiles(input(captureEndingBefore(prior, 1)));
      expect(oneShort.status).toBe("partial");
      if (oneShort.status === "partial") {
        expect(oneShort.result.gaps[0]).toContain("the last 1 ms of the current period");
      }
    });

    it("names only the captures that stop short, and states the longest shortfall first", () => {
      const prior = priorFor();
      const reaches = captureEndingBefore(prior, 0, { sourceLabel: "a.evtx", channel: "System" });
      const short = captureEndingBefore(prior, 90 * 60 * 1000, {
        sourceLabel: "b.evtx",
        channel: "Application",
      });
      const shorter = captureEndingBefore(prior, 5 * 60 * 1000, {
        sourceLabel: "c.evtx",
        channel: "Setup",
      });
      const outcome = compareLoadedFiles(
        input([...reaches, ...short, ...shorter], {
          visibility: visibility({ selectedChannels: new Set(["System", "Application", "Setup"]) }),
        })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.gaps).toHaveLength(2);
      expect(outcome.result.gaps[0]).toContain("b.evtx (Application)");
      expect(outcome.result.gaps[0]).toContain("the last 1 h 30 min");
      expect(outcome.result.gaps[1]).toContain("c.evtx (Setup)");
      expect(outcome.result.gaps[1]).toContain("the last 5 min");
    });

    it("lists a few short captures and counts the rest", () => {
      const prior = priorFor();
      const records = Array.from({ length: 8 }, (_, index) =>
        captureEndingBefore(prior, HOUR * (index + 1), {
          sourceLabel: `f${index}.evtx`,
          channel: `Channel${index}`,
        })
      ).flat();
      const outcome = compareLoadedFiles(
        input(records, {
          visibility: visibility({
            selectedChannels: new Set(Array.from({ length: 8 }, (_, i) => `Channel${i}`)),
          }),
        })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status === "partial") {
        expect(outcome.result.gaps).toHaveLength(6);
        expect(outcome.result.gaps[5]).toBe("and 3 more not shown.");
      }
    });
  });

  describe("holes the load reported", () => {
    const chunkGap = (overrides: Partial<EvtxCoverageGap> = {}): EvtxCoverageGap => ({
      source: "System.evtx",
      kind: "chunk",
      reason: "chunk 12 could not be parsed",
      chunkId: 12,
      ...overrides,
    });

    it("publishes the channels compared and those a hole or a short capture leaves untrustworthy", () => {
      const prior = priorFor();
      const records = [
        ...coveringRecords(prior),
        record({ channel: "Application", sourceLabel: "Application.evtx", timestampEpoch: prior.fromMs - HOUR }),
        record({ channel: "Application", sourceLabel: "Application.evtx", timestampEpoch: ANCHOR - 10 * HOUR }),
      ];
      const outcome = compareLoadedFiles(
        input(records, {
          coverageDetails: [chunkGap()],
        })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.comparedChannels).toEqual(["System", "Application"]);
      // System has a damaged chunk; Application's capture stops 10 h short of the anchor.
      expect(outcome.result.channelsWithGaps).toEqual(["System", "Application"]);
    });

    it("makes the comparison partial for a damaged chunk inside the previous period", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(
        input(coveringRecords(prior), { coverageDetails: [chunkGap()] })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.gaps).toEqual(["System.evtx chunk 12: chunk 12 could not be parsed"]);
      expect(outcome.result.counts.total).toBe(3);
    });

    it("carries record, XML and record-budget gaps, and a source the manifest could not read", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(
        input(coveringRecords(prior), {
          coverageDetails: [
            chunkGap({ kind: "record", reason: "record 9 unreadable", chunkId: undefined }),
            chunkGap({ kind: "xml", reason: "event XML could not be parsed: bad", chunkId: undefined }),
            chunkGap({
              kind: "limit",
              reason:
                "source manifest record budget of 1000000 records was exhausted; later records/files were omitted",
              chunkId: undefined,
            }),
          ],
          sourceCoverage: [
            { kind: "accessDenied", path: "C:/logs/Security.evtx", reason: "access denied" },
          ],
        })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.gaps).toHaveLength(4);
      expect(outcome.result.gaps).toContain("C:/logs/Security.evtx: access denied");
    });

    it("does not hold a gap in a source of unselected channels against this comparison", () => {
      const prior = priorFor();
      const records = [
        ...coveringRecords(prior),
        record({ sourceLabel: "Security.evtx", channel: "Security", timestampEpoch: ANCHOR }),
      ];
      const outcome = compareLoadedFiles(
        input(records, { coverageDetails: [chunkGap({ source: "Security.evtx" })] })
      );
      expect(outcome.status).toBe("complete");
    });

    it("does carry a gap from a source no loaded record mentions, which might hold a selected channel", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(
        input(coveringRecords(prior), { coverageDetails: [chunkGap({ source: "Lost.evtx" })] })
      );
      expect(outcome.status).toBe("partial");
      // It might hold any compared channel, so none of their zeros can be trusted.
      if (outcome.status === "partial") {
        expect(outcome.result.channelsWithGaps).toEqual(outcome.result.comparedChannels);
        expect(outcome.result.channelsWithGaps).toEqual(["System"]);
      }
    });

    it("ignores a provider-description gap unless a criterion reads the message", () => {
      const prior = priorFor();
      const providerGap = chunkGap({
        kind: "provider",
        reason: "message text unavailable",
        chunkId: undefined,
      });
      const plain = compareLoadedFiles(
        input(coveringRecords(prior), { coverageDetails: [providerGap] })
      );
      expect(plain.status).toBe("complete");

      for (const active of [
        visibility({ filterSearch: "timeout" }),
        visibility({ quickFilter: { ...DEFAULT_QUICK_FILTER, query: "timeout" } }),
      ]) {
        const searched = compareLoadedFiles(
          input(coveringRecords(prior), { coverageDetails: [providerGap], visibility: active })
        );
        expect(searched.status).toBe("partial");
        if (searched.status === "partial") {
          expect(searched.result.gaps).toEqual(["System.evtx: message text unavailable"]);
        }
      }
    });
  });

  describe("channels with no events", () => {
    function twoChannels(prior: PriorWindow, overrides = {}) {
      return [
        record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: prior.fromMs }),
        record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: ANCHOR }),
        record({ channel: "Setup", sourceLabel: "Setup.evtx", timestampEpoch: prior.fromMs - HOUR, ...overrides }),
        record({ channel: "Setup", sourceLabel: "Setup.evtx", timestampEpoch: ANCHOR, ...overrides }),
      ];
    }

    it("counts a channel read in full with no events in the period as 0, unlike an unread one", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(
        input(twoChannels(prior), {
          visibility: visibility({ selectedChannels: new Set(["System", "Setup"]) }),
        })
      );
      expect(outcome.status).toBe("complete");
      if (outcome.status !== "complete") return;
      expect(outcome.result.counts.channels.get("System")).toBe(1);
      expect(outcome.result.counts.channels.get("Setup")).toBe(0);
      expect(outcome.result.counts.channels.has("Application")).toBe(false);
    });

    it("does not call a channel 0 when any of its sources reported a hole", () => {
      const prior = priorFor();
      const records = [
        // Both captures span the previous period and neither holds an event inside it.
        record({ channel: "System", sourceLabel: "a.evtx", timestampEpoch: prior.fromMs - HOUR }),
        record({ channel: "System", sourceLabel: "a.evtx", timestampEpoch: ANCHOR }),
        record({ channel: "System", sourceLabel: "b.evtx", timestampEpoch: prior.fromMs - HOUR }),
        record({ channel: "System", sourceLabel: "b.evtx", timestampEpoch: ANCHOR }),
      ];
      const outcome = compareLoadedFiles(
        input(records, {
          visibility: visibility({ selectedChannels: new Set(["System"]) }),
          coverageDetails: [
            { source: "a.evtx", kind: "chunk", reason: "chunk 3 unreadable", chunkId: 3 },
          ],
        })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status === "partial") {
        // b.evtx is clean, but System also lives in a.evtx, whose damaged chunk may hold events.
        expect(outcome.result.counts.channels.has("System")).toBe(false);
      }
    });

    it("does not call any channel 0 when a hole is in a source no loaded record can place", () => {
      const prior = priorFor();
      const records = [
        record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: prior.fromMs - HOUR }),
        record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: ANCHOR }),
      ];
      const common = { visibility: visibility({ selectedChannels: new Set(["System"]) }) };

      // A source nothing was loaded from might hold any selected channel.
      const lost = compareLoadedFiles(
        input(records, {
          ...common,
          coverageDetails: [
            { source: "Lost.evtx", kind: "chunk", reason: "chunk 1 unreadable", chunkId: 1 },
          ],
        })
      );
      const unreadable = compareLoadedFiles(
        input(records, {
          ...common,
          sourceCoverage: [{ kind: "accessDenied", path: "C:/logs/Security.evtx", reason: "access denied" }],
        })
      );
      for (const outcome of [lost, unreadable]) {
        expect(outcome.status).toBe("partial");
        if (outcome.status === "partial") {
          expect(outcome.result.counts.channels.has("System")).toBe(false);
        }
      }
    });

    it("does not call a channel 0 when a visible event in it could not be placed in time", () => {
      const prior = priorFor();
      const records = [
        record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: prior.fromMs - HOUR }),
        record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: ANCHOR }),
        record({ channel: "Setup", sourceLabel: "Setup.evtx", timestampEpoch: prior.fromMs - HOUR }),
        record({ channel: "Setup", sourceLabel: "Setup.evtx", timestampEpoch: ANCHOR }),
        // It has no usable timestamp, so it may belong to the previous period.
        record({ channel: "Setup", sourceLabel: "Setup.evtx", timestampEpoch: 0 }),
      ];
      const outcome = compareLoadedFiles(
        input(records, {
          visibility: visibility({ selectedChannels: new Set(["System", "Setup"]) }),
        })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.counts.channels.get("System")).toBe(0);
      expect(outcome.result.counts.channels.has("Setup")).toBe(false);
    });

    it("does not call a channel 0 when its source reported a hole", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(
        input(twoChannels(prior), {
          visibility: visibility({ selectedChannels: new Set(["System", "Setup"]) }),
          coverageDetails: [
            { source: "Setup.evtx", kind: "chunk", reason: "chunk 3 unreadable", chunkId: 3 },
          ],
        })
      );
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.counts.channels.get("System")).toBe(1);
      expect(outcome.result.counts.channels.has("Setup")).toBe(false);
    });
  });
});

function reply(
  totalRecords: number | undefined,
  overrides: Partial<EvtxParseResult> = {}
): EvtxParseResult {
  return {
    records: [],
    channels: [],
    totalRecords: totalRecords as number,
    parseErrors: 0,
    errorMessages: [],
    coverageGaps: [],
    ...overrides,
  };
}

function gap(overrides: Partial<EvtxCoverageGap> = {}): EvtxCoverageGap {
  return { source: "System", kind: "record", reason: "unreadable record", ...overrides };
}

describe("a live comparison", () => {
  const cancelQuery = vi.fn<(requestId: string) => void>();
  const channels = ["System", "Application"];
  let inPrior: number;

  beforeEach(() => {
    vi.useFakeTimers();
    cancelComparison();
    cancelQuery.mockReset();
    inPrior = priorFor().fromMs + HOUR;
  });

  afterEach(() => {
    cancelComparison();
    vi.useRealTimers();
  });

  function begin(overrides: Partial<Parameters<typeof beginLiveComparison>[0]> = {}) {
    const session = beginLiveComparison({
      window: "24h",
      anchorEpoch: ANCHOR,
      remote: false,
      notes: [],
      currentPeriodHoleChannels: [],
      currentPeriodGaps: [],
      channels,
      visibility: visibility(),
      cancelQuery,
      ...overrides,
    });
    if (!session) throw new Error("expected the comparison to start");
    return session;
  }

  function batch(
    session: LiveComparisonSession,
    channel: string,
    sequence: number,
    records: EvtxRecord[]
  ) {
    observeComparisonBatch({ requestId: session.requestId, channel, sequence, records });
  }

  function terminal(
    session: LiveComparisonSession,
    channel: string,
    sequenceCount: number,
    totalRecords: number
  ) {
    observeComparisonComplete({ requestId: session.requestId, channel, sequenceCount, totalRecords });
  }

  function systemEvents(count: number, overrides: Partial<EvtxRecord> = {}): EvtxRecord[] {
    return Array.from({ length: count }, () =>
      record({ channel: "System", timestampEpoch: inPrior, ...overrides })
    );
  }

  /** Delivers a whole channel the way the backend does: batches, terminal, then the reply. */
  function deliver(session: LiveComparisonSession, channel: string, records: EvtxRecord[]) {
    if (records.length > 0) batch(session, channel, 0, records);
    terminal(session, channel, records.length > 0 ? 1 : 0, records.length);
    session.replied(channel, reply(records.length));
  }

  function settled() {
    const state = getComparisonState();
    if (state.phase !== "settled") throw new Error(`expected a settled comparison, got ${state.phase}`);
    return state.outcome;
  }

  it("takes a request ID from its own namespace, unique per comparison", () => {
    const first = begin();
    cancelComparison();
    const second = begin();
    expect(isComparisonRequestId(first.requestId)).toBe(true);
    expect(isComparisonRequestId(second.requestId)).toBe(true);
    expect(second.requestId).not.toBe(first.requestId);
    // The store's own requests must never be mistaken for a comparison.
    expect(isComparisonRequestId("event-log-1")).toBe(false);
    expect(isComparisonRequestId("event-log-tail-1")).toBe(false);
    expect(isComparisonRequestId("initial")).toBe(false);
  });

  it("publishes a running state, and no numbers, until every channel has settled", () => {
    const session = begin();
    const published: string[] = [];
    const unsubscribe = useComparisonStore.subscribe((value) => published.push(value.state.phase));

    expect(getComparisonState()).toMatchObject({
      phase: "running",
      requestId: session.requestId,
      prior: priorFor(),
    });
    deliver(session, "System", systemEvents(3));
    expect(getComparisonState().phase).toBe("running");
    expect(published).toEqual([]);

    deliver(session, "Application", []);
    unsubscribe();
    expect(published).toEqual(["settled"]);
  });

  it("completes with the aggregated counts when the stream reconciles with the replies", async () => {
    const session = begin();
    deliver(
      session,
      "System",
      systemEvents(2, { level: "Error", eventId: 7 }).concat(
        systemEvents(1, { level: "Warning", eventId: 8 })
      )
    );
    deliver(session, "Application", [
      record({
        channel: "Application",
        timestampEpoch: inPrior,
        level: "Error",
        eventId: 7,
        provider: "Other-Provider",
      }),
    ]);
    await session.done;

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status !== "complete") return;
    expect(outcome.result.mode).toBe("live");
    expect(outcome.result.gaps).toEqual([]);
    expect(outcome.result.unreadChannels).toEqual([]);
    expect(outcome.result.counts.total).toBe(4);
    expect(outcome.result.counts.levels.Error).toBe(3);
    expect(Object.fromEntries(outcome.result.counts.channels)).toEqual({ System: 3, Application: 1 });
    expect(outcome.result.counts.distinctEvents.size).toBe(3);
    expect(cancelQuery).not.toHaveBeenCalled();
  });

  it("does not finish early when the reply and terminal outrun the last batch", () => {
    const session = begin({ channels: ["System"] });
    batch(session, "System", 0, systemEvents(2));
    session.replied("System", reply(4));
    terminal(session, "System", 2, 4);
    expect(getComparisonState().phase).toBe("running");

    batch(session, "System", 1, systemEvents(2));
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.counts.total).toBe(4);
  });

  it("still waits for a batch the end-of-stream marker promises when the reply's count is already met", () => {
    // The reply says 2 events and the marker promises two batches. Trusting the reply alone would
    // settle now and drop the second batch; the marker keeps the channel open, and the
    // disagreement between the two reports is then stated rather than hidden.
    const session = begin({ channels: ["System"] });
    batch(session, "System", 0, systemEvents(2));
    session.replied("System", reply(2));
    terminal(session, "System", 2, 4);
    expect(getComparisonState().phase).toBe("running");

    batch(session, "System", 1, systemEvents(2));
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.counts.total).toBe(4);
    expect(outcome.result.gaps).toEqual(["System: more events arrived than the reader reported"]);
  });

  it("settles as partial, naming what was not received, once the stragglers' grace has passed", () => {
    const session = begin({ channels: ["System"] });
    batch(session, "System", 0, systemEvents(3));
    session.replied("System", reply(5));
    terminal(session, "System", 2, 5);
    expect(getComparisonState().phase).toBe("running");

    vi.runAllTimers();
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.counts.total).toBe(3);
    expect(outcome.result.gaps).toEqual([
      "System: 1 batch of events was not received",
      "System: 2 of 5 events did not reach the comparison",
    ]);
  });

  it("is partial when the end-of-stream marker never arrives, even if the counts line up", () => {
    const session = begin({ channels: ["System"] });
    batch(session, "System", 0, systemEvents(2));
    session.replied("System", reply(2));
    expect(getComparisonState().phase).toBe("running");

    vi.runAllTimers();
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.gaps).toEqual(["System: the end-of-stream marker was not received"]);
    }
  });

  it("counts a batch delivered twice once", () => {
    const session = begin({ channels: ["System"] });
    batch(session, "System", 0, systemEvents(2));
    batch(session, "System", 0, systemEvents(2));
    terminal(session, "System", 1, 2);
    session.replied("System", reply(2));
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.counts.total).toBe(2);
  });

  it("ignores a batch for a channel it did not ask for, or for another request", () => {
    const session = begin({ channels: ["System"] });
    batch(session, "Security", 0, systemEvents(5, { channel: "Security" }));
    observeComparisonBatch({
      requestId: "event-log-compare-0",
      channel: "System",
      sequence: 0,
      records: systemEvents(5),
    });
    deliver(session, "System", systemEvents(1));
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.counts.total).toBe(1);
  });

  it("drops batches that arrive after the channel has settled", () => {
    const session = begin({ channels: ["System", "Application"] });
    deliver(session, "System", systemEvents(1));
    batch(session, "System", 1, systemEvents(10));
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.counts.total).toBe(1);
  });

  it("records the anchor and that it comes from the load, and counts a channel with no events as 0", () => {
    const session = begin();
    deliver(session, "System", systemEvents(2));
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status !== "complete") return;
    expect(outcome.result.anchorBasis).toBe("load");
    expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR);
    expect(outcome.result.counts.channels.get("System")).toBe(2);
    expect(outcome.result.counts.channels.get("Application")).toBe(0);
    expect(outcome.result.notes).toEqual([]);
  });

  it("publishes the channels compared and those whose zero cannot be trusted", () => {
    const session = begin({
      channels: ["System", "Application"],
      currentPeriodGaps: ["Application: 3 events could not be read and are missing from this view"],
      currentPeriodHoleChannels: ["Application"],
    });
    deliver(session, "System", systemEvents(1));
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.comparedChannels).toEqual(["System", "Application"]);
    expect(outcome.result.channelsWithGaps).toEqual(["Application"]);
  });

  it("counts a channel whose stream lost a batch among those whose zero cannot be trusted", () => {
    const session = begin({ channels: ["System", "Application"] });
    batch(session, "System", 0, systemEvents(1));
    terminal(session, "System", 2, 2);
    session.replied("System", reply(2));
    vi.runAllTimers();
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.channelsWithGaps).toEqual(["System"]);
    }
  });

  it("carries the caller's notes after the remote one, without calling any of them a gap", () => {
    const session = begin({
      remote: true,
      notes: ["Events after 2026-08-10T12:00:00.000Z (live tail) are not included."],
    });
    deliver(session, "System", systemEvents(1));
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.notes).toEqual([
        "Periods are computed on this computer's clock",
        "Events after 2026-08-10T12:00:00.000Z (live tail) are not included.",
      ]);
      expect(outcome.result.gaps).toEqual([]);
    }
  });

  it("does not call a channel 0 when its stream lost batches, even if nothing it did deliver is counted", () => {
    // Two batches were promised and one arrived, holding an event the view's criteria hide. The
    // channel's count is unknown, not zero.
    const session = begin({
      channels: ["System"],
      visibility: visibility({ filterLevels: new Set<EvtxLevel>(["Error"]) }),
    });
    batch(session, "System", 0, systemEvents(1, { level: "Information" }));
    terminal(session, "System", 2, 3);
    session.replied("System", reply(3));
    vi.runAllTimers();

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.counts.total).toBe(0);
    expect(outcome.result.counts.channels.has("System")).toBe(false);
    expect(outcome.result.gaps.length).toBeGreaterThan(0);
  });

  it("does not call a channel 0 when an event it delivered could not be placed in time", () => {
    const session = begin({ channels: ["System", "Application"] });
    batch(session, "System", 0, [record({ channel: "System", timestampEpoch: 0 })]);
    terminal(session, "System", 1, 1);
    session.replied("System", reply(1));
    deliver(session, "Application", []);

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.counts.channels.has("System")).toBe(false);
    expect(outcome.result.counts.channels.get("Application")).toBe(0);
  });

  it("does not call a channel 0 when its reply reported a hole, though events arrived", () => {
    const session = begin({
      channels: ["System"],
      visibility: visibility({ filterLevels: new Set<EvtxLevel>(["Error"]) }),
    });
    batch(session, "System", 0, systemEvents(1, { level: "Information" }));
    terminal(session, "System", 1, 1);
    session.replied("System", reply(1, { coverageGaps: [gap({ kind: "record" })] }));

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.counts.channels.has("System")).toBe(false);
    }
  });

  it("notes whose clock cut the periods for a remote source, without calling it a gap", () => {
    const session = begin({ remote: true });
    deliver(session, "System", systemEvents(1));
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.notes).toEqual(["Periods are computed on this computer's clock"]);
      expect(outcome.result.gaps).toEqual([]);
    }
  });

  it("is partial, stating each shortfall, when the load reported gaps in the current period", () => {
    const session = begin({
      currentPeriodGaps: [
        "System: 40 events could not be rendered and are missing from this view",
        "Application: 3 events could not be read and are missing from this view",
      ],
    });
    deliver(session, "System", systemEvents(1));
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    // The previous period read cleanly; it is the period it is compared with that is short.
    expect(outcome.result.counts.total).toBe(1);
    expect(outcome.result.gaps).toEqual([
      "Current period: System: 40 events could not be rendered and are missing from this view",
      "Current period: Application: 3 events could not be read and are missing from this view",
    ]);
  });

  it("does not turn a current-period gap into an unavailable comparison when no channel could be read", () => {
    const session = begin({ currentPeriodGaps: ["System: something"] });
    session.failed("System", "Access is denied.");
    session.failed("Application", "Access is denied.");
    expect(settled()).toMatchObject({ status: "unavailable", reason: "queryFailed" });
    const outcome = settled();
    if (outcome.status === "unavailable") {
      expect(outcome.detail).toBe("System: Access is denied. Application: Access is denied.");
    }
  });

  it("counts a provider-description gap as a gap while a search reads the message text", () => {
    const providerGap = gap({
      kind: "provider",
      reason: "message text unavailable",
      source: "System",
    });
    const quiet = begin({ channels: ["System"] });
    batch(quiet, "System", 0, systemEvents(1));
    terminal(quiet, "System", 1, 1);
    quiet.replied("System", reply(1, { coverageGaps: [providerGap] }));
    expect(settled().status).toBe("complete");

    const searching = begin({
      channels: ["System"],
      visibility: visibility({ filterSearch: "timeout" }),
    });
    batch(searching, "System", 0, systemEvents(1, { message: "a timeout" }));
    terminal(searching, "System", 1, 1);
    searching.replied("System", reply(1, { coverageGaps: [providerGap] }));
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.gaps).toEqual(["System: message text unavailable"]);
    }
  });

  it("ignores the end-of-stream marker of a comparison that was superseded", () => {
    const first = begin({ channels: ["System"] });
    const second = begin({ channels: ["System"] });

    // The old marker promises five batches. It arrives after the new session's own marker, where
    // taking it would overwrite the right one and turn a clean channel into "batches were not
    // received".
    batch(second, "System", 0, systemEvents(2));
    terminal(second, "System", 1, 2);
    terminal(first, "System", 5, 99);
    second.replied("System", reply(2));

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.gaps).toEqual([]);
      expect(outcome.result.counts.total).toBe(2);
    }
  });

  describe("progress", () => {
    function progress(session: LiveComparisonSession, channel: string, fetched: number) {
      observeComparisonProgress({ requestId: session.requestId, channel, fetched });
    }
    const running = () => {
      const state = getComparisonState();
      if (state.phase !== "running") throw new Error(`expected running, got ${state.phase}`);
      return state;
    };

    it("publishes the events scanned so far, summed across channels, and no counts", () => {
      const session = begin();
      expect(running().scanned).toBe(0);

      progress(session, "System", 300);
      progress(session, "Application", 50);
      progress(session, "System", 700);
      expect(running().scanned).toBe(750);
      expect(Object.keys(running()).sort()).toEqual(
        ["mode", "phase", "prior", "requestId", "scanned"].sort()
      );
    });

    it("never moves backwards for a channel", () => {
      const session = begin();
      progress(session, "System", 700);
      progress(session, "System", 100);
      expect(running().scanned).toBe(700);
    });

    it("ignores progress for another request, an unknown channel, a settled channel and a cancelled comparison", () => {
      const session = begin();
      observeComparisonProgress({ requestId: "event-log-compare-0", channel: "System", fetched: 9 });
      progress(session, "Security", 9);
      expect(running().scanned).toBe(0);

      deliver(session, "System", systemEvents(1));
      progress(session, "System", 99);
      expect(running().scanned).toBe(0);

      cancelComparison();
      progress(session, "Application", 5);
      expect(getComparisonState()).toEqual({ phase: "idle" });
    });
  });

  describe("cancelling", () => {
    it("stops the query, clears the state and resolves done", async () => {
      const session = begin();
      deliver(session, "System", systemEvents(2));

      cancelComparison();

      expect(cancelQuery).toHaveBeenCalledTimes(1);
      expect(cancelQuery).toHaveBeenCalledWith(session.requestId);
      expect(getComparisonState()).toEqual({ phase: "idle" });
      expect(session.isActive()).toBe(false);
      await expect(session.done).resolves.toBeUndefined();
    });

    it("drops every late batch, terminal and reply, and publishes nothing afterwards", () => {
      const session = begin();
      cancelComparison();
      const published: string[] = [];
      const unsubscribe = useComparisonStore.subscribe((value) => published.push(value.state.phase));

      deliver(session, "System", systemEvents(3));
      deliver(session, "Application", systemEvents(3, { channel: "Application" }));
      session.failed("System", "late");
      vi.runAllTimers();
      unsubscribe();

      expect(published).toEqual([]);
      expect(getComparisonState()).toEqual({ phase: "idle" });
    });

    it("clears a finished result and does not stop a query that already ended", () => {
      const session = begin();
      deliver(session, "System", systemEvents(1));
      deliver(session, "Application", []);
      expect(getComparisonState().phase).toBe("settled");

      cancelComparison();

      expect(getComparisonState()).toEqual({ phase: "idle" });
      expect(cancelQuery).not.toHaveBeenCalled();
    });

    it("is a no-op, and publishes nothing, when idle", () => {
      const published: string[] = [];
      const unsubscribe = useComparisonStore.subscribe((value) => published.push(value.state.phase));
      cancelComparison();
      cancelComparison();
      unsubscribe();
      expect(published).toEqual([]);
    });

    it("is what starting another comparison does to the one in flight", () => {
      const first = begin();
      const second = begin();

      expect(cancelQuery).toHaveBeenCalledTimes(1);
      expect(cancelQuery).toHaveBeenCalledWith(first.requestId);
      expect(first.isActive()).toBe(false);
      expect(second.isActive()).toBe(true);

      // The first comparison's stragglers must not leak into the second one's counts.
      deliver(first, "System", systemEvents(9));
      deliver(second, "System", systemEvents(1));
      deliver(second, "Application", []);
      const outcome = settled();
      expect(outcome.status).toBe("complete");
      if (outcome.status === "complete") expect(outcome.result.counts.total).toBe(1);
    });
  });

  describe("when a channel cannot be read", () => {
    it("lists a rejected channel as unread rather than counting it as 0, and is partial", () => {
      const session = begin();
      deliver(session, "System", systemEvents(2));
      session.failed("Application", "Access is denied.");

      const outcome = settled();
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.unreadChannels).toEqual(["Application"]);
      expect(outcome.result.counts.channels.has("Application")).toBe(false);
      expect(outcome.result.gaps).toEqual(["Application: Access is denied."]);
    });

    it("is unavailable, never a table of zeros, when no channel could be read", () => {
      const session = begin();
      session.failed("System", "Access is denied.");
      session.failed("Application", "The channel was not found.");
      expect(settled()).toEqual({
        status: "unavailable",
        reason: "queryFailed",
        detail: "System: Access is denied. Application: The channel was not found.",
      });
    });

    it("treats a reply that reports a refusal and sent nothing as an unread channel", () => {
      const session = begin();
      terminal(session, "Application", 0, 0);
      session.replied(
        "Application",
        reply(0, {
          coverageGaps: [gap({ source: "Application", kind: "file", reason: "access denied" })],
          errorMessages: ["Application: access denied"],
        })
      );
      deliver(session, "System", systemEvents(1));

      const outcome = settled();
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.unreadChannels).toEqual(["Application"]);
      expect(outcome.result.gaps).toEqual(["Application: access denied"]);
    });

    it("keeps the events a partly read channel did deliver, and says it is partial", () => {
      const session = begin({ channels: ["System"] });
      batch(session, "System", 0, systemEvents(2));
      terminal(session, "System", 1, 2);
      session.replied(
        "System",
        reply(2, { coverageGaps: [gap({ kind: "record", reason: "record 9 unreadable" })] })
      );
      const outcome = settled();
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.counts.total).toBe(2);
      expect(outcome.result.unreadChannels).toEqual([]);
      expect(outcome.result.gaps).toEqual(["System: record 9 unreadable"]);
    });

    it("is not made partial by a provider-description gap, which does not change any count", () => {
      const session = begin({ channels: ["System"] });
      batch(session, "System", 0, systemEvents(2));
      terminal(session, "System", 1, 2);
      session.replied(
        "System",
        reply(2, {
          coverageGaps: [gap({ kind: "provider", reason: "message text unavailable" })],
          errorMessages: ["System: message text unavailable"],
        })
      );
      expect(settled().status).toBe("complete");
    });

    it("does not count events that arrive in the reply as well, and says they were left out", () => {
      const session = begin({ channels: ["System"] });
      batch(session, "System", 0, systemEvents(2));
      terminal(session, "System", 1, 2);
      session.replied("System", reply(2, { records: systemEvents(2) }));
      const outcome = settled();
      expect(outcome.status).toBe("partial");
      if (outcome.status !== "partial") return;
      expect(outcome.result.counts.total).toBe(2);
      expect(outcome.result.gaps).toEqual([
        "System: 2 events arrived in the reply instead of the stream and were not counted",
      ]);
    });

    it("treats a reply it cannot read as a failed channel", () => {
      const session = begin({ channels: ["System"] });
      session.replied("System", { channels: [] } as unknown as EvtxParseResult);
      expect(settled()).toMatchObject({ status: "unavailable", reason: "queryFailed" });
    });

    it("cannot verify completeness without a reported count, and says so", () => {
      const session = begin({ channels: ["System"] });
      batch(session, "System", 0, systemEvents(2));
      session.replied("System", reply(undefined));
      vi.runAllTimers();
      const outcome = settled();
      expect(outcome.status).toBe("partial");
      if (outcome.status === "partial") {
        expect(outcome.result.gaps).toContain(
          "System: the reader did not report how many events it sent"
        );
      }
    });
  });

  it("reports events stamped outside the previous period as a fault, not as counts", () => {
    const prior = priorFor();
    const session = begin({ channels: ["System"] });
    batch(session, "System", 0, [
      record({ channel: "System", timestampEpoch: inPrior }),
      record({ channel: "System", timestampEpoch: prior.toMs + 1 }),
    ]);
    terminal(session, "System", 1, 2);
    session.replied("System", reply(2));
    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.counts.total).toBe(1);
    expect(outcome.result.gaps).toEqual([
      "1 event the query returned lies outside the previous period and was not counted.",
    ]);
  });

  it("does not start for All time or without channels, and publishes why", () => {
    expect(
      beginLiveComparison({
        window: "all",
        anchorEpoch: ANCHOR,
        remote: false,
        notes: [],
        currentPeriodHoleChannels: [],
        currentPeriodGaps: [],
        channels,
        visibility: visibility(),
        cancelQuery,
      })
    ).toBeNull();
    expect(getComparisonState()).toMatchObject({
      phase: "settled",
      outcome: { status: "unavailable", reason: "allTime" },
    });

    expect(
      beginLiveComparison({
        window: "24h",
        anchorEpoch: ANCHOR,
        remote: false,
        notes: [],
        currentPeriodHoleChannels: [],
        currentPeriodGaps: [],
        channels: [],
        visibility: visibility(),
        cancelQuery,
      })
    ).toBeNull();
    expect(getComparisonState()).toMatchObject({
      phase: "settled",
      outcome: { status: "unavailable", reason: "noChannels" },
    });
    expect(cancelQuery).not.toHaveBeenCalled();
  });
});

describe("publishing a files comparison", () => {
  beforeEach(() => cancelComparison());
  afterEach(() => cancelComparison());

  it("publishes the outcome, and cancelling clears it", () => {
    const prior = priorFor();
    publishFilesComparison({
      records: [
        record({ timestampEpoch: prior.fromMs }),
        record({ timestampEpoch: prior.toMs }),
        record({ timestampEpoch: ANCHOR }),
      ],
      window: "24h",
      anchorEpoch: ANCHOR,
      visibility: visibility(),
      coverageDetails: [],
      sourceCoverage: [],
    });
    expect(getComparisonState()).toMatchObject({
      phase: "settled",
      outcome: { status: "complete" },
    });

    cancelComparison();
    expect(getComparisonState()).toEqual({ phase: "idle" });
  });

  it("publishes unavailable when the files do not cover the period", () => {
    publishFilesComparison({
      records: [record({ timestampEpoch: ANCHOR })],
      window: "24h",
      anchorEpoch: ANCHOR,
      visibility: visibility(),
      coverageDetails: [],
      sourceCoverage: [],
    });
    expect(getComparisonState()).toMatchObject({
      phase: "settled",
      outcome: { status: "unavailable", reason: "priorPeriodNotSpanned" },
    });
  });

  it("supersedes a live comparison in flight, stopping its query", () => {
    const cancelQuery = vi.fn();
    const session = beginLiveComparison({
      window: "24h",
      anchorEpoch: ANCHOR,
      remote: false,
      notes: [],
      currentPeriodHoleChannels: [],
      currentPeriodGaps: [],
      channels: ["System"],
      visibility: visibility(),
      cancelQuery,
    });
    expect(session).not.toBeNull();
    publishFilesComparison({
      records: [],
      window: "24h",
      anchorEpoch: ANCHOR,
      visibility: visibility(),
      coverageDetails: [],
      sourceCoverage: [],
    });
    expect(cancelQuery).toHaveBeenCalledWith(session?.requestId);
  });
});
