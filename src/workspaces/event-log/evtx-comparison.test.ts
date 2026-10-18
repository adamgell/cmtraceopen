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
  currentPeriodOf,
  eventIdentityKey,
  filesWindowAnchor,
  getComparisonState,
  isComparisonRequestId,
  isComparisonStale,
  markTailAppended,
  comparedChannelsOfComparison,
  messageTextCriterionActive,
  observeComparisonBatch,
  observeComparisonComplete,
  observeComparisonProgress,
  publishFilesComparison,
  resolveFilesPrior,
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

/** The sentence spec 8.16 gives the disabled control; a refusal starts with it, as written. */
const NOT_COVERED = "The loaded files do not cover the previous period.";
/** What a refusal says when every selected channel has a capture that fails, by why they fail. */
const NONE_UNSPANNED =
  "No selected channel can be compared: every one has a capture that does not cover the previous period.";
const NONE_UNTIMED =
  "No selected channel can be compared: every one has a capture that cannot show whether it covers the previous period.";
const NONE_MIXED =
  "No selected channel can be compared: every one has a capture that does not cover the previous period or cannot show whether it does.";

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

/**
 * An archived text-log line as the archive reader shapes it (archive.rs `text_entry_to_record`):
 * event ID 0, the component as the provider and the source label as the channel.
 */
function textLogLine(overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  return record({
    originKind: "log",
    eventId: 0,
    provider: "Contoso Setup",
    channel: "setup.log",
    sourceLabel: "setup.log",
    ...overrides,
  });
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

  describe("archived text-log lines", () => {
    it("count in the totals and levels the Charts tiles count, but are no event identity and no channel", () => {
      const prior = priorFor();
      const at = prior.fromMs + HOUR;
      const aggregator = createAggregator(
        prior,
        visibility({ selectedChannels: new Set(["System", "setup.log"]) })
      );
      aggregator.add([
        record({ timestampEpoch: at, level: "Error", eventId: 7, provider: "A", channel: "System" }),
        textLogLine({ timestampEpoch: at, level: "Error" }),
        textLogLine({ timestampEpoch: at, level: "Warning", provider: "Contoso Agent" }),
      ]);

      const { counts } = aggregator.finish();
      expect(counts.total).toBe(3);
      expect(counts.levels.Error).toBe(2);
      expect(counts.levels.Warning).toBe(1);
      // The pseudo identities (provider, 0) never reach the set a "new IDs" figure is read from.
      expect([...counts.distinctEvents]).toEqual([eventIdentityKey("A", 7)]);
      expect(Object.fromEntries(counts.channels)).toEqual({ System: 1 });
    });

    it("do not hide a real event whose ID is 0", () => {
      const prior = priorFor();
      const at = prior.fromMs + HOUR;
      const aggregator = createAggregator(prior, visibility());
      aggregator.add([
        record({ timestampEpoch: at, eventId: 0, provider: "A", originKind: "event" }),
        record({ timestampEpoch: at, eventId: 0, provider: "B" }),
      ]);
      const { counts } = aggregator.finish();
      expect([...counts.distinctEvents].sort()).toEqual(
        [eventIdentityKey("A", 0), eventIdentityKey("B", 0)].sort()
      );
      expect(counts.channels.get("System")).toBe(2);
    });

    it("still place a line without a usable timestamp, so its level count is not a quiet zero", () => {
      const prior = priorFor();
      const aggregator = createAggregator(
        prior,
        visibility({ selectedChannels: new Set(["setup.log"]) })
      );
      aggregator.add([textLogLine({ timestampEpoch: 0, level: "Error" })]);
      const tally = aggregator.finish();
      expect(tally.unplacedRecords).toBe(1);
      expect(tally.counts.levels.Error).toBe(0);
    });
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

  it("counts a text-log line in the levels but never as an event identity or a channel", () => {
    const prior = priorFor("24h");
    const records = [
      record({ timestampEpoch: ANCHOR - HOUR, level: "Error", provider: "A", eventId: 7 }),
      textLogLine({ timestampEpoch: ANCHOR - HOUR, level: "Error" }),
    ];
    const current = countCurrentPeriod(
      records,
      basisOf(prior, ["System"]),
      visibility({ selectedChannels: new Set(["System", "setup.log"]) })
    );
    expect(current.counts.levels.Error).toBe(2);
    expect([...current.counts.distinctEvents]).toEqual([eventIdentityKey("A", 7)]);
    expect(Object.fromEntries(current.counts.channels)).toEqual({ System: 1 });
  });

  describe("the tail rows it sets aside", () => {
    const tailRow = (channel: string, overrides: Partial<EvtxRecord> = {}) => {
      const row = record({ channel, timestampEpoch: ANCHOR - HOUR, ...overrides });
      markTailAppended([row]);
      return row;
    };

    it("counts the compared channels' tail rows that the view's criteria show, and no others", () => {
      const rows = [
        tailRow("System", { level: "Error" }),
        tailRow("System", { level: "Information" }),
        // Another channel is not compared, whatever the tail appended to it.
        tailRow("Application", { level: "Error" }),
        // A row the load read is not the tail's.
        record({ channel: "System", level: "Error", timestampEpoch: ANCHOR - HOUR }),
      ];
      const current = countCurrentPeriod(
        rows,
        basisOf(priorFor("24h"), ["System"]),
        visibility({
          selectedChannels: new Set(["System", "Application"]),
          filterLevels: new Set<EvtxLevel>(["Error"]),
        })
      );

      // The same criteria the counts use: the Information row is hidden, so it is not counted.
      expect(current.tailExcluded).toBe(1);
      // And the counts hold only the row the load read.
      expect(current.counts.total).toBe(1);
    });

    it("does not count a tail row the view's search hides", () => {
      const rows = [
        tailRow("System", { message: "the disk is full" }),
        tailRow("System", { message: "all well" }),
      ];
      const current = countCurrentPeriod(
        rows,
        basisOf(priorFor("24h"), ["System"]),
        visibility({ filterSearch: "disk" })
      );
      expect(current.tailExcluded).toBe(1);
    });

    it("does not count a tail row the view's quick filter hides", () => {
      const rows = [
        tailRow("System", { message: "the disk is full" }),
        tailRow("System", { message: "all well" }),
      ];
      const current = countCurrentPeriod(
        rows,
        basisOf(priorFor("24h"), ["System"]),
        visibility({ quickFilter: { ...DEFAULT_QUICK_FILTER, query: "disk" } })
      );
      expect(current.tailExcluded).toBe(1);
    });

    it("is zero when the tail appended nothing to the compared channels", () => {
      const current = countCurrentPeriod(
        [record({ channel: "System", timestampEpoch: ANCHOR - HOUR })],
        basisOf(priorFor("24h"), ["System"]),
        visibility()
      );
      expect(current.tailExcluded).toBe(0);
    });

    it("sets aside a tail row whatever its timestamp, outside the period as well as inside", () => {
      const rows = [
        tailRow("System", { timestampEpoch: ANCHOR - HOUR }),
        tailRow("System", { timestampEpoch: ANCHOR + HOUR }),
        tailRow("System", { timestampEpoch: 0 }),
      ];
      const current = countCurrentPeriod(rows, basisOf(priorFor("24h"), ["System"]), visibility());
      expect(current.tailExcluded).toBe(3);
      expect(current.counts.total).toBe(0);
      expect(current.unplacedRecords).toBe(0);
    });
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
  /** A read that replied as soon as it was issued. */
  const instant = (issuedEpoch: number) => ({ issuedEpoch, repliedEpoch: issuedEpoch });

  it("is silent for a channel read at the anchor, and up to one percent of the window after it", () => {
    expect(channelStartGap("System", instant(ANCHOR), ANCHOR, LENGTH)).toBeNull();
    expect(channelStartGap("System", instant(ANCHOR + ONE_PERCENT), ANCHOR, LENGTH)).toBeNull();
  });

  it("states the missing start as soon as it certainly exceeds one percent of the window", () => {
    expect(channelStartGap("System", instant(ANCHOR + ONE_PERCENT + 1), ANCHOR, LENGTH)).toEqual({
      definite: true,
      text: `System was read at ${iso(ANCHOR + ONE_PERCENT + 1)}, 14 min after the comparison anchor ${iso(ANCHOR)}, so the first 14 min of its current period is not covered.`,
    });
  });

  it("reports at most the whole window as missing", () => {
    const gap = channelStartGap("System", instant(ANCHOR + 10 * HOUR), ANCHOR, HOUR);
    expect(gap?.text).toContain("10 h after the comparison anchor");
    expect(gap?.text).toContain("so the first 1 h of its current period is not covered");
  });

  it("scales the tolerance with the window", () => {
    // One percent of an hour is 36 seconds; of 30 days, 7.2 hours.
    expect(channelStartGap("System", instant(ANCHOR + 40_000), ANCHOR, HOUR)).not.toBeNull();
    expect(channelStartGap("System", instant(ANCHOR + 30_000), ANCHOR, HOUR)).toBeNull();
    const month = EVTX_TIME_WINDOW_MS["30d"];
    expect(channelStartGap("System", instant(ANCHOR + 7 * HOUR), ANCHOR, month)).toBeNull();
    expect(channelStartGap("System", instant(ANCHOR + 8 * HOUR), ANCHOR, month)).not.toBeNull();
  });

  describe("when the instant the service evaluated the window is only bounded", () => {
    it("states a possible gap for the anchoring channel when its read was long", () => {
      // Issued at the anchor and replied 20 minutes later: the window may have been evaluated at
      // any point in between, so up to 20 minutes of its start may be missing.
      const gap = channelStartGap(
        "Security",
        { issuedEpoch: ANCHOR, repliedEpoch: ANCHOR + 20 * 60 * 1000 },
        ANCHOR,
        LENGTH
      );
      expect(gap).toEqual({
        definite: false,
        text: "Security may be missing up to 20 min at the start of its current period: the service evaluated its window at some point during a read that took 20 min.",
      });
    });

    it("leaves a short read on the anchoring channel unremarked", () => {
      const read = { issuedEpoch: ANCHOR, repliedEpoch: ANCHOR + ONE_PERCENT };
      expect(channelStartGap("Security", read, ANCHOR, LENGTH)).toBeNull();
      // A millisecond more and the most it could lack exceeds the tolerance.
      expect(
        channelStartGap("Security", { ...read, repliedEpoch: read.repliedEpoch + 1 }, ANCHOR, LENGTH)?.definite
      ).toBe(false);
    });

    it("bounds a later channel from both sides: certain when the least exceeds, possible when only the most does", () => {
      // Issued 10 minutes after the anchor (within the tolerance), replied 30 minutes after: the
      // missing start is between 10 and 30 minutes.
      const possible = channelStartGap(
        "Application",
        { issuedEpoch: ANCHOR + 10 * 60 * 1000, repliedEpoch: ANCHOR + 30 * 60 * 1000 },
        ANCHOR,
        LENGTH
      );
      expect(possible?.definite).toBe(false);
      expect(possible?.text).toContain("may be missing up to 30 min");
      expect(possible?.text).toContain("a read that took 20 min");

      // Issued 20 minutes after the anchor: at least that much is missing, whatever the reply.
      const certain = channelStartGap(
        "Application",
        { issuedEpoch: ANCHOR + 20 * 60 * 1000, repliedEpoch: ANCHOR + 50 * 60 * 1000 },
        ANCHOR,
        LENGTH
      );
      expect(certain?.definite).toBe(true);
      expect(certain?.text).toContain("20 min after the comparison anchor");
      expect(certain?.text).toContain("the first 20 min of its current period is not covered");
    });

    it("never lets a reply before the issue time shrink the band", () => {
      const gap = channelStartGap(
        "System",
        { issuedEpoch: ANCHOR + 20 * 60 * 1000, repliedEpoch: ANCHOR },
        ANCHOR,
        LENGTH
      );
      expect(gap?.definite).toBe(true);
    });

    it("caps a possible gap at the whole window", () => {
      const gap = channelStartGap(
        "System",
        { issuedEpoch: ANCHOR, repliedEpoch: ANCHOR + 10 * HOUR },
        ANCHOR,
        HOUR
      );
      expect(gap?.text).toContain("may be missing up to 1 h");
    });
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
        holdsEvents: true,
      },
    ]);
  });

  it("marks a text log as a capture that holds no events, and an event capture as one that does", () => {
    const prior = priorFor();
    const coverage = checkFilesCoverage(
      [
        ...spanning(prior),
        textLogLine({ timestampEpoch: prior.fromMs }),
        textLogLine({ timestampEpoch: prior.toMs }),
      ],
      new Set(["System", "setup.log"]),
      prior
    );
    expect(coverage.covered && coverage.captures.map((c) => [c.channel, c.holdsEvents])).toEqual([
      ["System", true],
      ["setup.log", false],
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

describe("what a refusal or a gap says of a capture", () => {
  const selected = new Set(["System", "Application", "setup.log"]);
  const prior = priorFor();
  /** A capture that spans the previous period and reaches the anchor. */
  const spans = (channel: string, sourceLabel: string, log = false): EvtxRecord[] =>
    [prior.fromMs, prior.toMs, ANCHOR].map((timestampEpoch) =>
      log
        ? textLogLine({ timestampEpoch })
        : record({ channel, sourceLabel, timestampEpoch })
    );
  const detailOf = (records: EvtxRecord[], chosen = selected) => {
    const coverage = checkFilesCoverage(records, chosen, prior);
    if (coverage.covered) throw new Error("expected a refusal");
    return coverage.detail;
  };

  describe("when nothing is loaded for the selected channels", () => {
    it("says entries, which a text log's lines are as well as events", () => {
      expect(detailOf([])).toBe("No entries are loaded for the selected channels.");
      expect(detailOf([record({ channel: "Security" })])).toBe(
        "No entries are loaded for the selected channels."
      );
    });
  });

  describe("when a capture has no entry with a usable timestamp", () => {
    const untimed = (channel: string, sourceLabel: string) =>
      record({ channel, sourceLabel, timestampEpoch: 0 });

    it("names an event capture, says it cannot show coverage, and offers to deselect its channel", () => {
      expect(detailOf([...spans("Application", "Application.evtx"), untimed("System", "System.evtx")])).toBe(
        "System.evtx (System) has no event with a usable timestamp, so it cannot show whether it covers the previous period. Deselect System to compare the other channels."
      );
    });

    it("names a text log by what it holds, and by its name once", () => {
      expect(
        detailOf([
          ...spans("System", "System.evtx"),
          textLogLine({ timestampEpoch: 0 }),
        ])
      ).toBe(
        "setup.log has no log line with a usable timestamp, so it cannot show whether it covers the previous period. Deselect setup.log to compare the other channels."
      );
    });

    it("lists every such capture together when there are several", () => {
      expect(
        detailOf([
          ...spans("Application", "Application.evtx"),
          untimed("System", "System.evtx"),
          textLogLine({ timestampEpoch: 0 }),
        ])
      ).toBe(
        "These loaded captures have no entry with a usable timestamp, so they cannot show whether they cover the previous period: System.evtx (System), setup.log. Deselect System, setup.log to compare the other channels."
      );
    });

    it("does not promise a comparison when no other channel would remain", () => {
      expect(detailOf([untimed("System", "System.evtx")])).toBe(
        `System.evtx (System) has no event with a usable timestamp, so it cannot show whether it covers the previous period. ${NONE_UNTIMED}`
      );
    });

    it("counts a channel as remaining only if a capture of another channel is loaded", () => {
      // System has two sources and one is untimed: deselecting System removes both, and Application
      // remains.
      expect(
        detailOf([
          ...spans("System", "a.evtx"),
          untimed("System", "b.evtx"),
          ...spans("Application", "Application.evtx"),
        ])
      ).toBe(
        "b.evtx (System) has no event with a usable timestamp, so it cannot show whether it covers the previous period. Deselect System to compare the other channels."
      );
    });
  });

  describe("when the captures do not span the previous period", () => {
    it("does not count a channel's other source as another channel that would remain", () => {
      // Deselecting System removes both of its sources, so nothing would remain to compare.
      const twoSources = [
        ...spans("System", "a.evtx"),
        record({ channel: "System", sourceLabel: "b.evtx", timestampEpoch: prior.toMs + HOUR }),
        record({ channel: "System", sourceLabel: "b.evtx", timestampEpoch: ANCHOR }),
      ];
      expect(detailOf(twoSources)).toBe(
        `${NOT_COVERED} b.evtx (System) does not span it. ${NONE_UNSPANNED}`
      );
    });

    it("names every failing capture under its own reason, the spec's sentence first, when they differ", () => {
      // The first failure is a capture with no timed entry and Application merely starts late. Both
      // are refused, so neither is a channel that would remain to compare.
      expect(
        detailOf([
          record({ channel: "System", sourceLabel: "System.evtx", timestampEpoch: 0 }),
          record({ channel: "Application", sourceLabel: "Application.evtx", timestampEpoch: prior.toMs + HOUR }),
          record({ channel: "Application", sourceLabel: "Application.evtx", timestampEpoch: ANCHOR }),
        ])
      ).toBe(
        `${NOT_COVERED} Application.evtx (Application) does not span it. System.evtx (System) has no event with a usable timestamp, so it cannot show whether it covers the previous period. ${NONE_MIXED}`
      );
    });

    const short = (channel: string, sourceLabel: string) => [
      record({ channel, sourceLabel, timestampEpoch: prior.toMs + HOUR }),
      record({ channel, sourceLabel, timestampEpoch: ANCHOR }),
    ];

    it("keeps the spec's sentence first, as written, then names the capture", () => {
      const detail = detailOf([...spans("Application", "Application.evtx"), ...short("System", "System.evtx")]);
      expect(detail.startsWith(NOT_COVERED)).toBe(true);
      expect(detail).toBe(
        `${NOT_COVERED} System.evtx (System) does not span it. Deselect System to compare the other channels.`
      );
    });

    it("names a text log by its name once", () => {
      expect(
        detailOf([
          ...spans("System", "System.evtx"),
          textLogLine({ timestampEpoch: prior.fromMs + 6 * HOUR }),
          textLogLine({ timestampEpoch: ANCHOR }),
        ])
      ).toBe(`${NOT_COVERED} setup.log does not span it. Deselect setup.log to compare the other channels.`);
    });

    it("lists every capture that does not span it, and no capture that does", () => {
      expect(
        detailOf([
          ...spans("Application", "Application.evtx"),
          ...short("System", "a.evtx"),
          ...short("System", "b.evtx"),
        ])
      ).toBe(
        `${NOT_COVERED} These do not span it: a.evtx (System), b.evtx (System). Deselect System to compare the other channels.`
      );
    });

    it("says no channel would remain when every selected capture fails", () => {
      expect(detailOf([...short("System", "System.evtx"), ...short("Application", "Application.evtx")])).toBe(
        `${NOT_COVERED} These do not span it: System.evtx (System), Application.evtx (Application). ${NONE_UNSPANNED}`
      );
    });

    it("caps a long list and counts the rest", () => {
      const many = ["A", "B", "C", "D", "E", "F", "G"];
      const detail = detailOf(
        [...many.flatMap((c) => short(c, `${c}.evtx`)), ...spans("Application", "Application.evtx")],
        new Set([...many, "Application"])
      );
      expect(detail).toBe(
        `${NOT_COVERED} These do not span it: A.evtx (A), B.evtx (B), C.evtx (C), D.evtx (D), E.evtx (E), and 2 more. ` +
          "Deselect A, B, C, D, E, and 2 more to compare the other channels."
      );
    });
  });

  describe("the channels a refusal tells the operator to deselect", () => {
    const short = (channel: string) => [
      record({ channel, sourceLabel: `${channel}.evtx`, timestampEpoch: prior.toMs + HOUR }),
      record({ channel, sourceLabel: `${channel}.evtx`, timestampEpoch: ANCHOR }),
    ];
    const failing = (names: string[]) => {
      const records = [...names.flatMap(short), ...spans("Application", "Application.evtx")];
      return detailOf(records, new Set([...names, "Application"]));
    };

    it("lists them all up to the cap, with nothing counted beyond it", () => {
      const detail = failing(["A", "B", "C", "D", "E"]);
      expect(detail.endsWith("Deselect A, B, C, D, E to compare the other channels.")).toBe(true);
      expect(detail).not.toContain("more");
    });

    it("counts the channels beyond the cap, one past it", () => {
      const detail = failing(["A", "B", "C", "D", "E", "F"]);
      expect(detail.endsWith("Deselect A, B, C, D, E, and 1 more to compare the other channels.")).toBe(true);
    });

    it("names each channel once however many of its captures fail", () => {
      const detail = detailOf(
        [...short("System"), ...short("System").map((r) => ({ ...r, sourceLabel: "b.evtx" })), ...spans("Application", "Application.evtx")],
        new Set(["System", "Application"])
      );
      expect(detail.endsWith("Deselect System to compare the other channels.")).toBe(true);
    });
  });

  describe("when captures fail for different reasons", () => {
    const late = (channel: string, sourceLabel: string) => [
      record({ channel, sourceLabel, timestampEpoch: prior.toMs + HOUR }),
      record({ channel, sourceLabel, timestampEpoch: ANCHOR }),
    ];
    const noTime = [textLogLine({ timestampEpoch: 0 })];
    const good = spans("Application", "Application.evtx");
    const system = late("System", "System.evtx");
    const all = new Set(["System", "Application", "setup.log"]);

    it("says the same whichever capture is read first, naming each reason's captures under it", () => {
      const groups = [system, noTime, good];
      const orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
      ];
      const expected =
        `${NOT_COVERED} System.evtx (System) does not span it. ` +
        "setup.log has no log line with a usable timestamp, so it cannot show whether it covers the previous period. " +
        "Deselect System, setup.log to compare the other channels.";
      for (const order of orders) {
        expect(detailOf(order.flatMap((index) => groups[index]), all)).toBe(expected);
      }
    });

    it("gives the reason code of the capture read first, whatever else fails", () => {
      const reasonOf = (records: EvtxRecord[]) => {
        const coverage = checkFilesCoverage(records, all, prior);
        return coverage.covered ? "covered" : coverage.reason;
      };
      expect(reasonOf([...noTime, ...system, ...good])).toBe("noTimedRecords");
      expect(reasonOf([...system, ...noTime, ...good])).toBe("priorPeriodNotSpanned");
    });

    it("puts the spec's sentence first whenever any capture fails to span the period", () => {
      const detail = detailOf([...noTime, ...system, ...good], all);
      expect(detail.startsWith(NOT_COVERED)).toBe(true);
    });

    it("does not promise a comparison when every selected channel has a capture that fails", () => {
      const detail = detailOf([...noTime, ...system], new Set(["System", "setup.log"]));
      expect(detail).toBe(
        `${NOT_COVERED} System.evtx (System) does not span it. ` +
          "setup.log has no log line with a usable timestamp, so it cannot show whether it covers the previous period. " +
          NONE_MIXED
      );
      expect(detail).not.toContain("Deselect");
    });

    // The advice is a promise, so it is kept: whenever a refusal says to deselect, deselecting
    // exactly the channels it names leaves a selection that is covered.
    const advice: Array<[string, EvtxRecord[], string[] | null]> = [
      ["a late capture and a channel that passes", [...system, ...good], ["System"]],
      ["an untimed capture and a channel that passes", [...noTime, ...good], ["setup.log"]],
      ["both reasons and a channel that passes", [...noTime, ...system, ...good], ["System", "setup.log"]],
      ["both reasons, read in the other order", [...system, ...good, ...noTime], ["System", "setup.log"]],
      ["both reasons and nothing that passes", [...noTime, ...system], null],
      ["a late capture and nothing that passes", [...system], null],
    ];
    it.each(advice)("%s: the advice is true", (_name, records, leaving) => {
      const detail = detailOf(records, all);
      if (leaving === null) {
        expect(detail).not.toContain("Deselect");
        expect(detail).toContain("No selected channel can be compared");
        return;
      }
      expect(detail).toContain(`Deselect ${leaving.join(", ")} to compare the other channels.`);
      const kept = new Set([...all].filter((channel) => !leaving.includes(channel)));
      expect(checkFilesCoverage(records, kept, prior).covered).toBe(true);
    });
  });

  describe("when a capture ends before the anchor", () => {
    it("names an event capture's events, as before", () => {
      const outcome = compareLoadedFiles({
        records: [
          record({ timestampEpoch: prior.fromMs }),
          record({ timestampEpoch: prior.toMs }),
          record({ timestampEpoch: ANCHOR - 20 * HOUR }),
        ],
        window: "24h",
        anchorEpoch: ANCHOR,
        visibility: visibility(),
        coverageDetails: [],
        sourceCoverage: [],
      });
      expect(outcome.status === "partial" && outcome.result.gaps).toEqual([
        `System.evtx (System) has no events after ${new Date(ANCHOR - 20 * HOUR).toISOString()}, so the last 20 h of the current period is not covered.`,
      ]);
    });

    it("names a text log's lines, and the log once", () => {
      const outcome = compareLoadedFiles({
        records: [
          record({ timestampEpoch: prior.fromMs }),
          record({ timestampEpoch: prior.toMs }),
          record({ timestampEpoch: ANCHOR }),
          textLogLine({ timestampEpoch: prior.fromMs }),
          textLogLine({ timestampEpoch: prior.toMs }),
          textLogLine({ timestampEpoch: ANCHOR - 20 * HOUR }),
        ],
        window: "24h",
        anchorEpoch: ANCHOR,
        visibility: visibility({ selectedChannels: new Set(["System", "setup.log"]) }),
        coverageDetails: [],
        sourceCoverage: [],
      });
      expect(outcome.status === "partial" && outcome.result.gaps).toEqual([
        `setup.log has no log lines after ${new Date(ANCHOR - 20 * HOUR).toISOString()}, so the last 20 h of the current period is not covered.`,
      ]);
    });
  });

  describe("the count of entries that could not be placed in time", () => {
    const covering = [
      record({ timestampEpoch: prior.fromMs }),
      record({ timestampEpoch: prior.toMs }),
      record({ timestampEpoch: ANCHOR }),
    ];
    const gapsOf = (extra: EvtxRecord[]) => {
      const outcome = compareLoadedFiles({
        records: [...covering, ...extra],
        window: "24h",
        anchorEpoch: ANCHOR,
        visibility: visibility({ selectedChannels: new Set(["System", "setup.log"]) }),
        coverageDetails: [],
        sourceCoverage: [],
      });
      return outcome.status === "partial" ? outcome.result.gaps : [`not partial: ${outcome.status}`];
    };

    it("says entry, in the singular, for one event", () => {
      expect(gapsOf([record({ timestampEpoch: 0 })])).toEqual([
        "1 loaded entry has no usable timestamp and could not be placed in either period.",
      ]);
    });

    it("counts events and text-log lines together as entries", () => {
      // Both kinds feed the totals and the levels, so both are uncertainty in what is compared.
      expect(
        gapsOf([
          // The text log spans the period, so the comparison runs; two of its lines carry no time.
          textLogLine({ timestampEpoch: prior.fromMs }),
          textLogLine({ timestampEpoch: prior.toMs }),
          textLogLine({ timestampEpoch: ANCHOR }),
          record({ timestampEpoch: 0 }),
          textLogLine({ timestampEpoch: 0 }),
          textLogLine({ timestampEpoch: Number.NaN }),
        ])
      ).toEqual(["3 loaded entries have no usable timestamp and could not be placed in either period."]);
    });
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
      detail: `${NOT_COVERED} System.evtx (System) does not span it. ${NONE_UNSPANNED}`,
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
      "1 loaded entry has no usable timestamp and could not be placed in either period.",
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

  describe("archived text-log lines", () => {
    /** One event capture and one text log, both bracketing the previous period and reaching the anchor. */
    function eventsAndATextLog(prior: PriorWindow, logOverrides: Partial<EvtxRecord> = {}) {
      return [
        record({ timestampEpoch: prior.fromMs, provider: "A", eventId: 1, level: "Error" }),
        record({ timestampEpoch: ANCHOR, provider: "A", eventId: 1 }),
        textLogLine({ timestampEpoch: prior.fromMs, level: "Error", ...logOverrides }),
        textLogLine({ timestampEpoch: prior.fromMs + HOUR, level: "Error", ...logOverrides }),
        textLogLine({ timestampEpoch: ANCHOR, ...logOverrides }),
      ];
    }
    const both = visibility({ selectedChannels: new Set(["System", "setup.log"]) });

    it("count in the levels, like the tiles, but add no event identity to the previous period", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(input(eventsAndATextLog(prior), { visibility: both }));
      expect(outcome.status).toBe("complete");
      if (outcome.status !== "complete") return;
      expect(outcome.result.counts.levels.Error).toBe(3);
      expect([...outcome.result.counts.distinctEvents]).toEqual([eventIdentityKey("A", 1)]);
    });

    it("are not a compared channel, and are never called a channel of 0 events", () => {
      const prior = priorFor();
      const outcome = compareLoadedFiles(input(eventsAndATextLog(prior), { visibility: both }));
      expect(outcome.status).toBe("complete");
      if (outcome.status !== "complete") return;
      expect(outcome.result.comparedChannels).toEqual(["System"]);
      expect(outcome.result.counts.channels.has("setup.log")).toBe(false);
      expect(outcome.result.channelsWithGaps).toEqual([]);
    });

    it("must still span the previous period, because their lines are counted in the levels", () => {
      const prior = priorFor();
      const records = [
        record({ timestampEpoch: prior.fromMs, provider: "A", eventId: 1 }),
        record({ timestampEpoch: ANCHOR, provider: "A", eventId: 1 }),
        // The log only starts inside the previous period, so its errors there would be undercounted.
        textLogLine({ timestampEpoch: prior.fromMs + 6 * HOUR, level: "Error" }),
        textLogLine({ timestampEpoch: ANCHOR }),
      ];
      expect(compareLoadedFiles(input(records, { visibility: both }))).toEqual({
        status: "unavailable",
        reason: "priorPeriodNotSpanned",
        detail: `${NOT_COVERED} setup.log does not span it. Deselect setup.log to compare the other channels.`,
      });
    });

    it("leave an event channel's zero alone when only the text log holds the period's lines", () => {
      const prior = priorFor();
      const records = [
        record({ timestampEpoch: prior.fromMs - HOUR, provider: "A", eventId: 1 }),
        record({ timestampEpoch: ANCHOR, provider: "A", eventId: 1 }),
        textLogLine({ timestampEpoch: prior.fromMs, level: "Error" }),
        textLogLine({ timestampEpoch: ANCHOR }),
      ];
      const outcome = compareLoadedFiles(input(records, { visibility: both }));
      expect(outcome.status).toBe("complete");
      if (outcome.status !== "complete") return;
      // System was read in full and holds nothing in the period: a real zero. The text log's line
      // is not System's.
      expect(outcome.result.counts.channels.get("System")).toBe(0);
      expect(outcome.result.counts.levels.Error).toBe(1);
    });
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
      currentPeriodGaps: [["Application: 3 events could not be read and are missing from this view"]],
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
      notes: ["2 events the live tail appended to the compared channels are not counted in the current period."],
    });
    deliver(session, "System", systemEvents(1));
    deliver(session, "Application", []);
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.notes).toEqual([
        "Periods are computed on this computer's clock",
        "2 events the live tail appended to the compared channels are not counted in the current period.",
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
    // The untimed event may belong to the period on either side, so the current side withholds
    // its zero for the channel too.
    expect(outcome.result.channelsWithGaps).toEqual(["System"]);
  });

  it("says events, not entries, for the unplaced count of a live comparison, which reads no text log", () => {
    const session = begin({ channels: ["System"] });
    batch(session, "System", 0, systemEvents(2, { timestampEpoch: 0 }));
    terminal(session, "System", 1, 2);
    session.replied("System", reply(2));

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.gaps).toEqual([
      "2 events have no usable timestamp and could not be placed in the previous period.",
    ]);
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
        ["System: 40 events could not be rendered and are missing from this view"],
        ["Application: 3 events could not be read and are missing from this view"],
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

  it("limits each cause of a gap on its own, so one flood cannot starve another", () => {
    const flood = Array.from({ length: 12 }, (_, index) => `Channel${index} was read late`);
    const session = begin({
      currentPeriodGaps: [flood, ["System: 3 events could not be read and are missing from this view"]],
    });
    deliver(session, "System", systemEvents(1));
    deliver(session, "Application", []);

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.gaps).toEqual([
      ...flood.slice(0, 5).map((line) => `Current period: ${line}`),
      "and 7 more not shown.",
      "Current period: System: 3 events could not be read and are missing from this view",
    ]);
  });

  it("limits the lines of the channels' own streams, and the failure detail built from them", () => {
    const names = ["Healthy", ...Array.from({ length: 11 }, (_, index) => `Broken${index}`)];
    const session = begin({ channels: names });
    deliver(session, "Healthy", systemEvents(1, { channel: "Healthy" }));
    for (const name of names.slice(1)) session.failed(name, "Access is denied.");

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.gaps).toHaveLength(6);
    expect(outcome.result.gaps[5]).toBe("and 6 more not shown.");
    // Every channel is still listed as unread; only the lines stating why are limited.
    expect(outcome.result.unreadChannels).toHaveLength(11);

    const allBroken = begin({ channels: names.slice(1) });
    for (const name of names.slice(1)) allBroken.failed(name, "Access is denied.");
    const failed = settled();
    expect(failed.status).toBe("unavailable");
    if (failed.status === "unavailable") {
      expect(failed.detail.endsWith("and 6 more not shown.")).toBe(true);
    }
  });

  it("does not turn a current-period gap into an unavailable comparison when no channel could be read", () => {
    const session = begin({ currentPeriodGaps: [["System: something"]] });
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

  it("says which channels a comparison depends on, whatever stage it is at", () => {
    expect(comparedChannelsOfComparison()).toEqual([]);

    const session = begin({ channels: ["System", "Application"] });
    expect(comparedChannelsOfComparison()).toEqual(["System", "Application"]);

    deliver(session, "System", systemEvents(1));
    deliver(session, "Application", []);
    expect(settled().status).toBe("complete");
    expect(comparedChannelsOfComparison()).toEqual(["System", "Application"]);

    cancelComparison();
    expect(comparedChannelsOfComparison()).toEqual([]);

    // A comparison that could not be made depends on no channel.
    beginLiveComparison({
      window: "all",
      anchorEpoch: ANCHOR,
      remote: false,
      notes: [],
      currentPeriodHoleChannels: [],
      currentPeriodGaps: [],
      channels: ["System"],
      visibility: visibility(),
      cancelQuery,
    });
    expect(settled().status).toBe("unavailable");
    expect(comparedChannelsOfComparison()).toEqual([]);
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
        ["channels", "mode", "phase", "prior", "requestId", "scanned"].sort()
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

describe("resolveFilesPrior", () => {
  const selected = new Set(["System", "Application"]);
  const prior = priorFor();
  const spans = [
    record({ timestampEpoch: prior.fromMs, channel: "System" }),
    record({ timestampEpoch: prior.toMs, channel: "System" }),
    record({ timestampEpoch: ANCHOR, channel: "System" }),
  ];

  it("returns the previous period and the captures when the loaded files cover it", () => {
    const resolved = resolveFilesPrior(spans, selected, "24h", ANCHOR);
    expect(resolved).toMatchObject({ status: "available", prior });
    expect(resolved.status === "available" && resolved.captures.map((c) => c.channel)).toEqual([
      "System",
    ]);
  });

  it("says why it is unavailable in the words the comparison itself uses", () => {
    expect(resolveFilesPrior(spans, selected, "all", ANCHOR)).toEqual({
      status: "unavailable",
      reason: "allTime",
      detail: "All time has no previous period.",
    });
    // The spec's sentence comes first, as written, then the capture it is about and the one action.
    expect(resolveFilesPrior([record({ timestampEpoch: ANCHOR })], selected, "24h", ANCHOR)).toEqual({
      status: "unavailable",
      reason: "priorPeriodNotSpanned",
      detail: `${NOT_COVERED} System.evtx (System) does not span it. ${NONE_UNSPANNED}`,
    });
    expect(resolveFilesPrior([], selected, "24h", ANCHOR)).toEqual({
      status: "unavailable",
      reason: "noTimedRecords",
      detail: "No entries are loaded for the selected channels.",
    });
  });

  // A control that is disabled for a reason the comparison would not give, or enabled when the
  // comparison would refuse, is a false statement. The two answer from one definition, and this
  // pins it over every kind of input the comparison distinguishes.
  it.each([
    ["covered", spans, "24h" as const, ANCHOR],
    ["covered but with an unplaced event", [...spans, record({ timestampEpoch: 0 })], "24h" as const, ANCHOR],
    ["all time", spans, "all" as const, ANCHOR],
    ["not spanned", [record({ timestampEpoch: ANCHOR })], "24h" as const, ANCHOR],
    ["nothing loaded", [], "24h" as const, ANCHOR],
    ["only unplaced events", [record({ timestampEpoch: 0 })], "24h" as const, ANCHOR],
    ["an unusable anchor", spans, "24h" as const, Number.NaN],
    ["another channel only", [record({ timestampEpoch: prior.fromMs, channel: "Setup" })], "24h" as const, ANCHOR],
  ])("agrees with compareLoadedFiles on %s", (_name, records, window, anchorEpoch) => {
    const resolved = resolveFilesPrior(records, selected, window, anchorEpoch);
    const outcome = compareLoadedFiles({
      records,
      window,
      anchorEpoch,
      visibility: visibility({ selectedChannels: selected }),
      coverageDetails: [],
      sourceCoverage: [],
    });
    if (outcome.status === "unavailable") {
      expect(resolved).toEqual({
        status: "unavailable",
        reason: outcome.reason,
        detail: outcome.detail,
      });
    } else {
      expect(resolved.status).toBe("available");
    }
  });
});

describe("currentPeriodOf", () => {
  it.each(["1h", "24h", "7d", "30d"] as const)(
    "is the %s ending at the anchor, meeting the previous period without overlap or gap",
    (window) => {
      const p = priorFor(window);
      const current = currentPeriodOf(p);
      expect(current).toEqual({ fromMs: ANCHOR - EVTX_TIME_WINDOW_MS[window], toMs: ANCHOR });
      expect(current.toMs - current.fromMs).toBe(p.lengthMs);
      // The previous period ends one millisecond before this one starts, so an instant is in one.
      expect(p.toMs + 1).toBe(current.fromMs);
    },
  );

  it("is what the current side is counted over", () => {
    const p = priorFor("24h");
    const { fromMs, toMs } = currentPeriodOf(p);
    const records = [fromMs - 1, fromMs, toMs, toMs + 1].map((timestampEpoch) =>
      record({ timestampEpoch }),
    );
    expect(countCurrentPeriod(records, basisOf(p), visibility()).counts.total).toBe(2);
  });
});

describe("isComparisonStale", () => {
  const windows = ["1h", "24h", "7d", "30d"] as const;

  it.each(windows)("is not stale at the anchor or up to 1% of a %s window either side of it", (window) => {
    const length = EVTX_TIME_WINDOW_MS[window];
    const p = priorFor(window);
    expect(isComparisonStale(p, ANCHOR)).toBe(false);
    expect(isComparisonStale(p, ANCHOR + length / 100)).toBe(false);
    expect(isComparisonStale(p, ANCHOR - length / 100)).toBe(false);
  });

  it.each(windows)("is stale one millisecond beyond 1% of a %s window, later or earlier", (window) => {
    const length = EVTX_TIME_WINDOW_MS[window];
    const p = priorFor(window);
    expect(isComparisonStale(p, ANCHOR + length / 100 + 1)).toBe(true);
    expect(isComparisonStale(p, ANCHOR - length / 100 - 1)).toBe(true);
  });

  it("cannot be shown to be current when the instant it is compared with is not a usable date", () => {
    const p = priorFor("24h");
    for (const unusable of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(isComparisonStale(p, unusable)).toBe(true);
    }
  });

  // The tolerance is the comparison's own start-band tolerance, not a second constant: the same
  // offset that channelStartGap calls silent is the offset this calls current.
  it.each(windows)("draws the line where channelStartGap does for a %s window", (window) => {
    const length = EVTX_TIME_WINDOW_MS[window];
    const p = priorFor(window);
    for (const offset of [length / 100 - 1, length / 100, length / 100 + 1]) {
      const silent =
        channelStartGap(
          "System",
          { issuedEpoch: ANCHOR + offset, repliedEpoch: ANCHOR + offset },
          ANCHOR,
          length
        ) === null;
      expect(isComparisonStale(p, ANCHOR + offset)).toBe(!silent);
    }
  });
});

describe("filesWindowAnchor", () => {
  const CLOCK = ANCHOR + 400 * DAY;

  it("is the latest usable timestamp across all the loaded records", () => {
    const records = [
      record({ timestampEpoch: ANCHOR - 3 * HOUR, channel: "System" }),
      record({ timestampEpoch: ANCHOR, channel: "Application" }),
      record({ timestampEpoch: ANCHOR - HOUR, channel: "System" }),
    ];
    expect(filesWindowAnchor(records, CLOCK)).toBe(ANCHOR);
  });

  it("does not depend on which channels are selected, so toggling a channel never moves the window", () => {
    // The function takes the records alone: there is no selection for it to read.
    expect(filesWindowAnchor.length).toBe(2);
  });

  it("reads a record that has no usable timestamp as no evidence of when the capture ended", () => {
    const records = [
      record({ timestampEpoch: ANCHOR - HOUR }),
      record({ timestampEpoch: 0 }),
      record({ timestampEpoch: Number.NaN }),
      record({ timestampEpoch: Number.POSITIVE_INFINITY }),
      record({ timestampEpoch: -5 }),
    ];
    expect(filesWindowAnchor(records, CLOCK)).toBe(ANCHOR - HOUR);
  });

  it("falls back to the clock when nothing is loaded or nothing can be placed", () => {
    expect(filesWindowAnchor([], CLOCK)).toBe(CLOCK);
    expect(filesWindowAnchor([record({ timestampEpoch: 0 })], CLOCK)).toBe(CLOCK);
  });

  it("counts an archived text-log line, which is among the loaded records", () => {
    const records = [
      record({ timestampEpoch: ANCHOR - 2 * HOUR }),
      textLogLine({ timestampEpoch: ANCHOR - HOUR }),
    ];
    expect(filesWindowAnchor(records, CLOCK)).toBe(ANCHOR - HOUR);
  });

  it("does not look at the clock when the records give an answer", () => {
    expect(filesWindowAnchor([record({ timestampEpoch: ANCHOR })], 1)).toBe(ANCHOR);
  });
});
