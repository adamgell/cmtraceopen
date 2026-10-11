import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginLiveComparison,
  cancelComparison,
  checkFilesCoverage,
  compareLoadedFiles,
  computePriorWindow,
  createAggregator,
  eventIdentityKey,
  getComparisonState,
  isComparisonRequestId,
  observeComparisonBatch,
  observeComparisonComplete,
  publishFilesComparison,
  useComparisonStore,
  type ComparisonVisibility,
  type LiveComparisonSession,
  type PriorWindow,
} from "./evtx-comparison";
import { DEFAULT_QUICK_FILTER, isWithinTimeWindow } from "./evtx-filter";
import {
  EVTX_TIME_WINDOW_MS,
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
      ],
      window: "24h",
      anchorEpoch: ANCHOR,
      visibility: visibility(),
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
    });
    expect(cancelQuery).toHaveBeenCalledWith(session?.requestId);
  });
});
