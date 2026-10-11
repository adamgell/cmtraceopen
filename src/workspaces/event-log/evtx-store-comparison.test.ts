/**
 * Routing a previous-period comparison through the Event Logs store.
 *
 * The comparison streams events over the same Tauri events as an ordinary load, so the store must
 * tell them apart by request ID. These tests pin the contract the spec demands: no comparison event
 * reaches `records`, and through it the grid, the diagnosis and the analysis session, which are all
 * derived from `records`.
 *
 * What each assertion proves differs. The assertions on `records` guard that a comparison never
 * shares a request ID with a load: the load's own gates already drop a foreign ID, so they cannot
 * fail from a change to the routing branch alone. The settling assertions, where the comparison
 * reaches `complete` with the counts it was streamed, are what prove the branch routes. Leakage is
 * made possible on purpose, with a real load reading the same channel while comparison batches
 * arrive.
 *
 * The live anchor is the instant the current load began, so the tests that assert an exact window
 * freeze `Date` at a fixed anchor. Tests that run a real load do not: the store's own settling
 * grace is measured on `Date`, and a frozen clock would never let it elapse.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginLiveComparison,
  cancelComparison,
  countCurrentPeriod,
  getComparisonState,
  isComparisonRequestId,
  useComparisonStore,
  type ComparisonOutcome,
} from "./evtx-comparison";
import { DEFAULT_QUICK_FILTER, selectVisibleRecords } from "./evtx-filter";
import type { EvtxChannelInfo, EvtxLevel, EvtxRecord } from "./types";

const invoke = vi.hoisted(() => vi.fn());

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => {});
  }),
}));

const { comparePreviousPeriod, useEvtxStore } = await import("./evtx-store");

const ALL_LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
const ANCHOR = Date.parse("2026-08-10T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
/** The previous 24 h is [2026-08-08T12:00:00.000Z, 2026-08-09T11:59:59.999Z]. */
const PRIOR_FROM = ANCHOR - 2 * DAY;
const PRIOR_TO = ANCHOR - DAY - 1;
const PRIOR_WINDOW_JSON =
  '{"kind":"between","from":"2026-08-08T12:00:00.000Z","to":"2026-08-09T11:59:59.999Z"}';

interface QueryArgs {
  channels: string[];
  maxEvents: number | null;
  filter: Record<string, unknown>;
  requestId: string;
  machine?: string;
}

interface PendingQuery {
  name: string;
  args: QueryArgs;
  resolve(value: unknown): void;
  reject(reason: unknown): void;
}

let queries: PendingQuery[] = [];

function installBridge(): void {
  queries = [];
  invoke.mockReset();
  invoke.mockImplementation((name: string, rawArgs: unknown) => {
    if (name === "evtx_query_channels" || name === "evtx_query_remote_channels") {
      return new Promise((resolve, reject) =>
        queries.push({ name, args: rawArgs as QueryArgs, resolve, reject })
      );
    }
    return Promise.resolve(undefined);
  });
}

function comparisonQueries(): PendingQuery[] {
  return queries.filter((query) => isComparisonRequestId(query.args.requestId));
}

function cancelCalls(): string[] {
  return invoke.mock.calls
    .filter((call) => call[0] === "evtx_cancel_channel_query")
    .map((call) => (call[1] as { requestId: string }).requestId);
}

function queryCommandCalls(): number {
  return invoke.mock.calls.filter(
    (call) => call[0] === "evtx_query_channels" || call[0] === "evtx_query_remote_channels"
  ).length;
}

function reply(totalRecords: number, overrides: Record<string, unknown> = {}) {
  return {
    records: [],
    channels: [],
    totalRecords,
    parseErrors: 0,
    errorMessages: [],
    coverageGaps: [],
    ...overrides,
  };
}

let nextRecord = 1;
function record(channel: string, overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  const id = nextRecord++;
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-10T11:00:00.000Z",
    timestampEpoch: ANCHOR - HOUR,
    provider: "Main-Provider",
    channel,
    eventId: 1,
    level: "Information",
    computer: "HOST",
    message: "m",
    eventData: [],
    rawXml: "<Event/>",
    sourceLabel: "Live",
    mapped: [],
    ...overrides,
  };
}

/** An event of the previous period, distinguishable from every event of the main load. */
function priorEvent(channel: string, overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  return record(channel, {
    timestampEpoch: PRIOR_FROM + HOUR,
    provider: "Compare-Provider",
    eventId: 4000,
    level: "Error",
    ...overrides,
  });
}

function deliver(channel: string, sequence: number, records: EvtxRecord[], requestId: string) {
  listeners.get("evtx-record-batch")?.({ payload: { requestId, channel, sequence, records } });
}

function complete(channel: string, sequenceCount: number, totalRecords: number, requestId: string) {
  listeners.get("evtx-record-stream-complete")?.({
    payload: { requestId, channel, sequenceCount, totalRecords },
  });
}

function progress(channel: string, fetched: number, requestId: string) {
  listeners.get("evtx-query-progress")?.({ payload: { requestId, channel, fetched } });
}

/** Ends the load that `loadAndCompareSystem` started: its end-of-stream marker, then its reply. */
function finishMainLoad(mainQuery: PendingQuery, total = 0): void {
  complete("System", total > 0 ? 1 : 0, total, mainQuery.args.requestId);
  mainQuery.resolve(reply(total, { channels: [liveInfo("System")] }));
}

function liveInfo(name: string): EvtxChannelInfo {
  return { name, eventCount: 0, sourceType: "live", enabledState: "enabled" };
}

const LIVE_CHANNELS = ["System", "Application", "Security"];

/**
 * Moves a frozen `Date` forward. The store measures its own settling grace on `Date`, so a load
 * run on a frozen clock would wait for ever unless the clock is moved past it. A no-op on the
 * real clock.
 */
function advanceFrozenClock(ms: number): void {
  if (vi.isFakeTimers()) vi.setSystemTime(Date.now() + ms);
}

/**
 * Awaits `work` while a frozen clock is moved along. The work has already started when this is
 * called, so anything it stamped on its first step was stamped before the clock moved.
 */
async function withClockRunning<T>(work: Promise<T>): Promise<T> {
  const timer = setInterval(() => advanceFrozenClock(50), 10);
  try {
    return await work;
  } finally {
    clearInterval(timer);
  }
}

/** A reply whose records travelled as batches, with its end-of-stream marker delivered first. */
function streamedReply(args: QueryArgs, rows: EvtxRecord[], coverageGaps: unknown[] = []) {
  const channelName = args.channels[0];
  if (rows.length > 0) deliver(channelName, 0, rows, args.requestId);
  complete(channelName, rows.length > 0 ? 1 : 0, rows.length, args.requestId);
  return reply(rows.length, {
    channels: [{ name: channelName, eventCount: rows.length, sourceType: "live" as const }],
    coverageGaps,
  });
}

/**
 * Runs a real load of `names` against empty replies, the way an operator's Load does. This is the
 * only way a channel gets its read time, so every test that needs a loaded channel goes through it.
 */
async function loadLive(names: string[]): Promise<void> {
  const previous = invoke.getMockImplementation();
  invoke.mockImplementation(async (_name: string, rawArgs: unknown) =>
    streamedReply(rawArgs as QueryArgs, [])
  );
  await withClockRunning(useEvtxStore.getState().queryChannels(names));
  if (previous) invoke.mockImplementation(previous);
}

/** Runs a real load with `Date` frozen at `epoch`, which is therefore when each channel was read. */
async function loadLiveAt(names: string[], epoch: number): Promise<void> {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(epoch);
  await loadLive(names);
  vi.setSystemTime(epoch);
}

/**
 * A live view as a load leaves it: a real load of System, Application and Security, then the
 * criteria and selection a test starts from, with `overrides` on top.
 */
async function resetStore(overrides: Record<string, unknown> = {}) {
  cancelComparison();
  useEvtxStore.getState().reset();
  useEvtxStore.setState({
    sourceMode: "live",
    channels: LIVE_CHANNELS.map(liveInfo),
    selectedChannels: new Set(LIVE_CHANNELS),
    remoteMachine: null,
    timeWindow: "24h",
  });
  await loadLive(LIVE_CHANNELS);
  useEvtxStore.setState({
    records: [],
    channels: [liveInfo("System"), liveInfo("Application")],
    coverageGaps: [],
    coverageDetails: [],
    tailCoverageGaps: [],
    sourceManifest: null,
    sourcePaths: [],
    loadedChannels: new Set(["System", "Application"]),
    selectedChannels: new Set(["System", "Application"]),
    remoteMachine: null,
    sourceMode: "live",
    isLoading: false,
    loadingChannel: null,
    loadingProgress: null,
    loadError: null,
    timeWindow: "24h",
    filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
    filterEventIds: "",
    filterSearch: "",
    quickFilter: DEFAULT_QUICK_FILTER,
    selectedRecordId: null,
    ...overrides,
  });
  // The load that set the view up is not part of what a test observes of the bridge.
  invoke.mockClear();
}

function settled(): ComparisonOutcome {
  const state = getComparisonState();
  if (state.phase !== "settled") throw new Error(`expected a settled comparison, got ${state.phase}`);
  return state.outcome;
}

/** Freezes `Date` at the anchor and loads, so each channel was read exactly at the anchor. */
async function freezeClockAtAnchor(): Promise<void> {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(ANCHOR);
  await resetStore();
  vi.setSystemTime(ANCHOR);
}

beforeEach(async () => {
  installBridge();
  await resetStore();
});

// A test that leaves a comparison running must not have the next test's setup stop it.
afterEach(() => {
  cancelComparison();
  vi.useRealTimers();
});

function startComparison(): Promise<void> {
  return comparePreviousPeriod(ANCHOR);
}

describe("routing comparison batches", () => {
  const sharedVisibility = {
    selectedChannels: new Set(["System"]),
    filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
    filterEventIds: "",
    filterSearch: "",
    quickFilter: DEFAULT_QUICK_FILTER,
  };

  /** A load reading System, and a comparison reading the same channel at the same time. */
  async function loadAndCompareSystem() {
    await resetStore({ selectedChannels: new Set(["System"]), loadedChannels: new Set<string>() });
    const load = useEvtxStore.getState().queryChannels(["System"], 100);
    await vi.waitFor(() => expect(queries).toHaveLength(1));
    const mainQuery = queries[0];

    const session = beginLiveComparison({
      window: "24h",
      anchorEpoch: ANCHOR,
      remote: false,
      notes: [],
      currentPeriodGaps: [],
      channels: ["System"],
      visibility: sharedVisibility,
      cancelQuery: vi.fn(),
    });
    if (!session) throw new Error("expected the comparison to start");
    return { load, mainQuery, session };
  }

  it("aggregates a comparison's events and keeps them out of the load reading the same channel", async () => {
    const { load, mainQuery, session } = await loadAndCompareSystem();
    const mainRequestId = mainQuery.args.requestId;
    expect(session.requestId).not.toBe(mainRequestId);

    const mainRows = [record("System"), record("System")];

    // Interleaved the way the backend interleaves two concurrent requests on one channel.
    deliver("System", 0, mainRows, mainRequestId);
    deliver("System", 0, [priorEvent("System"), priorEvent("System", { level: "Warning" })], session.requestId);
    progress("System", 3, session.requestId);
    deliver("System", 1, [priorEvent("System", { eventId: 4001 })], session.requestId);
    complete("System", 1, 2, mainRequestId);
    complete("System", 2, 3, session.requestId);
    session.replied("System", reply(3));

    // The comparison counted exactly what was streamed to it.
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status !== "complete") return;
    expect(outcome.result.counts.total).toBe(3);
    expect(outcome.result.counts.levels).toMatchObject({ Error: 2, Warning: 1 });
    expect(outcome.result.counts.distinctEvents.size).toBe(2);

    // The load neither merged those events nor took their progress as its own.
    expect(useEvtxStore.getState().loadingProgress).not.toBe(3);
    mainQuery.resolve(reply(2, { channels: [liveInfo("System")] }));
    await load;

    const state = useEvtxStore.getState();
    expect(state.records.map((r) => r.eventRecordId)).toEqual(
      mainRows.map((r) => r.eventRecordId)
    );
    expect(state.records.every((r) => r.provider === "Main-Provider")).toBe(true);
    expect(state.coverageGaps).toEqual([]);
    expect(state.loadError).toBeNull();
    expect(state.loadedChannels.has("System")).toBe(true);

    // The grid, the diagnosis and the analysis session are all built from these records.
    const visible = selectVisibleRecords({
      records: state.records,
      selectedChannels: state.selectedChannels,
      filterLevels: state.filterLevels,
      filterEventIds: "",
      filterSearch: "",
    });
    expect(visible.map((r) => r.provider)).toEqual(["Main-Provider", "Main-Provider"]);
  });

  it("never touches the store, so nothing derived from it can change, while a comparison streams", async () => {
    const { load, mainQuery, session } = await loadAndCompareSystem();
    const notifications = vi.fn();
    const unsubscribe = useEvtxStore.subscribe(notifications);

    deliver("System", 0, [priorEvent("System")], session.requestId);
    progress("System", 1, session.requestId);
    complete("System", 1, 1, session.requestId);
    session.replied("System", reply(1));
    expect(settled().status).toBe("complete");

    // Let any publication the store queued for a microtask run before looking.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(notifications).not.toHaveBeenCalled();
    unsubscribe();

    // Nor does anything wait in the load's own stream to be merged when the load finishes.
    finishMainLoad(mainQuery);
    await load;
    expect(useEvtxStore.getState().records).toEqual([]);
  });

  it("drops the late batches of a cancelled comparison without touching a load on the same channel", async () => {
    const { load, mainQuery, session } = await loadAndCompareSystem();
    cancelComparison();

    deliver("System", 0, [priorEvent("System"), priorEvent("System")], session.requestId);
    complete("System", 1, 2, session.requestId);
    session.replied("System", reply(2));
    finishMainLoad(mainQuery);
    await load;

    expect(useEvtxStore.getState().records).toEqual([]);
    expect(getComparisonState()).toEqual({ phase: "idle" });
  });

  it("leaves a load's own progress alone when it is the comparison that reports progress", async () => {
    const { load, mainQuery, session } = await loadAndCompareSystem();
    progress("System", 7, mainQuery.args.requestId);
    expect(useEvtxStore.getState().loadingProgress).toBe(7);

    progress("System", 9_999, session.requestId);

    expect(useEvtxStore.getState().loadingProgress).toBe(7);
    finishMainLoad(mainQuery);
    await load;
  });
});

describe("comparing a live source with its previous period", () => {
  beforeEach(freezeClockAtAnchor);

  it("queries every loaded selected channel under one comparison request ID, bounded to the previous period", async () => {
    void startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));

    const sent = comparisonQueries();
    expect(sent.map((query) => query.name)).toEqual(["evtx_query_channels", "evtx_query_channels"]);
    expect(sent.map((query) => query.args.channels).sort()).toEqual([["Application"], ["System"]]);
    expect(new Set(sent.map((query) => query.args.requestId)).size).toBe(1);
    expect(isComparisonRequestId(sent[0].args.requestId)).toBe(true);
    for (const query of sent) {
      expect(query.args.maxEvents).toBeNull();
      // The exact wire shape Rust's TimeWindow::Between reads, both bounds present and inclusive.
      expect(JSON.stringify(query.args.filter.time)).toBe(PRIOR_WINDOW_JSON);
    }
  });

  it("keeps the ordinary load's window in the shape it always had", async () => {
    await resetStore({ loadedChannels: new Set<string>() });
    void useEvtxStore.getState().queryChannels(["System"]);
    await vi.waitFor(() => expect(queries).toHaveLength(1));
    expect(JSON.stringify(queries[0].args.filter.time)).toBe(
      '{"kind":"last","milliseconds":86400000}'
    );
  });

  it("completes from the streamed batches and publishes once, with no store updates and no retained records", async () => {
    const before = useEvtxStore.getState().records;
    const notifications = vi.fn();
    const unsubscribe = useEvtxStore.subscribe(notifications);
    const published = vi.fn();

    const run = startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    const [first, second] = comparisonQueries();
    const requestId = first.args.requestId;
    const systemQuery = first.args.channels[0] === "System" ? first : second;
    const applicationQuery = systemQuery === first ? second : first;
    expect(getComparisonState()).toMatchObject({ phase: "running", requestId });

    const stopWatching = useComparisonStore.subscribe(published);

    deliver("System", 0, [priorEvent("System"), priorEvent("System")], requestId);
    deliver("Application", 0, [priorEvent("Application", { level: "Warning", eventId: 4001 })], requestId);
    complete("System", 1, 2, requestId);
    complete("Application", 1, 1, requestId);
    systemQuery.resolve(reply(2));
    applicationQuery.resolve(reply(1));
    await run;
    stopWatching();
    unsubscribe();

    expect(published).toHaveBeenCalledTimes(1);
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status !== "complete") return;
    expect(outcome.result.mode).toBe("live");
    expect(outcome.result.counts.total).toBe(3);
    expect(Object.fromEntries(outcome.result.counts.channels)).toEqual({ System: 2, Application: 1 });
    expect(outcome.result.prior.from).toBe("2026-08-08T12:00:00.000Z");

    expect(notifications).not.toHaveBeenCalled();
    expect(useEvtxStore.getState().records).toBe(before);
    expect(cancelCalls()).toEqual([]);
  });

  it("pushes the view's own criteria into the query and replaces only the window", async () => {
    await resetStore({
      filterLevels: new Set<EvtxLevel>(["Critical", "Error"]),
      filterEventIds: "4624, 100-200",
    });
    void startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));

    const filter = comparisonQueries()[0].args.filter;
    expect(filter.levels).toEqual([1, 2]);
    expect(filter.eventIdMode).toBe("include");
    expect(filter.eventIds).toEqual([
      { kind: "single", id: 4624 },
      { kind: "range", low: 100, high: 200 },
    ]);
    expect(JSON.stringify(filter.time)).toBe(PRIOR_WINDOW_JSON);
  });

  it("uses the remote command, with the machine, for a remote source", async () => {
    await resetStore({ remoteMachine: "SRV01" });
    void startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));

    for (const query of comparisonQueries()) {
      expect(query.name).toBe("evtx_query_remote_channels");
      expect(query.args.machine).toBe("SRV01");
      expect(JSON.stringify(query.args.filter.time)).toBe(PRIOR_WINDOW_JSON);
    }
  });

  it("reads only the channels that are both selected and loaded", async () => {
    await resetStore({
      selectedChannels: new Set(["System", "Security"]),
      loadedChannels: new Set(["System", "Application"]),
    });
    void startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(1));
    expect(comparisonQueries().map((query) => query.args.channels)).toEqual([["System"]]);
  });

  it("lists a channel whose query was rejected as unread instead of counting it as 0", async () => {
    const run = startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    const [first, second] = comparisonQueries();
    const requestId = first.args.requestId;
    const [systemQuery, applicationQuery] =
      first.args.channels[0] === "System" ? [first, second] : [second, first];

    deliver("System", 0, [priorEvent("System")], requestId);
    complete("System", 1, 1, requestId);
    systemQuery.resolve(reply(1));
    applicationQuery.reject(new Error("Access is denied."));
    await run;

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.unreadChannels).toEqual(["Application"]);
    expect(outcome.result.counts.channels.has("Application")).toBe(false);
    expect(outcome.result.gaps).toEqual(["Application: Access is denied."]);
  });
});

describe("when a comparison cannot be made", () => {
  function expectUnavailable(reason: string) {
    expect(getComparisonState()).toMatchObject({
      phase: "settled",
      outcome: { status: "unavailable", reason },
    });
    expect(queryCommandCalls()).toBe(0);
  }

  it("says so while the source is loading", async () => {
    await resetStore({ isLoading: true });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("notReady");
    expect(settled()).toMatchObject({ detail: "Events are still loading." });
  });

  it("says so when no source is open", async () => {
    await resetStore({ sourceMode: null });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("notReady");
    expect(settled()).toMatchObject({ detail: "No source is open." });
  });

  it("says so when the event ID filter is not valid, as the load itself reads nothing then", async () => {
    await resetStore({ filterEventIds: "not-an-id" });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("notReady");
    expect(settled()).toMatchObject({ detail: "The event ID filter is not valid." });
  });

  it("says All time has no previous period, in either mode", async () => {
    await resetStore({ timeWindow: "all" });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("allTime");

    await resetStore({ timeWindow: "all", sourceMode: "files", records: [] });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("allTime");
  });

  it("says so when none of the selected channels is loaded", async () => {
    await resetStore({ loadedChannels: new Set<string>() });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("noChannels");
  });
});

const AUTO_LOAD_MAX_EVENTS = 2_000;
const CAP_DETAIL_TAIL = "so the current period is only partly loaded.";

/** The way a stopped load leaves a channel: its rows on screen, the channel not loaded. */
const STOPPED_GAP = {
  source: "Security",
  kind: "cancelled" as const,
  reason: "operator stopped the load after 3 events were fetched (the channel may hold more)",
};

/** Reads each named core channel with the automatic load, which stops at its per-channel bound. */
async function autoLoad(counts: Record<string, number>): Promise<void> {
  await resetStore({
    sourceMode: null,
    selectedChannels: new Set<string>(),
    loadedChannels: new Set<string>(),
    channels: [],
  });
  invoke.mockImplementation(async (name: string, rawArgs: unknown) => {
    if (name === "evtx_enumerate_channels") return Object.keys(counts).map(liveInfo);
    const args = rawArgs as QueryArgs;
    const channel = args.channels[0];
    return streamedReply(
      args,
      Array.from({ length: counts[channel] }, () => record(channel))
    );
  });
  await withClockRunning(useEvtxStore.getState().enumerateChannels());
  installBridge();
}

/** Resolves every comparison query the way an empty previous period would, as each one appears. */
async function settleComparisonQueries(total: number): Promise<void> {
  const handled = new Set<PendingQuery>();
  await vi.waitFor(() => {
    for (const query of comparisonQueries()) {
      if (handled.has(query)) continue;
      handled.add(query);
      complete(query.args.channels[0], 0, 0, query.args.requestId);
      query.resolve(reply(0));
    }
    expect(handled.size).toBe(total);
  });
}

/** A Load of Security that the operator stopped, after System and Application were loaded. */
async function stoppedLoadOfSecurity(): Promise<void> {
  invoke.mockImplementation(async (_name: string, rawArgs: unknown) =>
    streamedReply(
      rawArgs as QueryArgs,
      [record("Security"), record("Security"), record("Security")],
      [STOPPED_GAP]
    )
  );
  await withClockRunning(useEvtxStore.getState().queryChannels(["Security"]));
  installBridge();
  expect(useEvtxStore.getState().loadedChannels.has("Security")).toBe(false);
}

describe("when the current period is not fully loaded", () => {
  it("is unavailable for a channel a stopped load left partly on screen, and names Load", async () => {
    await resetStore({
      channels: [liveInfo("Security")],
      selectedChannels: new Set(["Security"]),
      loadedChannels: new Set<string>(),
    });
    await stoppedLoadOfSecurity();
    expect(useEvtxStore.getState().records).toHaveLength(3);

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toEqual({
      status: "unavailable",
      reason: "currentPeriodIncomplete",
      detail: `Security was not read in full, ${CAP_DETAIL_TAIL} Load Security to read it in full.`,
    });
    expect(queryCommandCalls()).toBe(0);
  });

  it("is unavailable for a channel the automatic load cut off, and says to deselect it while others remain", async () => {
    await autoLoad({ Security: AUTO_LOAD_MAX_EVENTS, System: 5 });
    expect([...useEvtxStore.getState().loadedChannels].sort()).toEqual(["Security", "System"]);
    expect(
      useEvtxStore.getState().coverageGaps.some((gap) => gap.includes("may hold more"))
    ).toBe(true);

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toEqual({
      status: "unavailable",
      reason: "currentPeriodIncomplete",
      detail: `Security reached the automatic load's cap of 2,000 events, ${CAP_DETAIL_TAIL} Deselect Security to compare the other channels.`,
    });
    // No control reads a capped channel in full, so the copy must not offer one.
    expect((settled() as { detail: string }).detail).not.toMatch(/\bLoad\b/);
    expect(queryCommandCalls()).toBe(0);
  });

  it("says no channel can be compared when every selected channel is at the cap", async () => {
    await autoLoad({ Security: AUTO_LOAD_MAX_EVENTS, System: AUTO_LOAD_MAX_EVENTS });

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toEqual({
      status: "unavailable",
      reason: "currentPeriodIncomplete",
      detail: `System, Security reached the automatic load's cap of 2,000 events, ${CAP_DETAIL_TAIL} No channel can be compared while every loaded selected channel is at the cap.`,
    });
    expect((settled() as { detail: string }).detail).not.toContain("Deselect");
  });

  it("names Load for a stopped channel and Deselect for a capped one, when others remain", async () => {
    await autoLoad({ Security: AUTO_LOAD_MAX_EVENTS, System: 5 });
    invoke.mockImplementation(async (_name: string, rawArgs: unknown) =>
      streamedReply(rawArgs as QueryArgs, [record("Setup")], [{ ...STOPPED_GAP, source: "Setup" }])
    );
    await withClockRunning(useEvtxStore.getState().queryChannels(["Setup"]));
    installBridge();
    useEvtxStore.setState({ selectedChannels: new Set(["System", "Security", "Setup"]) });

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toEqual({
      status: "unavailable",
      reason: "currentPeriodIncomplete",
      detail: `Security reached the automatic load's cap of 2,000 events; Setup was not read in full, ${CAP_DETAIL_TAIL} Load Setup to read it in full. Deselect Security to compare the other channels.`,
    });
  });

  it("offers to deselect a capped channel when a channel still to be loaded in full would remain", async () => {
    await autoLoad({ Security: AUTO_LOAD_MAX_EVENTS });
    invoke.mockImplementation(async (_name: string, rawArgs: unknown) =>
      streamedReply(rawArgs as QueryArgs, [record("Setup")], [{ ...STOPPED_GAP, source: "Setup" }])
    );
    await withClockRunning(useEvtxStore.getState().queryChannels(["Setup"]));
    installBridge();
    useEvtxStore.setState({ selectedChannels: new Set(["Security", "Setup"]) });

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toEqual({
      status: "unavailable",
      reason: "currentPeriodIncomplete",
      detail: `Security reached the automatic load's cap of 2,000 events; Setup was not read in full, ${CAP_DETAIL_TAIL} Load Setup to read it in full. Deselect Security to compare the other channels.`,
    });
  });

  it("does not promise other channels when the only other selected channel was never loaded", async () => {
    // Deselecting Security would leave Application, which holds nothing and is not loaded: Compare
    // would then have no channel to compare. The copy must describe the channels that are compared.
    await autoLoad({ Security: AUTO_LOAD_MAX_EVENTS });
    useEvtxStore.setState({ selectedChannels: new Set(["Security", "Application"]) });
    expect(useEvtxStore.getState().loadedChannels.has("Application")).toBe(false);

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toEqual({
      status: "unavailable",
      reason: "currentPeriodIncomplete",
      detail: `Security reached the automatic load's cap of 2,000 events, ${CAP_DETAIL_TAIL} No channel can be compared while every loaded selected channel is at the cap.`,
    });
  });

  it("compares a channel the automatic load read to its end, anchored where that load read it", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(ANCHOR);
    await autoLoad({ Security: AUTO_LOAD_MAX_EVENTS - 1 });
    expect(
      useEvtxStore.getState().coverageGaps.some((gap) => gap.includes("may hold more"))
    ).toBe(false);
    // The comparison is anchored by the instant this load read Security. An earlier read, such as
    // the one that set the view up, must not be what the anchor comes from.
    const readAt = ANCHOR + 10 * HOUR;
    vi.setSystemTime(readAt);
    invoke.mockImplementation(async (name: string, rawArgs: unknown) => {
      if (name === "evtx_enumerate_channels") return [liveInfo("Security")];
      return streamedReply(
        rawArgs as QueryArgs,
        Array.from({ length: AUTO_LOAD_MAX_EVENTS - 1 }, () => record("Security"))
      );
    });
    useEvtxStore.setState({ sourceMode: null, loadedChannels: new Set<string>() });
    await withClockRunning(useEvtxStore.getState().enumerateChannels());
    installBridge();

    const run = startComparison();
    await settleComparisonQueries(1);
    await run;

    expect(comparisonQueries()[0].args.channels).toEqual(["Security"]);
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.gaps).toEqual([]);
      expect(outcome.result.prior.anchorEpoch).toBe(readAt);
    }
  });

  it("refuses All time before it looks at completeness, since no load could fix that", async () => {
    await autoLoad({ Security: AUTO_LOAD_MAX_EVENTS });
    useEvtxStore.setState({ timeWindow: "all" });

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toMatchObject({ status: "unavailable", reason: "allTime" });
    expect(queryCommandCalls()).toBe(0);
  });

  it("does not hold a partly loaded channel against a comparison that does not include it", async () => {
    await resetStore({
      records: [record("Security")],
      selectedChannels: new Set(["System"]),
      loadedChannels: new Set(["System"]),
      coverageGaps: [`Security: newest ${AUTO_LOAD_MAX_EVENTS} events shown (the channel may hold more)`],
    });

    void startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(1));
    expect(comparisonQueries()[0].args.channels).toEqual(["System"]);
  });
});

describe("what fixes the anchor of a live comparison", () => {
  beforeEach(freezeClockAtAnchor);

  const iso = (epoch: number) => new Date(epoch).toISOString();

  async function compareAll(total: number): Promise<void> {
    const run = comparePreviousPeriod(Date.now());
    await settleComparisonQueries(total);
    await run;
  }

  it("is not moved by a stopped load of a channel the comparison leaves out", async () => {
    // System and Application were read three hours before the Load of Security that was stopped.
    // Following the advice to deselect Security must not make them look short of that load.
    await loadLiveAt(["System", "Application"], ANCHOR - 3 * HOUR);
    vi.setSystemTime(ANCHOR);
    useEvtxStore.setState({ selectedChannels: new Set(["System", "Application", "Security"]) });
    await stoppedLoadOfSecurity();
    useEvtxStore.getState().setSelectedChannels(new Set(["System", "Application"]));

    await compareAll(2);

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR - 3 * HOUR);
      expect(outcome.result.gaps).toEqual([]);
    }
  });

  it("follows a refresh, which reads the loaded channels again", async () => {
    const refreshedAt = ANCHOR + 2 * HOUR;
    vi.setSystemTime(refreshedAt);
    invoke.mockImplementation(async (_name: string, rawArgs: unknown) =>
      streamedReply(rawArgs as QueryArgs, [])
    );
    await withClockRunning(useEvtxStore.getState().refreshLoadedChannels());
    installBridge();
    vi.setSystemTime(refreshedAt);

    await compareAll(2);

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.prior.anchorEpoch).toBe(refreshedAt);
  });

  it("does not take a stamp from a load that was superseded before it finished", async () => {
    // Load A reads Security at one instant and is superseded by Load B at a later one. A's reply
    // arrives last; it must not rewrite the instant B's current read set.
    useEvtxStore.setState({ selectedChannels: new Set(["Security"]), loadedChannels: new Set<string>() });
    const earlier = ANCHOR + HOUR;
    const later = ANCHOR + 2 * HOUR;
    vi.setSystemTime(earlier);
    const loadA = useEvtxStore.getState().queryChannels(["Security"]);
    await vi.waitFor(() => expect(queries).toHaveLength(1));
    vi.setSystemTime(later);
    const loadB = useEvtxStore.getState().queryChannels(["Security"]);
    await vi.waitFor(() => expect(queries).toHaveLength(2));

    queries[1].resolve(streamedReply(queries[1].args, []));
    await withClockRunning(loadB);
    queries[0].resolve(reply(0));
    await withClockRunning(loadA);
    expect(useEvtxStore.getState().loadedChannels.has("Security")).toBe(true);
    useEvtxStore.setState({ selectedChannels: new Set(["Security"]) });

    await compareAll(1);

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.prior.anchorEpoch).toBe(later);
  });

  it("is the earliest read among the compared channels, and states each later one's missing start", async () => {
    // Application was read three hours after System. Its own window starts three hours later, so
    // the first three hours of the comparison's current period are not in what it loaded.
    await loadLiveAt(["System"], ANCHOR - 3 * HOUR);
    await loadLiveAt(["Application"], ANCHOR);
    vi.setSystemTime(ANCHOR);

    await compareAll(2);

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR - 3 * HOUR);
    expect(outcome.result.gaps).toEqual([
      `Current period: Application was read at ${iso(ANCHOR)}, 3 h after the comparison anchor ${iso(ANCHOR - 3 * HOUR)}, so the first 3 h of its current period is not covered.`,
    ]);
  });

  it("reports only the part of a missing start that falls inside the window", async () => {
    // Last hour, with Application read ten hours after System: the whole window is missing, not ten
    // hours of it.
    useEvtxStore.setState({ timeWindow: "1h" });
    await loadLiveAt(["System"], ANCHOR);
    await loadLiveAt(["Application"], ANCHOR + 10 * HOUR);
    vi.setSystemTime(ANCHOR);
    useEvtxStore.setState({ timeWindow: "1h" });

    await compareAll(2);

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.gaps[0]).toContain("10 h after the comparison anchor");
      expect(outcome.result.gaps[0]).toContain("so the first 1 h of its current period is not covered");
    }
  });

  async function loadFiveThroughThePool(staggerMs: number): Promise<void> {
    // Five channels through a pool of four: the fifth is read only when one of the first four has
    // answered, `staggerMs` after they began.
    const names = ["System", "Application", "Security", "Setup", "Operational"];
    useEvtxStore.setState({ channels: names.map(liveInfo), selectedChannels: new Set(names) });
    const started = Date.now();
    invoke.mockImplementation(async (_name: string, rawArgs: unknown) => {
      const args = rawArgs as QueryArgs;
      if (args.channels[0] === "Operational") return streamedReply(args, []);
      await new Promise((resolve) => setTimeout(resolve, 10));
      vi.setSystemTime(started + staggerMs);
      return streamedReply(args, []);
    });
    const load = useEvtxStore.getState().queryChannels(names);
    // The fifth read is issued when one of the first four has answered. Only then does the clock
    // start moving, so that read is stamped at exactly the stagger.
    while (queryCommandCalls() < names.length) await new Promise((resolve) => setTimeout(resolve, 5));
    await withClockRunning(load);
    installBridge();
    vi.setSystemTime(started);
    expect([...useEvtxStore.getState().loadedChannels].sort()).toEqual([...names].sort());
  }

  it("states a later channel's missing start once it exceeds one percent of the window", async () => {
    // One percent of 24 h is 14.4 minutes.
    await loadFiveThroughThePool(20 * 60 * 1000);

    await compareAll(5);

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status !== "partial") return;
    expect(outcome.result.gaps).toEqual([
      `Current period: Operational was read at ${iso(ANCHOR + 20 * 60 * 1000)}, 20 min after the comparison anchor ${iso(ANCHOR)}, so the first 20 min of its current period is not covered.`,
    ]);
  });

  it("lets a later channel's start pass unremarked below one percent of the window", async () => {
    await loadFiveThroughThePool(5 * 60 * 1000);

    await compareAll(5);

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.gaps).toEqual([]);
      expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR);
    }
  });

  it("is unavailable, saying why, for a loaded channel whose read was never recorded", async () => {
    useEvtxStore.setState({
      selectedChannels: new Set(["System", "Mystery"]),
      loadedChannels: new Set(["System", "Mystery"]),
    });

    await comparePreviousPeriod(ANCHOR);

    expect(settled()).toEqual({
      status: "unavailable",
      reason: "notReady",
      detail: "When Mystery was read is not recorded, so the current period cannot be compared.",
    });
    expect(queryCommandCalls()).toBe(0);
  });
});

describe("comparing loaded files with their previous period", () => {
  function fileRecord(overrides: Partial<EvtxRecord>): EvtxRecord {
    return record("System", { sourceLabel: "System.evtx", ...overrides });
  }

  it("computes locally from the loaded records without querying anything", async () => {
    const records = [
      fileRecord({ timestampEpoch: PRIOR_FROM }),
      fileRecord({ timestampEpoch: PRIOR_FROM + HOUR, level: "Error", eventId: 55 }),
      fileRecord({ timestampEpoch: PRIOR_TO }),
      fileRecord({ timestampEpoch: ANCHOR }),
    ];
    await resetStore({ sourceMode: "files", records, loadedChannels: new Set<string>() });

    await comparePreviousPeriod(ANCHOR);

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.mode).toBe("files");
      expect(outcome.result.counts.total).toBe(3);
      expect(outcome.result.counts.levels.Error).toBe(1);
    }
    expect(invoke).not.toHaveBeenCalled();
    expect(useEvtxStore.getState().records).toBe(records);
  });

  it("is partial, stating the load's own holes, when the files were damaged or truncated", async () => {
    const records = [
      fileRecord({ timestampEpoch: PRIOR_FROM }),
      fileRecord({ timestampEpoch: PRIOR_TO }),
      fileRecord({ timestampEpoch: ANCHOR }),
    ];
    await resetStore({
      sourceMode: "files",
      records,
      loadedChannels: new Set<string>(),
      coverageDetails: [
        { source: "System.evtx", kind: "chunk", reason: "chunk 12 could not be parsed", chunkId: 12 },
      ],
      sourceManifest: {
        entries: [],
        coverage: [{ kind: "accessDenied", path: "C:/logs/Security.evtx", reason: "access denied" }],
      },
    });

    await comparePreviousPeriod(ANCHOR);

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.gaps).toEqual([
        "System.evtx chunk 12: chunk 12 could not be parsed",
        "C:/logs/Security.evtx: access denied",
      ]);
    }
    expect(invoke).not.toHaveBeenCalled();
  });

  it("is partial, stating the span, for an export captured before the anchor", async () => {
    await resetStore({
      sourceMode: "files",
      records: [
        fileRecord({ timestampEpoch: PRIOR_FROM }),
        fileRecord({ timestampEpoch: PRIOR_TO }),
        fileRecord({ timestampEpoch: ANCHOR - 20 * HOUR }),
      ],
      loadedChannels: new Set<string>(),
    });

    await comparePreviousPeriod(ANCHOR);

    const outcome = settled();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.gaps).toEqual([
        `System.evtx (System) has no events after ${new Date(ANCHOR - 20 * HOUR).toISOString()}, so the last 20 h of the current period is not covered.`,
      ]);
    }
  });

  it("is unavailable, not zero, when the files do not reach back to the previous period", async () => {
    await resetStore({
      sourceMode: "files",
      records: [fileRecord({ timestampEpoch: PRIOR_TO + 1 }), fileRecord({ timestampEpoch: ANCHOR })],
    });
    await comparePreviousPeriod(ANCHOR);
    expect(settled()).toEqual({
      status: "unavailable",
      reason: "priorPeriodNotSpanned",
      detail: "The loaded files do not cover the previous period.",
    });
    expect(invoke).not.toHaveBeenCalled();
  });
});

describe("a comparison is invalidated by what it compared", () => {
  const changes: Array<[string, () => void]> = [
    ["the source mode", () => useEvtxStore.setState({ sourceMode: "files" })],
    ["the source paths", () => useEvtxStore.setState({ sourcePaths: ["other.evtx"] })],
    ["the remote machine", () => useEvtxStore.setState({ remoteMachine: "SRV02" })],
    ["a channel being deselected", () => useEvtxStore.getState().toggleChannel("Application")],
    ["every channel being deselected", () => useEvtxStore.getState().deselectAllChannels()],
    ["the selected channels being replaced", () => useEvtxStore.getState().setSelectedChannels(new Set(["System"]))],
    ["the time window", () => useEvtxStore.getState().setTimeWindow("7d")],
    ["a level toggle", () => useEvtxStore.getState().toggleFilterLevel("Verbose")],
    ["the event ID filter", () => useEvtxStore.getState().setFilterEventIds("4624")],
    ["the search text", () => useEvtxStore.getState().setFilterSearch("needle")],
    [
      "the quick filter",
      () => useEvtxStore.getState().setQuickFilter({ ...DEFAULT_QUICK_FILTER, query: "x" }),
    ],
    ["a new load superseding the current one", () => void useEvtxStore.getState().supersedePendingLoad()],
  ];

  it.each(changes)("cancels a comparison in flight when %s changes", async (_name, change) => {
    const run = startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    const requestId = comparisonQueries()[0].args.requestId;

    change();

    expect(getComparisonState()).toEqual({ phase: "idle" });
    expect(cancelCalls()).toContain(requestId);

    // Whatever the abandoned queries still deliver or reply is dropped.
    deliver("System", 0, [priorEvent("System")], requestId);
    comparisonQueries().forEach((query) => query.resolve(reply(1)));
    await run;
    expect(getComparisonState()).toEqual({ phase: "idle" });
  });

  it.each(changes)("clears a finished comparison when %s changes", async (_name, change) => {
    const run = startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    const requestId = comparisonQueries()[0].args.requestId;
    complete("System", 0, 0, requestId);
    complete("Application", 0, 0, requestId);
    comparisonQueries().forEach((query) => query.resolve(reply(0)));
    await run;
    expect(getComparisonState().phase).toBe("settled");

    change();

    expect(getComparisonState()).toEqual({ phase: "idle" });
    // A finished comparison has no query left to stop.
    expect(cancelCalls()).not.toContain(requestId);
  });

  it("leaves a comparison alone for changes that do not alter what it compared", async () => {
    const run = startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    const requestId = comparisonQueries()[0].args.requestId;

    useEvtxStore.setState({ records: [record("System")] });
    useEvtxStore.getState().setSelectedRecordId(5);
    useEvtxStore.getState().setSortField("level");
    useEvtxStore.getState().setSortDirection("desc");
    useEvtxStore.getState().setGroupBy(["level"]);
    useEvtxStore.getState().toggleGroup("k");

    expect(getComparisonState()).toMatchObject({ phase: "running", requestId });
    expect(cancelCalls()).toEqual([]);
    complete("System", 0, 0, requestId);
    complete("Application", 0, 0, requestId);
    comparisonQueries().forEach((query) => query.resolve(reply(0)));
    await run;
    expect(settled().status).toBe("complete");
  });
});

describe("the anchor of a live comparison", () => {
  beforeEach(freezeClockAtAnchor);

  const iso = (epoch: number) => new Date(epoch).toISOString();
  const windowJson = (anchor: number) =>
    JSON.stringify({
      kind: "between",
      from: iso(anchor - 2 * DAY),
      to: iso(anchor - DAY - 1),
    });

  async function runAndSettle(nowEpoch: number) {
    const run = comparePreviousPeriod(nowEpoch);
    await settleComparisonQueries(2);
    await run;
    return comparisonQueries()[0].args.filter.time;
  }

  /** Lets a test start and stop a live tail through the real store actions. */
  function installTailBridge(): void {
    const base = invoke.getMockImplementation();
    invoke.mockImplementation((name: string, rawArgs: unknown) => {
      const args = rawArgs as { channel: string; requestId: string };
      if (name === "evtx_start_tail" || name === "evtx_stop_tail") {
        return Promise.resolve({
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: name === "evtx_start_tail",
          nextSequence: 0,
          coverageGaps: [],
        });
      }
      return base ? base(name, rawArgs) : Promise.resolve(undefined);
    });
  }

  function tailBatch(channel: string, records: EvtxRecord[]): void {
    listeners.get("evtx-tail-batch")?.({
      payload: {
        requestId: useEvtxStore.getState().tailRequestId,
        channel,
        sequence: 0,
        mode: "subscription",
        records,
        coverageGaps: [],
      },
    });
  }

  it("is when the channels were read, not the time the caller passes", async () => {
    vi.setSystemTime(ANCHOR + 3 * HOUR);

    const time = await runAndSettle(ANCHOR + 3 * HOUR);

    expect(JSON.stringify(time)).toBe(windowJson(ANCHOR));
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR);
      expect(outcome.result.anchorBasis).toBe("load");
      expect(outcome.result.notes).toEqual([]);
    }
  });

  it("is unmoved by a criterion change hours after the load, which would only move a clock-based anchor", async () => {
    vi.setSystemTime(ANCHOR + 3 * HOUR);
    useEvtxStore.getState().setFilterSearch("needle");

    const time = await runAndSettle(ANCHOR + 3 * HOUR);

    expect(JSON.stringify(time)).toBe(windowJson(ANCHOR));
    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR);
  });

  it("follows a new load, which evaluates its window again", async () => {
    vi.setSystemTime(ANCHOR + 3 * HOUR);
    await resetStore();
    vi.setSystemTime(ANCHOR + 3 * HOUR);

    const time = await runAndSettle(ANCHOR);

    expect(JSON.stringify(time)).toBe(windowJson(ANCHOR + 3 * HOUR));
  });

  it("does not count its own queries as a read of the current period", async () => {
    await loadLiveAt(["System"], ANCHOR - 3 * HOUR);
    vi.setSystemTime(ANCHOR + HOUR);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const run = comparePreviousPeriod(ANCHOR + HOUR);
      await vi.waitFor(() => expect(comparisonQueries().length).toBeGreaterThanOrEqual(2));
      const latest = comparisonQueries().slice(-2);
      for (const query of latest) {
        complete(query.args.channels[0], 0, 0, query.args.requestId);
        query.resolve(reply(0));
      }
      await run;
      // Application was read three hours after System, however often the previous period is read.
      expect(settled().status).toBe("partial");
    }
  });

  describe("with a live tail", () => {
    it("stays at the load when the tail starts after it, and does not claim the span the tail never read", async () => {
      // The tail subscribes to events that have not happened yet. Two hours after the load it
      // starts, so nothing between the load and the tail's start is in the records or in a gap.
      installTailBridge();
      vi.setSystemTime(ANCHOR + 2 * HOUR);
      await useEvtxStore.getState().startLiveTail();
      const tailEvent = record("System", { timestampEpoch: ANCHOR + 2 * HOUR + 60_000 });
      tailBatch("System", [tailEvent]);
      vi.setSystemTime(ANCHOR + 3 * HOUR);

      const time = await runAndSettle(ANCHOR + 3 * HOUR);

      expect(JSON.stringify(time)).toBe(windowJson(ANCHOR));
      const outcome = settled();
      expect(outcome.status).toBe("complete");
      if (outcome.status !== "complete") return;
      expect(outcome.result.prior.anchorEpoch).toBe(ANCHOR);
      expect(outcome.result.anchorBasis).toBe("load");
      expect(outcome.result.notes).toEqual([
        `Events after ${iso(ANCHOR)} (live tail) are not included.`,
      ]);
      // The tail's event is on the grid and in `records`, and outside the period compared.
      expect(useEvtxStore.getState().records).toContain(tailEvent);
      const current = countCurrentPeriod(
        useEvtxStore.getState().records,
        outcome.result.prior,
        {
          selectedChannels: useEvtxStore.getState().selectedChannels,
          filterLevels: useEvtxStore.getState().filterLevels,
          filterEventIds: "",
          filterSearch: "",
          quickFilter: DEFAULT_QUICK_FILTER,
        }
      );
      expect(current.counts.total).toBe(0);
      expect(current.outsideWindowRecords).toBe(1);
    });

    it("keeps saying so after the tail is stopped, since its events remain on the grid", async () => {
      installTailBridge();
      vi.setSystemTime(ANCHOR + HOUR);
      await useEvtxStore.getState().startLiveTail();
      tailBatch("System", [record("System", { timestampEpoch: ANCHOR + HOUR })]);
      await useEvtxStore.getState().stopLiveTail();
      expect(useEvtxStore.getState().tailRequestId).toBeNull();
      vi.setSystemTime(ANCHOR + 2 * HOUR);

      const time = await runAndSettle(ANCHOR + 2 * HOUR);

      expect(JSON.stringify(time)).toBe(windowJson(ANCHOR));
      const outcome = settled();
      expect(outcome.status).toBe("complete");
      if (outcome.status === "complete") {
        expect(outcome.result.notes).toEqual([
          `Events after ${iso(ANCHOR)} (live tail) are not included.`,
        ]);
      }
    });

    it("adds no note while the tail has appended nothing", async () => {
      installTailBridge();
      await useEvtxStore.getState().startLiveTail();

      await runAndSettle(ANCHOR);

      const outcome = settled();
      expect(outcome.status).toBe("complete");
      if (outcome.status === "complete") expect(outcome.result.notes).toEqual([]);
    });
  });
});

describe("the current period's own gaps", () => {
  beforeEach(freezeClockAtAnchor);

  async function compareAndSettle() {
    const run = comparePreviousPeriod(ANCHOR);
    await vi.waitFor(() => expect(comparisonQueries().length).toBeGreaterThan(0));
    const queued = comparisonQueries();
    for (const query of queued) {
      complete(query.args.channels[0], 0, 0, query.args.requestId);
      query.resolve(reply(0));
    }
    await run;
    return settled();
  }

  const renderGap = {
    source: "System",
    kind: "record" as const,
    reason: "40 events could not be rendered and are missing from this view",
  };

  it("makes the comparison partial, with the gap stated, for a loaded channel that is missing events", async () => {
    await resetStore({ coverageDetails: [renderGap] });

    const outcome = await compareAndSettle();

    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.gaps).toEqual([
        "Current period: System: 40 events could not be rendered and are missing from this view",
      ]);
    }
  });

  it("is not made partial by a live-tail gap, since the tail's events are never counted", async () => {
    await resetStore({ tailCoverageGaps: ["System: live tail batch 3 was not received"] });

    const outcome = await compareAndSettle();

    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") expect(outcome.result.gaps).toEqual([]);
  });

  it("does not count a gap that belongs to a channel the comparison does not read", async () => {
    await resetStore({
      coverageDetails: [{ ...renderGap, source: "Security" }],
      selectedChannels: new Set(["System"]),
    });
    expect((await compareAndSettle()).status).toBe("complete");
  });

  it("counts a provider-description gap only while a search reads the message text", async () => {
    const providerGap = {
      source: "System",
      kind: "provider" as const,
      reason: "message text unavailable",
    };
    await resetStore({ coverageDetails: [providerGap] });
    expect((await compareAndSettle()).status).toBe("complete");

    await resetStore({ coverageDetails: [providerGap], filterSearch: "timeout" });
    const outcome = await compareAndSettle();
    expect(outcome.status).toBe("partial");
    if (outcome.status === "partial") {
      expect(outcome.result.gaps).toEqual(["Current period: System: message text unavailable"]);
    }
  });
});

describe("a remote source", () => {
  beforeEach(freezeClockAtAnchor);

  it("notes whose clock cut the periods, without calling it a gap", async () => {
    await resetStore({ remoteMachine: "SRV01" });
    const run = comparePreviousPeriod(ANCHOR);
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    for (const query of comparisonQueries()) {
      complete(query.args.channels[0], 0, 0, query.args.requestId);
      query.resolve(reply(0));
    }
    await run;

    const outcome = settled();
    expect(outcome.status).toBe("complete");
    if (outcome.status === "complete") {
      expect(outcome.result.notes).toEqual(["Periods are computed on this computer's clock"]);
    }
  });
});

describe("a comparison's progress", () => {
  beforeEach(freezeClockAtAnchor);

  it("reaches the comparison and not the load", async () => {
    void comparePreviousPeriod(ANCHOR);
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    const requestId = comparisonQueries()[0].args.requestId;
    useEvtxStore.setState({ loadingChannel: "Application", loadingProgress: 7 });

    progress("System", 1_000, requestId);
    progress("Application", 250, requestId);

    expect(getComparisonState()).toMatchObject({ phase: "running", scanned: 1_250 });
    expect(useEvtxStore.getState().loadingProgress).toBe(7);
    expect(useEvtxStore.getState().loadingChannel).toBe("Application");
  });
});

describe("what makes a comparison depend on the clock and the columns", () => {
  beforeEach(freezeClockAtAnchor);

  async function runningComparison() {
    const run = comparePreviousPeriod(ANCHOR);
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));
    return { run, requestId: comparisonQueries()[0].args.requestId };
  }

  const changes: Array<[string, () => void]> = [
    ["the time zone", () => useEvtxStore.getState().setTimeZoneMode("utc")],
    ["the column order", () => useEvtxStore.getState().moveColumnBy("level", 1)],
  ];

  it.each(changes)("is cancelled by %s while a quick filter reads it", async (_name, change) => {
    useEvtxStore.getState().setQuickFilter({ ...DEFAULT_QUICK_FILTER, query: "needle" });
    const { requestId } = await runningComparison();

    change();

    expect(getComparisonState()).toEqual({ phase: "idle" });
    expect(cancelCalls()).toContain(requestId);
  });

  it.each(changes)("survives %s when no quick filter is set", async (_name, change) => {
    const { requestId } = await runningComparison();

    change();

    expect(getComparisonState()).toMatchObject({ phase: "running", requestId });
    expect(cancelCalls()).toEqual([]);
  });
});
