/**
 * Routing a previous-period comparison through the Event Logs store.
 *
 * The comparison streams events over the same Tauri events as an ordinary load, so the store must
 * tell them apart by request ID. These tests pin the contract the spec demands: no comparison event
 * reaches `records`, and through it the grid, the diagnosis and the analysis session, which are all
 * derived from `records`. Leakage is made possible on purpose, with a real load reading the same
 * channel while comparison batches arrive, because a store that simply drops foreign request IDs
 * would also keep `records` clean and prove nothing about routing.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginLiveComparison,
  cancelComparison,
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

function resetStore(overrides: Record<string, unknown> = {}) {
  cancelComparison();
  useEvtxStore.setState({
    records: [],
    channels: [liveInfo("System"), liveInfo("Application")],
    coverageGaps: [],
    coverageDetails: [],
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
}

function settled(): ComparisonOutcome {
  const state = getComparisonState();
  if (state.phase !== "settled") throw new Error(`expected a settled comparison, got ${state.phase}`);
  return state.outcome;
}

beforeEach(() => {
  installBridge();
  resetStore();
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
    resetStore({ selectedChannels: new Set(["System"]), loadedChannels: new Set<string>() });
    const load = useEvtxStore.getState().queryChannels(["System"], 100);
    await vi.waitFor(() => expect(queries).toHaveLength(1));
    const mainQuery = queries[0];

    const session = beginLiveComparison({
      window: "24h",
      anchorEpoch: ANCHOR,
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
    resetStore({ loadedChannels: new Set<string>() });
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
    resetStore({
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
    resetStore({ remoteMachine: "SRV01" });
    void startComparison();
    await vi.waitFor(() => expect(comparisonQueries()).toHaveLength(2));

    for (const query of comparisonQueries()) {
      expect(query.name).toBe("evtx_query_remote_channels");
      expect(query.args.machine).toBe("SRV01");
      expect(JSON.stringify(query.args.filter.time)).toBe(PRIOR_WINDOW_JSON);
    }
  });

  it("reads only the channels that are both selected and loaded", async () => {
    resetStore({
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
    resetStore({ isLoading: true });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("notReady");
    expect(settled()).toMatchObject({ detail: "Events are still loading." });
  });

  it("says so when no source is open", async () => {
    resetStore({ sourceMode: null });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("notReady");
    expect(settled()).toMatchObject({ detail: "No source is open." });
  });

  it("says so when the event ID filter is not valid, as the load itself reads nothing then", async () => {
    resetStore({ filterEventIds: "not-an-id" });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("notReady");
    expect(settled()).toMatchObject({ detail: "The event ID filter is not valid." });
  });

  it("says All time has no previous period, in either mode", async () => {
    resetStore({ timeWindow: "all" });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("allTime");

    resetStore({ timeWindow: "all", sourceMode: "files", records: [] });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("allTime");
  });

  it("says so when none of the selected channels is loaded", async () => {
    resetStore({ loadedChannels: new Set<string>() });
    await comparePreviousPeriod(ANCHOR);
    expectUnavailable("noChannels");
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
    ];
    resetStore({ sourceMode: "files", records, loadedChannels: new Set<string>() });

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

  it("is unavailable, not zero, when the files do not reach back to the previous period", async () => {
    resetStore({
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
