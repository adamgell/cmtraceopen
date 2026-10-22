/**
 * A before-load criterion refetches the loaded channels only when it changes what the service is
 * asked for.
 *
 * A live refetch empties the records and reloads every loaded channel. While Information is
 * selected the level predicate is never sent (it stays a local filter), so toggling Verbose changes
 * nothing the service sees, and reloading for it throws the whole view away for no reason. The same
 * holds for setting a criterion to the value it already had. Each setter compares the server filter
 * before and after and refetches only when they differ.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EVTX_LEVELS } from "./evtx-filter";
import { deferred } from "../../test-utils/deferred";
import type { EvtxLevel, EvtxRecord } from "./types";

const invoke = vi.hoisted(() => vi.fn());
// Captured so a test can deliver a record batch and the terminal marker the way the backend does.
const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => undefined);
  }),
}));

// Imported after the mocks: the store subscribes to the bridge at module scope.
const { serverFilterKey, useEvtxStore } = await import("./evtx-store");

const levels = (...names: EvtxLevel[]) => new Set<EvtxLevel>(names);
const ALL = () => levels(...EVTX_LEVELS);

type QueryArgs = {
  requestId?: string;
  channels: string[];
  maxEvents: number | null;
  filter: { levels?: number[]; eventIds?: unknown[]; time?: unknown };
};
const queries = () =>
  invoke.mock.calls
    .filter(([name]) => name === "evtx_query_channels")
    .map(([, args]) => args as QueryArgs);

/** Lets the store's microtask-scheduled refresh run. */
const settle = async () => {
  for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
};

describe("serverFilterKey", () => {
  it("is equal for criteria the service sees the same way", () => {
    expect(serverFilterKey("24h", "", ALL())).toBe(serverFilterKey("24h", "", ALL()));
    // Information selected: the level predicate is never sent, so these are one request.
    expect(serverFilterKey("24h", "", ALL())).toBe(
      serverFilterKey("24h", "", levels("Critical", "Error", "Warning", "Information")),
    );
    expect(serverFilterKey("24h", "", levels("Information", "Error"))).toBe(
      serverFilterKey("24h", "", levels("Information", "Verbose")),
    );
    // Whitespace and an empty list are no Event ID predicate.
    expect(serverFilterKey("all", "  ", ALL())).toBe(serverFilterKey("all", "", ALL()));
  });

  it("differs when the window, the Event IDs or the pushed level subset differ", () => {
    const base = serverFilterKey("24h", "", ALL());
    expect(serverFilterKey("7d", "", ALL())).not.toBe(base);
    expect(serverFilterKey("24h", "4624", ALL())).not.toBe(base);
    expect(serverFilterKey("24h", "4624", ALL())).not.toBe(serverFilterKey("24h", "4625", ALL()));
    // Dropping Information pushes the subset down.
    expect(serverFilterKey("24h", "", levels("Critical", "Error", "Warning", "Verbose"))).not.toBe(base);
    expect(serverFilterKey("24h", "", levels("Critical", "Error"))).not.toBe(
      serverFilterKey("24h", "", levels("Critical", "Warning")),
    );
  });

  it("keys an invalid Event ID list apart from none, because the refetch then reads nothing", () => {
    // buildServerFilter drops an invalid list, but the refetch sends maxEvents 0 for it: the request
    // is part of the key, not only the filter. "4624,abc" returns no records; "" returns the window.
    expect(serverFilterKey("24h", "4624,abc", ALL())).not.toBe(serverFilterKey("24h", "", ALL()));
    expect(serverFilterKey("24h", "4624,abc", ALL())).not.toBe(serverFilterKey("24h", "  ", ALL()));
    expect(serverFilterKey("24h", "4624,abc", ALL())).not.toBe(serverFilterKey("24h", "4624", ALL()));
    // Two invalid lists are the same zero-limit request.
    expect(serverFilterKey("24h", "4624,abc", ALL())).toBe(serverFilterKey("24h", "zzz", ALL()));
  });
});

describe("the level numbers the store sends, for every level subset", () => {
  // Written out here on purpose, apart from EVTX_RAW_LEVEL: this is the pin on the wire values the
  // Event Log service filters on (Windows levels 1 to 5), so a change to the shared map or to the
  // order of EVTX_LEVELS cannot move them unnoticed.
  const WIRE: Record<EvtxLevel, number> = {
    Critical: 1,
    Error: 2,
    Warning: 3,
    Information: 4,
    Verbose: 5,
  };
  const SUBSETS = Array.from({ length: 2 ** EVTX_LEVELS.length }, (_, mask) =>
    levels(...EVTX_LEVELS.filter((_level, index) => (mask >> index) & 1)),
  );

  it("sends the level numbers of a strict subset without Information, and no level predicate otherwise", () => {
    for (const subset of SUBSETS) {
      const label = [...subset].join(",") || "(none)";
      const sent = JSON.parse(serverFilterKey("all", "", subset)).filter.levels as number[] | undefined;
      const pushed = subset.size > 0 && subset.size < 5 && !subset.has("Information");
      if (pushed) {
        expect(sent, label).toEqual([...subset].map((level) => WIRE[level]).sort());
      } else {
        expect(sent, label).toBeUndefined();
      }
    }
  });
});

describe("a live refetch only when the server filter changes", () => {
  beforeEach(() => {
    invoke.mockReset();
    // The query stays pending: these tests count what was asked, not what came back.
    invoke.mockImplementation(async (name: string) =>
      name === "evtx_query_channels" ? new Promise(() => undefined) : undefined,
    );
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
      selectedChannels: new Set(["Application"]),
      timeWindow: "24h",
      filterLevels: ALL(),
      filterEventIds: "",
      isLoading: false,
    });
  });

  it("does not refetch when a toggle leaves the server filter alone (Information stays selected)", async () => {
    useEvtxStore.getState().toggleFilterLevel("Verbose");
    await settle();
    expect(queries()).toHaveLength(0);
    expect(useEvtxStore.getState().isLoading).toBe(false);
    expect(useEvtxStore.getState().filterLevels.has("Verbose")).toBe(false);
  });

  it("refetches once when a toggle changes what is pushed to the service", async () => {
    useEvtxStore.getState().toggleFilterLevel("Information");
    await settle();
    expect(queries()).toHaveLength(1);
    expect(queries()[0].filter.levels).toEqual([1, 2, 3, 5]);
  });

  it("refetches when the subset without Information changes, and not when it is set again", async () => {
    useEvtxStore.setState({ filterLevels: levels("Critical", "Error") });
    useEvtxStore.getState().setFilterLevels(levels("Critical", "Error"));
    await settle();
    expect(queries()).toHaveLength(0);

    useEvtxStore.getState().setFilterLevels(levels("Critical", "Warning"));
    await settle();
    expect(queries()).toHaveLength(1);
  });

  it("refetches once for a changed Event ID list and not for the same one", async () => {
    useEvtxStore.getState().setFilterEventIds("");
    await settle();
    expect(queries()).toHaveLength(0);

    useEvtxStore.getState().setFilterEventIds("4624");
    await settle();
    expect(queries()).toHaveLength(1);
    expect(queries()[0].filter.eventIds).toEqual([{ kind: "single", id: 4624 }]);
  });

  it("refetches for an invalid Event ID list, which reads nothing (maxEvents 0)", async () => {
    useEvtxStore.getState().setFilterEventIds("4624,abc");
    await settle();
    expect(queries()).toHaveLength(1);
    expect(queries()[0].maxEvents).toBe(0);
    expect(queries()[0].filter.eventIds).toBeUndefined();
  });

  it("refetches again when a saved invalid list is cleared, so a read capped at zero is not left on screen", async () => {
    // A filter saved before Event IDs were committed on Enter can hold a list like "4624;4625".
    useEvtxStore.setState({ filterEventIds: "4624" });
    useEvtxStore.getState().setBeforeLoadCriteria({
      levels: [...EVTX_LEVELS],
      eventIds: "4624;4625",
      timeWindow: "24h",
    });
    await settle();
    expect(queries()).toHaveLength(1);
    expect(queries()[0].maxEvents).toBe(0);

    // The zero-limit read came back empty with the channel loaded, then the operator removes the
    // list's chip.
    useEvtxStore.setState({ isLoading: false, loadedChannels: new Set(["Application"]) });
    useEvtxStore.getState().setFilterEventIds("");
    await settle();
    expect(queries()).toHaveLength(2);
    expect(queries()[1].maxEvents).not.toBe(0);
  });

  it("refetches when an invalid list is replaced by a valid one", async () => {
    useEvtxStore.setState({ filterEventIds: "4624,abc" });
    useEvtxStore.getState().setFilterEventIds("4624");
    await settle();
    expect(queries()).toHaveLength(1);
    expect(queries()[0].filter.eventIds).toEqual([{ kind: "single", id: 4624 }]);
  });

  it("refetches for a changed window and not for the same one", async () => {
    useEvtxStore.getState().setTimeWindow("24h");
    await settle();
    expect(queries()).toHaveLength(0);

    useEvtxStore.getState().setTimeWindow("7d");
    await settle();
    expect(queries()).toHaveLength(1);
  });

  it("does not refetch when a saved filter changes only the channel selection or local criteria", async () => {
    useEvtxStore.getState().setBeforeLoadCriteria({
      levels: EVTX_LEVELS.filter((level) => level !== "Verbose"),
      eventIds: "",
      timeWindow: "24h",
      selectedChannels: ["Application"],
    });
    await settle();
    expect(queries()).toHaveLength(0);
    expect(useEvtxStore.getState().filterLevels.has("Verbose")).toBe(false);
  });

  it("refetches when a saved filter changes the window", async () => {
    useEvtxStore.getState().setBeforeLoadCriteria({
      levels: [...EVTX_LEVELS],
      eventIds: "",
      timeWindow: "30d",
    });
    await settle();
    expect(queries()).toHaveLength(1);
  });

  it("does not refetch in file mode whatever changes", async () => {
    useEvtxStore.setState({ sourceMode: "files" });
    useEvtxStore.getState().toggleFilterLevel("Information");
    useEvtxStore.getState().setFilterEventIds("4624");
    await settle();
    expect(queries()).toHaveLength(0);
  });
});

describe("a change made while a refetch is running", () => {
  const record = (id: number): EvtxRecord => ({
    id,
    eventRecordId: id,
    timestamp: "2026-08-12T12:00:00.000Z",
    timestampEpoch: 1_000 + id,
    provider: "P",
    channel: "Application",
    eventId: 1,
    level: "Error",
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "<Event/>",
    sourceLabel: "Live",
    mapped: [],
  });

  /** A reply whose records travelled as a batch, with the terminal marker delivered first. */
  const streamed = (args: QueryArgs) => {
    const channel = args.channels[0];
    listeners.get("evtx-record-batch")?.({
      payload: { requestId: args.requestId, channel, sequence: 0, records: [record(1)] },
    });
    listeners.get("evtx-record-stream-complete")?.({
      payload: { requestId: args.requestId, channel, sequenceCount: 1, totalRecords: 1 },
    });
    return {
      records: [],
      channels: [{ name: channel, eventCount: 1, sourceType: "live" as const }],
      totalRecords: 1,
      parseErrors: 0,
      errorMessages: [],
    };
  };

  it("is queued and replayed when the load ends, so the control that made it can stay enabled", async () => {
    const firstReply = deferred<void>();
    let queryCount = 0;
    invoke.mockReset();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name !== "evtx_query_channels") return undefined;
      queryCount += 1;
      if (queryCount === 1) {
        await firstReply.promise;
      }
      return streamed(args);
    });
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
      selectedChannels: new Set(["Application"]),
      timeWindow: "24h",
      filterLevels: ALL(),
      filterEventIds: "",
      isLoading: false,
    });

    // A change that reloads starts the first refetch, and it is still running.
    useEvtxStore.getState().toggleFilterLevel("Information");
    await vi.waitFor(() => expect(queries()).toHaveLength(1));
    expect(useEvtxStore.getState().isLoading).toBe(true);

    // The window is changed during that load: nothing is sent yet.
    useEvtxStore.getState().setTimeWindow("7d");
    await settle();
    expect(queries()).toHaveLength(1);

    // When the first load ends, the queued change is replayed with the current window.
    firstReply.resolve();
    await vi.waitFor(() => expect(queries()).toHaveLength(2));
    expect(queries()[1].filter.time).toEqual({ kind: "last", milliseconds: 7 * 24 * 60 * 60 * 1000 });
    expect(queries()[1].filter.levels).toEqual([1, 2, 3, 5]);
  });
});
