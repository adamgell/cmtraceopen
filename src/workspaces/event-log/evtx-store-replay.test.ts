/**
 * The replay of a before-load change that was made while a live load ran.
 *
 * Changing the window, the levels or the Event IDs during a load cannot start a second read at
 * once, so the store remembers it and applies it when that load ends. One rule governs every place a
 * load ends (the channel refetch, the explicit Load, and the first live load):
 *
 * - Stop means stop. If the operator stopped the load that just ended, the queued change is dropped
 *   and no read starts on its own. The window keeps the operator's latest choice; the cancelled gaps
 *   already say the read is partial, and Load reads with the current criteria.
 * - Otherwise the change is replayed once against the channels the finished load attempted, not only
 *   those that ended usable, so a load in which every channel failed still applies it. Only a live
 *   source replays, and nothing retries: the flag is set only by an operator change.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
import { EVTX_LEVELS } from "./evtx-filter";
import type { EvtxRecord } from "./types";

const invoke = vi.hoisted(() => vi.fn());
const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => undefined);
  }),
}));

const { cancelActiveLoad, useEvtxStore } = await import("./evtx-store");

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

interface QueryArgs {
  requestId?: string;
  channels: string[];
  maxEvents: number | null;
  filter: { time?: { kind: string; milliseconds: number }; levels?: number[] };
}

const queries = () =>
  invoke.mock.calls
    .filter(([name]) => name === "evtx_query_channels")
    .map(([, args]) => args as QueryArgs);

const record = (channel: string, id: number): EvtxRecord => ({
  id,
  eventRecordId: id,
  timestamp: "2026-08-12T12:00:00.000Z",
  timestampEpoch: 1_000 + id,
  provider: "P",
  channel,
  eventId: 1,
  level: "Information",
  computer: "C",
  message: "m",
  eventData: [],
  rawXml: "<Event/>",
  sourceLabel: "Live",
  mapped: [],
});

const cancelledGap = (channel: string) => ({
  source: channel,
  kind: "cancelled" as const,
  reason: "operator stopped the load after 1 events were fetched (the channel may hold more)",
});

/** A finished read of one channel, its records delivered as a batch the way the backend does. */
function finished(args: QueryArgs, options: { cancelled?: boolean } = {}) {
  const channel = args.channels[0];
  listeners.get("evtx-record-batch")?.({
    payload: { requestId: args.requestId, channel, sequence: 0, records: [record(channel, 1)] },
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
    ...(options.cancelled ? { coverageGaps: [cancelledGap(channel)] } : {}),
  };
}

/** The channels as the service enumerates them. */
const enumerated = (...names: string[]) =>
  names.map((name) => ({
    name,
    eventCount: 1,
    sourceType: "live" as const,
    enabledState: "enabled" as const,
  }));

const settle = async () => {
  for (let turn = 0; turn < 20; turn += 1) await Promise.resolve();
};

function seedLive(loaded: string[], all = loaded) {
  useEvtxStore.getState().reset();
  useEvtxStore.setState({
    sourceMode: "live",
    channels: enumerated(...all),
    loadedChannels: new Set(loaded),
    selectedChannels: new Set(loaded),
    timeWindow: "24h",
    filterLevels: new Set(EVTX_LEVELS),
    filterEventIds: "",
    isLoading: false,
  });
}

const gapsText = () => useEvtxStore.getState().coverageGaps.join("\n");

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue(undefined);
});

describe("Stop means stop", () => {
  it("drops a change queued during a channel refetch that the operator stopped", async () => {
    const stopped = deferred<void>();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_cancel_channel_query") {
        stopped.resolve();
        return undefined;
      }
      if (name !== "evtx_query_channels") return undefined;
      const reply = finished(args, { cancelled: true });
      await stopped.promise;
      return reply;
    });
    seedLive(["Application"]);

    // A change that reloads starts the refetch; a wider window is chosen while it runs.
    useEvtxStore.getState().toggleFilterLevel("Information");
    await vi.waitFor(() => expect(queries()).toHaveLength(1));
    useEvtxStore.getState().setTimeWindow("7d");
    void cancelActiveLoad();
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
    await settle();

    expect(queries()).toHaveLength(1);
    const state = useEvtxStore.getState();
    expect(state.timeWindow).toBe("7d");
    expect(state.loadedChannels.size).toBe(0);
    expect(gapsText()).toContain("operator stopped the load");
  });

  it("drops a change queued during an explicit Load that the operator stopped", async () => {
    const stopped = deferred<void>();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_cancel_channel_query") {
        stopped.resolve();
        return undefined;
      }
      if (name !== "evtx_query_channels") return undefined;
      const reply = finished(args, { cancelled: true });
      await stopped.promise;
      return reply;
    });
    seedLive(["System"], ["System", "Application"]);

    const load = useEvtxStore.getState().queryChannels(["Application"]);
    await vi.waitFor(() => expect(queries()).toHaveLength(1));
    useEvtxStore.getState().setTimeWindow("7d");
    void cancelActiveLoad();
    await load;
    await settle();

    // Before the rule, the Load replayed on its own after Stop: a new unbounded read the operator
    // had just refused.
    expect(queries()).toHaveLength(1);
    expect(useEvtxStore.getState().timeWindow).toBe("7d");
    expect(gapsText()).toContain("operator stopped the load");
  });

  it("drops a change queued during a first live load that the operator stopped", async () => {
    const stopped = deferred<void>();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") return enumerated("Application", "System");
      if (name === "evtx_cancel_channel_query") {
        stopped.resolve();
        return undefined;
      }
      if (name !== "evtx_query_channels") return undefined;
      // Application is read in full at once; System is still reading when Stop is pressed.
      if (args.channels[0] === "Application") return finished(args);
      const reply = finished(args, { cancelled: true });
      await stopped.promise;
      return reply;
    });
    useEvtxStore.getState().reset();

    const first = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queries()).toHaveLength(2));
    useEvtxStore.getState().setTimeWindow("7d");
    void cancelActiveLoad();
    await first;
    await settle();

    // Application ended loaded, so the old rule refetched it for the queued change after Stop.
    expect(queries()).toHaveLength(2);
    expect(useEvtxStore.getState().loadedChannels.has("Application")).toBe(true);
    expect(useEvtxStore.getState().timeWindow).toBe("7d");
  });
});

describe("a queued change that was not stopped", () => {
  it("is replayed once against every channel a refetch attempted, even when all of them failed", async () => {
    const release = deferred<void>();
    let calls = 0;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name !== "evtx_query_channels") return undefined;
      calls += 1;
      if (calls <= 2) {
        // The refetch: both channels fail once the change has been queued.
        await release.promise;
        throw new Error("the service refused the read");
      }
      return finished(args);
    });
    seedLive(["Application", "System"]);

    useEvtxStore.getState().toggleFilterLevel("Information");
    await vi.waitFor(() => expect(queries()).toHaveLength(2));
    useEvtxStore.getState().setTimeWindow("7d");
    release.resolve();
    await vi.waitFor(() => expect(queries()).toHaveLength(4));
    await settle();

    // Exactly one replay, for both attempted channels, carrying the newer window.
    const replay = queries().slice(2);
    expect(queries()).toHaveLength(4);
    expect(replay.map((args) => args.channels[0]).sort()).toEqual(["Application", "System"]);
    for (const args of replay) {
      expect(args.filter.time).toEqual({ kind: "last", milliseconds: WEEK_MS });
    }
  });

  it("is replayed once after a first live load in which every core channel failed", async () => {
    const release = deferred<void>();
    let calls = 0;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") return enumerated("Application", "System");
      if (name !== "evtx_query_channels") return undefined;
      calls += 1;
      if (calls <= 2) {
        await release.promise;
        throw new Error("the service refused the read");
      }
      return finished(args);
    });
    useEvtxStore.getState().reset();

    const first = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queries()).toHaveLength(2));
    useEvtxStore.getState().setTimeWindow("7d");
    release.resolve();
    await first;
    await vi.waitFor(() => expect(queries()).toHaveLength(4));
    await settle();

    expect(queries()).toHaveLength(4);
    const replay = queries().slice(2);
    expect(replay.map((args) => args.channels[0]).sort()).toEqual(["Application", "System"]);
    for (const args of replay) {
      expect(args.filter.time).toEqual({ kind: "last", milliseconds: WEEK_MS });
    }
  });

  it("still replays a change queued during an explicit Load that finished normally", async () => {
    const release = deferred<void>();
    let calls = 0;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name !== "evtx_query_channels") return undefined;
      calls += 1;
      if (calls === 1) await release.promise;
      return finished(args);
    });
    seedLive(["System"], ["System", "Application"]);

    const load = useEvtxStore.getState().queryChannels(["Application"]);
    await vi.waitFor(() => expect(queries()).toHaveLength(1));
    useEvtxStore.getState().setTimeWindow("7d");
    release.resolve();
    await load;
    await vi.waitFor(() => expect(queries()).toHaveLength(3));
    await settle();

    // The Load re-reads the channels it queried plus those already loaded, once, with the new window.
    expect(queries()).toHaveLength(3);
    const replay = queries().slice(1);
    expect(replay.map((args) => args.channels[0]).sort()).toEqual(["Application", "System"]);
    for (const args of replay) {
      expect(args.filter.time).toEqual({ kind: "last", milliseconds: WEEK_MS });
    }
  });

  it("does not replay when the source is no longer live, and never retries", async () => {
    const release = deferred<void>();
    invoke.mockImplementation(async (name: string) => {
      if (name !== "evtx_query_remote_channels") return undefined;
      await release.promise;
      throw new Error("the service refused the read");
    });
    seedLive(["Application"]);
    useEvtxStore.setState({ remoteMachine: "SRV01" });
    const remoteQueries = () =>
      invoke.mock.calls.filter(([name]) => name === "evtx_query_remote_channels");

    useEvtxStore.getState().toggleFilterLevel("Information");
    await vi.waitFor(() => expect(remoteQueries()).toHaveLength(1));
    useEvtxStore.getState().setTimeWindow("7d");
    release.resolve();
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
    await settle();

    // A remote refetch in which everything failed drops the source (the source picker returns), so
    // nothing is replayed, and no later step sends anything on its own.
    expect(useEvtxStore.getState().sourceMode).toBeNull();
    expect(remoteQueries()).toHaveLength(1);
  });
});
