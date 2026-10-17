/**
 * The replay of a before-load change that was made while a live load ran.
 *
 * Changing the window, the levels or the Event IDs during a load cannot start a second read at
 * once, so the store remembers it and settles it when that load ends. One rule governs every place a
 * load ends (the channel refetch, the explicit Load, and the first live load), and it keeps one
 * invariant: the criteria the controls show equal the criteria the loaded data was read with.
 *
 * - A change that will not be replayed is restored. If the load that ended was stopped, or the source
 *   is no longer live once it ended (a remote refetch or first load that failed everywhere drops to no
 *   source), or the load failed before reading anything, the criteria go back to those the load read
 *   with, in the same update that ends the load, and no read starts on its own. A Stop does not mark
 *   every channel (a scan that had already finished leaves no cancelled gap, and a cancel can fail),
 *   and a dropped source leaves fragments, so the criteria cannot be left showing the newer window
 *   over data read with the older one. Quick filter and search are not server criteria and stay.
 * - Otherwise the change is replayed once against the channels the finished load attempted, not only
 *   those that ended usable, so a load in which every channel failed still applies it. Only a live
 *   source replays, and nothing retries: the flag is set only by an operator change.
 * - So after every load end, either the criteria equal the read's or exactly one replay runs.
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

const { cancelActiveLoad, serverFilterKey, useEvtxStore } = await import("./evtx-store");

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

type Kind = "refetch" | "load" | "firstLoad";

/**
 * Sets the store up for one kind of load and returns what starts it. The refetch has Application and
 * System loaded and starts by toggling Information (which changes what the service is asked for);
 * the explicit Load reads Application with System already loaded; the first load enumerates the
 * channels and reads the core ones. `remote` points the same load at a remote machine.
 */
function prepareLoad(kind: Kind, remote = false) {
  if (kind === "refetch") seedLive(["Application", "System"]);
  else if (kind === "load") seedLive(["System"], ["System", "Application"]);
  else useEvtxStore.getState().reset();
  if (remote) useEvtxStore.setState({ remoteMachine: "SRV01" });
  const start = {
    refetch: () => useEvtxStore.getState().toggleFilterLevel("Information"),
    load: () => void useEvtxStore.getState().queryChannels(["Application"]),
    firstLoad: () => void useEvtxStore.getState().enumerateChannels(),
  }[kind];
  return { start, ownReads: kind === "load" ? 1 : 2 };
}

/** Every read the store sent to a remote machine. */
const remoteReads = () =>
  invoke.mock.calls
    .filter(([name]) => name === "evtx_query_remote_channels")
    .map(([, args]) => args as QueryArgs);

/** The batch a channel streamed before its read failed: records delivered, no terminal marker. */
function streamedThenFail(args: QueryArgs) {
  const channel = args.channels[0];
  listeners.get("evtx-record-batch")?.({
    payload: { requestId: args.requestId, channel, sequence: 0, records: [record(channel, 1)] },
  });
}

/** A Stop that reaches the service: every read the test holds is released as cut. */
function installStoppableReads() {
  const stopped = deferred<void>();
  invoke.mockImplementation(async (name: string, args: QueryArgs) => {
    if (name === "evtx_enumerate_channels") return enumerated("Application", "System");
    if (name === "evtx_cancel_channel_query") {
      stopped.resolve();
      return undefined;
    }
    if (name !== "evtx_query_channels") return undefined;
    const reply = finished(args, { cancelled: true });
    await stopped.promise;
    return reply;
  });
}

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue(undefined);
});

describe("Stop means stop", () => {
  it("restores the criteria and sends nothing for a channel refetch the operator stopped", async () => {
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
    // The window shows what the (cut) read was made with, not the queued 7 days.
    expect(state.timeWindow).toBe("24h");
    expect(state.loadedChannels.size).toBe(0);
    expect(gapsText()).toContain("operator stopped the load");
  });

  it("restores the criteria and sends nothing for an explicit Load the operator stopped", async () => {
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
    expect(useEvtxStore.getState().timeWindow).toBe("24h");
    expect(gapsText()).toContain("operator stopped the load");
  });

  it("restores the criteria and sends nothing for a first live load the operator stopped", async () => {
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
    expect(useEvtxStore.getState().timeWindow).toBe("24h");
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

    // A remote refetch in which everything failed drops the source, so nothing is replayed and no
    // later step sends anything on its own. The fragments it left must not sit under the window the
    // operator chose afterwards, so the criteria are the ones the read used.
    expect(useEvtxStore.getState().sourceMode).toBeNull();
    expect(remoteQueries()).toHaveLength(1);
    expect(useEvtxStore.getState().timeWindow).toBe("24h");
  });
});

describe("what a restore puts back", () => {
  it.each(["refetch", "load", "firstLoad"] as const)(
    "puts back the window, the Event IDs and the levels the %s read used, and leaves quick filter and search",
    async (kind) => {
      installStoppableReads();
      const { start, ownReads } = prepareLoad(kind);
      useEvtxStore.setState({ filterEventIds: "1000" });
      start();
      await vi.waitFor(() => expect(queries()).toHaveLength(ownReads));
      const read = {
        timeWindow: useEvtxStore.getState().timeWindow,
        filterEventIds: useEvtxStore.getState().filterEventIds,
        levels: [...useEvtxStore.getState().filterLevels],
      };

      // While it runs: three server criteria change (queued), and two local ones.
      useEvtxStore.getState().setTimeWindow("7d");
      useEvtxStore.getState().setFilterEventIds("4624;4625");
      useEvtxStore.getState().toggleFilterLevel("Information");
      expect([...useEvtxStore.getState().filterLevels]).not.toEqual(read.levels);
      useEvtxStore.getState().setFilterSearch("logon");
      useEvtxStore.getState().setQuickFilter({
        ...useEvtxStore.getState().quickFilter,
        query: "noise",
        action: "hide",
      });

      void cancelActiveLoad();
      await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
      await settle();

      const state = useEvtxStore.getState();
      expect(state.timeWindow).toBe(read.timeWindow);
      expect(state.filterEventIds).toBe(read.filterEventIds);
      expect([...state.filterLevels]).toEqual(read.levels);
      expect(state.filterSearch).toBe("logon");
      expect(state.quickFilter.query).toBe("noise");
      expect(queries()).toHaveLength(ownReads);
    },
  );

  it.each(["refetch", "load", "firstLoad"] as const)(
    "writes the restored criteria in the same update that ends the %s, never after it",
    async (kind) => {
      installStoppableReads();
      const { start, ownReads } = prepareLoad(kind);
      start();
      await vi.waitFor(() => expect(queries()).toHaveLength(ownReads));
      useEvtxStore.getState().setTimeWindow("7d");

      // Every published state while the load ends: the window must never read 7d with isLoading
      // false, which a restore written in a second update after the end would publish.
      const seen: Array<{ isLoading: boolean; timeWindow: string }> = [];
      const unsubscribe = useEvtxStore.subscribe((state) => {
        seen.push({ isLoading: state.isLoading, timeWindow: state.timeWindow });
      });
      void cancelActiveLoad();
      await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
      unsubscribe();

      const ended = seen.filter((state) => !state.isLoading);
      expect(ended.length).toBeGreaterThan(0);
      expect(ended.every((state) => state.timeWindow === "24h")).toBe(true);
    },
  );

  it("restores the 24h a first load from a file source read, not the all it started from", async () => {
    // A file source leaves the window at "all"; a live first load reads with 24h, which it sets after
    // the request begins. The restore must put back what the read sent.
    installStoppableReads();
    useEvtxStore.getState().reset();
    useEvtxStore.setState({ timeWindow: "all" });
    void useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queries()).toHaveLength(2));
    expect(queries()[0].filter.time).toEqual({ kind: "last", milliseconds: 24 * 60 * 60 * 1000 });
    expect(useEvtxStore.getState().timeWindow).toBe("24h");

    useEvtxStore.getState().setTimeWindow("7d");
    void cancelActiveLoad();
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
    await settle();

    expect(useEvtxStore.getState().timeWindow).toBe("24h");
  });

  it("restores the criteria when the first load's enumeration fails before anything is read", async () => {
    // The catch path. Nothing was read, so it is observable only through the criteria: the window the
    // operator queued during the failed enumeration must not stay on the controls.
    const gate = deferred<void>();
    invoke.mockImplementation(async (name: string) => {
      if (name !== "evtx_enumerate_channels") return undefined;
      await gate.promise;
      throw new Error("the service could not enumerate the channels");
    });
    useEvtxStore.getState().reset();
    const first = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() =>
      expect(invoke.mock.calls.some(([name]) => name === "evtx_enumerate_channels")).toBe(true),
    );
    useEvtxStore.getState().setTimeWindow("7d");
    gate.resolve();
    await first;
    await settle();

    expect(useEvtxStore.getState().isLoading).toBe(false);
    expect(useEvtxStore.getState().loadError).toContain("could not enumerate");
    expect(useEvtxStore.getState().timeWindow).toBe("24h");
    expect(queries()).toHaveLength(0);
  });
});

describe("the criteria always match the data, whichever way a load ends", () => {
  type End = "normal" | "stopCutsSome" | "stopAfterScans" | "cancelFails" | "superseded";

  /** How many channels the finished load attempted, and so how many reads one replay makes. */
  const REPLAY_READS: Record<Kind, { own: number; afterSupersede: number }> = {
    refetch: { own: 2, afterSupersede: 1 },
    load: { own: 2, afterSupersede: 2 },
    firstLoad: { own: 2, afterSupersede: 1 },
  };
  const STOPPED: readonly End[] = ["stopCutsSome", "stopAfterScans", "cancelFails"];

  const rows = (["refetch", "load", "firstLoad"] as const).flatMap((kind) =>
    (["normal", "stopCutsSome", "stopAfterScans", "cancelFails", "superseded"] as const).flatMap(
      (end) =>
        [false, true].map((queued) => ({ kind, end, queued }) as { kind: Kind; end: End; queued: boolean }),
    ),
  );

  const keyNow = () => {
    const state = useEvtxStore.getState();
    return serverFilterKey(state.timeWindow, state.filterEventIds, state.filterLevels);
  };

  it.each(rows)(
    "$kind load ending $end, change queued: $queued",
    async ({ kind, end, queued }) => {
      const gate = deferred<void>();
      const cut = deferred<void>();
      let released = false;
      // The channel a Stop cuts: the last one the load reads.
      const cutChannel = kind === "load" ? "Application" : "System";

      invoke.mockImplementation(async (name: string, args: QueryArgs) => {
        if (name === "evtx_enumerate_channels") return enumerated("Application", "System");
        if (name === "evtx_cancel_channel_query") {
          if (end === "cancelFails") throw new Error("the cancel did not reach the service");
          cut.resolve();
          return undefined;
        }
        if (name !== "evtx_query_channels") return undefined;
        const channel = args.channels[0];
        // A read that starts after the load has been released (a replay) answers at once.
        if (released || channel === "Security") return finished(args);
        if (end === "stopCutsSome") {
          if (channel !== cutChannel) return finished(args);
          const reply = finished(args, { cancelled: true });
          await cut.promise;
          return reply;
        }
        // Every scan has finished; the reply is held until the end of the scenario.
        const reply = finished(args);
        await gate.promise;
        return reply;
      });

      const { start, ownReads } = prepareLoad(kind);
      start();
      await vi.waitFor(() => expect(queries()).toHaveLength(ownReads));

      // The criteria this request reads with, and then the operator's change while it runs.
      const readKey = keyNow();
      if (queued) useEvtxStore.getState().setTimeWindow("7d");
      const newKey = keyNow();
      expect(newKey === readKey).toBe(!queued);

      let supersedingReads = 0;
      if (end === "superseded") {
        supersedingReads = 1;
        void useEvtxStore.getState().queryChannels(["Security"]);
        await vi.waitFor(() => expect(queries()).toHaveLength(ownReads + 1));
      } else if (end !== "normal") {
        void cancelActiveLoad();
      }
      released = true;
      gate.resolve();

      await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
      await settle();
      await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));

      const replays = queries().slice(ownReads + supersedingReads);
      const storeKey = keyNow();
      const matchesTheRead = storeKey === readKey;
      const replayedOnce =
        storeKey === newKey &&
        replays.length ===
          (end === "superseded" ? REPLAY_READS[kind].afterSupersede : REPLAY_READS[kind].own) &&
        new Set(replays.map((args) => args.channels[0])).size === replays.length &&
        replays.every((args) => args.filter.time?.milliseconds === WEEK_MS);

      // The class: the criteria shown are the criteria the data was read with, or the change was
      // applied by exactly one replay. Nothing in between.
      expect(matchesTheRead || replayedOnce, `criteria ${storeKey} vs read ${readKey}`).toBe(true);

      if (STOPPED.includes(end)) {
        // Stop means stop: no read of any kind starts after it, and the window went back.
        expect(replays).toHaveLength(0);
        expect(matchesTheRead).toBe(true);
        expect(useEvtxStore.getState().timeWindow).toBe("24h");
      } else if (queued) {
        expect(replayedOnce).toBe(true);
        expect(useEvtxStore.getState().timeWindow).toBe("7d");
      } else {
        expect(replays).toHaveLength(0);
        expect(matchesTheRead).toBe(true);
      }
    },
  );
});

describe("a remote source whose load failed on every channel", () => {
  const remoteRows = (["refetch", "firstLoad", "load"] as const).flatMap((kind) =>
    [false, true].map((queued) => ({ kind, queued })),
  );

  const keyNow = () => {
    const state = useEvtxStore.getState();
    return serverFilterKey(state.timeWindow, state.filterEventIds, state.filterLevels);
  };

  it.each(remoteRows)(
    "remote $kind, change queued: $queued",
    async ({ kind, queued }) => {
      const gate = deferred<void>();
      let released = false;
      invoke.mockImplementation(async (name: string, args: QueryArgs) => {
        if (name === "evtx_enumerate_remote_channels") return enumerated("Application", "System");
        if (name !== "evtx_query_remote_channels") return undefined;
        // Reads that start after the release (a replay) succeed; the first ones lose the connection
        // after their channel has streamed a batch.
        if (released) return finished(args);
        streamedThenFail(args);
        await gate.promise;
        throw new Error("the connection to SRV01 dropped");
      });

      const { start, ownReads } = prepareLoad(kind, true);
      start();
      await vi.waitFor(() => expect(remoteReads()).toHaveLength(ownReads));
      const readKey = keyNow();
      if (queued) useEvtxStore.getState().setTimeWindow("7d");
      const newKey = keyNow();

      released = true;
      gate.resolve();
      await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
      await settle();
      await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));

      const replays = remoteReads().slice(ownReads);
      const storeKey = keyNow();
      const matchesTheRead = storeKey === readKey;
      const replayedOnce =
        storeKey === newKey &&
        replays.length === 2 &&
        new Set(replays.map((args) => args.channels[0])).size === 2 &&
        replays.every((args) => args.filter.time?.milliseconds === WEEK_MS);

      // The invariant, on every row: the criteria are the ones the read used, or one replay ran.
      expect(matchesTheRead || replayedOnce, `criteria ${storeKey} vs read ${readKey}`).toBe(true);

      if (kind === "load") {
        // An explicit Load never drops the source: it stays live, and the change replays once over
        // the channels it queried plus those already loaded.
        expect(useEvtxStore.getState().sourceMode).toBe("live");
        expect(replayedOnce).toBe(queued);
        expect(replays).toHaveLength(queued ? 2 : 0);
      } else {
        // A refetch or a first load that failed everywhere drops the source: nothing replays, and
        // the criteria are put back so the fragments are not shown under the newer window.
        expect(useEvtxStore.getState().sourceMode).toBeNull();
        expect(replays).toHaveLength(0);
        expect(matchesTheRead).toBe(true);
        expect(useEvtxStore.getState().timeWindow).toBe("24h");
      }
    },
  );
});

describe("a change queued for one source does not replay on the next", () => {
  const queueDuringRefetch = async () => {
    const release = deferred<void>();
    let calls = 0;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") return enumerated("Application", "System");
      if (name !== "evtx_query_channels") return undefined;
      calls += 1;
      const reply = finished(args);
      if (calls <= 2) await release.promise;
      return reply;
    });
    seedLive(["Application", "System"]);
    useEvtxStore.getState().toggleFilterLevel("Information");
    await vi.waitFor(() => expect(queries()).toHaveLength(2));
    useEvtxStore.getState().setTimeWindow("7d");
    return release;
  };

  it.each([
    ["enumerateLocalChannels", () => useEvtxStore.getState().enumerateLocalChannels()],
    ["reset and a new first load", async () => {
      useEvtxStore.getState().reset();
      await useEvtxStore.getState().enumerateChannels();
    }],
  ])("%s", async (_name, changeSource) => {
    const release = await queueDuringRefetch();
    await changeSource();
    release.resolve();
    await settle();

    // The new source's first load reads its two core channels once each, and nothing replays: the
    // stale flag died with the old source. Without that, the end of this load would read again.
    const reads = queries();
    expect(reads).toHaveLength(4);
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
    await settle();
    expect(queries()).toHaveLength(4);
  });

  it("enumerateRemoteChannels", async () => {
    const release = await queueDuringRefetch();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_remote_channels") return enumerated("Application", "System");
      if (name === "evtx_query_remote_channels") return finished(args);
      return undefined;
    });
    await useEvtxStore.getState().enumerateRemoteChannels("SRV01");
    release.resolve();
    await settle();
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
    await settle();

    // Two remote core reads for the new source and no replay of the old source's change.
    const remote = invoke.mock.calls.filter(([name]) => name === "evtx_query_remote_channels");
    expect(remote).toHaveLength(2);
  });
});

describe("completedSourceKey", () => {
  it("is already recorded when a replayed change starts reading in the same tick", async () => {
    const release = deferred<void>();
    let calls = 0;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") return enumerated("Application", "System");
      if (name !== "evtx_query_channels") return undefined;
      calls += 1;
      const reply = finished(args);
      if (calls <= 2) await release.promise;
      return reply;
    });
    useEvtxStore.getState().reset();
    const first = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queries()).toHaveLength(2));
    useEvtxStore.getState().setTimeWindow("7d");

    // Every published state: whenever a read is loading with nothing loaded yet, the first load must
    // already be recorded as completed, or the workspace would show its spinner for the replay.
    const seen: Array<{ isLoading: boolean; empty: boolean; key: string | null }> = [];
    const unsubscribe = useEvtxStore.subscribe((state) => {
      seen.push({
        isLoading: state.isLoading,
        empty: state.records.length === 0,
        key: state.completedSourceKey,
      });
    });
    release.resolve();
    await first;
    await vi.waitFor(() => expect(queries()).toHaveLength(4));
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
    unsubscribe();

    const replayStarted = seen.findIndex(
      (state, index) => index > 0 && state.isLoading && state.empty && !seen[index - 1].isLoading,
    );
    expect(replayStarted).toBeGreaterThan(0);
    expect(seen[replayStarted].key).toBe("live\u0000");
  });

  it("is cleared when the source goes", () => {
    useEvtxStore.setState({
      sourceMode: "live",
      completedSourceKey: "live\u0000",
      isLoading: false,
    });
    useEvtxStore.getState().reset();
    expect(useEvtxStore.getState().completedSourceKey).toBeNull();
  });
});
