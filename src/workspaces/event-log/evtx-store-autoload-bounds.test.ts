/**
 * Bounded automatic channel loading.
 *
 * Opening the workspace acquires the four core Windows Logs channels without being asked. On the
 * machine the defect was measured, Security held 239,704 events in twenty-four hours and took 318
 * seconds to read, so the workspace sat empty behind one channel with its controls disabled. These
 * tests pin the behaviour that keeps that read short and keeps the automatic load from stacking:
 * a per-channel bound, a bounded fan-out, rows that appear as channels land, one scan per
 * equivalent request, and a channel that was cut off saying so. The explicit Load stays unbounded,
 * so a whole channel remains reachable.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
import type {
  EvtxChannelEnabledState,
  EvtxChannelInfo,
  EvtxLevel,
  EvtxRecord,
} from "./types";

const invoke = vi.hoisted(() => vi.fn());

// The store subscribes to backend events at module scope. Capturing the handlers lets a test deliver
// a batch and the terminal marker exactly as the backend would.
const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => {});
  }),
}));

// Static import cannot work here: the store subscribes to the mocked bridge above at module scope,
// so it has to be imported after the mock is registered.
const { channelCanHoldEvents, useEvtxStore } = await import("./evtx-store");

/**
 * The bound the automatic load asks for: the newest two thousand events per channel.
 *
 * This is a policy choice, not a measurement of the machine. The measurement behind it is the
 * 239,704-event / 318-second Security read that the bound exists to cut short; the value comes from
 * the #611 behaviour contract.
 */
const AUTO_LOAD_MAX_EVENTS = 2_000;

/** Channel reads allowed in flight at once. */
const MAX_CONCURRENT_CHANNEL_QUERIES = 4;

/** The channels the automatic load acquires without being asked. */
const CORE_CHANNELS = ["Application", "System", "Security", "Setup"];

const ALL_LEVELS: EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

interface QueryArgs {
  channels?: string[];
  maxEvents?: number | null;
  filter?: Record<string, unknown>;
  requestId?: string;
  machine?: string;
}

/** A channel as the service enumerates it, carrying the recording state the #613 contract added. */
function channel(
  name: string,
  enabledState: EvtxChannelEnabledState,
  eventCount = 0
): EvtxChannelInfo {
  return { name, eventCount, sourceType: "live", enabledState };
}

function recordFor(channelName: string, id: number): EvtxRecord {
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-12T12:00:00.000Z",
    timestampEpoch: 1_000 + id,
    provider: "P",
    channel: channelName,
    eventId: 1,
    level: "Information",
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "<Event/>",
    sourceLabel: "Live",
    mapped: [],
  };
}

function queryCalls(): QueryArgs[] {
  return invoke.mock.calls
    .filter(
      (call) => call[0] === "evtx_query_channels" || call[0] === "evtx_query_remote_channels"
    )
    .map((call) => (call[1] ?? {}) as QueryArgs);
}

/** Delivers a record batch the way the backend emits one. */
function deliver(
  channelName: string,
  sequence: number,
  records: EvtxRecord[],
  requestId: string | undefined
): void {
  listeners.get("evtx-record-batch")?.({
    payload: { requestId, channel: channelName, sequence, records },
  });
}

/** Delivers the terminal marker that says a channel's batches are done. */
function complete(
  channelName: string,
  sequenceCount: number,
  totalRecords: number,
  requestId: string | undefined
): void {
  listeners.get("evtx-record-stream-complete")?.({
    payload: { requestId, channel: channelName, sequenceCount, totalRecords },
  });
}

/**
 * A reply whose records travelled as batches: it carries the channel's count and no rows.
 *
 * The terminal marker is delivered before the reply resolves, the way the backend delivers it. The
 * store waits for that marker before it reconciles, so a reply without one would hang the load
 * rather than fail it.
 */
function streamed(args: QueryArgs, totalRecords: number, records: EvtxRecord[] = []) {
  const channelName = args.channels?.[0] ?? "";
  if (records.length > 0) deliver(channelName, 0, records, args.requestId);
  complete(channelName, records.length > 0 ? 1 : 0, totalRecords, args.requestId);
  return {
    records: [],
    channels: [{ name: channelName, eventCount: totalRecords, sourceType: "live" as const }],
    totalRecords,
    parseErrors: 0,
    errorMessages: [],
  };
}

/** A turn the store's pool gets to start whatever it is ever going to start. */
async function turns(count = 50): Promise<void> {
  for (let turn = 0; turn < count; turn += 1) await Promise.resolve();
}

describe("the automatic load's per-channel bound", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      coverageDetails: [],
      sourceManifest: null,
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
      remoteMachine: null,
      sourceMode: null,
      isLoading: false,
      loadError: null,
      timeWindow: "24h",
      filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
      filterEventIds: "",
    });
  });

  it("asks for the newest two thousand events per channel on the automatic load", async () => {
    // The window alone never bounded a channel: Security carried 239,704 events inside twenty-four
    // hours and took 318 seconds to read, and the workspace had nothing to show until it finished.
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return CORE_CHANNELS.map((core) => channel(core, "enabled"));
      }
      return streamed(args, 0);
    });

    await useEvtxStore.getState().enumerateChannels();

    expect(queryCalls().map((args) => args.maxEvents)).toEqual(
      CORE_CHANNELS.map(() => AUTO_LOAD_MAX_EVENTS)
    );
  });

  it("asks for the same bound when the time window refetches the loaded channels", async () => {
    // Changing the window refetches whatever is on screen. Reading a channel in full there puts the
    // multi-minute read straight back on the path the bound exists to keep short, and a channel cut
    // off by the bound has to say so here too: the same slice must not look whole on this path.
    useEvtxStore.setState({
      sourceMode: "live",
      loadedChannels: new Set(["Security"]),
    });
    invoke.mockImplementation(async (_name: string, args: QueryArgs) =>
      streamed(
        args,
        AUTO_LOAD_MAX_EVENTS,
        Array.from({ length: AUTO_LOAD_MAX_EVENTS }, (_, index) =>
          recordFor("Security", index + 1)
        )
      )
    );

    await useEvtxStore.getState().refreshLoadedChannels();

    expect(queryCalls().map((args) => args.maxEvents)).toEqual([AUTO_LOAD_MAX_EVENTS]);
    expect(
      useEvtxStore.getState().coverageGaps.find((gap) => gap.includes("may hold more"))
    ).toBeDefined();
  });

  it("leaves the explicit Load unbounded so a whole channel stays reachable", async () => {
    // The bound belongs to the load nobody asked for. `Load` is the operator asking for everything.
    useEvtxStore.setState({
      selectedChannels: new Set(["Security"]),
      loadedChannels: new Set<string>(),
    });
    invoke.mockImplementation(async (_name: string, args: QueryArgs) => streamed(args, 0));

    await useEvtxStore.getState().loadSelectedChannels();

    expect(queryCalls().map((args) => args.maxEvents)).toEqual([null]);
  });

  it("says a capped channel is showing a slice instead of presenting it as whole", async () => {
    // The read stopped at the bound, so this side cannot tell whether the channel held more.
    // The note reports what was not read and leaves the possibility open.
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return [channel("Security", "enabled", AUTO_LOAD_MAX_EVENTS)];
      }
      const rows = Array.from({ length: AUTO_LOAD_MAX_EVENTS }, (_, index) =>
        recordFor("Security", index + 1)
      );
      return streamed(args, AUTO_LOAD_MAX_EVENTS, rows);
    });

    await useEvtxStore.getState().enumerateChannels();

    const note = useEvtxStore
      .getState()
      .coverageGaps.find((gap) => gap.startsWith("Security") && gap.includes("newest"));
    expect(note).toBeDefined();
    expect(note).toContain(String(AUTO_LOAD_MAX_EVENTS));
    expect(note).toContain("may hold more");
  });

  it("does not call a channel capped when it came back under the bound", async () => {
    // The boundary the other way: a channel that ended below the bound was read to its end, and a
    // note there would be a false accusation about a complete view.
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return [channel("Security", "enabled", 5)];
      }
      return streamed(
        args,
        5,
        Array.from({ length: 5 }, (_, index) => recordFor("Security", index + 1))
      );
    });

    await useEvtxStore.getState().enumerateChannels();

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });
});

describe("the fan-out behind a channel load", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      coverageDetails: [],
      sourceManifest: null,
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
      remoteMachine: null,
      sourceMode: null,
      isLoading: false,
      loadError: null,
      timeWindow: "24h",
      filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
      filterEventIds: "",
    });
  });

  it("reads a whole-machine selection four channels at a time", async () => {
    // Select all names every channel on the machine. Issuing one request per channel at once queues
    // hundreds of reads at a service that serializes much of that work.
    const channels = Array.from({ length: 12 }, (_, index) => `Channel-${index}`);
    const gate = deferred<void>();
    let started = 0;
    invoke.mockImplementation(async (_name: string, args: QueryArgs) => {
      started += 1;
      await gate.promise;
      return streamed(args, 0);
    });

    const load = useEvtxStore.getState().queryChannels(channels);
    await vi.waitFor(() => expect(started).toBeGreaterThan(0));
    await turns();

    expect(started).toBe(MAX_CONCURRENT_CHANNEL_QUERIES);

    gate.resolve(undefined);
    await load;

    expect(useEvtxStore.getState().loadedChannels.size).toBe(channels.length);
  });

  it("keeps one automatic scan when the workspace remounts while it is reading", async () => {
    // A remount used to start a second scan of every channel while the first was still reading,
    // which is what stacked three concurrent Security scans on the measuring machine. The remount
    // arrives after the running scan has started reading, which is what a workspace remount does.
    const gate = deferred<void>();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return CORE_CHANNELS.map((core) => channel(core, "enabled"));
      }
      await gate.promise;
      return streamed(args, 0);
    });

    const first = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queryCalls()).toHaveLength(CORE_CHANNELS.length));
    const remount = useEvtxStore.getState().enumerateChannels();
    await turns();
    gate.resolve(undefined);
    await Promise.all([first, remount]);

    expect(queryCalls()).toHaveLength(CORE_CHANNELS.length);
    expect(queryCalls().map((args) => args.channels?.[0] ?? "").sort()).toEqual(
      [...CORE_CHANNELS].sort()
    );
  });

  it("keeps the automatic fan-out inside the same four-read bound when a mount repeats", async () => {
    // The stacked scans are the same defect seen from the service's side: eight reads where four is
    // the bound, all of them for channels the running scan is already reading.
    const gate = deferred<void>();
    let inFlight = 0;
    let peakInFlight = 0;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return CORE_CHANNELS.map((core) => channel(core, "enabled"));
      }
      inFlight += 1;
      peakInFlight = Math.max(peakInFlight, inFlight);
      await gate.promise;
      inFlight -= 1;
      return streamed(args, 0);
    });

    const first = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queryCalls()).toHaveLength(CORE_CHANNELS.length));
    const remount = useEvtxStore.getState().enumerateChannels();
    await turns();
    gate.resolve(undefined);
    await Promise.all([first, remount]);

    expect(peakInFlight).toBe(MAX_CONCURRENT_CHANNEL_QUERIES);
  });

  it("starts its own scan instead of joining a load a newer request superseded", async () => {
    // A running scan whose request has been superseded writes nothing: every result it produces is
    // rejected as stale. A mount that joined it would wait for a load that can never fill the view.
    const gate = deferred<void>();
    let reads = 0;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return CORE_CHANNELS.map((core) => channel(core, "enabled"));
      }
      reads += 1;
      // The automatic scan's own four reads are the ones left hanging.
      if (reads <= CORE_CHANNELS.length) await gate.promise;
      return streamed(args, 0);
    });

    const superseded = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queryCalls()).toHaveLength(CORE_CHANNELS.length));

    // A different request takes over the view.
    await useEvtxStore.getState().queryChannels(["Application"]);

    const remount = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queryCalls()).toHaveLength(CORE_CHANNELS.length * 2 + 1));

    gate.resolve(undefined);
    await Promise.all([superseded, remount]);
  });

  it("shows a channel as it lands instead of waiting for the slowest one", async () => {
    // Collecting every channel before merging any of them leaves the view empty until the slowest
    // one answers, and Security alone is minutes on a busy machine.
    const slow = deferred<void>();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return CORE_CHANNELS.map((core) => channel(core, "enabled"));
      }
      const target = args.channels?.[0] ?? "";
      if (target === "Security") await slow.promise;
      return streamed(args, 1, [recordFor(target, 1)]);
    });

    const load = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() =>
      expect(
        useEvtxStore.getState().records.some((record) => record.channel === "Application")
      ).toBe(true)
    );

    expect(useEvtxStore.getState().records.some((record) => record.channel === "Security")).toBe(
      false
    );

    slow.resolve(undefined);
    await load;

    expect([...useEvtxStore.getState().records.map((record) => record.channel)].sort()).toEqual(
      [...CORE_CHANNELS].sort()
    );
  });

  it("does not fold a differently-scoped automatic load into the one in flight", async () => {
    // Joining a load is only correct for an equivalent request. Once the window has changed, the
    // running scan is the wrong scan, and folding it in would answer the new criteria with the old
    // request's slice.
    const gate = deferred<void>();
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") return [channel("Security", "enabled")];
      await gate.promise;
      return streamed(args, 0);
    });

    const first = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(queryCalls()).toHaveLength(1));

    // Set directly: the window's own refetch has its own test, and its queueing would put a third
    // scan in the middle of this one.
    useEvtxStore.setState({ timeWindow: "1h" });
    const second = useEvtxStore.getState().enumerateChannels();
    gate.resolve(undefined);
    await Promise.all([first, second]);

    expect(queryCalls()).toHaveLength(2);
    expect(queryCalls()[0].filter).not.toEqual(queryCalls()[1].filter);
    expect(queryCalls()[1].filter).toMatchObject({ time: { kind: "last", milliseconds: 3_600_000 } });
  });

  it("keeps a superseded automatic load's records out of the view", async () => {
    // A mount superseded while it runs must not publish what it read: those records answer a
    // request the operator has already left.
    const gate = deferred<void>();
    let supersededRequestId: string | undefined;
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") {
        return CORE_CHANNELS.map((core) => channel(core, "enabled"));
      }
      if (args.channels?.[0] === "Security") {
        supersededRequestId = args.requestId;
        await gate.promise;
        return streamed(args, 1, [recordFor("Security", 7)]);
      }
      return streamed(args, 0);
    });

    const superseded = useEvtxStore.getState().enumerateChannels();
    await vi.waitFor(() => expect(supersededRequestId).toBeDefined());

    invoke.mockImplementation(async (_name: string, args: QueryArgs) =>
      streamed(args, 1, [recordFor("System", 1)])
    );
    await useEvtxStore.getState().queryChannels(["System"]);

    gate.resolve(undefined);
    await superseded;

    expect(useEvtxStore.getState().records.map((record) => record.channel)).toEqual(["System"]);
  });

  it("acquires exactly the core channels the eligibility contract admits", async () => {
    // The #613 contract this load consumes, asserted against the predicate itself rather than a
    // second copy of the rule: a channel the service reports as switched off is not acquired, and a
    // channel whose configuration could not be read still is, because silence is not "off".
    const enumerated = [
      channel("Application", "enabled", 10),
      channel("System", "unknown", 20),
      channel("Security", "disabled"),
      channel("Setup", "enabled", 30),
    ];
    invoke.mockImplementation(async (name: string, args: QueryArgs) => {
      if (name === "evtx_enumerate_channels") return enumerated;
      return streamed(args, 1);
    });

    await useEvtxStore.getState().enumerateChannels();

    const admitted = enumerated
      .filter((info) => channelCanHoldEvents(info))
      .map((info) => info.name)
      .sort();
    expect(admitted).toEqual(["Application", "Setup", "System"]);
    expect(queryCalls().map((args) => args.channels?.[0] ?? "").sort()).toEqual(admitted);
    expect([...useEvtxStore.getState().selectedChannels].sort()).toEqual(admitted);
  });
});
