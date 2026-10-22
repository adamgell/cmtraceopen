/**
 * The transient criteria (spec section 9): a time range and a record scope that live in the view.
 *
 * They are local to the loaded events, so they never refetch; they are cleared when a load starts or
 * the source changes, because both replace the records they were drawn over; and the record scope
 * holds record OBJECTS, because `EvtxRecord.id` is an index the store rewrites on every merge.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  EVTX_LEVELS,
  selectVisibleRecords,
  type EvtxRecordScope,
  type EvtxRecordScopeCounts,
} from "./evtx-filter";
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

// Imported after the mocks: the store subscribes to the bridge at module scope.
const { useEvtxStore } = await import("./evtx-store");

const NO_COUNTS: EvtxRecordScopeCounts = {
  notLoaded: 0,
  noUsableIdentity: 0,
  ambiguous: 0,
  bounded: false,
};

function record(eventRecordId: number, channel = "Application", timestampEpoch = eventRecordId): EvtxRecord {
  return {
    id: 0,
    eventRecordId,
    timestamp: "2026-01-01T00:00:00Z",
    timestampEpoch,
    provider: "Test",
    channel,
    eventId: 1,
    level: "Error",
    computer: "TEST",
    message: `event ${eventRecordId}`,
    eventData: [],
    rawXml: `<Event><EventRecordID>${eventRecordId}</EventRecordID></Event>`,
    sourceLabel: "Live",
  };
}

const scopeOf = (records: EvtxRecord[], overrides: Partial<EvtxRecordScope> = {}): EvtxRecordScope => ({
  kind: "finding",
  title: "A finding",
  records: new Set(records),
  counts: { ...NO_COUNTS },
  ...overrides,
});

/** Lets the store's microtask-scheduled refresh run. */
const settle = async () => {
  for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
};

const queries = () => invoke.mock.calls.filter(([name]) => name === "evtx_query_channels");

let loaded: EvtxRecord[];

beforeEach(() => {
  invoke.mockReset();
  // Every request stays pending: these tests look at what was asked and at the state right after.
  invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
    if (name === "evtx_start_tail") {
      return {
        requestId: args.requestId,
        channel: args.channel,
        mode: "subscription",
        active: true,
        nextSequence: 0,
        coverageGaps: [],
      };
    }
    if (name === "evtx_clear_channel") return { channel: args.channel, result: { status: "cleared" } };
    return new Promise(() => undefined);
  });
  useEvtxStore.getState().reset();
  loaded = [record(10), record(20), record(30), record(40, "System"), record(50, "System")];
  loaded.forEach((entry, index) => {
    entry.id = index;
  });
  useEvtxStore.setState({
    sourceMode: "live",
    channels: [
      { name: "Application", eventCount: 3, sourceType: "live" },
      { name: "System", eventCount: 2, sourceType: "live" },
    ],
    records: loaded,
    loadedChannels: new Set(["Application", "System"]),
    selectedChannels: new Set(["Application", "System"]),
    isLoading: false,
  });
});

describe("setTimeRange", () => {
  it("stores the range as given and clears it with null", () => {
    expect(useEvtxStore.getState().setTimeRange({ startMs: 10, endMs: 30 })).toBe(true);
    expect(useEvtxStore.getState().timeRange).toEqual({ startMs: 10, endMs: 30 });
    expect(useEvtxStore.getState().setTimeRange(null)).toBe(true);
    expect(useEvtxStore.getState().timeRange).toBeNull();
  });

  it("puts a reversed pair in order", () => {
    useEvtxStore.getState().setTimeRange({ startMs: 30, endMs: 10 });
    expect(useEvtxStore.getState().timeRange).toEqual({ startMs: 10, endMs: 30 });
  });

  it("refuses a range that is not finite or holds no time, and keeps the one it had", () => {
    useEvtxStore.getState().setTimeRange({ startMs: 10, endMs: 30 });
    for (const range of [
      { startMs: 5, endMs: 5 },
      { startMs: Number.NaN, endMs: 5 },
      { startMs: 5, endMs: Infinity },
    ]) {
      expect(useEvtxStore.getState().setTimeRange(range), JSON.stringify(range)).toBe(false);
    }
    expect(useEvtxStore.getState().timeRange).toEqual({ startMs: 10, endMs: 30 });
  });

  it("refuses a range while a load runs, which holds no range, and still accepts a clear", () => {
    useEvtxStore.setState({ isLoading: true });
    expect(useEvtxStore.getState().setTimeRange({ startMs: 1, endMs: 2 })).toBe(false);
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(useEvtxStore.getState().setTimeRange(null)).toBe(true);
  });
});

describe("setRecordScope", () => {
  it("stores the scope and clears it with null", () => {
    const scope = scopeOf([loaded[0], loaded[2]]);
    expect(useEvtxStore.getState().setRecordScope(scope)).toBe(true);
    const held = useEvtxStore.getState().recordScope;
    expect([...(held?.records ?? [])]).toEqual([loaded[0], loaded[2]]);
    expect(held?.title).toBe("A finding");
    expect(useEvtxStore.getState().setRecordScope(null)).toBe(true);
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });

  it("holds its own copy of the set", () => {
    const records = new Set([loaded[0]]);
    useEvtxStore.getState().setRecordScope({ ...scopeOf([]), records });
    records.add(loaded[1]);
    expect(useEvtxStore.getState().recordScope?.records.size).toBe(1);
  });

  it("refuses an empty scope, which would show nothing", () => {
    expect(useEvtxStore.getState().setRecordScope(scopeOf([]))).toBe(false);
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });

  it("drops records that are not loaded and counts them, rather than keeping them silently", () => {
    const stranger = record(99);
    useEvtxStore.getState().setRecordScope(
      scopeOf([loaded[0], stranger], { counts: { ...NO_COUNTS, notLoaded: 2 } }),
    );
    const held = useEvtxStore.getState().recordScope;
    expect([...(held?.records ?? [])]).toEqual([loaded[0]]);
    expect(held?.counts.notLoaded).toBe(3);
  });

  it("refuses a scope none of whose records is loaded", () => {
    expect(useEvtxStore.getState().setRecordScope(scopeOf([record(99)]))).toBe(false);
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });

  it("refuses a scope while a load runs", () => {
    useEvtxStore.setState({ isLoading: true });
    expect(useEvtxStore.getState().setRecordScope(scopeOf([loaded[0]]))).toBe(false);
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });
});

describe("no transient criterion refetches", () => {
  it("sends no query and starts no load on a live source that holds records", async () => {
    useEvtxStore.getState().setTimeRange({ startMs: 10, endMs: 30 });
    useEvtxStore.getState().setRecordScope(scopeOf([loaded[0]]));
    useEvtxStore.getState().setTimeRange(null);
    useEvtxStore.getState().setRecordScope(null);
    useEvtxStore.getState().clearTransientCriteria();
    await settle();
    expect(queries()).toHaveLength(0);
    expect(useEvtxStore.getState().isLoading).toBe(false);
    expect(useEvtxStore.getState().records).toBe(loaded);
  });
});

describe("a load start clears both criteria", () => {
  const arm = () => {
    useEvtxStore.getState().setTimeRange({ startMs: 10, endMs: 30 });
    useEvtxStore.getState().setRecordScope(scopeOf([loaded[0]]));
    expect(useEvtxStore.getState().timeRange).not.toBeNull();
    expect(useEvtxStore.getState().recordScope).not.toBeNull();
  };
  const cleared = () => {
    expect(useEvtxStore.getState().isLoading).toBe(true);
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(useEvtxStore.getState().recordScope).toBeNull();
  };

  it("when channels are queried (an explicit Load)", () => {
    arm();
    void useEvtxStore.getState().queryChannels(["Application"]);
    cleared();
  });

  it("when the loaded channels are refreshed", () => {
    arm();
    void useEvtxStore.getState().refreshLoadedChannels();
    cleared();
  });

  it("when a level toggle makes the service filter change and the channels are read again", async () => {
    arm();
    useEvtxStore.getState().toggleFilterLevel("Information");
    await settle();
    cleared();
  });

  it("when files are parsed", () => {
    arm();
    void useEvtxStore.getState().parseFiles(["C:\\logs\\System.evtx"]);
    cleared();
  });

  it("when a source manifest is parsed", () => {
    arm();
    void useEvtxStore.getState().parseManifest({ entries: [], coverage: [] });
    cleared();
  });

  it("when the channels are enumerated again", () => {
    arm();
    void useEvtxStore.getState().enumerateChannels();
    cleared();
  });

  it("and does not bring them back when the load ends", () => {
    arm();
    void useEvtxStore.getState().queryChannels(["Application"]);
    useEvtxStore.setState({ isLoading: false });
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });
});

describe("a change of source clears both criteria", () => {
  const arm = () => {
    useEvtxStore.getState().setTimeRange({ startMs: 10, endMs: 30 });
    useEvtxStore.getState().setRecordScope(scopeOf([loaded[0]]));
  };

  it.each([
    ["the mode", { sourceMode: "files" as const }],
    ["the remote machine", { remoteMachine: "lab-host" }],
    ["the source paths", { sourcePaths: ["C:\\logs\\System.evtx"] }],
  ])("when %s changes", (_label, change) => {
    arm();
    useEvtxStore.setState(change);
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });

  it("when the store is reset", () => {
    arm();
    useEvtxStore.getState().reset();
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });

  it("but not when something unrelated changes", () => {
    arm();
    useEvtxStore.setState({ filterSearch: "disk", selectedRecordId: 2 });
    expect(useEvtxStore.getState().timeRange).not.toBeNull();
    expect(useEvtxStore.getState().recordScope).not.toBeNull();
  });
});

describe("a live-tail merge", () => {
  it("keeps the same events in the scope when another channel's earlier batch renumbers their ids", async () => {
    useEvtxStore.setState({ records: [], selectedRecordId: null });
    await useEvtxStore.getState().startLiveTail();
    const requestId = useEvtxStore.getState().tailRequestId;
    const deliver = (channel: string, sequence: number, records: EvtxRecord[]) =>
      listeners.get("evtx-tail-batch")?.({
        payload: { requestId, channel, sequence, mode: "subscription", records, coverageGaps: [] },
      });

    deliver("Application", 0, [record(100, "Application", 100), record(200, "Application", 200), record(300, "Application", 300)]);
    const scoped = useEvtxStore.getState().records.filter((entry) => entry.channel === "Application");
    expect(scoped).toHaveLength(3);
    const idsBefore = scoped.map((entry) => entry.id);
    expect(useEvtxStore.getState().setRecordScope(scopeOf(scoped))).toBe(true);

    // The System tail delivers events that sort BEFORE all of them: every id moves up.
    deliver("System", 0, [record(1, "System", 1), record(2, "System", 2)]);

    const after = useEvtxStore.getState();
    expect(scoped.map((entry) => entry.id)).not.toEqual(idsBefore);
    expect(after.recordScope?.records.size).toBe(3);
    const visible = selectVisibleRecords({
      records: after.records,
      selectedChannels: new Set(["Application", "System"]),
      filterLevels: new Set(EVTX_LEVELS),
      filterEventIds: "",
      filterSearch: "",
      timeRange: null,
      scopeRecords: after.recordScope?.records ?? null,
    });
    expect(visible).toEqual(scoped);
    expect(visible.map((entry) => entry.eventRecordId)).toEqual([100, 200, 300]);
  });
});

describe("a scope's counts are of references", () => {
  // loaded: Application has [0] [1] [2], System has [3] [4].
  const refScope = (references: EvtxRecord[][], counts: Partial<EvtxRecordScopeCounts> = {}) =>
    scopeOf([...new Set(references.flat())], {
      references,
      counts: { ...NO_COUNTS, ...counts },
    });
  const held = () => useEvtxStore.getState().recordScope;

  it("when a channel holding every candidate of an ambiguous reference is cleared, that reference is not loaded and is no longer ambiguous", async () => {
    // A cites one event in System; B cites one that matches two events in Application.
    useEvtxStore
      .getState()
      .setRecordScope(refScope([[loaded[3]], [loaded[0], loaded[1]]], { ambiguous: 1 }));
    expect(held()?.counts).toMatchObject({ notLoaded: 0, ambiguous: 1 });

    await useEvtxStore.getState().clearChannel("Application", true);

    expect([...(held()?.records ?? [])]).toEqual([loaded[3]]);
    expect(held()?.counts).toMatchObject({ notLoaded: 1, ambiguous: 0 });
  });

  it("when only one of two candidates of a reference leaves, the reference still resolves and is no longer ambiguous", () => {
    const stranger = record(99);
    useEvtxStore
      .getState()
      .setRecordScope(refScope([[loaded[3]], [loaded[0], stranger]], { ambiguous: 1 }));
    expect(held()?.counts).toMatchObject({ notLoaded: 0, ambiguous: 0 });
    expect(held()?.references).toEqual([[loaded[3]], [loaded[0]]]);
  });

  it("reads a reference that is cut down to one candidate as a match, not as ambiguous", async () => {
    // B matches two events in Application and one more in System; only the System one is left.
    useEvtxStore
      .getState()
      .setRecordScope(refScope([[loaded[0]], [loaded[1], loaded[2], loaded[3]]], { ambiguous: 1 }));
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(held()?.references).toEqual([[], [loaded[3]]]);
    expect(held()?.counts).toMatchObject({ notLoaded: 1, ambiguous: 0 });
  });

  it("keeps a reference that still has two candidates ambiguous, and counts it once", async () => {
    // B matches one event in Application and two in System. Clearing Application takes A, which had
    // only that one, and leaves B with its two System candidates.
    useEvtxStore
      .getState()
      .setRecordScope(refScope([[loaded[0]], [loaded[1], loaded[3], loaded[4]]], { ambiguous: 1 }));
    expect(held()?.counts).toMatchObject({ notLoaded: 0, ambiguous: 1 });

    await useEvtxStore.getState().clearChannel("Application", true);

    expect(held()?.references).toEqual([[], [loaded[3], loaded[4]]]);
    expect([...(held()?.records ?? [])]).toEqual([loaded[3], loaded[4]]);
    expect(held()?.counts).toMatchObject({ notLoaded: 1, ambiguous: 1 });
  });

  it("counts a reference that was not loaded when the scope was made along with those that stop being loaded", async () => {
    useEvtxStore
      .getState()
      .setRecordScope(refScope([[loaded[0]], [], [loaded[3]]], { notLoaded: 1 }));
    expect(held()?.counts.notLoaded).toBe(1);
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(held()?.counts.notLoaded).toBe(2);
    expect([...(held()?.records ?? [])]).toEqual([loaded[3]]);
  });

  it("is the same count however many times the same channel's clear is repeated", async () => {
    useEvtxStore
      .getState()
      .setRecordScope(refScope([[loaded[3]], [loaded[0], loaded[1]]], { ambiguous: 1 }));
    await useEvtxStore.getState().clearChannel("Application", true);
    const once = held()?.counts;
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(held()?.counts).toEqual(once);
  });

  it("keeps the no-usable-identity count and the bounded flag through a prune", async () => {
    useEvtxStore.getState().setRecordScope(
      refScope([[loaded[3]], [loaded[0]]], { noUsableIdentity: 2, bounded: true }),
    );
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(held()?.counts).toEqual({ notLoaded: 1, noUsableIdentity: 2, ambiguous: 0, bounded: true });
  });

  it("keeps the unresolved count through a prune, as its own class and not as not loaded", async () => {
    useEvtxStore.getState().setRecordScope(
      refScope([[loaded[3]], [loaded[0]]], { unresolved: 4 }),
    );
    expect(held()?.counts.unresolved).toBe(4);
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(held()?.counts).toEqual({
      notLoaded: 1,
      noUsableIdentity: 0,
      ambiguous: 0,
      bounded: false,
      unresolved: 4,
    });
  });

  it("keeps the unresolved count for a scope with no references too", async () => {
    useEvtxStore
      .getState()
      .setRecordScope(scopeOf([loaded[0], loaded[3]], { counts: { ...NO_COUNTS, unresolved: 2 } }));
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(held()?.counts).toMatchObject({ notLoaded: 1, unresolved: 2 });
  });

  it("falls back to one reference per record for a scope that has none", async () => {
    useEvtxStore.getState().setRecordScope(scopeOf([loaded[0], loaded[1], loaded[3]]));
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(held()?.counts.notLoaded).toBe(2);
  });
});

describe("clearing a channel", () => {
  it("drops that channel's events from the scope and counts them as not loaded", async () => {
    useEvtxStore.getState().setRecordScope(scopeOf([loaded[0], loaded[1], loaded[3]]));
    await useEvtxStore.getState().clearChannel("Application", true);
    const held = useEvtxStore.getState().recordScope;
    expect([...(held?.records ?? [])]).toEqual([loaded[3]]);
    expect(held?.counts.notLoaded).toBe(2);
  });

  it("clears the scope when none of its events is left", async () => {
    useEvtxStore.getState().setRecordScope(scopeOf([loaded[0], loaded[1]]));
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });

  it("leaves a scope in another channel as it was", async () => {
    useEvtxStore.getState().setRecordScope(scopeOf([loaded[3], loaded[4]]));
    const before = useEvtxStore.getState().recordScope;
    await useEvtxStore.getState().clearChannel("Application", true);
    expect(useEvtxStore.getState().recordScope).toBe(before);
  });
});
