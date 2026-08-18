/**
 * Coverage-gap handling through the store's real load paths.
 *
 * `evtx-coverage.test.ts` covers the merge rule in isolation. That is not enough: the rule can be
 * right while a call site drops the gaps entirely, which is exactly what `queryChannels` did. These
 * drive the store itself so a regression in a load path fails here.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EventLogSourceManifest } from "./types";
import type { EvtxRecord } from "./types";

const invoke = vi.hoisted(() => vi.fn());

// The store subscribes to backend events at module scope. Capturing the handlers lets a test
// deliver a batch exactly as the backend would, including delivering none.
const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => {});
  }),
}));

const { useEvtxStore, drainStreamedRecords, resetStreamedRecords } = await import("./evtx-store");

/** Delivers a batch the way the backend emits one. */
function emitBatch(channel: string, sequence: number, records: unknown[], requestId?: string) {
  const latestCall = invoke.mock.calls[invoke.mock.calls.length - 1];
  const currentRequestId =
    requestId ?? (latestCall?.[1] as { requestId?: string } | undefined)?.requestId;
  listeners.get("evtx-record-batch")?.({
    payload: { requestId: currentRequestId, channel, sequence, records },
  });
}
function emitTerminal(
  channel: string,
  sequenceCount: number,
  totalRecords: number,
  requestId?: string
) {
  const latestCall = invoke.mock.calls[invoke.mock.calls.length - 1];
  const currentRequestId =
    requestId ?? (latestCall?.[1] as { requestId?: string } | undefined)?.requestId;
  listeners.get("evtx-record-stream-complete")?.({
    payload: { channel, sequenceCount, totalRecords, requestId: currentRequestId },
  });
}

/** A collecting reply is paired with its terminal event just as the backend does. */

function streamedRecord(channel: string, id = 0): EvtxRecord {
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-11T12:00:00.000Z",
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
  };
}

function result(channel: string, gaps: string[], eventCount = 0) {
  const response = {
    records: [],
    channels: [{ name: channel, eventCount, sourceType: "live" as const }],
    totalRecords: 0,
    parseErrors: gaps.length,
    errorMessages: gaps,
  };
  Object.defineProperty(response, "then", {
    enumerable: true,
    value: function (
      this: typeof response,
      resolve: (value: typeof response) => void,
      _reject?: (reason?: unknown) => void
    ) {
      const latestCall = [...invoke.mock.calls]
        .reverse()
        .find((call) =>
          ((call[1] as { channels?: string[] } | undefined)?.channels ?? []).includes(channel)
        );
      const requestId = (latestCall?.[1] as { requestId?: string } | undefined)?.requestId;
      queueMicrotask(() => {
        emitTerminal(channel, 0, response.totalRecords, requestId);
        const resolved = { ...this };
        Object.defineProperty(resolved, "then", { enumerable: true, value: undefined });
        resolve(resolved);
      });
    },
  });
  return response;
}

describe("coverage gaps through the store", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      sourceManifest: null,
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
    });
  });

  it("keeps the gaps a channel query reported", async () => {
    // queryChannels previously discarded these, so a partly unreadable channel looked complete.
    invoke.mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]));

    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([
      "Application: 3 records unreadable",
    ]);
  });

  it("retains structured parser locations alongside the banner text", async () => {
    invoke.mockResolvedValueOnce({
      ...result("Application", ["Application: malformed XML"]),
      coverageGaps: [
        {
          source: "Application.evtx",
          kind: "xml",
          reason: "event XML could not be parsed",
          eventRecordId: 42,
        },
      ],
    });

    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageDetails).toEqual([
      {
        source: "Application.evtx",
        kind: "xml",
        reason: "event XML could not be parsed",
        eventRecordId: 42,
      },
    ]);
    expect(useEvtxStore.getState().coverageGaps).toContain("Application: malformed XML");
  });

  it("accumulates gaps as channels load one at a time", async () => {
    invoke
      .mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]))
      .mockResolvedValueOnce(result("System", ["System: stopped at 100000 events"]));

    await useEvtxStore.getState().queryChannels(["Application"]);
    await useEvtxStore.getState().queryChannels(["System"]);

    expect(useEvtxStore.getState().coverageGaps).toHaveLength(2);
  });

  it("does not repeat a gap when the same channel is queried again", async () => {
    invoke
      .mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]))
      .mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]));

    await useEvtxStore.getState().queryChannels(["Application"]);
    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toHaveLength(1);
  });

  it("reports nothing when a channel loads cleanly", async () => {
    invoke.mockResolvedValueOnce(result("Application", []));

    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("clears a failed channel gap after a clean retry", async () => {
    invoke.mockRejectedValueOnce(new Error("access denied"));
    await useEvtxStore.getState().queryChannels(["Application"]);
    expect(useEvtxStore.getState().coverageGaps).toContain(
      "Application: not read (access denied)"
    );

    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("a refresh drops gaps from the records it replaced", async () => {
    // The refresh clears the records, so gaps describing them must go too, or the banner reports a
    // gap in a set that is no longer on screen.
    invoke.mockResolvedValueOnce(result("Application", ["Application: stale gap"], 1));
    await useEvtxStore.getState().queryChannels(["Application"]);
    expect(useEvtxStore.getState().coverageGaps).toHaveLength(1);

    invoke.mockResolvedValueOnce(result("Application", ["Application: fresh gap"], 1));
    await useEvtxStore.getState().refreshLoadedChannels();

    expect(useEvtxStore.getState().coverageGaps).toEqual(["Application: fresh gap"]);
  });

  it("records a channel whose refresh failed instead of showing the cleared view as complete", async () => {

    // The refresh clears coverageGaps with the records it replaced. A channel whose refresh then
    // fails contributes zero records to the replaced view, so the failure must be recorded or the
    // view reports full coverage while missing a whole channel.
    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().queryChannels(["Application"]);

    invoke.mockRejectedValueOnce(new Error("access denied"));
    await useEvtxStore.getState().refreshLoadedChannels();

    const state = useEvtxStore.getState();
    expect(
      state.coverageGaps.some((g) => g.includes("Application") && g.includes("access denied"))
    ).toBe(true);
    expect(state.loadError).toContain("Application");
    expect(state.loadError).toContain("access denied");
    expect(state.isLoading).toBe(false);
  });
  it("exposes remote recovery after every refreshed channel is denied", async () => {
    useEvtxStore.setState({
      sourceMode: "live",
      remoteMachine: "lab-host",
      channels: [
        {
          name: "Security",
          eventCount: 0,
          sourceType: { remote: { machine: "lab-host" } },
        },
      ],
      loadedChannels: new Set(["Security"]),
      selectedChannels: new Set(["Security"]),
      records: [],
    });
    invoke.mockRejectedValueOnce(new Error("access denied"));

    await useEvtxStore.getState().refreshLoadedChannels();

    const state = useEvtxStore.getState();
    expect(state.sourceMode).toBeNull();
    expect(state.coverageGaps).toEqual([
      "lab-host/Security: not read (access denied)",
    ]);
    expect(state.loadError).toBe("lab-host/Security: access denied");
  });

  it("ignores a late batch from a superseded source query", async () => {
    let oldRequestId: string | undefined;
    let resolveOld: ((value: unknown) => void) | undefined;
    invoke.mockImplementationOnce((_name: string, args: { requestId: string }) => {
      oldRequestId = args.requestId;
      return new Promise((resolve) => {
        resolveOld = resolve;
      });
    });

    const oldQuery = useEvtxStore.getState().queryChannels(["Application"]);
    await Promise.resolve();

    invoke.mockResolvedValueOnce([]);
    const sourceSwitch = useEvtxStore.getState().enumerateRemoteChannels("new-host");
    await Promise.resolve();

    emitBatch("Application", 0, [streamedRecord("Application")], oldRequestId);
    resolveOld?.(result("Application", []));
    await oldQuery;
    await sourceSwitch;

    expect(useEvtxStore.getState().records).toEqual([]);
  });

  it("clears stale data and rejects late batches on an invalid source switch", async () => {
    let oldRequestId: string | undefined;
    let resolveOld: ((value: unknown) => void) | undefined;
    invoke.mockImplementationOnce((_name: string, args: { requestId: string }) => {
      oldRequestId = args.requestId;
      return new Promise((resolve) => {
        resolveOld = resolve;
      });
    });

    const oldQuery = useEvtxStore.getState().queryChannels(["Application"]);
    await Promise.resolve();
    const invalidSwitch = useEvtxStore.getState().enumerateRemoteChannels("bad\0host");
    emitBatch("Application", 0, [streamedRecord("Application")], oldRequestId);
    resolveOld?.(result("Application", []));
    await oldQuery;
    await invalidSwitch;

    const state = useEvtxStore.getState();
    expect(state.records).toEqual([]);
    expect(state.channels).toEqual([]);
    expect(state.sourceMode).toBeNull();
    expect(state.loadError).toBe("Enter a valid remote computer name.");
  });

  it("clears remote state before a file parse failure", async () => {
    useEvtxStore.setState({
      remoteMachine: "old-host",
      sourceMode: "live",
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      records: [streamedRecord("Application")],
      loadedChannels: new Set(["Application"]),
    });
    invoke.mockRejectedValueOnce(new Error("file read failed"));

    await useEvtxStore.getState().parseFiles(["missing.evtx"]);

    const state = useEvtxStore.getState();
    expect(state.remoteMachine).toBeNull();
    expect(state.sourceMode).toBeNull();
    expect(state.channels).toEqual([]);
    expect(state.records).toEqual([]);
    expect(state.loadedChannels).toEqual(new Set());
    expect(state.loadError).toBe("file read failed");
  });
});
it("preserves source manifest provenance and coverage through manifest loading", async () => {
  const manifest: EventLogSourceManifest = {
    entries: [
      {
        sourceId: "/logs/first/application.evtx",
        path: "/logs/first/Application.evtx",
        kind: "folder",
      },
    ],
    coverage: [
      {
        kind: "missing",
        path: "/logs/second/System.evtx",
        reason: "source path does not exist",
      },
    ],
  };
  invoke.mockResolvedValueOnce({
    records: [
      {
        ...streamedRecord("Application"),
        sourceLabel: "/logs/first/Application.evtx",
      },
    ],
    channels: [{ name: "Application", eventCount: 1, sourceType: { file: "/logs/first/Application.evtx" } }],
    totalRecords: 1,
    parseErrors: 1,
    errorMessages: ["/logs/second/System.evtx: source path does not exist"],
  });

  await useEvtxStore.getState().parseManifest(manifest);

  const state = useEvtxStore.getState();
  expect(state.sourceManifest).toEqual(manifest);
  expect(state.coverageGaps).toContain("/logs/second/System.evtx: source path does not exist");
  expect(state.records[0].sourceLabel).toBe("/logs/first/Application.evtx");
});

describe("live batch delivery through initial and refresh loads", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      sourceManifest: null,
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
      remoteMachine: null,
      sourceMode: null,
    });
  });

  it("assembles streamed batches during initial channel enumeration", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_channels") {
        return [{ name: "Application", eventCount: 1, sourceType: "live" }];
      }
      emitBatch("Application", 0, [streamedRecord("Application")]);
      emitTerminal("Application", 1, 1);
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
        totalRecords: 1,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().enumerateChannels();

    expect(useEvtxStore.getState().records).toHaveLength(1);
    expect(useEvtxStore.getState().records[0].channel).toBe("Application");
  });

  it("reports an initial-query trailing batch shortfall", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_channels") {
        return [{ name: "Application", eventCount: 2, sourceType: "live" }];
      }
      emitBatch("Application", 0, [streamedRecord("Application")]);
      emitTerminal("Application", 1, 2);
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 2, sourceType: "live" }],
        totalRecords: 2,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().enumerateChannels();

    expect(useEvtxStore.getState().coverageGaps).toContain(
      "Application: 1 of 2 events did not reach the view"
    );
  });

  it("clears batches left by a failed initial query before retrying", async () => {
    let queryAttempts = 0;
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_channels") {
        return [{ name: "Application", eventCount: 1, sourceType: "live" }];
      }
      queryAttempts += 1;
      if (queryAttempts === 1) {
        emitBatch("Application", 0, [streamedRecord("Application", 99)]);
        throw new Error("transient query failure");
      }
      emitBatch("Application", 0, [streamedRecord("Application")]);
      emitTerminal("Application", 1, 1);
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
        totalRecords: 1,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().enumerateChannels();
    await useEvtxStore.getState().enumerateChannels();

    expect(queryAttempts).toBe(2);
    expect(useEvtxStore.getState().records).toHaveLength(1);
    expect(useEvtxStore.getState().records[0].eventRecordId).toBe(0);
  });

  it("assembles streamed batches during refresh", async () => {
    useEvtxStore.setState({
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
    });
    invoke.mockImplementation(async () => {
      emitTerminal("Application", 1, 1);
      emitBatch("Application", 0, [streamedRecord("Application")]);
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
        totalRecords: 1,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().refreshLoadedChannels();

    expect(useEvtxStore.getState().records).toHaveLength(1);
    expect(useEvtxStore.getState().records[0].channel).toBe("Application");
  });

  it("reports a refresh trailing batch shortfall and sets loading state", async () => {
    useEvtxStore.setState({
      channels: [{ name: "Application", eventCount: 2, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
      loadError: "stale error",
    });
    let loadingAtInvoke = false;
    invoke.mockImplementation(async () => {
      loadingAtInvoke = useEvtxStore.getState().isLoading;
      emitTerminal("Application", 1, 2);
      emitBatch("Application", 0, [streamedRecord("Application")]);
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 2, sourceType: "live" }],
        totalRecords: 2,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().refreshLoadedChannels();

    expect(loadingAtInvoke).toBe(true);
    expect(useEvtxStore.getState().loadError).toBeNull();
    expect(useEvtxStore.getState().coverageGaps).toContain(
      "Application: 1 of 2 events did not reach the view"
    );
  });
});

describe("a multi-channel query is delivered one channel at a time", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
    });
  });

  function withRecords(channel: string, count: number) {
    const response = {
      records: Array.from({ length: count }, (_, i) => ({
        id: i,
        eventRecordId: i,
        timestamp: "2026-08-11T12:00:00.000Z",
        timestampEpoch: 1_000 + i,
        provider: "P",
        channel,
        eventId: 1,
        level: "information",
        computer: "C",
        message: "m",
        eventData: [],
        rawXml: "<Event/>",
        sourceLabel: "Live",
        mapped: null,
      })),
      channels: [{ name: channel, eventCount: count, sourceType: "live" as const }],
      totalRecords: count,
      parseErrors: 0,
      errorMessages: [],
    };
    queueMicrotask(() => emitTerminal(channel, 0, count));
    return response;
  }

  it("asks for each channel separately rather than all of them at once", async () => {
    // The backend collects a whole request into one vector before replying, so a single request
    // naming every channel holds every event of every channel in memory before anything is shown.
    invoke
      .mockResolvedValueOnce(withRecords("Application", 1))
      .mockResolvedValueOnce(withRecords("System", 1));

    await useEvtxStore.getState().queryChannels(["Application", "System"]);

    expect(invoke).toHaveBeenCalledTimes(2);
    const requested = invoke.mock.calls.map(
      (call) => (call[1] as { channels: string[] }).channels
    );
    expect(requested).toEqual([["Application"], ["System"]]);
  });

  it("keeps the channels that succeeded when one of them fails", async () => {
    // A single request fails as a whole. One unreadable channel used to discard the results of
    // every channel queried alongside it and leave the view empty.
    invoke
      .mockRejectedValueOnce(new Error("access denied"))
      .mockResolvedValueOnce(withRecords("System", 3));

    await useEvtxStore.getState().queryChannels(["Security", "System"]);

    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(3);
    expect(state.loadedChannels.has("System")).toBe(true);
    expect(state.loadedChannels.has("Security")).toBe(false);
  });

  it("records the unreadable channel as a gap, not only as an error string", async () => {
    // loadError is replaced by the next load. A gap describes the view currently on screen, and
    // events that never arrived look exactly like evidence that nothing happened.
    invoke
      .mockRejectedValueOnce(new Error("access denied"))
      .mockResolvedValueOnce(withRecords("System", 1));

    await useEvtxStore.getState().queryChannels(["Security", "System"]);

    const gaps = useEvtxStore.getState().coverageGaps;
    expect(gaps.some((g) => g.includes("Security") && g.includes("access denied"))).toBe(true);
  });

  it("still reports the failure through loadError", async () => {
    invoke.mockRejectedValueOnce(new Error("access denied"));

    await useEvtxStore.getState().queryChannels(["Security"]);

    expect(useEvtxStore.getState().loadError).toContain("Security");
    expect(useEvtxStore.getState().isLoading).toBe(false);
  });

  it("qualifies manual remote query failures with the host", async () => {
    useEvtxStore.setState({ remoteMachine: "lab-host" });
    invoke.mockRejectedValueOnce(new Error("access denied"));

    await useEvtxStore.getState().queryChannels(["Security"]);

    const state = useEvtxStore.getState();
    expect(state.loadError).toBe("lab-host/Security: access denied");
    expect(state.coverageGaps).toContain("lab-host/Security: not read (access denied)");
  });
});

describe("the time window reaches the service", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
      timeWindow: "1h",
    });
  });

  const filterOf = (call: number) =>
    (
      invoke.mock.calls[call]?.[1] as {
        filter?: {
          time?: { milliseconds: number };
          eventIds?: unknown[];
          levels?: number[];
        };
      }
    )?.filter;

  it("sends the selected window when a channel is queried", () => {
    invoke.mockResolvedValueOnce(result("Application", []));
    return useEvtxStore
      .getState()
      .queryChannels(["Application"])
      .then(() => {
        expect(filterOf(0)?.time?.milliseconds).toBe(60 * 60 * 1000);
      });
  });

  it("sends it on refresh too", async () => {
    // The window is a server-side predicate and a refresh is the only thing that applies it.
    // Omitting it made the control a no-op: selecting 1h triggered a refresh that then fetched the
    // channel unbounded, so the view filled with events outside the window still shown as selected.
    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().queryChannels(["Application"]);

    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().refreshLoadedChannels();

    expect(filterOf(1)?.time?.milliseconds).toBe(60 * 60 * 1000);
  });

  it("sends no time predicate when the window is all time", async () => {
    useEvtxStore.setState({ timeWindow: "all" });
    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(filterOf(0)?.time).toBeUndefined();
  });
  it("pushes only valid Event ID ranges into the before-load query", async () => {
    useEvtxStore.setState({ filterEventIds: "4624-4626" });
    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(filterOf(0)?.eventIds).toEqual([
      { kind: "range", low: 4624, high: 4626 },
    ]);
  });

  it("pushes selected levels into the before-load query", async () => {
    useEvtxStore.setState({ filterLevels: new Set(["Error", "Warning"]) });
    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(filterOf(0)?.levels).toEqual([2, 3]);
  });

  it("keeps on-load quick-filter state when a time-window refresh refetches", async () => {
    const quickFilter = {
      mode: "allWords" as const,
      query: "boot failed",
      scope: "visibleColumns" as const,
      action: "hide" as const,
      caseSensitive: true,
      highlight: true,
    };
    useEvtxStore.setState({ quickFilter, timeWindow: "1h" });
    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().queryChannels(["Application"]);

    invoke.mockResolvedValueOnce(result("Application", []));
    await useEvtxStore.getState().refreshLoadedChannels();

    expect(useEvtxStore.getState().quickFilter).toEqual(quickFilter);
  });


  it("drops a non-string gap the reader sent rather than rendering it", () => {
    // The guard normalizes, but only if callers use what it returns. Ignoring the return value
    // left the raw reply in place and stored 42 in coverageGaps.
    invoke.mockImplementationOnce(async () => {
      emitTerminal("Application", 0, 0);
      return {
        records: [],
        channels: [],
        totalRecords: 0,
        parseErrors: 1,
        errorMessages: ["real gap", 42, null],
      };
    });

    return useEvtxStore
      .getState()
      .queryChannels(["Application"])
      .then(() => {
        expect(useEvtxStore.getState().coverageGaps).toEqual(["real gap"]);
      });
  });
});
  it("refetches loaded live channels when before-load levels broaden", async () => {
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
      filterLevels: new Set(["Error"]),
    });
    invoke.mockResolvedValueOnce(result("Application", []));

    useEvtxStore.getState().setFilterLevels(new Set(["Error", "Information"]));
    await vi.waitFor(() => expect(invoke).toHaveBeenCalled());

    expect(
      invoke.mock.calls.some(
        (call) =>
          (call[1] as { filter?: { levels?: number[] } })?.filter?.levels === undefined
      )
    ).toBe(true);
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));
  });
  it("restores all levels when toggling off the final active level", () => {
    useEvtxStore.setState({
      sourceMode: null,
      loadedChannels: new Set<string>(),
      filterLevels: new Set(["Error"]),
    });

    useEvtxStore.getState().toggleFilterLevel("Error");

    expect([...useEvtxStore.getState().filterLevels].sort()).toEqual([
      "Critical",
      "Error",
      "Information",
      "Verbose",
      "Warning",
    ]);
  });



  it("keeps latest before-load criteria across rapid commits", async () => {
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
    });
    invoke.mockResolvedValue(result("Application", []));

    useEvtxStore.getState().setFilterLevels(new Set(["Error"]));
    useEvtxStore.getState().setFilterEventIds("4624-4626");
    await vi.waitFor(() => expect(invoke).toHaveBeenCalled());
    await vi.waitFor(() => expect(useEvtxStore.getState().isLoading).toBe(false));

    expect(invoke.mock.calls.length).toBeGreaterThan(0);
    expect(
      invoke.mock.calls.some((call) =>
        JSON.stringify(
          (call[1] as { filter?: { eventIds?: unknown[] } })?.filter?.eventIds
        ).includes('"low":4624')
      )
    ).toBe(true);
  });
  it("ignores stale query results after a newer filter query starts", async () => {
    let resolveOld!: (value: unknown) => void;
    const oldResult = new Promise((resolve) => {
      resolveOld = resolve;
    });
    const fresh = {
      ...result("Application", []),
      records: [streamedRecord("Application", 99)],
    };
    invoke.mockImplementationOnce(() => oldResult).mockResolvedValueOnce(fresh);

    const oldQuery = useEvtxStore.getState().queryChannels(["Application"]);
    const freshQuery = useEvtxStore.getState().queryChannels(["Application"]);
    await freshQuery;
    resolveOld({ ...result("Application", []), records: [streamedRecord("Application", 1)] });
    await oldQuery;

    expect(useEvtxStore.getState().records.map((item) => item.eventRecordId)).toEqual([99]);
  });
  it("rejects an old stream batch after a newer request resets the channel", async () => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
      selectedRecordId: null,
    });
    let resolveQuery!: (value: unknown) => void;
    const pending = new Promise<unknown>((resolve) => {
      resolveQuery = resolve;
    });
    invoke.mockImplementationOnce(() => pending);

    const query = useEvtxStore.getState().queryChannels(["Application"]);
    await Promise.resolve();
    const latestCall = invoke.mock.calls[invoke.mock.calls.length - 1];
    const requestArgs = latestCall?.[1];
    if (
      requestArgs === null ||
      typeof requestArgs !== "object" ||
      !("requestId" in requestArgs) ||
      typeof requestArgs.requestId !== "string"
    ) {
      throw new Error("query request did not include a request ID");
    }
    const requestId = requestArgs.requestId;
    resetStreamedRecords(["Application"], requestId);
    emitBatch("Application", 0, [streamedRecord("Application", 1)], "old-request");
    emitBatch("Application", 0, [streamedRecord("Application", 2)], requestId);
    emitTerminal("Application", 1, 1, requestId);
    expect(
      drainStreamedRecords("Application", requestId).records.map((item) => item.eventRecordId)
    ).toEqual([2]);
    resolveQuery({
      records: [],
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" as const }],
      totalRecords: 1,
      parseErrors: 0,
      errorMessages: [],
    });
    await query;

    expect(useEvtxStore.getState().records.map((item) => item.eventRecordId)).toEqual([2]);
  });
describe("records that arrive in batches while the query runs", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
      selectedRecordId: null,
      sourceMode: null,
      remoteMachine: null,
      isLoading: false,
      loadError: null,
    });
  });

  function record(channel: string, epoch: number) {
    return {
      id: 0,
      eventRecordId: epoch,
      timestamp: "2026-08-12T12:00:00.000Z",
      timestampEpoch: epoch,

      provider: "P",
      channel,
      eventId: 1,
      level: "information",
      computer: "C",
      message: "m",
      eventData: [],
      rawXml: "<Event/>",
      sourceLabel: "Live",
      mapped: null,
    };
  }

  /** A reply that streamed everything: it carries the count but none of the records. */
  function streamedReply(channel: string, totalRecords: number) {
    return {
      records: [],
      channels: [{ name: channel, eventCount: totalRecords, sourceType: "live" as const }],
      totalRecords,
      parseErrors: 0,
      errorMessages: [],
    };
  }

  it("assembles the view from batches the reply did not carry", async () => {
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1), record("System", 2)]);
      emitBatch("System", 1, [record("System", 3)]);
      emitTerminal("System", 2, 3);
      return streamedReply("System", 3);
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(3);
    expect(state.coverageGaps).toEqual([]);
  });

  it("remaps the selected record when an earlier streamed event reorders rows", async () => {
    let resolveQuery!: (value: unknown) => void;
    const pending = new Promise<unknown>((resolve) => {
      resolveQuery = resolve;
    });
    invoke.mockImplementationOnce(() => pending);
    const selected = { ...record("Selection", 100), id: 0 } as unknown as EvtxRecord;
    useEvtxStore.setState({ records: [selected], selectedRecordId: 0 });

    const query = useEvtxStore.getState().queryChannels(["Selection"]);
    await Promise.resolve();
    const latestCall = invoke.mock.calls[invoke.mock.calls.length - 1];
    const requestArgs = latestCall?.[1];
    if (
      requestArgs === null ||
      typeof requestArgs !== "object" ||
      !("requestId" in requestArgs) ||
      typeof requestArgs.requestId !== "string"
    ) {
      throw new Error("query request did not include a request ID");
    }
    const requestId = requestArgs.requestId;
    emitBatch("Selection", 0, [{ ...record("Selection", 1), id: 1 }], requestId);
    emitTerminal("Selection", 1, 1, requestId);
    resolveQuery({
      records: [],
      channels: [{ name: "Selection", eventCount: 1, sourceType: "live" as const }],
      totalRecords: 1,
      parseErrors: 0,
      errorMessages: [],
    });
    await query;

    const state = useEvtxStore.getState();
    expect(state.records.map((item) => item.eventRecordId)).toEqual([1, 100]);
    expect(state.selectedRecordId).toBe(1);
    expect(state.records[state.selectedRecordId ?? -1]?.eventRecordId).toBe(100);
  });

  it("reports a batch that never arrived instead of showing a short list as complete", async () => {
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1)]);
      emitBatch("System", 2, [record("System", 3)]);
      emitTerminal("System", 3, 3);
      return streamedReply("System", 3);
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    const gaps = useEvtxStore.getState().coverageGaps;
    expect(gaps.some((g) => g.includes("System") && g.includes("batches"))).toBe(true);
  });

  it("reports a shortfall against the count the reader sent", async () => {
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1)]);
      emitTerminal("System", 1, 9);
      return streamedReply("System", 9);
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    const gaps = useEvtxStore.getState().coverageGaps;
    expect(gaps.some((g) => g.includes("8 of 9"))).toBe(true);
  });

  it("does not invent a shortfall when the reader gave no count", async () => {
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1)]);
      emitTerminal("System", 1, 0);
      return { ...streamedReply("System", 0), totalRecords: "unknown" };
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    expect(useEvtxStore.getState().records).toHaveLength(1);
    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("still works when the reader returned the records in the reply instead", async () => {
    invoke.mockImplementationOnce(async () => {
      const response = {
        records: [record("System", 1), record("System", 2)],
        channels: [{ name: "System", eventCount: 2, sourceType: "live" as const }],
        totalRecords: 2,
        parseErrors: 0,
        errorMessages: [],
      };
      emitTerminal("System", 0, 2);
      return response;
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    expect(useEvtxStore.getState().records).toHaveLength(2);
    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("does not count a previous attempt's batches towards a retry", async () => {
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1)]);
      throw new Error("interrupted");
    });
    await useEvtxStore.getState().queryChannels(["System"]);

    useEvtxStore.setState({ records: [], coverageGaps: [], loadedChannels: new Set<string>() });
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 5)]);
      emitTerminal("System", 1, 1);
      return streamedReply("System", 1);
    });
    await useEvtxStore.getState().queryChannels(["System"]);

    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(1);
    expect(state.records[0].eventRecordId).toBe(5);
  });

  it("finds the highest batch number without spreading every one", async () => {
    const batches = 200_000;
    invoke.mockImplementationOnce(async () => {
      for (let sequence = 0; sequence < batches; sequence++) {
        emitBatch("Huge", sequence, []);
      }
      emitTerminal("Huge", batches, 0);
      return streamedReply("Huge", 0);
    });

    await useEvtxStore.getState().queryChannels(["Huge"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("does not leave the workspace stuck loading when a reply is unreadable", async () => {
    invoke.mockImplementationOnce(async () => {
      emitTerminal("Application", 0, 0);
      return { records: null, channels: [] };
    });

    await useEvtxStore.getState().queryChannels(["Application"]);

    const state = useEvtxStore.getState();
    expect(state.isLoading).toBe(false);
    expect(state.loadError).toContain("Application");
    expect(state.coverageGaps.some((g) => g.includes("Application"))).toBe(true);
  });
  it("waits for a terminal-before-batch stream to drain before acknowledging it", async () => {
    let resolveReply!: (value: unknown) => void;
    invoke.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveReply = () => resolve(streamedReply("Race", 1));
        })
    );

    const query = useEvtxStore.getState().queryChannels(["Race"]);
    await Promise.resolve();
    emitTerminal("Race", 1, 1);
    emitBatch("Race", 0, [record("Race", 1)]);
    resolveReply(undefined);
    await query;

    expect(useEvtxStore.getState().records.map((item) => item.eventRecordId)).toEqual([1]);
    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("reconciles a reply-before-terminal stream without using the reply as proof of coverage", async () => {
    let resolveReply!: (value: unknown) => void;
    invoke.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveReply = resolve;
        })
    );

    const query = useEvtxStore.getState().queryChannels(["Race"]);
    await Promise.resolve();
    resolveReply(streamedReply("Race", 1));
    await Promise.resolve();
    emitTerminal("Race", 1, 1);
    emitBatch("Race", 0, [record("Race", 1)]);
    await query;

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("accepts event-delivery lag after reply and terminal while the consumer is draining", async () => {
    let resolveReply!: (value: unknown) => void;
    invoke.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveReply = resolve;
        })
    );

    const query = useEvtxStore.getState().queryChannels(["Race"]);
    await Promise.resolve();
    emitTerminal("Race", 2, 2);
    resolveReply(streamedReply("Race", 2));
    await Promise.resolve();
    emitBatch("Race", 0, [record("Race", 1)]);
    emitBatch("Race", 1, [record("Race", 2)]);
    await query;

    expect(useEvtxStore.getState().records.map((item) => item.eventRecordId)).toEqual([1, 2]);
    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("remaps selection when a query merge reorders records", async () => {
    const selected = { ...record("Selection", 100), id: 1 } as unknown as EvtxRecord;
    useEvtxStore.setState({ records: [selected], selectedRecordId: 1 });
    invoke.mockImplementationOnce(async () => {
      emitTerminal("Selection", 0, 2);
      return {
        records: [{ ...record("Selection", 1), id: 0 }],
        channels: [{ name: "Selection", eventCount: 2, sourceType: "live" as const }],
        totalRecords: 2,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().queryChannels(["Selection"]);

    const state = useEvtxStore.getState();
    expect(state.records.map((item) => item.eventRecordId)).toEqual([1, 100]);
    expect(state.records[state.selectedRecordId ?? -1]?.eventRecordId).toBe(100);
  });

  it("remaps selection when enumerate merges a refreshed channel", async () => {
    const selected = { ...record("Application", 100), id: 1 } as unknown as EvtxRecord;
    useEvtxStore.setState({ records: [selected], selectedRecordId: 1 });
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_channels") {
        return [{ name: "Application", eventCount: 2, sourceType: "live" as const }];
      }
      emitTerminal("Application", 0, 2);
      return {
        records: [
          { ...record("Application", 1), id: 0 },
          selected,
        ],
        channels: [{ name: "Application", eventCount: 2, sourceType: "live" as const }],
        totalRecords: 2,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().enumerateChannels();

    const state = useEvtxStore.getState();
    expect(state.records[state.selectedRecordId ?? -1]?.eventRecordId).toBe(100);
  });

  it("remaps selection when refresh merges a replacement channel", async () => {
    const selected = { ...record("Application", 100), id: 1 } as unknown as EvtxRecord;
    useEvtxStore.setState({
      channels: [{ name: "Application", eventCount: 2, sourceType: "live" as const }],
      loadedChannels: new Set(["Application"]),
      records: [selected],
      selectedRecordId: 1,
    });
    invoke.mockImplementationOnce(async () => {
      emitTerminal("Application", 0, 2);
      return {
        records: [
          { ...record("Application", 1), id: 0 },
          selected,
        ],
        channels: [{ name: "Application", eventCount: 2, sourceType: "live" as const }],
        totalRecords: 2,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().refreshLoadedChannels();

    const state = useEvtxStore.getState();
    expect(state.records[state.selectedRecordId ?? -1]?.eventRecordId).toBe(100);
  });
});
describe("remote event sources", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [],
      coverageGaps: [],
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
      remoteMachine: null,
    });
  });

  it("uses the remote command with only a machine name and preserves remote provenance", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_remote_channels") {
        return [{ name: "Application", eventCount: 0, sourceType: { remote: { machine: "lab-host" } } }];
      }
      emitTerminal("Application", 0, 0);
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 0, sourceType: { remote: { machine: "lab-host" } } }],
        totalRecords: 0,
        parseErrors: 0,
        errorMessages: [],
      };
    });

    await useEvtxStore.getState().enumerateRemoteChannels("lab-host");

    expect(invoke).toHaveBeenCalledWith("evtx_enumerate_remote_channels", { machine: "lab-host" });
    expect(invoke).toHaveBeenCalledWith(
      "evtx_query_remote_channels",
      expect.objectContaining({
        machine: "lab-host",
        channels: ["Application"],
      })
    );
    expect(useEvtxStore.getState().channels[0]?.sourceType).toEqual({
      remote: { machine: "lab-host" },
    });
    expect(useEvtxStore.getState().remoteMachine).toBe("lab-host");
    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("canonicalizes UNC remote names in empty-source coverage", async () => {
    invoke.mockResolvedValueOnce([]);

    await useEvtxStore.getState().enumerateRemoteChannels("\\\\lab-host");

    expect(invoke).toHaveBeenCalledWith("evtx_enumerate_remote_channels", {
      machine: "lab-host",
    });
    expect(useEvtxStore.getState().remoteMachine).toBe("lab-host");
    expect(useEvtxStore.getState().coverageGaps).toEqual([
      "lab-host: remote source is empty (no channels available)",
    ]);
  });

  it("rejects control characters before sending a remote machine name", async () => {
    await useEvtxStore.getState().enumerateRemoteChannels("lab\0host");

    expect(invoke).not.toHaveBeenCalled();
    expect(useEvtxStore.getState().remoteMachine).toBeNull();
    expect(useEvtxStore.getState().loadError).toBe("Enter a valid remote computer name.");
  });

  it("clears local data before a failed remote source switch", async () => {
    useEvtxStore.setState({
      sourceMode: "live",
      remoteMachine: null,
      channels: [{ name: "Application", eventCount: 3, sourceType: "live" }],
      records: [{ ...streamedRecord("Application"), id: 0 }],
    });
    invoke.mockRejectedValueOnce(new Error("access denied"));

    await useEvtxStore.getState().enumerateRemoteChannels("lab-host");

    const state = useEvtxStore.getState();
    expect(state.remoteMachine).toBe("lab-host");
    expect(state.channels).toEqual([]);
    expect(state.records).toEqual([]);
    expect(state.coverageGaps).toEqual([
      "lab-host: remote source access denied (access denied)",
    ]);
  });

  it("records remote enumeration denial or unavailability as coverage", async () => {
    invoke.mockRejectedValueOnce(
      new Error("lab-host: remote source unavailable (error 53)")
    );

    await useEvtxStore.getState().enumerateRemoteChannels("lab-host");

    expect(useEvtxStore.getState().coverageGaps).toEqual([
      "lab-host: remote source unavailable (error 53)",
    ]);
    expect(useEvtxStore.getState().loadError).toContain("remote source unavailable");
  });

  it("keeps denied remote sources distinct from an empty source", async () => {
    invoke.mockImplementationOnce(async () => {
      emitTerminal("Security", 0, 0);
      return {
        records: [],
        channels: [
          {
            name: "Security",
            eventCount: 0,
            sourceType: { remote: { machine: "lab-host" } },
          },
        ],
        totalRecords: 0,
        parseErrors: 1,
        errorMessages: ["lab-host/Security: access denied"],
      };
    });

    useEvtxStore.setState({
      remoteMachine: "lab-host",
      channels: [
        {
          name: "Security",
          eventCount: 0,
          sourceType: { remote: { machine: "lab-host" } },
        },
      ],
    });
    await useEvtxStore.getState().queryChannels(["Security"]);


    const state = useEvtxStore.getState();
    expect(state.channels).toHaveLength(1);
    expect(state.channels[0]?.eventCount).toBe(0);
    expect(state.coverageGaps).toEqual(["lab-host/Security: access denied"]);
  });
  it("records a denied core channel during remote enumeration", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_remote_channels") {
        return [
          {
            name: "Security",
            eventCount: 0,
            sourceType: { remote: { machine: "lab-host" } },
          },
        ];
      }
      throw new Error("access denied");
    });

    await useEvtxStore.getState().enumerateRemoteChannels("lab-host");

    const state = useEvtxStore.getState();
    expect(state.coverageGaps).toHaveLength(1);
    expect(state.coverageGaps).toContain("lab-host/Security: not read (access denied)");
    expect(state.loadError).toBe("lab-host/Security: access denied");
    expect(state.sourceMode).toBeNull();
    expect(state.records).toEqual([]);
  });

  it("does not mark an error result as a loaded remote channel", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_remote_channels") {
        return [
          {
            name: "Security",
            eventCount: 0,
            sourceType: { remote: { machine: "lab-host" } },
          },
        ];
      }
      emitTerminal("Security", 0, 0);
      return {
        records: [],
        channels: [
          {
            name: "Security",
            eventCount: 0,
            sourceType: { remote: { machine: "lab-host" } },
          },
        ],
        totalRecords: 0,
        parseErrors: 1,
        errorMessages: ["lab-host/Security: access denied"],
      };
    });

    await useEvtxStore.getState().enumerateRemoteChannels("lab-host");

    const state = useEvtxStore.getState();
    expect(state.loadedChannels.size).toBe(0);
    expect(state.sourceMode).toBeNull();
    expect(state.coverageGaps).toContain("lab-host/Security: access denied");
  });
  it("preserves successful remote channels when another core channel is denied", async () => {
    invoke.mockImplementation(async (name: string, args?: { channels?: string[] }) => {
      if (name === "evtx_enumerate_remote_channels") {
        return [
          { name: "Application", eventCount: 0, sourceType: { remote: { machine: "lab-host" } } },
          { name: "Security", eventCount: 0, sourceType: { remote: { machine: "lab-host" } } },
        ];
      }
      if (args?.channels?.[0] === "Application") {
        emitTerminal("Application", 0, 0);
        return {
          records: [],
          channels: [
            {
              name: "Application",
              eventCount: 0,
              sourceType: { remote: { machine: "lab-host" } },
            },
          ],
          totalRecords: 0,
          parseErrors: 0,
          errorMessages: [],
        };
      }
      throw new Error("access denied");
    });

    await useEvtxStore.getState().enumerateRemoteChannels("lab-host");

    const state = useEvtxStore.getState();
    expect(state.sourceMode).toBe("live");
    expect(state.channels.map((channel) => channel.name)).toEqual(["Application", "Security"]);
    expect(state.coverageGaps).toContain("lab-host/Security: not read (access denied)");
  });

  it("keeps local source selection local after a remote attempt", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_channels") {
        return [{ name: "Application", eventCount: 0, sourceType: "live" }];
      }
      emitTerminal("Application", 0, 0);
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 0, sourceType: "live" }],
        totalRecords: 0,
        parseErrors: 0,
        errorMessages: [],
      };
    });
    useEvtxStore.setState({ remoteMachine: "stale-remote" });

    await useEvtxStore.getState().enumerateLocalChannels();

    expect(invoke).toHaveBeenCalledWith("evtx_enumerate_channels");
    expect(useEvtxStore.getState().remoteMachine).toBeNull();
  });

  it("represents an empty remote source as coverage instead of local live data", async () => {
    invoke.mockResolvedValueOnce([]);

    await useEvtxStore.getState().enumerateRemoteChannels("empty-host");

    expect(useEvtxStore.getState().channels).toEqual([]);
    expect(useEvtxStore.getState().coverageGaps).toEqual([
      "empty-host: remote source is empty (no channels available)",
    ]);
    expect(useEvtxStore.getState().remoteMachine).toBe("empty-host");
    expect(useEvtxStore.getState().sourceMode).toBeNull();
  });
});
