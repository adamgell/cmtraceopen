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

const { useEvtxStore } = await import("./evtx-store");

/** Delivers a batch the way the backend emits one. */
function emitBatch(channel: string, sequence: number, records: unknown[]) {
  listeners.get("evtx-record-batch")?.({ payload: { channel, sequence, records } });
}

function streamedRecord(channel: string, id = 0) {
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

function result(channel: string, gaps: string[]) {
  return {
    records: [],
    channels: [{ name: channel, eventCount: 0, sourceType: "live" }],
    totalRecords: 0,
    parseErrors: gaps.length,
    errorMessages: gaps,
  };
}

describe("coverage gaps through the store", () => {
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

  it("keeps the gaps a channel query reported", async () => {
    // queryChannels previously discarded these, so a partly unreadable channel looked complete.
    invoke.mockResolvedValueOnce(result("Application", ["Application: 3 records unreadable"]));

    await useEvtxStore.getState().queryChannels(["Application"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([
      "Application: 3 records unreadable",
    ]);
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

  it("a refresh drops gaps from the records it replaced", async () => {
    // The refresh clears the records, so gaps describing them must go too, or the banner reports a
    // gap in a set that is no longer on screen.
    invoke.mockResolvedValueOnce(result("Application", ["Application: stale gap"]));
    await useEvtxStore.getState().queryChannels(["Application"]);
    expect(useEvtxStore.getState().coverageGaps).toHaveLength(1);

    invoke.mockResolvedValueOnce(result("Application", ["Application: fresh gap"]));
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
});
describe("live batch delivery through initial and refresh loads", () => {
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

  it("assembles streamed batches during initial channel enumeration", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_channels") {
        return [{ name: "Application", eventCount: 1, sourceType: "live" }];
      }
      emitBatch("Application", 0, [streamedRecord("Application")]);
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
    return {
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
      channels: [{ name: channel, eventCount: count, sourceType: "live" }],
      totalRecords: count,
      parseErrors: 0,
      errorMessages: [],
    };
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
    (invoke.mock.calls[call]?.[1] as { filter?: { time?: { milliseconds: number } } })?.filter;

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

  it("drops a non-string gap the reader sent rather than rendering it", () => {
    // The guard normalizes, but only if callers use what it returns. Ignoring the return value
    // left the raw reply in place and stored 42 in coverageGaps.
    invoke.mockResolvedValueOnce({
      records: [],
      channels: [],
      totalRecords: 0,
      parseErrors: 1,
      errorMessages: ["real gap", 42, null],
    });

    return useEvtxStore
      .getState()
      .queryChannels(["Application"])
      .then(() => {
        expect(useEvtxStore.getState().coverageGaps).toEqual(["real gap"]);
      });
  });
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
      channels: [{ name: channel, eventCount: totalRecords, sourceType: "live" }],
      totalRecords,
      parseErrors: 0,
      errorMessages: [],
    };
  }

  it("assembles the view from batches the reply did not carry", async () => {
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1), record("System", 2)]);
      emitBatch("System", 1, [record("System", 3)]);
      return streamedReply("System", 3);
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(3);
    expect(state.coverageGaps).toEqual([]);
  });

  it("reports a batch that never arrived instead of showing a short list as complete", async () => {
    // Sequence 1 is skipped. Its events are simply absent, and an absent event is indistinguishable
    // from an event that never happened unless the gap is stated.
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1)]);
      emitBatch("System", 2, [record("System", 3)]);
      return streamedReply("System", 3);
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    const gaps = useEvtxStore.getState().coverageGaps;
    expect(gaps.some((g) => g.includes("System") && g.includes("batches"))).toBe(true);
  });

  it("reports a shortfall against the count the reader sent", async () => {
    // Every batch arrived in order, but fewer events than the reader says it sent.
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1)]);
      return streamedReply("System", 9);
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    const gaps = useEvtxStore.getState().coverageGaps;
    expect(gaps.some((g) => g.includes("8 of 9"))).toBe(true);
  });

  it("does not invent a shortfall when the reader gave no count", async () => {
    // An absent count means completeness cannot be checked. Treating it as zero would report every
    // arriving record as unexpected; treating it as a shortfall would cry wolf on every load.
    invoke.mockImplementationOnce(async () => {
      emitBatch("System", 0, [record("System", 1)]);
      return { ...streamedReply("System", 0), totalRecords: "unknown" };
    });

    await useEvtxStore.getState().queryChannels(["System"]);

    expect(useEvtxStore.getState().records).toHaveLength(1);
    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("still works when the reader returned the records in the reply instead", async () => {
    // Collecting callers exist, and a backend that did not stream must not look like a total loss.
    invoke.mockResolvedValueOnce({
      records: [record("System", 1), record("System", 2)],
      channels: [{ name: "System", eventCount: 2, sourceType: "live" }],
      totalRecords: 2,
      parseErrors: 0,
      errorMessages: [],
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
      return streamedReply("System", 1);
    });
    await useEvtxStore.getState().queryChannels(["System"]);

    const state = useEvtxStore.getState();
    expect(state.records).toHaveLength(1);
    expect(state.records[0].eventRecordId).toBe(5);
  });

  it("finds the highest batch number without spreading every one", async () => {
    // The highest sequence is found by reduction. Spreading the set into Math.max(...) arguments
    // throws RangeError once a channel produces more batches than the engine accepts as arguments,
    // which a reduced fetch batch makes reachable for a channel the size of Security.
    const batches = 200_000;
    invoke.mockImplementationOnce(async () => {
      for (let sequence = 0; sequence < batches; sequence++) {
        emitBatch("Huge", sequence, []);
      }
      return streamedReply("Huge", 0);
    });

    await useEvtxStore.getState().queryChannels(["Huge"]);

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("does not leave the workspace stuck loading when a reply is unreadable", async () => {
    // assertParseResultShape throws by design on a reply this build cannot read. The processing
    // loop was unguarded, so the throw rejected queryChannels before isLoading was cleared and the
    // operator saw an endless spinner with no error.
    invoke.mockResolvedValueOnce({ records: null, channels: [] });

    await useEvtxStore.getState().queryChannels(["Application"]);

    const state = useEvtxStore.getState();
    expect(state.isLoading).toBe(false);
    expect(state.loadError).toContain("Application");
    expect(state.coverageGaps.some((g) => g.includes("Application"))).toBe(true);
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
    invoke.mockResolvedValueOnce({
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

    expect(useEvtxStore.getState().coverageGaps).toHaveLength(1);
    expect(useEvtxStore.getState().coverageGaps).toContain(
      "Security: not read (access denied)"
    );
    expect(useEvtxStore.getState().loadError).toBe("Security: access denied");
  });
  it("keeps local source selection local after a remote attempt", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_channels") {
        return [{ name: "Application", eventCount: 0, sourceType: "live" }];
      }
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
  });
});
