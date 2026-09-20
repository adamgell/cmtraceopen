/**
 * Stopping an in-flight live channel load.
 *
 * The explicit Load is deliberately unbounded, because a whole channel has to stay reachable by an
 * operator who asks for it. On a channel the size of the measured Security log that read is
 * minutes long, so the operator gets a stop control and an honest report of what a stopped read
 * did not fetch. These tests pin both halves of that contract: the stop command goes out under the
 * current request, and a reply that carries a `cancelled` coverage gap leaves the partial records
 * visible without marking the channel loaded — Load stays available for a fresh full read.
 *
 * The Tauri bridge is mocked because the store imports it at module scope.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
import type { EvtxLevel, EvtxRecord } from "./types";

const invoke = vi.hoisted(() => vi.fn());

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => {});
  }),
}));

const { cancelActiveLoad, useEvtxStore } = await import("./evtx-store");

const ALL_LEVELS: EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

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

interface QueryArgs {
  channels?: string[];
  maxEvents?: number | null;
  requestId?: string;
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

function resetStore() {
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
}

describe("cancelling an in-flight channel load", () => {
  beforeEach(() => {
    invoke.mockReset();
    resetStore();
  });

  it("sends the stop command under the request that is currently reading", async () => {
    invoke.mockResolvedValue(undefined);
    useEvtxStore.setState({ isLoading: true });

    await cancelActiveLoad();

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("evtx_cancel_channel_query", {
      requestId: expect.any(String) as string,
    });
  });

  it("stays silent when nothing is loading", async () => {
    await cancelActiveLoad();

    expect(invoke).not.toHaveBeenCalled();
  });

  it("keeps the partial records, says the load was stopped, and leaves Load available", async () => {
    // A deliberately stopped read is a partial read. The rows that did arrive are real and stay
    // on screen; the gap says what was not fetched; and the channel must not count as loaded,
    // because the operator's only path back to a full read is the unbounded Load button.
    const gate = deferred<void>();
    const cancelledGap = {
      source: "Security",
      kind: "cancelled" as const,
      reason:
        "operator stopped the load after 3 events were fetched (the channel may hold more)",
    };
    invoke.mockImplementation(async (name: string, rawArgs: unknown) => {
      if (name === "evtx_cancel_channel_query") {
        gate.resolve(undefined);
        return undefined;
      }
      const args = rawArgs as QueryArgs;
      const channelName = args.channels?.[0] ?? "";
      deliver(
        channelName,
        0,
        [recordFor("Security", 1), recordFor("Security", 2), recordFor("Security", 3)],
        args.requestId
      );
      complete(channelName, 1, 3, args.requestId);
      await gate.promise;
      return {
        records: [],
        channels: [{ name: channelName, eventCount: 3, sourceType: "live" as const }],
        totalRecords: 3,
        parseErrors: 0,
        errorMessages: [],
        coverageGaps: [cancelledGap],
      };
    });

    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Security", eventCount: 3, sourceType: "live" }],
      selectedChannels: new Set(["Security"]),
      loadedChannels: new Set<string>(),
    });
    const load = useEvtxStore.getState().queryChannels(["Security"]);
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenCalledWith(
        "evtx_query_channels",
        expect.objectContaining({ channels: ["Security"], maxEvents: null })
      )
    );

    void cancelActiveLoad();
    await load;

    const state = useEvtxStore.getState();
    expect(state.isLoading).toBe(false);
    expect(state.records.map((record) => record.eventRecordId)).toEqual([1, 2, 3]);
    expect(state.loadedChannels.has("Security")).toBe(false);
    expect(
      state.coverageGaps.find(
        (gap) => gap.startsWith("Security") && gap.includes("operator stopped the load")
      )
    ).toBeDefined();
  });
});
