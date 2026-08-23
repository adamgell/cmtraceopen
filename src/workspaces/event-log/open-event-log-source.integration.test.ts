import { beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
import type {
  EventLogSourceManifest,
  EvtxParseResult,
  EvtxRecord,
} from "./types";

const expandEventLogSources = vi.hoisted(() => vi.fn());
const invoke = vi.hoisted(() => vi.fn());

vi.mock("../../lib/commands", () => ({
  clearEventLogChannel: vi.fn(),
  expandEventLogSources,
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => undefined)),
}));

const { useEvtxStore } = await import("./evtx-store");
const { openEventLogSources } = await import("./open-event-log-source");

function manifest(path: string): EventLogSourceManifest {
  return {
    entries: [{ sourceId: path.toLowerCase(), path, kind: "file" }],
    coverage: [],
  };
}

function record(channel: string): EvtxRecord {
  return {
    id: 1,
    eventRecordId: 1,
    timestamp: "2026-08-22T12:00:00.000Z",
    timestampEpoch: 1,
    provider: "Provider",
    channel,
    eventId: 1000,
    level: "Information",
    computer: "HOST",
    message: `${channel} event`,
    eventData: [],
    rawXml: "<Event/>",
    sourceLabel: `${channel}.evtx`,
    mapped: [],
  };
}

function parseResult(event: EvtxRecord): EvtxParseResult {
  return {
    records: [event],
    channels: [
      {
        name: event.channel,
        eventCount: 1,
        sourceType: { file: { path: event.sourceLabel } },
      },
    ],
    totalRecords: 1,
    parseErrors: 0,
    errorMessages: [],
  };
}

describe("source-open integration", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
    expandEventLogSources.mockReset();
    invoke.mockReset();
  });

  it("does not commit an older parse while a newer source is still expanding", async () => {
    const olderManifest = manifest("/logs/older/Application.evtx");
    const newerExpansion = deferred<EventLogSourceManifest>();
    const olderParse = deferred<EvtxParseResult>();
    expandEventLogSources
      .mockResolvedValueOnce(olderManifest)
      .mockReturnValueOnce(newerExpansion.promise);
    invoke.mockReturnValueOnce(olderParse.promise);

    const olderOpen = openEventLogSources([
      { kind: "folder", path: "/logs/older" },
    ]);
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("evtx_parse_manifest", {
        manifest: olderManifest,
      }),
    );

    const newerResult = openEventLogSources([
      { kind: "folder", path: "/logs/newer" },
    ]).then(
      () => null,
      (error: unknown) => error,
    );
    olderParse.resolve(parseResult(record("Older")));
    await olderOpen;

    expect(useEvtxStore.getState().records).toEqual([]);

    newerExpansion.reject(new Error("newer expansion failed"));
    expect(await newerResult).toEqual(new Error("newer expansion failed"));
    expect(useEvtxStore.getState().loadError).toBe("newer expansion failed");
  });

  it("keeps stable live data and tailing when a new expansion fails", async () => {
    const existingRecord = record("Application");
    useEvtxStore.setState({
      records: [existingRecord],
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      sourceMode: "live",
      loadedChannels: new Set(["Application"]),
    });
    invoke.mockImplementationOnce(
      (_command: string, args: { requestId: string; channel: string }) =>
        Promise.resolve({
          requestId: args.requestId,
          channel: args.channel,
          mode: "poll",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        }),
    );
    await useEvtxStore.getState().startLiveTail();
    const tailRequestId = useEvtxStore.getState().tailRequestId;
    invoke.mockClear();
    expandEventLogSources.mockRejectedValueOnce(
      new Error("expansion unavailable"),
    );

    await expect(
      openEventLogSources([{ kind: "folder", path: "/logs/newer" }]),
    ).rejects.toThrow("expansion unavailable");

    const state = useEvtxStore.getState();
    expect(state.records).toEqual([existingRecord]);
    expect(state.tailMode).toBe("poll");
    expect(state.tailRequestId).toBe(tailRequestId);
    expect(state.tailChannels).toEqual(new Set(["Application"]));
    expect(invoke).not.toHaveBeenCalledWith(
      "evtx_stop_tail",
      expect.anything(),
    );
  });
});
