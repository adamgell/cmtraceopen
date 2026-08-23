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
const { openEventLogSource, openEventLogSources } =
  await import("./open-event-log-source");

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

  it("does not let an older enumeration replace a newer expanding source", async () => {
    const existingRecord = record("Existing");
    const olderEnumeration = deferred<
      Array<{ name: string; eventCount: number; sourceType: "live" }>
    >();
    const newerExpansion = deferred<EventLogSourceManifest>();
    useEvtxStore.setState({
      records: [existingRecord],
      channels: [
        {
          name: "Existing",
          eventCount: 1,
          sourceType: { file: { path: "Existing.evtx" } },
        },
      ],
      sourceMode: "files",
    });
    invoke.mockImplementation((command: string) => {
      if (command === "evtx_enumerate_channels") return olderEnumeration.promise;
      throw new Error(`Unexpected command: ${command}`);
    });
    expandEventLogSources.mockReturnValueOnce(newerExpansion.promise);

    const enumerationResult = useEvtxStore.getState().enumerateChannels();
    const newerResult = openEventLogSources([
      { kind: "folder", path: "/logs/newer" },
    ]).then(
      () => null,
      (error: unknown) => error,
    );
    olderEnumeration.resolve([
      { name: "Custom", eventCount: 0, sourceType: "live" },
    ]);
    await enumerationResult;
    newerExpansion.reject(new Error("newer expansion failed"));
    expect(await newerResult).toEqual(new Error("newer expansion failed"));

    const state = useEvtxStore.getState();
    expect(state.records).toEqual([existingRecord]);
    expect(state.channels).toEqual([
      {
        name: "Existing",
        eventCount: 1,
        sourceType: { file: { path: "Existing.evtx" } },
      },
    ]);
    expect(state.sourceMode).toBe("files");
    expect(state.loadError).toBe("newer expansion failed");
  });

  it("rejects a current file parse failure after recording it", async () => {
    invoke.mockRejectedValueOnce(new Error("file parse failed"));

    await expect(
      openEventLogSource({ kind: "file", path: "/logs/broken.evtx" }),
    ).rejects.toThrow("file parse failed");

    const state = useEvtxStore.getState();
    expect(state.isLoading).toBe(false);
    expect(state.loadError).toBe("file parse failed");
  });

  it("rejects a current manifest parse failure after recording it", async () => {
    const brokenManifest = manifest("/logs/broken/Application.evtx");
    expandEventLogSources.mockResolvedValueOnce(brokenManifest);
    invoke.mockRejectedValueOnce(new Error("manifest parse failed"));

    await expect(
      openEventLogSources([{ kind: "folder", path: "/logs/broken" }]),
    ).rejects.toThrow("manifest parse failed");

    const state = useEvtxStore.getState();
    expect(state.isLoading).toBe(false);
    expect(state.loadError).toBe("manifest parse failed");
    expect(state.sourceManifest).toEqual(brokenManifest);
  });

  it("resolves a stale parse failure without replacing the current error", async () => {
    const olderManifest = manifest("/logs/older/Application.evtx");
    const olderParse = deferred<EvtxParseResult>();
    expandEventLogSources
      .mockResolvedValueOnce(olderManifest)
      .mockRejectedValueOnce(new Error("newer expansion failed"));
    invoke.mockReturnValueOnce(olderParse.promise);

    const olderResult = openEventLogSources([
      { kind: "folder", path: "/logs/older" },
    ]).then(
      () => null,
      (error: unknown) => error,
    );
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
    expect(await newerResult).toEqual(new Error("newer expansion failed"));

    olderParse.reject(new Error("older parse failed"));
    expect(await olderResult).toBeNull();
    expect(useEvtxStore.getState().loadError).toBe("newer expansion failed");
  });

  it("does not parse an older expansion after local enumeration becomes current", async () => {
    const olderManifest = manifest("/logs/older/Application.evtx");
    const olderExpansion = deferred<EventLogSourceManifest>();
    expandEventLogSources.mockReturnValueOnce(olderExpansion.promise);
    invoke.mockImplementation((command: string) => {
      if (command === "evtx_enumerate_channels") return Promise.resolve([]);
      if (command === "evtx_parse_manifest") {
        return Promise.resolve(parseResult(record("Older")));
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    const olderOpen = openEventLogSources([
      { kind: "folder", path: "/logs/older" },
    ]);
    await useEvtxStore.getState().enumerateLocalChannels();
    olderExpansion.resolve(olderManifest);
    await olderOpen;

    expect(invoke).not.toHaveBeenCalledWith("evtx_parse_manifest", {
      manifest: olderManifest,
    });
    expect(useEvtxStore.getState().sourceMode).toBe("live");
    expect(useEvtxStore.getState().records).toEqual([]);
  });

  it("does not parse an older expansion after remote validation becomes current", async () => {
    const olderManifest = manifest("/logs/older/Application.evtx");
    const olderExpansion = deferred<EventLogSourceManifest>();
    expandEventLogSources.mockReturnValueOnce(olderExpansion.promise);
    invoke.mockImplementation((command: string) => {
      if (command === "evtx_parse_manifest") {
        return Promise.resolve(parseResult(record("Older")));
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    const olderOpen = openEventLogSources([
      { kind: "folder", path: "/logs/older" },
    ]);
    await useEvtxStore.getState().enumerateRemoteChannels("bad\0host");
    olderExpansion.resolve(olderManifest);
    await olderOpen;

    expect(invoke).not.toHaveBeenCalledWith("evtx_parse_manifest", {
      manifest: olderManifest,
    });
    expect(useEvtxStore.getState().sourceMode).toBeNull();
    expect(useEvtxStore.getState().loadError).toBe(
      "Enter a valid remote computer name.",
    );
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
          mode: "polling",
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
    expect(state.tailMode).toBe("polling");
    expect(state.tailRequestId).toBe(tailRequestId);
    expect(state.tailChannels).toEqual(new Set(["Application"]));
    expect(invoke).not.toHaveBeenCalledWith(
      "evtx_stop_tail",
      expect.anything(),
    );
  });
});
