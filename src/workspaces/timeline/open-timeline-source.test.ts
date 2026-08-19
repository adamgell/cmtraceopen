import { beforeEach, describe, expect, it, vi } from "vitest";
import { listLogFolder } from "../../lib/commands";
import { buildTimelineFromSources } from "../../components/timeline/hooks/useTimelineBundle";
import { useTimelineStore } from "../../stores/timeline-store";
import type { TimelineBundle } from "../../types/timeline";
import {
  openTimelineSource,
  replaceTimelineSource,
} from "./open-timeline-source";

vi.mock("../../lib/commands", () => ({
  listLogFolder: vi.fn(),
}));

vi.mock("../../components/timeline/hooks/useTimelineBundle", () => ({
  buildTimelineFromSources: vi.fn(async () => ({ sources: [] })),
}));
function deferred<T>() {
  let resolvePromise: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });

  return {
    promise,
    resolve(value: T) {
      if (!resolvePromise) {
        throw new Error("Deferred promise resolver was not initialized");
      }
      resolvePromise(value);
    },
  };
}

function bundleFor(paths: string[]): TimelineBundle {
  return {
    id: "fixture",
    sources: paths.map((path, idx) => ({
      idx,
      kind: "intuneEvents",
      path,
      displayName: path,
      color: "#000000",
      entryCount: 0,
    })),
    timeRangeMs: [0, 0],
    totalEntries: 0,
    incidents: [],
    deniedGuids: [],
    errors: [],
    tunables: {
      overlapWindowMs: 5_000,
      minSourceCount: 2,
      maxIncidentSpanMs: 60_000,
      enabledSignalKinds: ["errorSeverity"],
    },
  };
}

describe("openTimelineSource", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useTimelineStore.setState({ bundle: null, loadError: null });
  });

  it("builds a timeline from a single file", async () => {
    await openTimelineSource({ kind: "file", path: "/tmp/AppEnforce.log" });
    expect(buildTimelineFromSources).toHaveBeenCalledWith([
      { path: "/tmp/AppEnforce.log" },
    ]);
  });
  it("builds a timeline from a known file source", async () => {
    const defaultPath = "/tmp/known.log";

    await openTimelineSource({
      kind: "known",
      sourceId: "known-file",
      defaultPath,
      pathKind: "file",
    });

    expect(buildTimelineFromSources).toHaveBeenCalledWith([
      { path: defaultPath },
    ]);
    expect(listLogFolder).not.toHaveBeenCalled();
  });

  it("expands a known folder source before building", async () => {
    const defaultPath = "/tmp/known-logs";
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "known",
      source: {
        kind: "known",
        sourceId: "known-folder",
        defaultPath,
        pathKind: "folder",
      },
      entries: [
        {
          name: "known.log",
          path: `${defaultPath}/known.log`,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
      ],
    });

    await openTimelineSource({
      kind: "known",
      sourceId: "known-folder",
      defaultPath,
      pathKind: "folder",
    });

    expect(listLogFolder).toHaveBeenCalledWith(defaultPath);
    expect(buildTimelineFromSources).toHaveBeenCalledWith([
      { path: `${defaultPath}/known.log` },
    ]);
  });

  it("unions folder files with an existing timeline", async () => {
    useTimelineStore.setState({
      bundle: bundleFor(["/tmp/existing.log"]),
    });
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/logs" },
      entries: [
        {
          name: "a.log",
          path: "/tmp/logs/a.log",
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
        {
          name: "dir",
          path: "/tmp/logs/dir",
          isDir: true,
          sizeBytes: null,
          modifiedUnixMs: null,
        },
      ],
    });

    await openTimelineSource({ kind: "folder", path: "/tmp/logs" });
    expect(buildTimelineFromSources).toHaveBeenCalledWith([
      { path: "/tmp/existing.log" },
      { path: "/tmp/logs/a.log" },
    ]);
  });
  it("replaces pending timeline appends instead of merging stale sources", async () => {
    useTimelineStore.setState({
      bundle: bundleFor(["/tmp/existing.log"]),
    });
    const firstBuild = deferred<TimelineBundle>();
    const secondBuild = deferred<TimelineBundle>();
    vi.mocked(buildTimelineFromSources)
      .mockImplementationOnce(async () => {
        const bundle = await firstBuild.promise;
        useTimelineStore.getState().setBundle(bundle);
        return bundle;
      })
      .mockImplementationOnce(async () => {
        const bundle = await secondBuild.promise;
        useTimelineStore.getState().setBundle(bundle);
        return bundle;
      });

    const append = openTimelineSource({ kind: "file", path: "/tmp/old.log" });
    await vi.waitFor(() => {
      expect(buildTimelineFromSources).toHaveBeenCalledTimes(1);
    });
    const replacement = replaceTimelineSource({
      kind: "file",
      path: "/tmp/new.log",
    });

    firstBuild.resolve(bundleFor(["/tmp/existing.log", "/tmp/old.log"]));
    await vi.waitFor(() => {
      expect(buildTimelineFromSources).toHaveBeenCalledTimes(2);
    });
    expect(buildTimelineFromSources).toHaveBeenNthCalledWith(2, [
      { path: "/tmp/new.log" },
    ]);

    secondBuild.resolve(bundleFor(["/tmp/new.log"]));
    await Promise.all([append, replacement]);
  });
  it("clears the current timeline for an empty replacement folder", async () => {
    useTimelineStore.setState({
      bundle: bundleFor(["/tmp/existing.log"]),
    });
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/empty-replacement" },
      entries: [],
    });

    await replaceTimelineSource({
      kind: "folder",
      path: "/tmp/empty-replacement",
    });

    expect(useTimelineStore.getState().bundle).toBeNull();
    expect(buildTimelineFromSources).not.toHaveBeenCalled();
  });

  it("clears the current timeline before a replacement load failure", async () => {
    useTimelineStore.setState({
      bundle: bundleFor(["/tmp/existing.log"]),
    });
    vi.mocked(listLogFolder).mockRejectedValue(new Error("access denied"));

    await expect(
      replaceTimelineSource({ kind: "folder", path: "/tmp/denied" }),
    ).rejects.toThrow("access denied");

    expect(useTimelineStore.getState().bundle).toBeNull();
    expect(useTimelineStore.getState().loadError).toBe("access denied");
  });

  it("adds the folder itself when IME logs are present", async () => {
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/ime" },
      entries: [
        {
          name: "IntuneManagementExtension.log",
          path: "/tmp/ime/IntuneManagementExtension.log",
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
        {
          name: "AgentExecutor.log",
          path: "/tmp/ime/AgentExecutor.log",
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
      ],
    });

    await openTimelineSource({ kind: "folder", path: "/tmp/ime" });
    expect(buildTimelineFromSources).toHaveBeenCalledWith([
      { path: "/tmp/ime/IntuneManagementExtension.log" },
      { path: "/tmp/ime/AgentExecutor.log" },
      { path: "/tmp/ime" },
    ]);
  });

  it("does not treat an empty folder as an IntuneEvents source", async () => {
    useTimelineStore.setState({
      bundle: bundleFor(["/tmp/existing.log"]),
      loadError: "stale error",
    });
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/empty" },
      entries: [],
    });

    await openTimelineSource({ kind: "folder", path: "/tmp/empty" });
    expect(buildTimelineFromSources).not.toHaveBeenCalled();
    expect(useTimelineStore.getState().loadError).toBeNull();
  });
  it("serializes overlapping opens so later files are not lost", async () => {
    const listing = deferred<Awaited<ReturnType<typeof listLogFolder>>>();
    const firstBuild = deferred<TimelineBundle>();
    const secondBuild = deferred<TimelineBundle>();
    const folderSource = { kind: "folder" as const, path: "/tmp/logs" };
    const fileSource = { kind: "file" as const, path: "/tmp/other.log" };

    vi.mocked(listLogFolder).mockReturnValueOnce(listing.promise);
    vi.mocked(buildTimelineFromSources)
      .mockImplementationOnce(async () => {
        const bundle = await firstBuild.promise;
        useTimelineStore.getState().setBundle(bundle);
        return bundle;
      })
      .mockImplementationOnce(async () => {
        const bundle = await secondBuild.promise;
        useTimelineStore.getState().setBundle(bundle);
        return bundle;
      });

    const folderOpen = openTimelineSource(folderSource);
    const fileOpen = openTimelineSource(fileSource);

    listing.resolve({
      sourceKind: "folder",
      source: folderSource,
      entries: [
        {
          name: "a.log",
          path: "/tmp/logs/a.log",
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
      ],
    });

    await vi.waitFor(() => {
      expect(buildTimelineFromSources).toHaveBeenCalledTimes(1);
    });
    expect(buildTimelineFromSources).toHaveBeenNthCalledWith(1, [
      { path: "/tmp/logs/a.log" },
    ]);

    firstBuild.resolve(bundleFor(["/tmp/logs/a.log"]));
    await vi.waitFor(() => {
      expect(buildTimelineFromSources).toHaveBeenCalledTimes(2);
    });
    expect(buildTimelineFromSources).toHaveBeenNthCalledWith(2, [
      { path: "/tmp/logs/a.log" },
      { path: "/tmp/other.log" },
    ]);

    secondBuild.resolve(bundleFor(["/tmp/logs/a.log", "/tmp/other.log"]));
    await Promise.all([folderOpen, fileOpen]);

    expect(
      useTimelineStore.getState().bundle?.sources.map((s) => s.path),
    ).toEqual(["/tmp/logs/a.log", "/tmp/other.log"]);
  });
});
