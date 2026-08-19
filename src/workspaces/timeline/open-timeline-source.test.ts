import { beforeEach, describe, expect, it, vi } from "vitest";
import { listLogFolder } from "../../lib/commands";
import { buildTimelineFromSources } from "../../components/timeline/hooks/useTimelineBundle";
import { useTimelineStore } from "../../stores/timeline-store";
import { openTimelineSource } from "./open-timeline-source";

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

type TimelineBuildResult = Awaited<ReturnType<typeof buildTimelineFromSources>>;

function bundleFor(paths: string[]): TimelineBuildResult {
  return {
    sources: paths.map((path, idx) => ({ path, idx })),
  } as TimelineBuildResult;
}

describe("openTimelineSource", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useTimelineStore.setState({ bundle: null } as never);
  });

  it("builds a timeline from a single file", async () => {
    await openTimelineSource({ kind: "file", path: "/tmp/AppEnforce.log" });
    expect(buildTimelineFromSources).toHaveBeenCalledWith([
      { path: "/tmp/AppEnforce.log" },
    ]);
  });

  it("unions folder files with an existing timeline", async () => {
    useTimelineStore.setState({
      bundle: { sources: [{ path: "/tmp/existing.log" }] },
    } as never);
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/logs" },
      entries: [
        { name: "a.log", path: "/tmp/logs/a.log", isDir: false, sizeBytes: 1, modifiedUnixMs: null },
        { name: "dir", path: "/tmp/logs/dir", isDir: true, sizeBytes: null, modifiedUnixMs: null },
      ],
    });

    await openTimelineSource({ kind: "folder", path: "/tmp/logs" });
    expect(buildTimelineFromSources).toHaveBeenCalledWith([
      { path: "/tmp/existing.log" },
      { path: "/tmp/logs/a.log" },
    ]);
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
      bundle: { sources: [{ path: "/tmp/existing.log" }] },
    } as never);
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/empty" },
      entries: [],
    });

    await openTimelineSource({ kind: "folder", path: "/tmp/empty" });
    expect(buildTimelineFromSources).not.toHaveBeenCalled();
  });
  it("serializes overlapping opens so later files are not lost", async () => {
    const listing = deferred<Awaited<ReturnType<typeof listLogFolder>>>();
    const firstBuild = deferred<TimelineBuildResult>();
    const secondBuild = deferred<TimelineBuildResult>();
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

    secondBuild.resolve(
      bundleFor(["/tmp/logs/a.log", "/tmp/other.log"]),
    );
    await Promise.all([folderOpen, fileOpen]);

    expect(useTimelineStore.getState().bundle?.sources.map((s) => s.path)).toEqual([
      "/tmp/logs/a.log",
      "/tmp/other.log",
    ]);
  });

});
