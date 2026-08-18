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
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/empty" },
      entries: [],
    });

    await openTimelineSource({ kind: "folder", path: "/tmp/empty" });
    expect(buildTimelineFromSources).not.toHaveBeenCalled();
  });

});
