import { describe, it, expect, beforeEach, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { loadFilesAsLogSource, loadPathAsLogSource } from "./log-source";
import { restoreSession } from "./session-restore";
import { useFilterStore } from "../stores/filter-store";

// Keep restore off the real backend/file loaders — we only care that the saved
// filter clauses end up in the filter store (issue #193).
vi.mock("./log-source", () => ({
  loadPathAsLogSource: vi.fn().mockResolvedValue({}),
  loadFilesAsLogSource: vi.fn().mockResolvedValue(undefined),
}));

const restoredLoadResult = {
  source: { kind: "file", path: "/tmp/app.log" } as const,
  entries: [],
  selectedFilePath: "/tmp/app.log",
  parseResult: null,
};

function sessionJson(clauses: unknown[], tabCount = 1): string {
  const tabs = Array.from({ length: tabCount }, (_, index) => {
    const filePath = index === 0 ? "/tmp/app.log" : `/tmp/app-${index}.log`;
    return {
      filePath,
      fileHash: "abc",
      fileSize: 100,
      selectedId: null,
      scrollPosition: null,
      activeColumns: [],
    };
  });

  return JSON.stringify({
    version: 1,
    savedAt: "2026-01-01T00:00:00Z",
    workspace: "log",
    tabs,
    activeTabIndex: 0,
    mergedTabState: null,
    filters: {
      clauses,
      findQuery: "",
      findCaseSensitive: false,
      findUseRegex: false,
      highlightText: "",
    },
    workspaceState: { type: "log" },
  });
}

describe("restoreSession filter restore (issue #193)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(loadPathAsLogSource)
      .mockReset()
      .mockResolvedValue(restoredLoadResult);
    vi.mocked(loadFilesAsLogSource).mockReset().mockResolvedValue(undefined);
    // compute_file_hash returns a matching hash so the tab is considered valid.
    vi.mocked(invoke).mockResolvedValue({ hash: "abc", sizeBytes: 100 });
    useFilterStore.getState().clearFilter();
  });

  it("writes the saved filter clauses back into the filter store", async () => {
    vi.mocked(readTextFile).mockResolvedValue(
      sessionJson([{ field: "Message", op: "Contains", value: "error" }])
    );

    expect(useFilterStore.getState().clauses).toHaveLength(0);

    await restoreSession("/tmp/session.cmtrace");

    const clauses = useFilterStore.getState().clauses;
    expect(clauses).toEqual([{ field: "Message", op: "Contains", value: "error" }]);
  });

  it("does not aggregate after an individual restore is superseded", async () => {
    vi.mocked(readTextFile).mockResolvedValue(sessionJson([], 2));
    vi.mocked(loadPathAsLogSource).mockResolvedValueOnce(null);

    await expect(restoreSession("/tmp/session.cmtrace")).resolves.toBeNull();
    expect(loadPathAsLogSource).toHaveBeenCalledTimes(1);
    expect(loadFilesAsLogSource).not.toHaveBeenCalled();
  });

  it("leaves the filter cleared when the session had no clauses", async () => {
    vi.mocked(readTextFile).mockResolvedValue(sessionJson([]));

    await restoreSession("/tmp/session.cmtrace");

    expect(useFilterStore.getState().clauses).toHaveLength(0);
  });
});
