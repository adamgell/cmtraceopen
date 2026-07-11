import { describe, it, expect, beforeEach, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { restoreSession } from "./session-restore";
import { useFilterStore } from "../stores/filter-store";

// Keep restore off the real backend/file loaders — we only care that the saved
// filter clauses end up in the filter store (issue #193).
vi.mock("./log-source", () => ({
  loadPathAsLogSource: vi.fn().mockResolvedValue(undefined),
  loadFilesAsLogSource: vi.fn().mockResolvedValue(undefined),
}));

function sessionJson(clauses: unknown[]): string {
  return JSON.stringify({
    version: 1,
    savedAt: "2026-01-01T00:00:00Z",
    workspace: "log",
    tabs: [
      {
        filePath: "/tmp/app.log",
        fileHash: "abc",
        fileSize: 100,
        selectedId: null,
        scrollPosition: null,
        activeColumns: [],
      },
    ],
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

  it("leaves the filter cleared when the session had no clauses", async () => {
    vi.mocked(readTextFile).mockResolvedValue(sessionJson([]));

    await restoreSession("/tmp/session.cmtrace");

    expect(useFilterStore.getState().clauses).toHaveLength(0);
  });
});
