import { invoke } from "@tauri-apps/api/core";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useFilterStore } from "../stores/filter-store";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import { restoreSession } from "./session-restore";

vi.mock("./log-source", () => ({
  loadPathAsLogSource: vi.fn(async (filePath: string) => {
    useUiStore.getState().openTab(filePath, filePath.split(/[\\/]/).pop() ?? filePath, {
      sourceKind: "file",
      sourcePath: null,
      source: { kind: "file", path: filePath },
    });
  }),
  loadFilesAsLogSource: vi.fn(),
}));

describe("restoreSession", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
    vi.mocked(readTextFile).mockReset();
    useLogStore.getState().clear();
    useUiStore.getState().clearTabs();
    useFilterStore.getState().clearFilter();
  });

  it("restores saved filter clauses", async () => {
    vi.mocked(invoke).mockResolvedValue({ hash: "abc123", sizeBytes: 42 });
    vi.mocked(readTextFile).mockResolvedValue(JSON.stringify({
      version: 1,
      savedAt: "2026-05-12T22:00:00.000Z",
      workspace: "log",
      tabs: [
        {
          filePath: "/tmp/test.log",
          fileHash: "abc123",
          fileSize: 42,
          selectedId: null,
          scrollPosition: null,
          activeColumns: [],
        },
      ],
      activeTabIndex: 0,
      mergedTabState: null,
      filters: {
        clauses: [
          { field: "Message", op: "Contains", value: "error" },
          { field: "NotAField", op: "Contains", value: "ignored" },
        ],
        findQuery: "needle",
        findCaseSensitive: true,
        findUseRegex: false,
        highlightText: "warn",
      },
      workspaceState: { type: "log" },
    }));

    await expect(restoreSession("/tmp/session.cmtrace")).resolves.toBe("/tmp/session.cmtrace");

    expect(useFilterStore.getState().clauses).toEqual([
      { field: "Message", op: "Contains", value: "error" },
    ]);
    expect(useLogStore.getState().findQuery).toBe("needle");
    expect(useLogStore.getState().highlightText).toBe("warn");
  });
});
