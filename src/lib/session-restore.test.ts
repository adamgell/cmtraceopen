import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { useFilterStore } from "../stores/filter-store";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";

vi.mock("./log-source", () => ({
  loadPathAsLogSource: vi.fn(),
  loadFilesAsLogSource: vi.fn(),
}));

import { loadFilesAsLogSource, loadPathAsLogSource } from "./log-source";
import { restoreSession } from "./session-restore";

function createMockLoadResult(filePath: string) {
  return {
    source: { kind: "file" as const, path: filePath },
    entries: [],
    selectedFilePath: filePath,
    parseResult: null,
  };
}

function createSessionJson(filters: Record<string, unknown>) {
  return JSON.stringify({
    version: 1,
    savedAt: "2024-01-01T00:00:00.000Z",
    workspace: "log",
    tabs: [
      {
        filePath: "/logs/app.log",
        fileHash: "",
        fileSize: 0,
        selectedId: 12,
        scrollPosition: 24,
        activeColumns: [],
      },
    ],
    activeTabIndex: 0,
    mergedTabState: null,
    filters,
    workspaceState: { type: "log" },
  });
}

describe("session restore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    localStorage.clear();

    useLogStore.getState().clear();
    useLogStore.setState({
      highlightText: "",
      findQuery: "",
      findCaseSensitive: false,
      findUseRegex: false,
    });
    useFilterStore.getState().clearFilter();
    useUiStore.getState().clearTabs();
    useUiStore.getState().clearRecentSessions();
    useUiStore.getState().setActiveWorkspace("log");

    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "compute_file_hash") {
        return { hash: "abc123", sizeBytes: 10 };
      }

      throw new Error(`unexpected invoke: ${command}`);
    });

    vi.mocked(loadFilesAsLogSource).mockResolvedValue(undefined);
    vi.mocked(loadPathAsLogSource).mockImplementation(async (filePath: string) => {
      const fileName = filePath.split(/[\/]/).pop() ?? filePath;
      useUiStore.getState().openTab(filePath, fileName);
      return createMockLoadResult(filePath);
    });
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("restores saved filter clauses after files load without directly executing filters", async () => {
    const savedClauses = [
      { field: "Message", op: "Contains", value: "error" },
      { field: "Severity", op: "Equals", value: "warning" },
    ];
    const events: string[] = [];
    const filterStore = useFilterStore.getState();
    const originalSetClauses = filterStore.setClauses;

    vi.mocked(readTextFile).mockResolvedValue(createSessionJson({
      clauses: savedClauses,
      findQuery: "needle",
      findCaseSensitive: true,
      findUseRegex: true,
      highlightText: "focus",
    }));
    vi.mocked(loadPathAsLogSource).mockImplementation(async (filePath: string) => {
      events.push(`load:${filePath}`);
      const fileName = filePath.split(/[\/]/).pop() ?? filePath;
      useUiStore.getState().openTab(filePath, fileName);
      return createMockLoadResult(filePath);
    });
    vi.spyOn(filterStore, "setClauses").mockImplementation((clauses) => {
      events.push("setClauses");
      originalSetClauses(clauses);
    });

    const result = await restoreSession("/sessions/example.cmtrace");
    vi.runAllTimers();

    expect(result).toBe("/sessions/example.cmtrace");
    expect(useFilterStore.getState().clauses).toEqual(savedClauses);
    expect(useLogStore.getState().findQuery).toBe("needle");
    expect(useLogStore.getState().findCaseSensitive).toBe(true);
    expect(useLogStore.getState().findUseRegex).toBe(true);
    expect(useLogStore.getState().highlightText).toBe("focus");
    expect(events).toEqual(["load:/logs/app.log", "setClauses"]);
    expect(vi.mocked(loadFilesAsLogSource)).not.toHaveBeenCalled();
    expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).toEqual(["compute_file_hash"]);
  });

  it("sanitizes malformed saved clauses during restore without rejecting the session", async () => {
    vi.mocked(readTextFile).mockResolvedValue(createSessionJson({
      clauses: [
        { field: "Component", op: "Equals", value: "SmsProvider" },
        { field: "Component", op: "Bogus", value: "bad" },
        { field: "Unknown", op: "Contains", value: "bad" },
        { field: "Thread", op: "Contains" },
        null,
      ],
      findQuery: "component",
      findCaseSensitive: false,
      findUseRegex: false,
      highlightText: "provider",
    }));

    const result = await restoreSession("/sessions/malformed-filters.cmtrace");
    vi.runAllTimers();

    expect(result).toBe("/sessions/malformed-filters.cmtrace");
    expect(useFilterStore.getState().clauses).toEqual([
      { field: "Component", op: "Equals", value: "SmsProvider" },
    ]);
    expect(useLogStore.getState().findQuery).toBe("component");
    expect(useLogStore.getState().highlightText).toBe("provider");
  });
});
