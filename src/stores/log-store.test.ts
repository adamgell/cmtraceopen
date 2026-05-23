import { describe, it, expect, beforeEach } from "vitest";
import { useLogStore, getCachedTabSnapshot, setCachedTabSnapshot, clearAllTabSnapshots } from "./log-store";
import type { LargeFileModeMetadata, LogEntry } from "../types/log";

function makeEntry(overrides: Partial<LogEntry> & { id: number }): LogEntry {
  return {
    lineNumber: overrides.id,
    message: `message ${overrides.id}`,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Plain",
    filePath: "/test.log",
    timezoneOffset: null,
    ...overrides,
  };
}

describe("log-store", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
    clearAllTabSnapshots();
  });

  function makeLargeFileMode(
    overrides: Partial<LargeFileModeMetadata> = {}
  ): LargeFileModeMetadata {
    return {
      isActive: true,
      thresholdBytes: 50 * 1024 * 1024,
      loadedByteCount: 60 * 1024 * 1024,
      ...overrides,
    };
  }

  describe("setEntries / entries", () => {
    it("sets entries and reads them back", () => {
      const entries = [makeEntry({ id: 1 }), makeEntry({ id: 2 })];
      useLogStore.getState().setEntries(entries);
      expect(useLogStore.getState().entries).toHaveLength(2);
      expect(useLogStore.getState().entries[0].id).toBe(1);
    });

    it("clears selectedId if selected entry removed", () => {
      const entries = [makeEntry({ id: 1 }), makeEntry({ id: 2 })];
      useLogStore.getState().setEntries(entries);
      useLogStore.getState().selectEntry(2);
      expect(useLogStore.getState().selectedId).toBe(2);

      useLogStore.getState().setEntries([makeEntry({ id: 1 })]);
      expect(useLogStore.getState().selectedId).toBeNull();
    });

    it("preserves selectedId if selected entry still exists", () => {
      const entries = [makeEntry({ id: 1 }), makeEntry({ id: 2 })];
      useLogStore.getState().setEntries(entries);
      useLogStore.getState().selectEntry(1);

      useLogStore.getState().setEntries([makeEntry({ id: 1 }), makeEntry({ id: 3 })]);
      expect(useLogStore.getState().selectedId).toBe(1);
    });
  });

  describe("appendEntries", () => {
    it("appends to existing entries and increments totalLines", () => {
      useLogStore.getState().setEntries([makeEntry({ id: 1 })]);
      useLogStore.getState().setTotalLines(1);
      useLogStore.getState().appendEntries([makeEntry({ id: 2 }), makeEntry({ id: 3 })]);

      expect(useLogStore.getState().entries).toHaveLength(3);
      expect(useLogStore.getState().totalLines).toBe(3);
    });
  });

  describe("selectEntry", () => {
    it("sets and clears selection", () => {
      useLogStore.getState().selectEntry(5);
      expect(useLogStore.getState().selectedId).toBe(5);

      useLogStore.getState().selectEntry(null);
      expect(useLogStore.getState().selectedId).toBeNull();
    });
  });

  describe("togglePause", () => {
    it("toggles isPaused state", () => {
      expect(useLogStore.getState().isPaused).toBe(false);
      useLogStore.getState().togglePause();
      expect(useLogStore.getState().isPaused).toBe(true);
      useLogStore.getState().togglePause();
      expect(useLogStore.getState().isPaused).toBe(false);
    });
  });

  describe("largeFileMode", () => {
    it("sets and reads active large file mode metadata", () => {
      const largeFileMode = makeLargeFileMode();

      useLogStore.getState().setLargeFileMode(largeFileMode);

      expect(useLogStore.getState().largeFileMode).toEqual(largeFileMode);
    });

    it("treats null or disabled metadata as normal mode", () => {
      expect(useLogStore.getState().largeFileMode).toBeNull();

      const disabledMode = makeLargeFileMode({
        isActive: false,
        loadedByteCount: 1024,
      });
      useLogStore.getState().setLargeFileMode(disabledMode);

      expect(useLogStore.getState().largeFileMode).toEqual(disabledMode);
      expect(useLogStore.getState().largeFileMode?.isActive).toBe(false);

      useLogStore.getState().setLargeFileMode(null);
      expect(useLogStore.getState().largeFileMode).toBeNull();
    });
  });

  describe("clear", () => {
    it("resets all state to defaults", () => {
      useLogStore.getState().setEntries([makeEntry({ id: 1 })]);
      useLogStore.getState().selectEntry(1);
      useLogStore.getState().setOpenFilePath("/test.log");
      useLogStore.getState().setLargeFileMode(makeLargeFileMode());

      useLogStore.getState().clear();

      const state = useLogStore.getState();
      expect(state.entries).toHaveLength(0);
      expect(state.selectedId).toBeNull();
      expect(state.openFilePath).toBeNull();
      expect(state.largeFileMode).toBeNull();
      expect(state.sourceStatus.kind).toBe("idle");
    });
  });

  describe("clearActiveFile", () => {
    it("clears file-specific state but keeps source context", () => {
      useLogStore.getState().setEntries([makeEntry({ id: 1 })]);
      useLogStore.getState().setActiveSource({ kind: "folder", path: "/logs" });
      useLogStore.getState().setLargeFileMode(makeLargeFileMode());

      useLogStore.getState().clearActiveFile();

      expect(useLogStore.getState().entries).toHaveLength(0);
      expect(useLogStore.getState().largeFileMode).toBeNull();
      // activeSource should be preserved
      expect(useLogStore.getState().activeSource).not.toBeNull();
    });
  });

  describe("hasActiveSource", () => {
    it("returns false when no source or file", () => {
      expect(useLogStore.getState().hasActiveSource()).toBe(false);
    });

    it("returns true when file path set", () => {
      useLogStore.getState().setOpenFilePath("/test.log");
      expect(useLogStore.getState().hasActiveSource()).toBe(true);
    });

    it("returns true when active source set", () => {
      useLogStore.getState().setActiveSource({ kind: "file", path: "/test.log" });
      expect(useLogStore.getState().hasActiveSource()).toBe(true);
    });
  });

  describe("find functionality", () => {
    it("findNext cycles through matches", () => {
      const entries = [
        makeEntry({ id: 1, message: "error in module A" }),
        makeEntry({ id: 2, message: "info message" }),
        makeEntry({ id: 3, message: "error in module B" }),
      ];
      useLogStore.getState().setEntries(entries);
      useLogStore.getState().setFindQuery("error");

      // Wait for debounce to settle — use direct recompute
      useLogStore.getState().recomputeFindMatches();

      expect(useLogStore.getState().findMatchIds).toHaveLength(2);
      expect(useLogStore.getState().findMatchIds).toEqual([1, 3]);

      useLogStore.getState().findNext("test");
      expect(useLogStore.getState().findCurrentIndex).toBe(1);
      expect(useLogStore.getState().selectedId).toBe(3);

      useLogStore.getState().findNext("test");
      expect(useLogStore.getState().findCurrentIndex).toBe(0);
      expect(useLogStore.getState().selectedId).toBe(1);
    });

    it("findPrevious cycles backwards", () => {
      const entries = [
        makeEntry({ id: 1, message: "error A" }),
        makeEntry({ id: 2, message: "error B" }),
      ];
      useLogStore.getState().setEntries(entries);
      useLogStore.getState().setFindQuery("error");
      useLogStore.getState().recomputeFindMatches();

      useLogStore.getState().findPrevious("test");
      expect(useLogStore.getState().findCurrentIndex).toBe(1);
    });

    it("clearFind resets find state", () => {
      useLogStore.getState().setFindQuery("test");
      useLogStore.getState().clearFind();

      const state = useLogStore.getState();
      expect(state.findQuery).toBe("");
      expect(state.findMatchIds).toHaveLength(0);
      expect(state.findCurrentIndex).toBe(-1);
    });
  });

  describe("error navigation", () => {
    it("wraps next and previous across visible Error entries", () => {
      useLogStore.getState().setEntries([
        makeEntry({ id: 1, severity: "Info" }),
        makeEntry({ id: 2, severity: "Error" }),
        makeEntry({ id: 3, severity: "Warning" }),
        makeEntry({ id: 4, severity: "Error" }),
      ]);
      useLogStore.getState().setVisibleEntryIds([1, 2, 3, 4]);

      expect(useLogStore.getState().canNavigateVisibleErrors()).toBe(true);

      useLogStore.getState().selectEntry(4);
      useLogStore.getState().selectNextVisibleError("test.next-wrap");
      expect(useLogStore.getState().selectedId).toBe(2);

      useLogStore.getState().selectPreviousVisibleError("test.previous-wrap");
      expect(useLogStore.getState().selectedId).toBe(4);
    });

    it("selects the first or last visible Error when nothing is selected", () => {
      useLogStore.getState().setEntries([
        makeEntry({ id: 1, severity: "Error" }),
        makeEntry({ id: 2, severity: "Info" }),
        makeEntry({ id: 3, severity: "Error" }),
      ]);
      useLogStore.getState().setVisibleEntryIds([1, 2, 3]);

      useLogStore.getState().selectNextVisibleError("test.next-no-selection");
      expect(useLogStore.getState().selectedId).toBe(1);

      useLogStore.getState().selectEntry(null);
      useLogStore.getState().selectPreviousVisibleError("test.previous-no-selection");
      expect(useLogStore.getState().selectedId).toBe(3);
    });

    it("uses the current visible order and exact Error severity", () => {
      useLogStore.getState().setEntries([
        makeEntry({ id: 1, severity: "Error" }),
        makeEntry({ id: 2, severity: "Info" }),
        makeEntry({ id: 3, severity: "Warning" }),
        makeEntry({ id: 4, severity: "Error" }),
      ]);
      useLogStore.getState().setVisibleEntryIds([4, 3, 2]);

      expect(useLogStore.getState().visibleErrorEntryIds).toEqual([4]);

      useLogStore.getState().selectEntry(3);
      useLogStore.getState().selectNextVisibleError("test.filtered-visible-order");
      expect(useLogStore.getState().selectedId).toBe(4);
    });

    it("does nothing when there are no visible Error entries", () => {
      useLogStore.getState().setEntries([
        makeEntry({ id: 1, severity: "Info" }),
        makeEntry({ id: 2, severity: "Warning" }),
      ]);
      useLogStore.getState().setVisibleEntryIds([1, 2]);
      useLogStore.getState().selectEntry(1);

      expect(useLogStore.getState().canNavigateVisibleErrors()).toBe(false);
      expect(useLogStore.getState().visibleErrorEntryIds).toEqual([]);

      useLogStore.getState().selectNextVisibleError("test.no-visible-errors");
      expect(useLogStore.getState().selectedId).toBe(1);

      useLogStore.getState().setEntries([]);
      useLogStore.getState().setVisibleEntryIds([]);
      useLogStore.getState().selectEntry(null);
      useLogStore.getState().selectPreviousVisibleError("test.no-entries");
      expect(useLogStore.getState().selectedId).toBeNull();
    });
  });

  describe("source status", () => {
    it("setSourceStatus and clearSourceStatus", () => {
      useLogStore.getState().setSourceStatus({ kind: "loading", message: "Loading..." });
      expect(useLogStore.getState().sourceStatus.kind).toBe("loading");

      useLogStore.getState().clearSourceStatus();
      expect(useLogStore.getState().sourceStatus.kind).toBe("idle");
      expect(useLogStore.getState().sourceStatus.message).toBe("Ready");
    });
  });

  describe("folder load progress", () => {
    it("sets and clears progress", () => {
      useLogStore.getState().setFolderLoadProgress({
        current: 3,
        total: 10,
        currentFile: "file3.log",
      });

      const state = useLogStore.getState();
      expect(state.folderLoadProgress).toBeCloseTo(0.3);
      expect(state.folderLoadCurrentFile).toBe("file3.log");
      expect(state.folderLoadTotalFiles).toBe(10);

      useLogStore.getState().setFolderLoadProgress(null);
      expect(useLogStore.getState().folderLoadProgress).toBeNull();
    });
  });
});

describe("tab entry cache", () => {
  beforeEach(() => {
    clearAllTabSnapshots();
  });

  it("stores and retrieves snapshots", () => {
    const snapshot = {
      entries: [makeEntry({ id: 1 })],
      formatDetected: null,
      parserSelection: null,
      totalLines: 1,
      byteOffset: 0,
      largeFileMode: null,
      selectedSourceFilePath: null,
      sourceOpenMode: null as "single-file" | "aggregate-folder" | null,
      activeColumns: ["message" as const] as ("message")[],
    };

    setCachedTabSnapshot("/test.log", snapshot);
    expect(getCachedTabSnapshot("/test.log")).toBe(snapshot);
  });

  it("returns undefined for uncached paths", () => {
    expect(getCachedTabSnapshot("/nonexistent.log")).toBeUndefined();
  });
});
