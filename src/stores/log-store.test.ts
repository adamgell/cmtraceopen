import { describe, it, expect, beforeEach } from "vitest";
import { useLogStore, getCachedTabSnapshot, setCachedTabSnapshot, clearAllTabSnapshots } from "./log-store";
import type { LogEntry } from "../types/log";

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

  describe("clear", () => {
    it("resets all state to defaults", () => {
      useLogStore.getState().setEntries([makeEntry({ id: 1 })]);
      useLogStore.getState().selectEntry(1);
      useLogStore.getState().setOpenFilePath("/test.log");

      useLogStore.getState().clear();

      const state = useLogStore.getState();
      expect(state.entries).toHaveLength(0);
      expect(state.selectedId).toBeNull();
      expect(state.openFilePath).toBeNull();
      expect(state.sourceStatus.kind).toBe("idle");
    });
  });

  describe("clearActiveFile", () => {
    it("clears file-specific state but keeps source context", () => {
      useLogStore.getState().setEntries([makeEntry({ id: 1 })]);
      useLogStore.getState().setActiveSource({ kind: "folder", path: "/logs" });

      useLogStore.getState().clearActiveFile();

      expect(useLogStore.getState().entries).toHaveLength(0);
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
