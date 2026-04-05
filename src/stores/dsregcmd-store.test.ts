import { describe, it, expect, beforeEach } from "vitest";
import { useDsregcmdStore } from "../workspaces/dsregcmd/dsregcmd-store";

describe("dsregcmd-store", () => {
  beforeEach(() => {
    useDsregcmdStore.getState().clear();
  });

  describe("initial state", () => {
    it("starts in idle phase", () => {
      const state = useDsregcmdStore.getState();
      expect(state.analysisState.phase).toBe("idle");
      expect(state.isAnalyzing).toBe(false);
      expect(state.result).toBeNull();
      expect(state.rawInput).toBe("");
    });
  });

  describe("state transitions", () => {
    it("idle -> analyzing on beginAnalysis", () => {
      useDsregcmdStore.getState().beginAnalysis({
        kind: "file",
        path: "/dsregcmd.txt",
      });

      const state = useDsregcmdStore.getState();
      expect(state.analysisState.phase).toBe("analyzing");
      expect(state.isAnalyzing).toBe(true);
      expect(state.sourceContext.displayLabel).toBe("/dsregcmd.txt");
    });

    it("analyzing -> analyzing with clipboard source", () => {
      useDsregcmdStore.getState().beginAnalysis({ kind: "clipboard" });

      const state = useDsregcmdStore.getState();
      expect(state.analysisState.phase).toBe("analyzing");
      expect(state.sourceContext.displayLabel).toBe("Clipboard");
    });

    it("analyzing -> analyzing with capture source", () => {
      useDsregcmdStore.getState().beginAnalysis({ kind: "capture" });

      const state = useDsregcmdStore.getState();
      expect(state.analysisState.phase).toBe("analyzing");
      expect(state.sourceContext.displayLabel).toBe("Live capture");
      expect(state.analysisState.message).toContain("Capturing");
    });

    it("analyzing -> error on failAnalysis", () => {
      useDsregcmdStore.getState().beginAnalysis({
        kind: "file",
        path: "/dsregcmd.txt",
      });
      useDsregcmdStore.getState().failAnalysis("Permission denied");

      const state = useDsregcmdStore.getState();
      expect(state.analysisState.phase).toBe("error");
      expect(state.isAnalyzing).toBe(false);
      expect(state.analysisState.lastError).toBe("Permission denied");
    });

    it("failAnalysis handles Error objects", () => {
      useDsregcmdStore.getState().beginAnalysis({
        kind: "file",
        path: "/test.txt",
      });
      useDsregcmdStore.getState().failAnalysis(new Error("File not found"));

      expect(useDsregcmdStore.getState().analysisState.lastError).toBe("File not found");
    });

    it("failAnalysis handles unknown error types", () => {
      useDsregcmdStore.getState().beginAnalysis({
        kind: "file",
        path: "/test.txt",
      });
      useDsregcmdStore.getState().failAnalysis(42);

      expect(useDsregcmdStore.getState().analysisState.lastError).toContain(
        "could not be analyzed"
      );
    });
  });

  describe("clear", () => {
    it("resets to initial state", () => {
      useDsregcmdStore.getState().beginAnalysis({
        kind: "file",
        path: "/test.txt",
      });
      useDsregcmdStore.getState().clear();

      const state = useDsregcmdStore.getState();
      expect(state.analysisState.phase).toBe("idle");
      expect(state.isAnalyzing).toBe(false);
      expect(state.result).toBeNull();
      expect(state.activeTab).toBe("analysis");
    });
  });

  describe("tab management", () => {
    it("switches active tab", () => {
      useDsregcmdStore.getState().setActiveTab("event-logs");
      expect(useDsregcmdStore.getState().activeTab).toBe("event-logs");

      useDsregcmdStore.getState().setActiveTab("analysis");
      expect(useDsregcmdStore.getState().activeTab).toBe("analysis");
    });
  });

  describe("event log filters", () => {
    it("sets channel filter and clears selection", () => {
      useDsregcmdStore.getState().selectEventLogEntry(5);
      useDsregcmdStore.getState().setEventLogFilterChannel("DeviceManagementAdmin");

      const state = useDsregcmdStore.getState();
      expect(state.eventLogFilterChannel).toBe("DeviceManagementAdmin");
      expect(state.selectedEventLogEntryId).toBeNull();
    });

    it("sets severity filter and clears selection", () => {
      useDsregcmdStore.getState().selectEventLogEntry(5);
      useDsregcmdStore.getState().setEventLogFilterSeverity("Error");

      const state = useDsregcmdStore.getState();
      expect(state.eventLogFilterSeverity).toBe("Error");
      expect(state.selectedEventLogEntryId).toBeNull();
    });

    it("toggles event log entry selection", () => {
      useDsregcmdStore.getState().selectEventLogEntry(3);
      expect(useDsregcmdStore.getState().selectedEventLogEntryId).toBe(3);

      // Selecting same entry deselects
      useDsregcmdStore.getState().selectEventLogEntry(3);
      expect(useDsregcmdStore.getState().selectedEventLogEntryId).toBeNull();
    });
  });

  describe("resultRevision", () => {
    it("increments on setResults", () => {
      const initialRevision = useDsregcmdStore.getState().resultRevision;

      useDsregcmdStore.getState().setResults(
        "raw output text",
        { factGroups: [], insights: [], joinType: "unknown" } as any,
        {
          source: { kind: "file", path: "/test.txt" },
          requestedPath: "/test.txt",
          resolvedPath: "/test.txt",
          bundlePath: null,
          displayLabel: "test.txt",
          evidenceFilePath: null,
          rawLineCount: 10,
          rawCharCount: 200,
        }
      );

      expect(useDsregcmdStore.getState().resultRevision).toBe(initialRevision + 1);
    });
  });
});
