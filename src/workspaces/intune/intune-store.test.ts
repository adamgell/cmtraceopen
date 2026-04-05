import { describe, it, expect, beforeEach } from "vitest";
import { useIntuneStore } from "./intune-store";

describe("intune-store", () => {
  beforeEach(() => {
    useIntuneStore.getState().clear();
  });

  describe("initial state", () => {
    it("starts in idle phase", () => {
      const state = useIntuneStore.getState();
      expect(state.analysisState.phase).toBe("idle");
      expect(state.isAnalyzing).toBe(false);
      expect(state.events).toHaveLength(0);
      expect(state.downloads).toHaveLength(0);
    });
  });

  describe("state transitions", () => {
    it("idle -> analyzing on beginAnalysis", () => {
      useIntuneStore.getState().beginAnalysis("/logs/intune.log", "file");

      const state = useIntuneStore.getState();
      expect(state.analysisState.phase).toBe("analyzing");
      expect(state.isAnalyzing).toBe(true);
    });

    it("analyzing -> ready on setResults", () => {
      useIntuneStore.getState().beginAnalysis("/logs/intune.log", "file");

      const event = {
        id: 1,
        eventType: "Win32App" as const,
        name: "Test App",
        guid: "test-guid",
        status: "Success" as const,
        startTime: "2026-03-28T10:00:00Z",
        endTime: "2026-03-28T10:05:00Z",
        durationSecs: 300,
        errorCode: null,
        detail: "Installed successfully",
        sourceFile: "intune.log",
        lineNumber: 100,
        startTimeEpoch: 1743206400000,
        endTimeEpoch: 1743206700000,
      };

      const summary = {
        totalEvents: 1,
        win32Apps: 1,
        wingetApps: 0,
        scripts: 0,
        remediations: 0,
        succeeded: 1,
        failed: 0,
        inProgress: 0,
        pending: 0,
        timedOut: 0,
        totalDownloads: 0,
        successfulDownloads: 0,
        failedDownloads: 0,
        failedScripts: 0,
        logTimeSpan: null,
      };

      useIntuneStore.getState().setResults(
        [event],
        [],
        summary,
        [],
        "/logs/intune.log",
        ["/logs/intune.log"]
      );

      const state = useIntuneStore.getState();
      expect(state.analysisState.phase).toBe("ready");
      expect(state.isAnalyzing).toBe(false);
      expect(state.events).toHaveLength(1);
      expect(state.events[0].name).toBe("Test App");
    });

    it("analyzing -> error on failAnalysis", () => {
      useIntuneStore.getState().beginAnalysis("/logs/intune.log", "file");
      useIntuneStore.getState().failAnalysis("File not found");

      const state = useIntuneStore.getState();
      expect(state.analysisState.phase).toBe("error");
      expect(state.isAnalyzing).toBe(false);
      expect(state.analysisState.lastError).toBe("File not found");
    });

    it("analyzing -> empty when no logs found", () => {
      useIntuneStore.getState().beginAnalysis("/logs/", "folder");
      useIntuneStore.getState().failAnalysis("Directory does not contain any .log files");

      const state = useIntuneStore.getState();
      expect(state.analysisState.phase).toBe("empty");
    });
  });

  describe("clear", () => {
    it("resets to idle state", () => {
      useIntuneStore.getState().beginAnalysis("/test.log", "file");
      useIntuneStore.getState().clear();

      const state = useIntuneStore.getState();
      expect(state.analysisState.phase).toBe("idle");
      expect(state.isAnalyzing).toBe(false);
      expect(state.events).toHaveLength(0);
    });
  });

  describe("event selection", () => {
    it("selects and deselects events", () => {
      useIntuneStore.getState().selectEvent(42);
      expect(useIntuneStore.getState().selectedEventId).toBe(42);

      useIntuneStore.getState().selectEvent(null);
      expect(useIntuneStore.getState().selectedEventId).toBeNull();
    });
  });

  describe("time window", () => {
    it("sets time window preset", () => {
      useIntuneStore.getState().setTimeWindow("last-7-days");
      expect(useIntuneStore.getState().timeWindow).toBe("last-7-days");

      useIntuneStore.getState().setTimeWindow("all");
      expect(useIntuneStore.getState().timeWindow).toBe("all");
    });
  });

  describe("filters", () => {
    it("sets event type filter", () => {
      useIntuneStore.getState().setFilterEventType("Win32App");
      expect(useIntuneStore.getState().filterEventType).toBe("Win32App");

      useIntuneStore.getState().setFilterEventType("All");
      expect(useIntuneStore.getState().filterEventType).toBe("All");
    });

    it("sets status filter", () => {
      useIntuneStore.getState().setFilterStatus("Failed");
      expect(useIntuneStore.getState().filterStatus).toBe("Failed");
    });
  });

  describe("active tab", () => {
    it("switches tabs", () => {
      useIntuneStore.getState().setActiveTab("downloads");
      expect(useIntuneStore.getState().activeTab).toBe("downloads");

      useIntuneStore.getState().setActiveTab("summary");
      expect(useIntuneStore.getState().activeTab).toBe("summary");
    });
  });
});
