import { create } from "zustand";
import type {
  SysmonAnalysisResult,
  SysmonConfig,
  SysmonDashboardData,
  SysmonEvent,
  SysmonEventType,
  SysmonSeverity,
  SysmonSummary,
} from "./types";

export type SysmonWorkspaceTab = "dashboard" | "events" | "summary" | "config";

export interface SysmonAnalysisProgress {
  requestId: string;
  stage: string;
  message: string;
  completedFiles: number;
  totalFiles: number;
}

interface SysmonState {
  events: SysmonEvent[];
  summary: SysmonSummary | null;
  config: SysmonConfig | null;
  dashboard: SysmonDashboardData | null;
  sourcePath: string | null;
  isAnalyzing: boolean;
  analysisError: string | null;
  progressMessage: string | null;
  /** requestId of the active analysis — used to discard stale progress events. */
  currentRequestId: string | null;

  // Interaction state
  selectedEventId: number | null;
  activeTab: SysmonWorkspaceTab;
  filterEventType: SysmonEventType | "All";
  filterSeverity: SysmonSeverity | "All";
  searchQuery: string;

  // Actions
  beginAnalysis: (path: string, requestId: string) => void;
  setResults: (result: SysmonAnalysisResult) => void;
  failAnalysis: (error: string) => void;
  updateProgress: (progress: SysmonAnalysisProgress) => void;
  selectEvent: (id: number | null) => void;
  setActiveTab: (tab: SysmonWorkspaceTab) => void;
  setFilterEventType: (type_: SysmonEventType | "All") => void;
  setFilterSeverity: (severity: SysmonSeverity | "All") => void;
  setSearchQuery: (query: string) => void;
  clear: () => void;
}

export const useSysmonStore = create<SysmonState>((set) => ({
  events: [],
  summary: null,
  config: null,
  dashboard: null,
  sourcePath: null,
  isAnalyzing: false,
  analysisError: null,
  progressMessage: null,
  currentRequestId: null,
  selectedEventId: null,
  activeTab: "events",
  filterEventType: "All",
  filterSeverity: "All",
  searchQuery: "",

  beginAnalysis: (path, requestId) =>
    set({
      events: [],
      summary: null,
      config: null,
      dashboard: null,
      sourcePath: path,
      isAnalyzing: true,
      analysisError: null,
      progressMessage: "Starting Sysmon analysis...",
      currentRequestId: requestId,
      selectedEventId: null,
      filterEventType: "All",
      filterSeverity: "All",
      searchQuery: "",
    }),

  setResults: (result) =>
    set({
      events: result.events,
      summary: result.summary,
      config: result.config,
      dashboard: result.dashboard,
      sourcePath: result.sourcePath,
      isAnalyzing: false,
      analysisError: null,
      progressMessage: null,
      activeTab: "dashboard",
    }),

  failAnalysis: (error) =>
    set({
      isAnalyzing: false,
      analysisError: error,
      progressMessage: null,
    }),

  updateProgress: (progress) =>
    set((state) => {
      if (!state.isAnalyzing) return state;
      if (state.currentRequestId !== null && state.currentRequestId !== progress.requestId) {
        return state;
      }
      return { progressMessage: progress.message };
    }),

  selectEvent: (id) => set({ selectedEventId: id }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  setFilterEventType: (type_) =>
    set({ filterEventType: type_, selectedEventId: null }),

  setFilterSeverity: (severity) =>
    set({ filterSeverity: severity, selectedEventId: null }),

  setSearchQuery: (query) => set({ searchQuery: query }),

  clear: () =>
    set({
      events: [],
      summary: null,
      config: null,
      dashboard: null,
      sourcePath: null,
      isAnalyzing: false,
      analysisError: null,
      progressMessage: null,
      currentRequestId: null,
      selectedEventId: null,
      activeTab: "events",
      filterEventType: "All",
      filterSeverity: "All",
      searchQuery: "",
    }),
}));
