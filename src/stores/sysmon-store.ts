import { create } from "zustand";
import type {
  SysmonAnalysisResult,
  SysmonConfig,
  SysmonEvent,
  SysmonEventType,
  SysmonSeverity,
  SysmonSummary,
} from "../types/sysmon";

export type SysmonWorkspaceTab = "events" | "summary" | "config";

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
  sourcePath: string | null;
  isAnalyzing: boolean;
  analysisError: string | null;
  progressMessage: string | null;

  // Interaction state
  selectedEventId: number | null;
  activeTab: SysmonWorkspaceTab;
  filterEventType: SysmonEventType | "All";
  filterSeverity: SysmonSeverity | "All";
  searchQuery: string;

  // Actions
  beginAnalysis: (path: string) => void;
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
  sourcePath: null,
  isAnalyzing: false,
  analysisError: null,
  progressMessage: null,
  selectedEventId: null,
  activeTab: "events",
  filterEventType: "All",
  filterSeverity: "All",
  searchQuery: "",

  beginAnalysis: (path) =>
    set({
      events: [],
      summary: null,
      config: null,
      sourcePath: path,
      isAnalyzing: true,
      analysisError: null,
      progressMessage: "Starting Sysmon analysis...",
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
      sourcePath: result.sourcePath,
      isAnalyzing: false,
      analysisError: null,
      progressMessage: null,
    }),

  failAnalysis: (error) =>
    set({
      isAnalyzing: false,
      analysisError: error,
      progressMessage: null,
    }),

  updateProgress: (progress) =>
    set({
      progressMessage: progress.message,
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
      sourcePath: null,
      isAnalyzing: false,
      analysisError: null,
      progressMessage: null,
      selectedEventId: null,
      activeTab: "events",
      filterEventType: "All",
      filterSeverity: "All",
      searchQuery: "",
    }),
}));
