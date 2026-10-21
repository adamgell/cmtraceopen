import { create } from "zustand";
import type {
  DsregcmdAnalysisResult,
  DsregcmdAnalysisState,
  DsregcmdSourceContext,
  DsregcmdSourceDescriptor,
} from "./types";
import type { EventLogChannel, EventLogSeverity } from "../../types/event-log";

const emptySourceContext: DsregcmdSourceContext = {
  source: null,
  requestedPath: null,
  resolvedPath: null,
  bundlePath: null,
  displayLabel: "No dsregcmd source selected",
  evidenceFilePath: null,
  rawLineCount: 0,
  rawCharCount: 0,
  capturedAt: null,
};

const defaultAnalysisState: DsregcmdAnalysisState = {
  phase: "idle",
  message: "Choose a dsregcmd source to analyze.",
  detail: null,
  requestedKind: null,
  requestedPath: null,
  lastError: null,
};

export type DsregcmdTabId = "analysis" | "event-logs";

/** Analysis-view sections the left navigation can target. Order is nav order. */
export const DSREGCMD_SECTION_IDS = [
  "overview",
  "findings",
  "facts",
  "flows",
  "timeline",
  "export",
] as const;
export type DsregcmdSectionId = (typeof DSREGCMD_SECTION_IDS)[number];

/** DOM id of a section's anchor element; also the nav item's `href` fragment. */
export function dsregcmdSectionDomId(section: DsregcmdSectionId | "event-logs"): string {
  return `dsregcmd-section-${section}`;
}

interface DsregcmdState {
  result: DsregcmdAnalysisResult | null;
  rawInput: string;
  sourceContext: DsregcmdSourceContext;
  analysisState: DsregcmdAnalysisState;
  isAnalyzing: boolean;
  resultRevision: number;

  activeTab: DsregcmdTabId;
  /** Section the scroll-spy (or a nav click) last marked as current. */
  activeSection: DsregcmdSectionId;
  /** Section a nav click asked the workspace to scroll to once it is mounted. */
  pendingScrollSection: DsregcmdSectionId | null;
  /** Whether "Not reported" fact rows are shown; shared so nav counts match the page. */
  showNotReported: boolean;
  eventLogFilterChannel: EventLogChannel | "All";
  eventLogFilterSeverity: EventLogSeverity | "All";
  selectedEventLogEntryId: number | null;

  beginAnalysis: (source: DsregcmdSourceDescriptor, detail?: string | null) => void;
  setResults: (
    rawInput: string,
    result: DsregcmdAnalysisResult,
    context: DsregcmdSourceContext
  ) => void;
  failAnalysis: (error: unknown) => void;
  clear: () => void;
  setActiveTab: (tab: DsregcmdTabId) => void;
  setActiveSection: (section: DsregcmdSectionId) => void;
  /** Return to the analysis view and scroll to `section`. */
  navigateToSection: (section: DsregcmdSectionId) => void;
  clearPendingScroll: () => void;
  setShowNotReported: (show: boolean) => void;
  setEventLogFilterChannel: (channel: EventLogChannel | "All") => void;
  setEventLogFilterSeverity: (severity: EventLogSeverity | "All") => void;
  selectEventLogEntry: (id: number | null) => void;
}

export const useDsregcmdStore = create<DsregcmdState>((set) => ({
  result: null,
  rawInput: "",
  sourceContext: emptySourceContext,
  analysisState: defaultAnalysisState,
  isAnalyzing: false,
  resultRevision: 0,

  activeTab: "analysis" as DsregcmdTabId,
  activeSection: "overview" as DsregcmdSectionId,
  pendingScrollSection: null as DsregcmdSectionId | null,
  showNotReported: false,
  eventLogFilterChannel: "All" as EventLogChannel | "All",
  eventLogFilterSeverity: "All" as EventLogSeverity | "All",
  selectedEventLogEntryId: null,

  beginAnalysis: (source, detail = null) =>
    set({
      result: null,
      rawInput: "",
      sourceContext: {
        ...emptySourceContext,
        source,
        requestedPath: "path" in source ? source.path : null,
        displayLabel:
          source.kind === "clipboard"
            ? "Clipboard"
            : source.kind === "capture"
              ? "Live capture"
              : source.kind === "text"
                ? source.label
                : source.path,
      },
      analysisState: {
        phase: "analyzing",
        message:
          source.kind === "folder"
            ? "Analyzing dsregcmd evidence bundle..."
            : source.kind === "capture"
              ? "Capturing dsregcmd /status..."
              : source.kind === "clipboard"
                ? "Reading clipboard..."
                : "Analyzing dsregcmd source...",
        detail,
        requestedKind: source.kind,
        requestedPath: "path" in source ? source.path : null,
        lastError: null,
      },
      isAnalyzing: true,
    }),

  setResults: (rawInput, result, context) =>
    set((state) => ({
      rawInput,
      result,
      sourceContext: context,
      analysisState: {
        phase: "ready",
        message: "dsregcmd analysis complete.",
        detail: context.resolvedPath ?? context.displayLabel,
        requestedKind: context.source?.kind ?? null,
        requestedPath: context.requestedPath,
        lastError: null,
      },
      isAnalyzing: false,
      resultRevision: state.resultRevision + 1,
    })),

  failAnalysis: (error) =>
    set((state) => {
      const detail =
        error instanceof Error
          ? error.message
          : typeof error === "string"
            ? error
            : "The selected dsregcmd source could not be analyzed.";

      return {
        result: null,
        rawInput: "",
        analysisState: {
          phase: "error",
          message: "dsregcmd analysis failed.",
          detail,
          requestedKind: state.analysisState.requestedKind,
          requestedPath: state.analysisState.requestedPath,
          lastError: detail,
        },
        isAnalyzing: false,
      };
    }),

  clear: () =>
    set({
      result: null,
      rawInput: "",
      sourceContext: emptySourceContext,
      analysisState: defaultAnalysisState,
      isAnalyzing: false,
      activeTab: "analysis",
      activeSection: "overview",
      pendingScrollSection: null,
      showNotReported: false,
      selectedEventLogEntryId: null,
    }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  setActiveSection: (section) => set({ activeSection: section }),

  navigateToSection: (section) =>
    set({
      activeTab: "analysis",
      activeSection: section,
      pendingScrollSection: section,
    }),

  clearPendingScroll: () => set({ pendingScrollSection: null }),

  setShowNotReported: (show) => set({ showNotReported: show }),

  setEventLogFilterChannel: (channel) =>
    set({ eventLogFilterChannel: channel, selectedEventLogEntryId: null }),

  setEventLogFilterSeverity: (severity) =>
    set({ eventLogFilterSeverity: severity, selectedEventLogEntryId: null }),

  selectEventLogEntry: (id) =>
    set((state) => ({
      selectedEventLogEntryId:
        state.selectedEventLogEntryId === id ? null : id,
    })),
}));
