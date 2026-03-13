import { create } from "zustand";
import type {
  DsregcmdAnalysisResult,
  DsregcmdAnalysisState,
  DsregcmdSourceContext,
  DsregcmdSourceDescriptor,
} from "../types/dsregcmd";

const emptySourceContext: DsregcmdSourceContext = {
  source: null,
  requestedPath: null,
  resolvedPath: null,
  displayLabel: "No dsregcmd source selected",
  evidenceFilePath: null,
  rawLineCount: 0,
  rawCharCount: 0,
};

const defaultAnalysisState: DsregcmdAnalysisState = {
  phase: "idle",
  message: "Choose a dsregcmd source to analyze.",
  detail: null,
  requestedKind: null,
  requestedPath: null,
  lastError: null,
};

interface DsregcmdState {
  result: DsregcmdAnalysisResult | null;
  rawInput: string;
  sourceContext: DsregcmdSourceContext;
  analysisState: DsregcmdAnalysisState;
  isAnalyzing: boolean;
  resultRevision: number;

  beginAnalysis: (source: DsregcmdSourceDescriptor, detail?: string | null) => void;
  setResults: (
    rawInput: string,
    result: DsregcmdAnalysisResult,
    context: DsregcmdSourceContext
  ) => void;
  failAnalysis: (error: unknown) => void;
  clear: () => void;
}

export const useDsregcmdStore = create<DsregcmdState>((set) => ({
  result: null,
  rawInput: "",
  sourceContext: emptySourceContext,
  analysisState: defaultAnalysisState,
  isAnalyzing: false,
  resultRevision: 0,

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
    }),
}));
