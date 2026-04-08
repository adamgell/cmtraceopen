import { create } from "zustand";
import type {
  SecureBootAnalysisResult,
  SecureBootAnalysisState,
  SecureBootStage,
  SecureBootTabId,
} from "./types";

export { type SecureBootTabId };

const STAGE_LABELS: Record<SecureBootStage, string> = {
  stage0: "Secure Boot Disabled",
  stage1: "Opt-in Not Configured",
  stage2: "Awaiting Windows Update",
  stage3: "Update In Progress",
  stage4: "Pending Reboot",
  stage5: "Compliant",
};

export function stageLabel(stage: SecureBootStage): string {
  return STAGE_LABELS[stage];
}

const defaultAnalysisState: SecureBootAnalysisState = {
  phase: "idle",
  message: "Choose a source to analyze.",
  detail: null,
};

interface SecureBootState {
  result: SecureBootAnalysisResult | null;
  analysisState: SecureBootAnalysisState;
  isAnalyzing: boolean;
  activeTab: SecureBootTabId;
  scriptRunning: string | null;

  beginAnalysis: (message?: string) => void;
  setResult: (result: SecureBootAnalysisResult) => void;
  failAnalysis: (error: unknown) => void;
  setActiveTab: (tab: SecureBootTabId) => void;
  setScriptRunning: (script: string | null) => void;
  clear: () => void;
}

export const useSecureBootStore = create<SecureBootState>((set) => ({
  result: null,
  analysisState: defaultAnalysisState,
  isAnalyzing: false,
  activeTab: "diagnostics",
  scriptRunning: null,

  beginAnalysis: (message = "Analyzing Secure Boot state...") =>
    set({
      result: null,
      analysisState: {
        phase: "analyzing",
        message,
        detail: null,
      },
      isAnalyzing: true,
    }),

  setResult: (result) =>
    set({
      result,
      analysisState: {
        phase: "done",
        message: "Secure Boot analysis complete.",
        detail: stageLabel(result.stage),
      },
      isAnalyzing: false,
    }),

  failAnalysis: (error) => {
    const detail =
      error instanceof Error
        ? error.message
        : typeof error === "string"
          ? error
          : "The Secure Boot analysis could not be completed.";

    set({
      result: null,
      analysisState: {
        phase: "error",
        message: "Secure Boot analysis failed.",
        detail,
      },
      isAnalyzing: false,
    });
  },

  setActiveTab: (tab) => set({ activeTab: tab }),

  setScriptRunning: (script) => set({ scriptRunning: script }),

  clear: () =>
    set({
      result: null,
      analysisState: defaultAnalysisState,
      isAnalyzing: false,
      activeTab: "diagnostics",
      scriptRunning: null,
    }),
}));
