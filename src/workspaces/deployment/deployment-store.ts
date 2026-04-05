import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";

export interface DeploymentLogFile {
  path: string;
  fileName: string;
  format:
    | "psadt-cmtrace"
    | "psadt-legacy"
    | "msi-verbose"
    | "psadt-wrapper"
    | "burn"
    | "patchmypc"
    | "unknown";
  outcome: "success" | "failure" | "deferred" | "unknown";
  exitCode: number | null;
  errorSummary: string | null;
  errorLines: DeploymentErrorLine[];
  appName: string | null;
  appVersion: string | null;
  deployType: string | null;
  startTime: string | null;
  endTime: string | null;
}

export interface DeploymentErrorLine {
  lineNumber: number;
  message: string;
  severity: "Error" | "Warning";
}

export interface DeploymentAnalysisResult {
  folderPath: string;
  files: DeploymentLogFile[];
  totalFiles: number;
  succeeded: number;
  failed: number;
  deferred: number;
  unknown: number;
}

export type DeploymentPhase =
  | "idle"
  | "analyzing"
  | "ready"
  | "error"
  | "empty";

interface DeploymentState {
  phase: DeploymentPhase;
  result: DeploymentAnalysisResult | null;
  errorMessage: string | null;
  expandedErrorIndex: number | null;

  analyzeFolder: (folderPath: string) => Promise<void>;
  reset: () => void;
  toggleErrorExpanded: (index: number) => void;
}

export const useDeploymentStore = create<DeploymentState>((set, get) => ({
  phase: "idle",
  result: null,
  errorMessage: null,
  expandedErrorIndex: null,

  analyzeFolder: async (folderPath: string) => {
    set({ phase: "analyzing", errorMessage: null, expandedErrorIndex: null });
    try {
      const result = await invoke<DeploymentAnalysisResult>(
        "analyze_deployment_folder",
        { folderPath }
      );
      if (result.totalFiles === 0) {
        set({ phase: "empty", result });
      } else {
        set({ phase: "ready", result });
      }
    } catch (error) {
      set({
        phase: "error",
        errorMessage:
          error instanceof Error ? error.message : String(error),
      });
    }
  },

  reset: () => {
    set({
      phase: "idle",
      result: null,
      errorMessage: null,
      expandedErrorIndex: null,
    });
  },

  toggleErrorExpanded: (index: number) => {
    const current = get().expandedErrorIndex;
    set({ expandedErrorIndex: current === index ? null : index });
  },
}));
