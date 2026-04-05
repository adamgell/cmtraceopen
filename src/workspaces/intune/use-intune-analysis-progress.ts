import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useIntuneStore } from "./intune-store";
import type { IntuneAnalysisProgressEvent } from "./types";

const INTUNE_ANALYSIS_PROGRESS_EVENT = "intune-analysis-progress";

export function useIntuneAnalysisProgress() {
  const updateAnalysisProgress = useIntuneStore((s) => s.updateAnalysisProgress);

  useEffect(() => {
    const unlisten = listen<IntuneAnalysisProgressEvent>(
      INTUNE_ANALYSIS_PROGRESS_EVENT,
      (event) => {
        updateAnalysisProgress(event.payload);
      }
    );

    return () => {
      unlisten.then((dispose) => dispose());
    };
  }, [updateAnalysisProgress]);
}