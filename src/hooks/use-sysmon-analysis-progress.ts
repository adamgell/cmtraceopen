import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useSysmonStore, type SysmonAnalysisProgress } from "../stores/sysmon-store";

const SYSMON_ANALYSIS_PROGRESS_EVENT = "sysmon-analysis-progress";

export function useSysmonAnalysisProgress() {
  const updateProgress = useSysmonStore((s) => s.updateProgress);

  useEffect(() => {
    const unlisten = listen<SysmonAnalysisProgress>(
      SYSMON_ANALYSIS_PROGRESS_EVENT,
      (event) => {
        updateProgress(event.payload);
      }
    );

    return () => {
      unlisten.then((dispose) => dispose());
    };
  }, [updateProgress]);
}
