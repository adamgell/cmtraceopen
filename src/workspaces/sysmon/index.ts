// src/workspaces/sysmon/index.ts
import { startTransition, lazy } from "react";
import type { WorkspaceDefinition } from "../types";

const LIVE_SYSMON_SOURCE_ID = "windows-sysmon-live-events";

function shouldIncludeSysmonLiveEventLogs(source: import("../../types/log").LogSource): boolean {
  return source.kind === "known" && source.sourceId === LIVE_SYSMON_SOURCE_ID;
}

export const sysmonWorkspace: WorkspaceDefinition = {
  id: "sysmon",
  label: "Sysmon",
  platforms: ["windows"],
  component: lazy(() =>
    import("./SysmonWorkspace").then((m) => ({ default: m.SysmonWorkspace }))
  ),
  sidebar: lazy(() =>
    import("./SysmonSidebar").then((m) => ({ default: m.SysmonSidebar }))
  ),
  capabilities: {},
  fileFilters: [
    { name: "EVTX Files", extensions: ["evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open EVTX File",
    folder: "Open EVTX Folder",
    placeholder: "Open Sysmon Source...",
  },
  onOpenSource: async (source, trigger) => {
    const [{ useUiStore }, { getLogSourcePath }, { analyzeSysmonLogs }, { useSysmonStore }] =
      await Promise.all([
        import("../../stores/ui-store"),
        import("../../lib/log-source"),
        import("../../lib/commands"),
        import("./sysmon-store"),
      ]);

    useUiStore.getState().ensureWorkspaceVisible("sysmon", trigger);
    const sourcePath = getLogSourcePath(source);
    const requestId = `sysmon-${Date.now()}`;
    useSysmonStore.getState().beginAnalysis(sourcePath, requestId);

    try {
      const result = await analyzeSysmonLogs(sourcePath, requestId, {
        includeLiveEventLogs: shouldIncludeSysmonLiveEventLogs(source),
      });
      startTransition(() => {
        useSysmonStore.getState().setResults(result);
      });
    } catch (error) {
      console.error("[sysmon] failed to analyze Sysmon source", {
        source,
        trigger,
        error,
      });
      useSysmonStore.getState().failAnalysis(error instanceof Error ? error.message : String(error));
    }
  },
};
